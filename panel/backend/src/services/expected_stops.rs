//! Deliberate container stops - the one place that records, reads and clears them.
//!
//! The alert engine cannot otherwise tell "the operator stopped this" from "this
//! crashed": it sees `exited`/`dead` in a 120-second poll of the agent's `/apps`
//! and fires `container_down`. Every writer that stops a managed container on
//! purpose records a row here; the engine reads it before firing and deletes it
//! the moment the container is observed in any state that is not exited/dead.
//!
//! Keyed on `(server_id, container_name)` - the same key `alert_state` uses for
//! this alert type - never on `container_id`, which changes on every app Update
//! (`update_app`/`change_container_image`/`update_env` re-create the container)
//! and is not unique across a cloned fleet member. See the migration for the
//! full reasoning.

use sqlx::PgPool;
use std::collections::HashSet;
use uuid::Uuid;

/// Why a container is stopped. Stored verbatim so the UI can say it in words.
pub const REASON_OPERATOR_STOP: &str = "operator_stop";
pub const REASON_MANUAL_SLEEP: &str = "manual_sleep";
pub const REASON_AUTO_SLEEP: &str = "auto_sleep";
pub const REASON_STACK_STOP: &str = "stack_stop";
/// Update/change-image/edit-env recreate the container - `docker rm` then
/// `docker create` (or its blue-green equivalent) - which is genuinely
/// exited/absent for part of that window even though nobody asked it to stay
/// down. Recorded BEFORE the agent call starts, unlike every other reason
/// here: those record only after a stop has already succeeded, but a
/// recreate's whole point is to interrupt a running container on purpose, so
/// the healer must be blind to the gap from the moment it opens, not after.
/// [[project_dockpanel_tech_debt_p185]] carry G.
pub const REASON_RECREATE: &str = "recreate_in_progress";
/// An app data backup or restore: the agent stops the running containers that
/// mount the data for the copy or the extraction and starts them again itself.
/// Recorded BEFORE the agent call, like [`REASON_RECREATE`], because the stop
/// happens inside that call and lasts minutes - the healer must not "repair"
/// an app in the middle of a restore. Unlike every other reason it EXPIRES
/// after [`BACKUP_STOP_TTL_SECS`]: if the agent dies mid-operation and never
/// restarts the containers, the healer and the down alert take over again.
pub const REASON_BACKUP: &str = "backup_in_progress";

/// Lifetime of a [`REASON_BACKUP`] expectation, from the moment it is recorded:
/// the policy executor's whole budget for one archive
/// (`backup_policy_executor::APP_DATA_BACKUP_TIMEOUT_SECS`, 1800 s) plus ten
/// minutes. It also covers a restore that outlived its 270 s request, which the
/// agent carries on (its own budget is shorter than this).
pub const BACKUP_STOP_TTL_SECS: i64 = 2400;

/// Record that this container was stopped on purpose.
///
/// ⚠ Call this only AFTER the stop has actually succeeded. Recording it first
/// and having the agent refuse would mark a still-RUNNING container as
/// expectedly stopped, and the next genuine crash would be suppressed.
pub async fn record(
    pool: &PgPool,
    server_id: Uuid,
    container_name: &str,
    reason: &str,
    actor_email: Option<&str>,
) {
    let res = sqlx::query(
        "INSERT INTO container_expected_stops (server_id, container_name, reason, actor_email, stopped_at) \
         VALUES ($1, $2, $3, $4, NOW()) \
         ON CONFLICT (server_id, container_name) DO UPDATE SET \
             reason = $3, actor_email = $4, stopped_at = NOW()",
    )
    .bind(server_id)
    .bind(container_name)
    .bind(reason)
    .bind(actor_email)
    .execute(pool)
    .await;

    if let Err(e) = res {
        // Deliberately not fatal: failing to record an expectation costs a
        // spurious alert, while failing the operator's stop costs them the
        // action they asked for. But it must be visible - a silent miss here
        // looks exactly like the defect this table exists to fix.
        tracing::warn!(
            "Could not record expected stop for '{container_name}' on server {server_id}: {e}"
        );
    }
}

/// Forget the expectation - the container is running again, or is being started.
pub async fn clear(pool: &PgPool, server_id: Uuid, container_name: &str) {
    let _ = sqlx::query(
        "DELETE FROM container_expected_stops WHERE server_id = $1 AND container_name = $2",
    )
    .bind(server_id)
    .bind(container_name)
    .execute(pool)
    .await;
}

/// Clear from OBSERVATION, without racing a stop recorded mid-sweep.
///
/// `check_container_health` takes ONE `/apps` snapshot and then walks it with
/// awaited database and notification calls per container, so several seconds can
/// pass between the observation and this call. In that window the operator may
/// have pressed Stop. Deleting unconditionally would discard an expectation that
/// is NEWER than the evidence being used to discard it, and the next sweep would
/// then fire the alert this table exists to prevent.
///
/// `observed_at` is stamped before the snapshot is fetched, so only an
/// expectation that predates the observation is cleared.
pub async fn clear_if_older_than(
    pool: &PgPool,
    server_id: Uuid,
    container_name: &str,
    observed_at: chrono::DateTime<chrono::Utc>,
) {
    // A live backup expectation is recorded BEFORE the agent stops anything,
    // so seeing the container still running says nothing against it: it is
    // left to the backup's own clear, or to its expiry.
    let _ = sqlx::query(
        "DELETE FROM container_expected_stops \
         WHERE server_id = $1 AND container_name = $2 AND stopped_at < $3 \
           AND NOT (reason = $4 AND stopped_at >= NOW() - make_interval(secs => $5))",
    )
    .bind(server_id)
    .bind(container_name)
    .bind(observed_at)
    .bind(REASON_BACKUP)
    .bind(BACKUP_STOP_TTL_SECS as f64)
    .execute(pool)
    .await;
}

// ── App data backup and restore: stops the agent makes inside one call ─────

/// Where backup expectations are written. A trait so the record/clear cycle
/// around an agent call can be tested without a database.
pub(crate) trait BackupStopLedger {
    async fn record_all(&self, names: &[String]);
    async fn clear_all(&self, names: &[String]);
}

/// The real ledger: `container_expected_stops` rows of one server.
pub(crate) struct DbBackupStops<'a> {
    pub pool: &'a PgPool,
    pub server_id: Uuid,
}

impl BackupStopLedger for DbBackupStops<'_> {
    /// Insert-if-absent: a container that already carries an expectation (an
    /// operator stop, a sleep) keeps it, and its reason. The agent only stops
    /// RUNNING containers, so such a container is not touched by the backup.
    async fn record_all(&self, names: &[String]) {
        for name in names {
            if let Err(e) = sqlx::query(
                "INSERT INTO container_expected_stops (server_id, container_name, reason, actor_email, stopped_at) \
                 VALUES ($1, $2, $3, NULL, NOW()) ON CONFLICT (server_id, container_name) DO NOTHING",
            )
            .bind(self.server_id)
            .bind(name)
            .bind(REASON_BACKUP)
            .execute(self.pool)
            .await
            {
                tracing::warn!(
                    "Could not record the backup stop of '{name}' on server {}: {e} - the auto-healer may restart it mid-operation",
                    self.server_id
                );
            }
        }
    }

    /// Deletes only this reason's rows, never an operator's own stop.
    async fn clear_all(&self, names: &[String]) {
        for name in names {
            if let Err(e) = sqlx::query(
                "DELETE FROM container_expected_stops \
                 WHERE server_id = $1 AND container_name = $2 AND reason = $3",
            )
            .bind(self.server_id)
            .bind(name)
            .bind(REASON_BACKUP)
            .execute(self.pool)
            .await
            {
                tracing::warn!(
                    "Could not clear the backup stop of '{name}' on server {}: {e} - it expires after {BACKUP_STOP_TTL_SECS}s",
                    self.server_id
                );
            }
        }
    }
}

/// Is this agent error our own client-side timeout? Then the agent is still
/// working (and holding the app stopped), whatever we answer.
pub fn is_agent_timeout(e: &crate::services::agent::AgentError) -> bool {
    matches!(e, crate::services::agent::AgentError::Request(d) if d.contains("timed out"))
}

/// Run one agent call that may stop `names` (the running containers that mount
/// the data), with those containers recorded as expectedly stopped for its
/// whole duration.
///
/// Cleared after the call on success and on every agent error: the agent
/// restarts the containers itself before it answers, failure included. NOT
/// cleared when the call timed out on OUR side: the agent is then still
/// copying or extracting with the app stopped, and clearing would let the
/// healer start the app in the middle of it. That row ends with
/// [`BACKUP_STOP_TTL_SECS`], after which a container still down is healed and
/// alerted like any crash - which is also what happens if the agent dies
/// mid-operation.
pub(crate) async fn guard_backup_stops<L, T, F>(
    ledger: &L,
    names: &[String],
    call: F,
) -> Result<T, crate::services::agent::AgentError>
where
    L: BackupStopLedger,
    F: std::future::Future<Output = Result<T, crate::services::agent::AgentError>>,
{
    if names.is_empty() {
        return call.await;
    }
    ledger.record_all(names).await;
    let result = call.await;
    match &result {
        Err(e) if is_agent_timeout(e) => {
            tracing::warn!(
                "App data operation outlived its request with {} container(s) stopped; \
                 their expected stop is kept until the agent restarts them or it expires ({BACKUP_STOP_TTL_SECS}s)",
                names.len()
            );
        }
        _ => ledger.clear_all(names).await,
    }
    result
}

#[cfg(test)]
mod backup_stop_tests {
    use super::*;
    use crate::services::agent::AgentError;
    use std::sync::Mutex;

    #[derive(Default)]
    struct FakeLedger {
        log: Mutex<Vec<String>>,
    }

    impl BackupStopLedger for FakeLedger {
        async fn record_all(&self, names: &[String]) {
            self.log.lock().unwrap().push(format!("record {}", names.join(",")));
        }
        async fn clear_all(&self, names: &[String]) {
            self.log.lock().unwrap().push(format!("clear {}", names.join(",")));
        }
    }

    fn names() -> Vec<String> {
        vec!["demo-db-1".to_string(), "demo-app-1".to_string()]
    }

    fn block<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread().build().unwrap().block_on(f)
    }

    #[test]
    fn success_records_before_and_clears_after() {
        let l = FakeLedger::default();
        let r = block(guard_backup_stops(&l, &names(), async {
            // The expectation must already be there while the agent works.
            Ok::<_, AgentError>(1)
        }));
        assert_eq!(r.unwrap(), 1);
        assert_eq!(*l.log.lock().unwrap(), vec!["record demo-db-1,demo-app-1", "clear demo-db-1,demo-app-1"]);
    }

    #[test]
    fn the_record_happens_before_the_call_runs() {
        let l = FakeLedger::default();
        let r = block(guard_backup_stops(&l, &names(), async {
            Ok::<_, AgentError>(l.log.lock().unwrap().len())
        }));
        assert_eq!(r.unwrap(), 1, "one record entry existed when the call ran");
    }

    #[test]
    fn an_agent_error_still_clears() {
        for e in [
            AgentError::Status(500, "tar failed".into()),
            AgentError::Status(422, "integrity".into()),
            AgentError::Status(507, "disk".into()),
            AgentError::Connection("refused".into()),
            AgentError::Request("connection reset".into()),
        ] {
            let l = FakeLedger::default();
            let r = block(guard_backup_stops(&l, &names(), async move { Err::<(), _>(e) }));
            assert!(r.is_err());
            assert_eq!(l.log.lock().unwrap().len(), 2, "record then clear");
            assert!(l.log.lock().unwrap()[1].starts_with("clear"));
        }
    }

    #[test]
    fn our_timeout_keeps_the_expectation_for_its_expiry() {
        let l = FakeLedger::default();
        let r = block(guard_backup_stops(&l, &names(), async {
            Err::<(), _>(AgentError::Request("agent request timed out after 270s".into()))
        }));
        assert!(r.is_err());
        assert_eq!(*l.log.lock().unwrap(), vec!["record demo-db-1,demo-app-1"]);
    }

    #[test]
    fn nothing_to_protect_touches_nothing() {
        let l = FakeLedger::default();
        let r = block(guard_backup_stops(&l, &[], async { Ok::<_, AgentError>(()) }));
        assert!(r.is_ok());
        assert!(l.log.lock().unwrap().is_empty());
    }

    #[test]
    fn the_expiry_outlasts_every_app_data_budget() {
        use crate::services::backup_policy_executor as bpe;
        assert!(BACKUP_STOP_TTL_SECS as u64 > bpe::APP_DATA_BACKUP_TIMEOUT_SECS);
        assert!(BACKUP_STOP_TTL_SECS as u64 > bpe::APP_DATA_ROUTE_TIMEOUT_SECS);
    }
}

/// Forget every expectation for a container this host no longer reports.
///
/// [`clear_if_older_than`] above runs from OBSERVING a container alive, so it
/// can only ever reach a container that still exists. A REMOVED one is never
/// observed again in any state, and nothing else reaches its row: the engine
/// keeps skipping its `container_down` branch, the auto-heal restart leg keeps
/// skipping it, and the Apps page keeps calling it "stopped on purpose" and
/// naming whoever stopped the container that is gone. Not for a container that
/// is absent - for the NEXT container of that name, which is the one that
/// crashed.
///
/// Removing an app and redeploying it under the same name is the supported way
/// to rebuild it while keeping its data (the data tree is keyed on the app's own
/// name, not on the container), so the container this silences is not a corner
/// case. It is the repair loop: stop it because it is misbehaving, remove it,
/// redeploy it, and it is still misbehaving.
///
/// `alert_engine` runs the identical sweep for `alert_state` at the same call
/// site, for the identical reason and after an identical live incident that ran
/// four months. This is that sweep's missing twin.
///
/// ⚠ `observed` MUST be the host's complete listing, and an empty one does
/// nothing. `container_name <> ALL('{}')` is true for every row, so a listing
/// that is empty because the host could not be read would clear every
/// expectation at once - and the next sweep would fire `container_down` for
/// every container the operator had deliberately stopped, which is the defect
/// this table was created to remove. An empty listing is the one observation
/// that cannot tell "nothing is here" from "I can see nothing", and the cost of
/// reading it wrong is not symmetric. A host with no containers has nothing for
/// an expectation to suppress anyway; the removal doors clear their own row.
///
/// `stopped_at < observed_at` is the guard [`clear_if_older_than`] carries, for
/// the same race: the snapshot is taken once and walked with awaited calls per
/// container, so an expectation recorded inside that window is NEWER than the
/// evidence being used to discard it.
pub async fn clear_absent(
    pool: &PgPool,
    server_id: Uuid,
    observed: &[String],
    observed_at: chrono::DateTime<chrono::Utc>,
) {
    if observed.is_empty() {
        return;
    }

    let _ = sqlx::query(
        "DELETE FROM container_expected_stops \
         WHERE server_id = $1 AND stopped_at < $2 AND container_name <> ALL($3)",
    )
    .bind(server_id)
    .bind(observed_at)
    .bind(observed)
    .execute(pool)
    .await;
}

/// Every container this host is expected to be holding stopped.
///
/// Loaded once per member per sweep rather than queried per container: the
/// health check already walks every container the host reports, and a query
/// each would multiply the sweep's database round-trips by the app count.
///
/// An expired [`REASON_BACKUP`] row is not an expectation any more: the
/// operation it covered has outlived every budget, so a container still down is
/// treated as crashed (healed, alerted).
pub async fn expected_on_server(pool: &PgPool, server_id: Uuid) -> HashSet<String> {
    sqlx::query_as::<_, (String,)>(
        "SELECT container_name FROM container_expected_stops WHERE server_id = $1 \
         AND NOT (reason = $2 AND stopped_at < NOW() - make_interval(secs => $3))",
    )
    .bind(server_id)
    .bind(REASON_BACKUP)
    .bind(BACKUP_STOP_TTL_SECS as f64)
    .fetch_all(pool)
    .await
    .map(|rows| rows.into_iter().map(|(n,)| n).collect())
    .unwrap_or_default()
}

/// The reason a container is stopped (plus who stopped it, if a person did),
/// for the operator-facing surfaces. `actor_email` is NULL for auto_sleep,
/// which no person initiates - see `record()`'s own doc comment.
pub async fn reasons_on_server(
    pool: &PgPool,
    server_id: Uuid,
) -> Vec<(String, String, Option<String>)> {
    sqlx::query_as::<_, (String, String, Option<String>)>(
        "SELECT container_name, reason, actor_email FROM container_expected_stops WHERE server_id = $1",
    )
    .bind(server_id)
    .fetch_all(pool)
    .await
    .unwrap_or_default()
}

/// Close out an alert the container had already raised before it was stopped.
///
/// The sequence this exists for is the common one, and it is the reverse of the
/// one the suppression models: the container CRASHES, `container_down` fires and
/// an incident opens, and THEN the operator presses Stop to take it out of
/// service while they investigate. From that moment the engine's exited arm is
/// skipped, so nothing re-evaluates the row - the recovery arm cannot resolve it
/// (the container is deliberately down) and the stale sweep cannot either (an
/// exited container is still listed by the agent). The row would stay 'firing'
/// for ever, escalating for seven days, with the incident published throughout.
///
/// So recording an expectation is also a resolve point.
pub async fn resolve_open_container_down(pool: &PgPool, server_id: Uuid, container_name: &str) {
    let owner: Option<(Uuid,)> = sqlx::query_as("SELECT user_id FROM servers WHERE id = $1")
        .bind(server_id)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();
    let Some((user_id,)) = owner else { return };

    let firing: Option<(String,)> = sqlx::query_as(
        "SELECT current_state FROM alert_state \
         WHERE server_id = $1 AND alert_type = 'container_down' AND state_key = $2",
    )
    .bind(server_id)
    .bind(container_name)
    .fetch_optional(pool)
    .await
    .ok()
    .flatten();

    if firing.as_ref().map(|s| s.0.as_str()) != Some("firing") {
        return;
    }

    let _ = sqlx::query(
        "UPDATE alert_state SET current_state = 'ok', fired_at = NULL, last_notified_at = NULL \
         WHERE server_id = $1 AND alert_type = 'container_down' AND state_key = $2",
    )
    .bind(server_id)
    .bind(container_name)
    .execute(pool)
    .await;

    crate::services::notifications::resolve_alert(
        pool,
        user_id,
        Some(server_id),
        None,
        "container_down",
        container_name,
        &format!("Container '{container_name}' was stopped deliberately"),
        &format!(
            "Docker container '{container_name}' is stopped because it was asked to be. \
             The earlier alert has been resolved."
        ),
    )
    .await;

    // `resolve_alert` writes to `alerts` and nothing else - it has no reference
    // to `managed_incidents` - so an incident auto-opened for this container
    // would otherwise stay `investigating` on the public status page until a
    // human closed it by hand. Matched on the EXACT generated title for both
    // terminal states, never a LIKE, so a container whose name is a prefix of
    // another's cannot close its neighbour's incident.
    for state in ["exited", "dead"] {
        let _ = sqlx::query(
            "UPDATE managed_incidents SET status = 'resolved', resolved_at = NOW() \
             WHERE user_id = $1 AND title = $2 AND status NOT IN ('resolved', 'postmortem')",
        )
        .bind(user_id)
        .bind(format!("Container '{container_name}' is {state}"))
        .execute(pool)
        .await;
    }
}
