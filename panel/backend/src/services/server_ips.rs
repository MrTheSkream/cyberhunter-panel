//! Multi-IP: which address an object uses (conception/01-multi-ip.md §5.3).
//!
//! Three questions, answered once here so the vhost, the DNS writers, the DNS
//! checks and the mail sync cannot disagree:
//!
//! * **Bind address of a site** — `sites.ip_id`, else the primary address. The
//!   backend cannot know the primary address (its idea of the local box's address
//!   comes from ipify), so "primary" is sent to the agent as the literal
//!   [`PRIMARY`] and the agent resolves it.
//! * **Send address of a mail domain** — `mail_domains.send_ip_id` (forced), else
//!   the address of the same-named site on the same server, else primary — the
//!   HestiaCP behaviour, where a mail domain follows its web domain's address.
//! * **Address to publish in DNS** — the declared row's `public_ip` (NAT), else its
//!   `ip`, else [`crate::helpers::public_ip_for_server`] for the primary address.
//!
//! The precedence lives in the pure functions below; the async ones only load rows.

use uuid::Uuid;

use crate::models::Site;

/// The `bind_ip` value that asks the agent for its own primary address.
pub const PRIMARY: &str = "primary";

/// The parts of a `server_ips` row the resolution needs.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub struct DeclaredIp {
    pub id: Uuid,
    pub ip: String,
    pub public_ip: Option<String>,
    pub ptr: Option<String>,
}

impl DeclaredIp {
    /// The address other machines see: `public_ip` when one is set (NAT), else `ip`.
    pub fn dns_address(&self) -> String {
        self.public_ip
            .as_deref()
            .map(str::trim)
            .filter(|p| !p.is_empty())
            .unwrap_or(&self.ip)
            .to_string()
    }

    /// The HELO name for mail sent from this address — its PTR, if one was read.
    pub fn helo(&self) -> Option<String> {
        self.ptr
            .as_deref()
            .map(|p| p.trim().trim_end_matches('.'))
            .filter(|p| !p.is_empty())
            .map(str::to_string)
    }
}

/// The `bind_ip` the agent receives for a site: the declared address, or
/// [`PRIMARY`] when the site has none. Never absent from a backend-built body.
pub fn bind_ip_value(declared_ip: Option<&str>) -> String {
    declared_ip
        .map(str::trim)
        .filter(|ip| !ip.is_empty())
        .unwrap_or(PRIMARY)
        .to_string()
}

/// Why a mail domain sends from the address it does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendIpSource {
    /// `send_ip_id` is set.
    Forced,
    /// Automatic, following the same-named site, which has its own address.
    Site,
    /// Automatic, and nothing names an address: the primary one.
    Primary,
}

impl SendIpSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Forced => "forced",
            Self::Site => "site",
            Self::Primary => "primary",
        }
    }
}

/// The resolved send address of a mail domain. `ip: None` = the primary address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SendIp {
    pub ip: Option<DeclaredIp>,
    pub source: SendIpSource,
}

/// Forced → same-named site's address → primary.
///
/// `same_domain_site`: `None` = no site of that name on the server;
/// `Some(None)` = a site on the primary address; `Some(Some(ip))` = a site with
/// its own address. A site on the primary address resolves to `Primary`, not
/// `Site`: the address is the primary one either way, and `Site` is reserved for
/// "this domain sends from an address because its site has one".
pub fn resolve_send_ip(
    forced: Option<DeclaredIp>,
    same_domain_site: Option<Option<DeclaredIp>>,
) -> SendIp {
    if let Some(ip) = forced {
        return SendIp { ip: Some(ip), source: SendIpSource::Forced };
    }
    match same_domain_site {
        Some(Some(ip)) => SendIp { ip: Some(ip), source: SendIpSource::Site },
        _ => SendIp { ip: None, source: SendIpSource::Primary },
    }
}

/// The DNS address for an object on `declared` (None = primary), given the
/// server's published primary address.
pub fn dns_address(declared: Option<&DeclaredIp>, server_public: Option<&str>) -> Option<String> {
    match declared {
        Some(ip) => Some(ip.dns_address()),
        None => server_public
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string),
    }
}

/// The two addresses a mail domain's records carry: `(A @, SPF ip4:)`.
///
/// SPF authorises the SEND address. The apex A record is the website's address
/// when a same-named site exists (it is the same record the site's auto-DNS
/// publishes, so the two writers must agree), else the send address.
pub fn mail_dns_addresses(
    same_domain_site: Option<Option<&DeclaredIp>>,
    send: &SendIp,
    server_public: Option<&str>,
) -> (Option<String>, Option<String>) {
    let spf = dns_address(send.ip.as_ref(), server_public);
    let a = match same_domain_site {
        Some(site_ip) => dns_address(site_ip, server_public),
        None => spf.clone(),
    };
    (a, spf)
}

/// Whether resolving these needs the server's primary public address at all —
/// so callers skip the (possibly outbound) [`crate::helpers::public_ip_for_server`]
/// lookup when every address is declared.
pub fn needs_primary_address(same_domain_site: Option<Option<&DeclaredIp>>, send: &SendIp) -> bool {
    send.ip.is_none() || matches!(same_domain_site, Some(None))
}

// ── loaders ─────────────────────────────────────────────────────────────

/// One declared address by id.
pub async fn declared_ip(db: &sqlx::PgPool, id: Uuid) -> Result<Option<DeclaredIp>, sqlx::Error> {
    sqlx::query_as("SELECT id, ip, public_ip, ptr FROM server_ips WHERE id = $1")
        .bind(id)
        .fetch_optional(db)
        .await
}

/// One declared address by id, only if it belongs to `server_id` — the check
/// every write that attaches an address to an object makes (§3: the address must
/// be on the object's own server).
pub async fn declared_ip_on_server(
    db: &sqlx::PgPool,
    id: Uuid,
    server_id: Uuid,
) -> Result<Option<DeclaredIp>, sqlx::Error> {
    sqlx::query_as("SELECT id, ip, public_ip, ptr FROM server_ips WHERE id = $1 AND server_id = $2")
        .bind(id)
        .bind(server_id)
        .fetch_optional(db)
        .await
}

/// The `bind_ip` to put in this site's vhost body.
///
/// `None` only when the lookup itself failed: the caller then omits the key and
/// the agent keeps the address already written in the vhost — which is the safe
/// direction. Sending [`PRIMARY`] on a failed read would move the site.
pub async fn nginx_bind_ip(db: &sqlx::PgPool, site: &Site) -> Option<String> {
    let Some(ip_id) = site.ip_id else {
        return Some(PRIMARY.to_string());
    };
    match declared_ip(db, ip_id).await {
        Ok(Some(row)) => Some(bind_ip_value(Some(&row.ip))),
        Ok(None) => {
            // Unreachable while the FK holds.
            tracing::warn!("Site {}: ip_id {ip_id} names no server_ips row — leaving the vhost's address as it is", site.domain);
            None
        }
        Err(e) => {
            tracing::warn!("Site {}: could not read its address ({e}) — leaving the vhost's address as it is", site.domain);
            None
        }
    }
}

/// Fill the response-only `bind_ip` field of a site.
pub async fn fill_bind_ip(db: &sqlx::PgPool, site: &mut Site) {
    fill_bind_ips(db, std::slice::from_mut(site)).await;
}

/// Fill the response-only `bind_ip` field of several sites in one query.
pub async fn fill_bind_ips(db: &sqlx::PgPool, sites: &mut [Site]) {
    let ids: Vec<Uuid> = sites.iter().filter_map(|s| s.ip_id).collect();
    if ids.is_empty() {
        for s in sites.iter_mut() {
            s.bind_ip = None;
        }
        return;
    }
    let rows: Vec<(Uuid, String)> = sqlx::query_as("SELECT id, ip FROM server_ips WHERE id = ANY($1)")
        .bind(&ids)
        .fetch_all(db)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("Could not read site addresses: {e}");
            Vec::new()
        });
    for s in sites.iter_mut() {
        s.bind_ip = s
            .ip_id
            .and_then(|id| rows.iter().find(|(rid, _)| *rid == id).map(|(_, ip)| ip.clone()));
    }
}

/// The address to publish in DNS for a site on `server_id` bound to `ip_id`.
pub async fn site_dns_address(
    db: &sqlx::PgPool,
    server_id: Option<Uuid>,
    ip_id: Option<Uuid>,
) -> Option<String> {
    if let Some(id) = ip_id {
        match declared_ip(db, id).await {
            Ok(Some(row)) => return Some(row.dns_address()),
            Ok(None) => {}
            Err(e) => {
                // A read failure must not fall through to the primary address:
                // that would publish (or match for deletion) the wrong machine.
                tracing::warn!("Could not read address {id}: {e}");
                return None;
            }
        }
    }
    crate::helpers::public_ip_for_server(db, server_id).await
}

/// Everything the send-address resolution needs for one mail domain.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct MailIpRow {
    pub id: Uuid,
    pub domain: String,
    pub enabled: bool,
    pub catch_all: Option<String>,
    pub f_id: Option<Uuid>,
    pub f_ip: Option<String>,
    pub f_public_ip: Option<String>,
    pub f_ptr: Option<String>,
    pub has_site: bool,
    pub s_id: Option<Uuid>,
    pub s_ip: Option<String>,
    pub s_public_ip: Option<String>,
    pub s_ptr: Option<String>,
}

impl MailIpRow {
    fn forced(&self) -> Option<DeclaredIp> {
        Some(DeclaredIp {
            id: self.f_id?,
            ip: self.f_ip.clone()?,
            public_ip: self.f_public_ip.clone(),
            ptr: self.f_ptr.clone(),
        })
    }

    /// `None` = no same-named site; `Some(None)` = one on the primary address.
    pub fn site(&self) -> Option<Option<DeclaredIp>> {
        if !self.has_site {
            return None;
        }
        Some(match (self.s_id, self.s_ip.clone()) {
            (Some(id), Some(ip)) => Some(DeclaredIp {
                id,
                ip,
                public_ip: self.s_public_ip.clone(),
                ptr: self.s_ptr.clone(),
            }),
            _ => None,
        })
    }

    pub fn send_ip(&self) -> SendIp {
        resolve_send_ip(self.forced(), self.site())
    }
}

/// The projection behind [`MailIpRow`]. The same-named site is the one on the
/// domain's own server, matched the way the rest of the mail module matches it
/// (`lower(s.domain) = md.domain`).
const MAIL_IP_SELECT: &str = "SELECT md.id, md.domain, md.enabled, md.catch_all, md.send_ip_id, \
     f.id AS f_id, f.ip AS f_ip, f.public_ip AS f_public_ip, f.ptr AS f_ptr, \
     (st.id IS NOT NULL) AS has_site, \
     sip.id AS s_id, sip.ip AS s_ip, sip.public_ip AS s_public_ip, sip.ptr AS s_ptr \
     FROM mail_domains md \
     LEFT JOIN server_ips f ON f.id = md.send_ip_id \
     LEFT JOIN LATERAL (SELECT s.id, s.ip_id FROM sites s \
         WHERE s.server_id = md.server_id AND lower(s.domain) = md.domain \
         ORDER BY s.created_at LIMIT 1) st ON true \
     LEFT JOIN server_ips sip ON sip.id = st.ip_id";

/// Resolution rows for every mail domain on one server, ordered by domain.
pub async fn mail_ip_rows_for_server(
    db: &sqlx::PgPool,
    server_id: Uuid,
) -> Result<Vec<MailIpRow>, sqlx::Error> {
    sqlx::query_as(&format!("{MAIL_IP_SELECT} WHERE md.server_id = $1 ORDER BY md.domain"))
        .bind(server_id)
        .fetch_all(db)
        .await
}

/// Resolution rows for the given mail domain ids.
pub async fn mail_ip_rows_by_ids(
    db: &sqlx::PgPool,
    ids: &[Uuid],
) -> Result<Vec<MailIpRow>, sqlx::Error> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    sqlx::query_as(&format!("{MAIL_IP_SELECT} WHERE md.id = ANY($1)"))
        .bind(ids)
        .fetch_all(db)
        .await
}

/// `(A @, SPF ip4:)` for a mail domain, by name on its server. Either is `None`
/// when the address it needs cannot be resolved — callers already treat that as
/// "unknown" (reads) or "refuse" (writes).
pub async fn mail_dns_addresses_for(
    db: &sqlx::PgPool,
    server_id: Option<Uuid>,
    domain: &str,
) -> (Option<String>, Option<String>) {
    let row: Option<MailIpRow> = match server_id {
        Some(sid) => sqlx::query_as(&format!("{MAIL_IP_SELECT} WHERE md.server_id = $1 AND md.domain = $2"))
            .bind(sid)
            .bind(domain)
            .fetch_optional(db)
            .await
            .unwrap_or_else(|e| {
                tracing::warn!("Could not read mail address context for {domain}: {e}");
                None
            }),
        None => None,
    };

    let (site, send) = match &row {
        Some(r) => (r.site(), r.send_ip()),
        None => (None, resolve_send_ip(None, None)),
    };
    let site_ref = site.as_ref().map(|o| o.as_ref());
    let server_public = if needs_primary_address(site_ref, &send) {
        crate::helpers::public_ip_for_server(db, server_id).await
    } else {
        None
    };
    mail_dns_addresses(site_ref, &send, server_public.as_deref())
}

/// The mail-sync fields for one domain: `(send_ip, helo)`. Both null when the
/// domain sends from the primary address — including a forced address that the
/// agent reports as its primary, which needs no dedicated transport.
pub fn sync_send_fields(send: &SendIp, agent_primary: Option<&str>) -> (Option<String>, Option<String>) {
    match &send.ip {
        Some(ip) if Some(ip.ip.as_str()) != agent_primary => (Some(ip.ip.clone()), ip.helo()),
        _ => (None, None),
    }
}

/// The global HELO: the PTR of the agent's primary address, when that address is
/// declared and its PTR was read.
pub fn primary_helo(declared: &[DeclaredIp], agent_primary: Option<&str>) -> Option<String> {
    let primary = agent_primary?;
    declared.iter().find(|d| d.ip == primary).and_then(DeclaredIp::helo)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(n: u8, public: Option<&str>, ptr: Option<&str>) -> DeclaredIp {
        DeclaredIp {
            id: Uuid::from_u128(n as u128),
            ip: format!("10.0.0.{n}"),
            public_ip: public.map(str::to_string),
            ptr: ptr.map(str::to_string),
        }
    }

    #[test]
    fn a_site_without_an_address_binds_to_primary_never_to_nothing() {
        assert_eq!(bind_ip_value(None), "primary");
        assert_eq!(bind_ip_value(Some("  ")), "primary");
        assert_eq!(bind_ip_value(Some("192.0.2.107")), "192.0.2.107");
    }

    #[test]
    fn a_forced_send_address_wins_over_the_site() {
        let r = resolve_send_ip(Some(ip(2, None, None)), Some(Some(ip(3, None, None))));
        assert_eq!(r.source, SendIpSource::Forced);
        assert_eq!(r.ip.unwrap().ip, "10.0.0.2");
    }

    #[test]
    fn an_automatic_domain_follows_its_sites_address() {
        let r = resolve_send_ip(None, Some(Some(ip(3, None, None))));
        assert_eq!(r.source, SendIpSource::Site);
        assert_eq!(r.ip.unwrap().ip, "10.0.0.3");
    }

    #[test]
    fn a_site_on_the_primary_address_or_no_site_means_primary() {
        for site in [None, Some(None)] {
            let r = resolve_send_ip(None, site);
            assert_eq!(r.source, SendIpSource::Primary);
            assert!(r.ip.is_none());
        }
        assert_eq!(SendIpSource::Primary.as_str(), "primary");
        assert_eq!(SendIpSource::Site.as_str(), "site");
        assert_eq!(SendIpSource::Forced.as_str(), "forced");
    }

    #[test]
    fn dns_prefers_the_public_address_then_the_bound_one_then_the_server() {
        assert_eq!(dns_address(Some(&ip(4, Some("192.0.2.104"), None)), Some("1.1.1.1")).unwrap(), "192.0.2.104");
        assert_eq!(dns_address(Some(&ip(4, Some(" "), None)), Some("1.1.1.1")).unwrap(), "10.0.0.4");
        assert_eq!(dns_address(None, Some("1.1.1.1")).unwrap(), "1.1.1.1");
        assert_eq!(dns_address(None, None), None);
    }

    #[test]
    fn spf_names_the_send_address_and_a_names_the_site() {
        let site_ip = ip(5, None, None);
        let send = resolve_send_ip(Some(ip(6, None, None)), Some(Some(site_ip.clone())));
        let (a, spf) = mail_dns_addresses(Some(Some(&site_ip)), &send, Some("1.1.1.1"));
        assert_eq!(a.as_deref(), Some("10.0.0.5"));
        assert_eq!(spf.as_deref(), Some("10.0.0.6"));
    }

    #[test]
    fn a_mail_only_domain_points_its_a_record_at_the_send_address() {
        let send = resolve_send_ip(Some(ip(7, Some("192.0.2.107"), None)), None);
        let (a, spf) = mail_dns_addresses(None, &send, Some("1.1.1.1"));
        assert_eq!(a.as_deref(), Some("192.0.2.107"));
        assert_eq!(spf.as_deref(), Some("192.0.2.107"));
        assert!(!needs_primary_address(None, &send));
    }

    #[test]
    fn a_forced_domain_whose_site_is_on_primary_publishes_both() {
        let send = resolve_send_ip(Some(ip(8, None, None)), Some(None));
        let (a, spf) = mail_dns_addresses(Some(None), &send, Some("1.1.1.1"));
        assert_eq!(a.as_deref(), Some("1.1.1.1"));
        assert_eq!(spf.as_deref(), Some("10.0.0.8"));
        assert!(needs_primary_address(Some(None), &send));
    }

    #[test]
    fn the_sync_carries_an_address_and_its_ptr_only_off_primary() {
        let send = resolve_send_ip(None, Some(Some(ip(9, None, Some("mail9.example.fr.")))));
        assert_eq!(
            sync_send_fields(&send, Some("10.0.0.1")),
            (Some("10.0.0.9".into()), Some("mail9.example.fr".into()))
        );
        // The agent says this IS its primary address: no dedicated transport.
        assert_eq!(sync_send_fields(&send, Some("10.0.0.9")), (None, None));
        // Primary resolution never sends an address.
        assert_eq!(sync_send_fields(&resolve_send_ip(None, None), None), (None, None));
        // No PTR read → helo null, address still sent.
        let bare = resolve_send_ip(Some(ip(2, None, None)), None);
        assert_eq!(sync_send_fields(&bare, None), (Some("10.0.0.2".into()), None));
    }

    #[test]
    fn the_global_helo_is_the_declared_primarys_ptr() {
        let declared = vec![ip(1, None, Some("srv.example.fr")), ip(2, None, Some("other.example.fr"))];
        assert_eq!(primary_helo(&declared, Some("10.0.0.1")).as_deref(), Some("srv.example.fr"));
        assert_eq!(primary_helo(&declared, Some("10.0.0.3")), None);
        assert_eq!(primary_helo(&declared, None), None);
        assert_eq!(primary_helo(&[ip(1, None, Some(" "))], Some("10.0.0.1")), None);
    }
}
