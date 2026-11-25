-- Legacy site archives a policy took get the policy_id 20261203000000 left NULL.
--
-- 20261203000000 added `backups.policy_id` and the retention sweep now prunes
-- site archives two ways: a per-site schedule prunes `policy_id IS NULL`, a
-- policy prunes `policy_id = $policy`. Every archive a policy took BEFORE that
-- migration still reads NULL, so on a site with no per-site schedule neither
-- sweep ever reaches it: those archives stay on disk for ever.
--
-- A blanket UPDATE is not an option. Three writers put rows in `backups` and two
-- of them write NULL legitimately: the manual "Back up now" route and the
-- per-site schedule (pre-deploy and pre-delete archives write no row at all).
-- A manual archive and a legacy policy archive with no destination are
-- column-for-column identical, so the only evidence of which policy took a row
-- is the run history (`backup_policy_runs`, since 20261127000000): a policy
-- writes at most one archive per site per run, between that run's `started_at`
-- and `finished_at`, and every site it failed on is named in `errors` with
-- kind "site" - which in every release that wrote this table means no row.
--
-- A NULL row is handed to a policy only when ALL of these hold:
--   1. its site has no per-site schedule with retention_count > 0 - the sites
--      the bug strands; on a scheduled site the schedule already prunes these
--      rows, and a second unattended NULL writer makes attribution unsafe;
--   2. it was written inside a FINISHED run of a policy that covers the site
--      today (backup_sites, same owner) - an open run (process died) proves
--      nothing and is ignored;
--   3. that run named no "site" error for the site's domain, and no "listing"
--      error for "sites" (the owner's sites could not be listed, so no site
--      was archived at all);
--   4. it is the ONLY row of the site in that run's window, whatever its
--      policy_id - two rows mean a manual or second archive landed beside the
--      policy's, and which is which cannot be told;
--   5. exactly one policy passes 2-4 for it (policies run one after another
--      in a single executor, so two windows overlapping is not expected);
--   6. that policy has retention_count > 0 - the sweep's own predicate. A
--      policy's count is CHECKed 1..365 (20260322000000), so this only holds if
--      that constraint is ever relaxed into a "keep for ever" 0; such a policy
--      would still count in 5, so a row it may have taken is never handed to
--      another one.
-- Everything else stays NULL and is kept, exactly as before.
--
-- Known gaps, both left NULL rather than guessed at: rows older than the run
-- history (it keeps the newest 100 runs per policy and did not exist before
-- 20261127000000), and rows whose run window is gone. Two residual risks, both
-- needing a manual archive taken during a policy run and alone in its window:
-- a run names a failed site by its domain AT RUN TIME, so for a site renamed
-- since, rule 3 cannot see that failure; and a policy that had backup_sites
-- off at run time and on today leaves no trace that it took no site archive.
--
-- Idempotent: it only ever fills `policy_id IS NULL`, and a second run finds
-- nothing left that qualifies. Guarded on the run history existing (created by
-- 20261127000000, which sorts before this file).
DO $$
BEGIN
    IF to_regclass('public.backup_policy_runs') IS NULL THEN
        RETURN;
    END IF;

    WITH candidate AS (
        SELECT b.id AS backup_id, r.policy_id
        FROM backups b
        JOIN sites s ON s.id = b.site_id
        JOIN backup_policy_runs r
          ON r.finished_at IS NOT NULL
         AND b.created_at BETWEEN r.started_at AND r.finished_at
        JOIN backup_policies p
          ON p.id = r.policy_id
         AND p.backup_sites
         AND p.user_id = s.user_id
        WHERE b.policy_id IS NULL
          AND NOT EXISTS (
              SELECT 1 FROM backup_schedules bs
              WHERE bs.site_id = b.site_id AND bs.retention_count > 0
          )
          AND NOT EXISTS (
              SELECT 1 FROM jsonb_array_elements(r.errors) e
              WHERE (e->>'kind' = 'site' AND e->>'subject' = s.domain)
                 OR (e->>'kind' = 'listing' AND e->>'subject' = 'sites')
          )
          AND (
              SELECT COUNT(*) FROM backups o
              WHERE o.site_id = b.site_id
                AND o.created_at BETWEEN r.started_at AND r.finished_at
          ) = 1
    ),
    attributed AS (
        SELECT backup_id, MIN(policy_id::text)::uuid AS policy_id
        FROM candidate
        GROUP BY backup_id
        HAVING COUNT(DISTINCT policy_id) = 1
    )
    UPDATE backups b
    SET policy_id = a.policy_id
    FROM attributed a
    JOIN backup_policies p ON p.id = a.policy_id
    WHERE b.id = a.backup_id
      AND b.policy_id IS NULL
      AND p.retention_count > 0;
END
$$;
