-- Run on the panel database BEFORE upgrading (read-only): `psql -f`.
-- Preview (read-only): what the first retention pass after deploying the
-- backfill migration will delete, and what the migration leaves NULL.
WITH candidate AS (
    SELECT b.id AS backup_id, r.policy_id
    FROM backups b
    JOIN sites s ON s.id = b.site_id
    JOIN backup_policy_runs r
      ON r.finished_at IS NOT NULL
     AND b.created_at BETWEEN r.started_at AND r.finished_at
    JOIN backup_policies p
      ON p.id = r.policy_id AND p.backup_sites AND p.user_id = s.user_id
    WHERE b.policy_id IS NULL
      AND NOT EXISTS (SELECT 1 FROM backup_schedules bs
                      WHERE bs.site_id = b.site_id AND bs.retention_count > 0)
      AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(r.errors) e
                      WHERE (e->>'kind' = 'site' AND e->>'subject' = s.domain) OR (e->>'kind' = 'listing' AND e->>'subject' = 'sites'))
      AND (SELECT COUNT(*) FROM backups o
           WHERE o.site_id = b.site_id
             AND o.created_at BETWEEN r.started_at AND r.finished_at) = 1
),
attributed AS (
    SELECT c.backup_id, MIN(c.policy_id::text)::uuid AS policy_id
    FROM candidate c
    GROUP BY c.backup_id
    HAVING COUNT(DISTINCT c.policy_id) = 1
),
after_backfill AS (
    SELECT b.id, b.site_id, b.filename, b.size_bytes, b.created_at,
           COALESCE(b.policy_id, a.policy_id) AS policy_id,
           (b.policy_id IS NULL) AS legacy
    FROM backups b
    LEFT JOIN attributed a ON a.backup_id = b.id
    LEFT JOIN backup_policies ap ON ap.id = a.policy_id
    WHERE b.policy_id IS NOT NULL OR ap.retention_count > 0
),
ranked AS (
    SELECT x.*, p.name AS policy, p.retention_count,
           ROW_NUMBER() OVER (PARTITION BY x.policy_id, x.site_id ORDER BY x.created_at DESC) AS rn
    FROM after_backfill x JOIN backup_policies p ON p.id = x.policy_id
    WHERE p.retention_count > 0
)
SELECT s.domain, r.policy, r.retention_count, r.filename, r.created_at,
       pg_size_pretty(r.size_bytes) AS size, r.legacy
FROM ranked r JOIN sites s ON s.id = r.site_id
WHERE r.rn > r.retention_count
ORDER BY s.domain, r.created_at;

-- ── Rows the backfill leaves NULL (kept as before) ──
-- Read-only: NULL-policy rows on sites with no per-site schedule that the
-- backfill can NOT attribute (they stay kept for ever, as today). Run before deploy.
WITH candidate AS (
    SELECT b.id AS backup_id, r.policy_id
    FROM backups b
    JOIN sites s ON s.id = b.site_id
    JOIN backup_policy_runs r ON r.finished_at IS NOT NULL
     AND b.created_at BETWEEN r.started_at AND r.finished_at
    JOIN backup_policies p ON p.id = r.policy_id AND p.backup_sites AND p.user_id = s.user_id
    WHERE b.policy_id IS NULL
      AND NOT EXISTS (SELECT 1 FROM backup_schedules bs WHERE bs.site_id = b.site_id AND bs.retention_count > 0)
      AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements(r.errors) e WHERE (e->>'kind' = 'site' AND e->>'subject' = s.domain) OR (e->>'kind' = 'listing' AND e->>'subject' = 'sites'))
      AND (SELECT COUNT(*) FROM backups o WHERE o.site_id = b.site_id
             AND o.created_at BETWEEN r.started_at AND r.finished_at) = 1
),
attributed AS (
    SELECT backup_id FROM candidate GROUP BY backup_id HAVING COUNT(DISTINCT policy_id) = 1
)
SELECT s.domain, COUNT(*) AS rows_left_null, pg_size_pretty(SUM(b.size_bytes)) AS size,
       MIN(b.created_at) AS oldest, MAX(b.created_at) AS newest
FROM backups b JOIN sites s ON s.id = b.site_id
WHERE b.policy_id IS NULL
  AND NOT EXISTS (SELECT 1 FROM backup_schedules bs WHERE bs.site_id = b.site_id AND bs.retention_count > 0)
  AND b.id NOT IN (SELECT backup_id FROM attributed)
GROUP BY s.domain ORDER BY COUNT(*) DESC;
