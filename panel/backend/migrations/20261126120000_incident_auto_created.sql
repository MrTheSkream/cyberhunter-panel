-- Tell the incidents the panel opened by itself from the ones an operator declared.
-- Only a declared incident is a deliberate freeze on the owner's deployments.
ALTER TABLE managed_incidents
    ADD COLUMN IF NOT EXISTS auto_created BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE managed_incidents i
SET auto_created = TRUE
WHERE i.title LIKE 'Auto-healer exhausted: %'
   OR i.title LIKE 'Backup policy ''%'
   OR EXISTS (
        SELECT 1 FROM incident_updates u
        WHERE u.incident_id = i.id
          AND u.author_email = 'system'
          AND (u.message LIKE 'Auto-detected: %' OR u.message LIKE 'Auto-created from %')
   );

-- Close the monitor incidents whose monitor no longer exists: nothing can ever
-- report their recovery.
WITH orphans AS (
    UPDATE managed_incidents i
    SET status = 'resolved', resolved_at = NOW(), updated_at = NOW()
    WHERE i.auto_created
      AND i.status NOT IN ('resolved', 'postmortem')
      AND i.title LIKE '% is down'
      AND EXISTS (
            SELECT 1 FROM incident_updates u
            WHERE u.incident_id = i.id
              AND u.author_email = 'system'
              AND u.message LIKE 'Auto-detected: %'
      )
      AND NOT EXISTS (
            SELECT 1 FROM monitors m
            WHERE m.user_id = i.user_id AND m.name || ' is down' = i.title
      )
    RETURNING i.id
)
INSERT INTO incident_updates (incident_id, status, message, author_email)
SELECT id, 'resolved', 'Closed automatically: the monitor no longer exists', 'system'
FROM orphans;
