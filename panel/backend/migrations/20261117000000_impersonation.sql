-- Feature 3: an administrator signs in as another user ("login as user").
-- Design: conception/03-login-as-user.md, contracts: conception/03-login-as-user-contrats.md (D).
--
-- user_sessions.impersonator_id marks a session an admin opened on someone
-- else's account, so it shows up in that user's session list as "Admin x" and
-- so revoking the ADMIN's sessions (suspend, demote, delete) also reaches the
-- sessions they opened as other people (revoke_all_user_sessions). CASCADE:
-- a deleted admin's impersonation rows go with them; their jti was already
-- blacklisted by the revocation that runs before the delete.
ALTER TABLE user_sessions ADD COLUMN IF NOT EXISTS impersonator_id UUID NULL REFERENCES users(id) ON DELETE CASCADE;
CREATE INDEX IF NOT EXISTS idx_user_sessions_impersonator ON user_sessions(impersonator_id) WHERE impersonator_id IS NOT NULL;

-- Attribution of every action taken during such a session: the row stays in
-- the impersonated user's name, these say which admin was actually acting.
-- No foreign key on purpose: the trail must survive the admin's deletion.
ALTER TABLE activity_logs ADD COLUMN IF NOT EXISTS impersonator_id UUID NULL;
ALTER TABLE activity_logs ADD COLUMN IF NOT EXISTS impersonator_email TEXT NULL;

-- security_audit_log is immutable through a BEFORE UPDATE OR DELETE row
-- trigger (20260324000000_security_enhancements.sql). ALTER TABLE is DDL and
-- does not fire row triggers - 20260908120000_mcp_audit_attribution.sql
-- already added columns this way. Free text, not a FK: an ON DELETE SET NULL
-- referential action is an UPDATE, which that trigger would refuse, blocking
-- the deletion of the referenced user.
ALTER TABLE security_audit_log ADD COLUMN IF NOT EXISTS impersonator_email TEXT NULL;
