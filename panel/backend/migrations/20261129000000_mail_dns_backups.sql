-- Mail and DNS backups (Backup Orchestrator, lot 3).
--
-- `backup_policies.backup_mail` / `backup_dns`: the two new legs of a policy.
-- Mail and DNS are shared by every tenant of a host, so the API accepts them
-- only from an administrator, and the executor runs them only for a policy
-- whose owner is one.
--
-- `mail_backups`: one row per archive the agent wrote under
-- /var/backups/dockpanel/mail/:
--   * kind 'mailbox'  one mailbox's maildir (`mail_domain` + `mailbox`, the
--                     local part), `mail-{domain}-{local_b64url}-{stamp}.tar.gz[.enc]`;
--   * kind 'config'   the manifest of the mail configuration exported from the
--                     panel database plus the DKIM files, `mailcfg-{stamp}.tar.gz.enc`,
--                     always encrypted.
-- `dns_backups`: one row per file under /var/backups/dockpanel/dns/:
--   * kind 'zone'     one zone exported through the PowerDNS API (`zone`
--                     without its final dot), `dns-zone-{zone}-{stamp}.json[.enc]`;
--   * kind 'snapshot' the whole PowerDNS database (`backend` sqlite or pgsql),
--                     `dns-snapshot-{backend}-{stamp}.gz.enc`, always encrypted.
--
-- `encryption_key_version` records which derivation produced the passphrase,
-- so a restore recomputes the key with THIS version, never the current one.
-- `server_id` is the host that holds the file; restore goes back to it.
--
-- Single transaction, IF NOT EXISTS throughout.

BEGIN;

ALTER TABLE backup_policies ADD COLUMN IF NOT EXISTS backup_mail BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE backup_policies ADD COLUMN IF NOT EXISTS backup_dns BOOLEAN NOT NULL DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS mail_backups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id UUID REFERENCES servers(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('mailbox', 'config')),
    mail_domain TEXT,
    mailbox TEXT,
    filename TEXT NOT NULL,
    size_bytes BIGINT NOT NULL DEFAULT 0,
    encrypted BOOLEAN NOT NULL DEFAULT FALSE,
    encryption_key_version SMALLINT NOT NULL DEFAULT 2,
    policy_id UUID REFERENCES backup_policies(id) ON DELETE SET NULL,
    destination_id UUID REFERENCES backup_destinations(id) ON DELETE SET NULL,
    uploaded BOOLEAN NOT NULL DEFAULT FALSE,
    sha256_hash TEXT,
    previous_hash TEXT,
    chain_valid BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_mail_backups_server_created
    ON mail_backups(server_id, created_at DESC);
-- Retention partitions, the integrity chain and "latest backup of this
-- mailbox" all key on this identity.
CREATE INDEX IF NOT EXISTS idx_mail_backups_target
    ON mail_backups(server_id, kind, mail_domain, mailbox, created_at DESC);

CREATE TABLE IF NOT EXISTS dns_backups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id UUID REFERENCES servers(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('zone', 'snapshot')),
    zone TEXT,
    backend TEXT CHECK (backend IS NULL OR backend IN ('sqlite', 'pgsql')),
    filename TEXT NOT NULL,
    size_bytes BIGINT NOT NULL DEFAULT 0,
    encrypted BOOLEAN NOT NULL DEFAULT FALSE,
    encryption_key_version SMALLINT NOT NULL DEFAULT 2,
    policy_id UUID REFERENCES backup_policies(id) ON DELETE SET NULL,
    destination_id UUID REFERENCES backup_destinations(id) ON DELETE SET NULL,
    uploaded BOOLEAN NOT NULL DEFAULT FALSE,
    sha256_hash TEXT,
    previous_hash TEXT,
    chain_valid BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_dns_backups_server_created
    ON dns_backups(server_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_dns_backups_target
    ON dns_backups(server_id, kind, zone, backend, created_at DESC);

COMMIT;
