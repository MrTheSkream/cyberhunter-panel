-- Off-site disaster recovery snapshots (lot 2, steps 2.3 and 2.4).
--
-- `dr_recipients`: the age X25519 recipients the off-site archives are
--   encrypted to. ONLY the public key ("age1...") and its fingerprint are
--   stored: the identity (the operator's "recovery key") is shown once at
--   enrolment and never written anywhere on this server. A rotation retires the
--   previous row (`retired_at`) instead of deleting it, so the history says
--   which key opens which remote archive.
-- `dr_settings`: a single row (id = 1) holding the schedule, the destinations,
--   the remote retention and the outcome of the last run. `active_recipient_id`
--   is the recipient new archives are encrypted to.
-- `dr_remote_snapshots`: one row per archive sent (or tried) to one
--   destination. `remote_key` is the key the agent's `/backups/list` reports
--   for the archive, the one `/backups/download` takes back. `deleted_at` is
--   stamped when remote retention removed it. `pinned` is reserved (step 2.7):
--   the agent's prune does not honour it yet.
--
-- Single transaction, IF NOT EXISTS throughout.

BEGIN;

CREATE TABLE IF NOT EXISTS dr_recipients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    public_key TEXT NOT NULL UNIQUE CHECK (public_key LIKE 'age1%'),
    fingerprint TEXT NOT NULL,
    created_by TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    retired_at TIMESTAMPTZ
);
-- At most one recipient is active (not retired) at a time.
CREATE UNIQUE INDEX IF NOT EXISTS idx_dr_recipients_one_active
    ON dr_recipients ((retired_at IS NULL)) WHERE retired_at IS NULL;

CREATE TABLE IF NOT EXISTS dr_settings (
    id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    schedule TEXT NOT NULL DEFAULT '30 3 * * *',
    destination_ids UUID[] NOT NULL DEFAULT '{}',
    remote_retention INTEGER NOT NULL DEFAULT 14 CHECK (remote_retention BETWEEN 1 AND 365),
    active_recipient_id UUID REFERENCES dr_recipients(id) ON DELETE SET NULL,
    enabled_at TIMESTAMPTZ,
    last_run_at TIMESTAMPTZ,
    last_status TEXT CHECK (last_status IS NULL OR last_status IN ('running', 'success', 'partial', 'failed')),
    last_error TEXT,
    last_alert_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO dr_settings (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

CREATE TABLE IF NOT EXISTS dr_remote_snapshots (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_id UUID REFERENCES panel_snapshots(id) ON DELETE SET NULL,
    destination_id UUID REFERENCES backup_destinations(id) ON DELETE SET NULL,
    status TEXT NOT NULL DEFAULT 'uploaded' CHECK (status IN ('uploaded', 'failed')),
    error TEXT,
    remote_key TEXT,
    filename TEXT NOT NULL,
    size_bytes BIGINT NOT NULL DEFAULT 0,
    sha256 TEXT NOT NULL,
    recipient_fingerprint TEXT NOT NULL,
    from_version TEXT NOT NULL,
    pinned BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    uploaded_at TIMESTAMPTZ,
    deleted_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_dr_remote_snapshots_dest_uploaded
    ON dr_remote_snapshots(destination_id, uploaded_at DESC);
CREATE INDEX IF NOT EXISTS idx_dr_remote_snapshots_created
    ON dr_remote_snapshots(created_at DESC);

COMMIT;
