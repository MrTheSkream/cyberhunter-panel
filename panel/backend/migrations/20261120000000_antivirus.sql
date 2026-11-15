-- Fonctionnalité 5 : antivirus ClamAV (scans des fichiers des sites).
-- Voir conception/06-clamav.md et 06-clamav-contrats.md (B-M).

CREATE TABLE IF NOT EXISTS av_scans (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    site_id UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    trigger TEXT NOT NULL CHECK (trigger IN ('manual', 'scheduled')),
    status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'failed')),
    agent_job_id TEXT,
    files_scanned BIGINT NOT NULL DEFAULT 0,
    files_skipped BIGINT NOT NULL DEFAULT 0,
    files_errors BIGINT NOT NULL DEFAULT 0,
    infected_count INT NOT NULL DEFAULT 0,
    progress_done BIGINT,
    progress_total BIGINT,
    signatures_version BIGINT,
    error TEXT,
    requested_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_av_scans_server_status ON av_scans (server_id, status, created_at);
CREATE INDEX IF NOT EXISTS idx_av_scans_site_created ON av_scans (site_id, created_at DESC);

CREATE TABLE IF NOT EXISTS av_detections (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id UUID NOT NULL REFERENCES av_scans(id) ON DELETE CASCADE,
    site_id UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    file_path TEXT NOT NULL,
    signature TEXT NOT NULL,
    size BIGINT NOT NULL,
    sha256 TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'quarantined', 'deleted', 'ignored', 'restored')),
    quarantine_id TEXT,
    handled_by UUID REFERENCES users(id) ON DELETE SET NULL,
    handled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Une seule détection ouverte par fichier et contenu : un nouveau scan la met à jour.
CREATE UNIQUE INDEX IF NOT EXISTS uq_av_detections_open
    ON av_detections (site_id, file_path, sha256) WHERE status = 'open';
CREATE INDEX IF NOT EXISTS idx_av_detections_site_status ON av_detections (site_id, status);
CREATE INDEX IF NOT EXISTS idx_av_detections_scan ON av_detections (scan_id);

CREATE TABLE IF NOT EXISTS av_ignored (
    site_id UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    sha256 TEXT NOT NULL,
    signature TEXT NOT NULL,
    note TEXT,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (site_id, sha256)
);

CREATE TABLE IF NOT EXISTS av_schedules (
    server_id UUID PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
    enabled BOOLEAN NOT NULL DEFAULT true,
    hour SMALLINT NOT NULL DEFAULT 3 CHECK (hour BETWEEN 0 AND 23),
    interval_days SMALLINT NOT NULL DEFAULT 1 CHECK (interval_days BETWEEN 1 AND 30),
    last_run_at TIMESTAMPTZ
);
