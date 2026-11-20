-- CVE scanner, batch 1 (engine): targets, findings, per-server state.
-- See conception/13-scanner-cve-contrats.md (section 3) and 13-scanner-cve-lot1-contrat.md.
-- SBOMs stay on each server's disk; Postgres only keeps targets and findings.

CREATE TABLE IF NOT EXISTS vuln_targets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
    kind VARCHAR(16) NOT NULL CHECK (kind IN ('site', 'image', 'system')),
    ref VARCHAR(512) NOT NULL,
    site_id UUID NULL REFERENCES sites(id) ON DELETE CASCADE,
    git_deploy_id UUID NULL REFERENCES git_deploys(id) ON DELETE SET NULL,
    app_name VARCHAR(128) NULL,
    exposed BOOLEAN NULL,
    fingerprint TEXT,
    sbom_at TIMESTAMPTZ,
    matched_at TIMESTAMPTZ,
    needs_inventory BOOLEAN NOT NULL DEFAULT TRUE,
    last_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (server_id, kind, ref)
);
CREATE INDEX IF NOT EXISTS idx_vuln_targets_site ON vuln_targets (site_id);

CREATE TABLE IF NOT EXISTS vuln_findings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id UUID NOT NULL REFERENCES vuln_targets(id) ON DELETE CASCADE,
    vuln_id VARCHAR(64) NOT NULL,
    aliases TEXT[] NOT NULL DEFAULT '{}',
    package VARCHAR(256) NOT NULL,
    version VARCHAR(128) NOT NULL,
    pkg_type VARCHAR(32),
    location TEXT,
    severity VARCHAR(10) NOT NULL DEFAULT 'unknown'
        CHECK (severity IN ('critical', 'high', 'medium', 'low', 'unknown')),
    cvss REAL,
    kev BOOLEAN NOT NULL DEFAULT FALSE,
    kev_ransomware BOOLEAN NOT NULL DEFAULT FALSE,
    epss REAL,
    epss_percentile REAL,
    risk REAL,
    fix_state VARCHAR(16) NOT NULL DEFAULT 'unknown'
        CHECK (fix_state IN ('fixed', 'not-fixed', 'wont-fix', 'unknown')),
    fixed_version VARCHAR(128),
    title TEXT,
    url TEXT,
    first_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen TIMESTAMPTZ NOT NULL DEFAULT now(),
    resolved_at TIMESTAMPTZ NULL,
    notified BOOLEAN NOT NULL DEFAULT FALSE,
    UNIQUE (target_id, vuln_id, package, version)
);
CREATE INDEX IF NOT EXISTS idx_vuln_findings_open ON vuln_findings (target_id) WHERE resolved_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_vuln_findings_rank ON vuln_findings (kev DESC, risk DESC NULLS LAST);

CREATE TABLE IF NOT EXISTS vuln_server_state (
    server_id UUID PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
    db_built TIMESTAMPTZ,
    db_checked_at TIMESTAMPTZ,
    last_match_at TIMESTAMPTZ,
    last_error TEXT,
    installed_versions JSONB
);

INSERT INTO settings (key, value) VALUES ('vuln_scan_enabled', 'true') ON CONFLICT (key) DO NOTHING;
INSERT INTO settings (key, value) VALUES ('vuln_match_hour', '4') ON CONFLICT (key) DO NOTHING;
