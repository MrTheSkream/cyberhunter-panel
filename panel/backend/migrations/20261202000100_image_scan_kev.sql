-- CVE scanner, batch 5 (deploy gate): how many of an image's matches are in the
-- CISA KEV catalogue (actively exploited), as reported by the agent's image scan.
-- Existing rows, and reports from an agent older than this column, read 0.
-- image_scan_deploy_gate now also accepts 'kev' (validated by the API, no CHECK).
ALTER TABLE image_scan_findings
    ADD COLUMN IF NOT EXISTS kev_count INT NOT NULL DEFAULT 0;
