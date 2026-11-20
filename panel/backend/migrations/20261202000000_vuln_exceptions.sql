-- CVE scanner, batch 2 (alerts and exceptions).
-- See conception/13-scanner-cve-lots2-5-contrat.md (section "Lot 2").
--
-- An exception accepts one CVE on one target until `expires_at` (90 days at
-- most, checked by the API). An accepted CVE never counts towards the alert
-- threshold and is hidden from the list and the summary by default. The row
-- is keyed on the CVE, not on the component: accepting CVE-X on a target
-- covers every package of that target where CVE-X shows up.

CREATE TABLE IF NOT EXISTS vuln_exceptions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    target_id UUID NOT NULL REFERENCES vuln_targets(id) ON DELETE CASCADE,
    vuln_id VARCHAR(64) NOT NULL,
    reason TEXT NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 500),
    expires_at TIMESTAMPTZ NOT NULL,
    created_by UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (target_id, vuln_id)
);

-- When the target last raised a `vuln_scan` alert: at most one per target and per 24 hours.
ALTER TABLE vuln_targets ADD COLUMN IF NOT EXISTS alerted_at TIMESTAMPTZ NULL;

INSERT INTO settings (key, value) VALUES ('vuln_alert_min', 'kev_and_fixable_high') ON CONFLICT (key) DO NOTHING;
