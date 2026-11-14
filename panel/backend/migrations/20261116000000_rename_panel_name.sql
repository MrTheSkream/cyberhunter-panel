-- Rebrand: the default panel name seeded by 20260311230000_settings_and_activity
-- was 'DockPanel'. That migration cannot be edited (sqlx checksums applied
-- migrations), so the new default is applied here. A name the operator chose
-- themselves is left alone: only the untouched seed value is rewritten.
UPDATE settings
SET value = 'CyberHunter - Panel', updated_at = NOW()
WHERE key = 'panel_name' AND value = 'DockPanel';
