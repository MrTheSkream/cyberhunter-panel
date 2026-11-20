-- Certificat `mail.<domaine>` présenté par SNI (conception 14, D4).
--
-- `host_cert_status` :
--   * none         jamais traité ;
--   * pending_dns  `mail.<d>` ne pointe pas sur le serveur du domaine (aucune commande ACME) ;
--   * active       émis par CyberHunter - Panel (Let's Encrypt) ;
--   * imported     installé depuis l'archive HestiaCP ;
--   * failed       dernière émission en échec (`host_cert_error`, message court sans secret).
-- `host_cert_checked_at` : dernier passage de l'étape `auto_renew_mail_host_certs`,
-- qui espace les vérifications (1 h) et les nouveaux essais après échec (6 h).
ALTER TABLE mail_domains
    ADD COLUMN IF NOT EXISTS host_cert_status TEXT NOT NULL DEFAULT 'none',
    ADD COLUMN IF NOT EXISTS host_cert_expiry TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS host_cert_checked_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS host_cert_error TEXT;

ALTER TABLE mail_domains DROP CONSTRAINT IF EXISTS mail_domains_host_cert_status_check;
ALTER TABLE mail_domains ADD CONSTRAINT mail_domains_host_cert_status_check
    CHECK (host_cert_status IN ('none', 'pending_dns', 'active', 'imported', 'failed'));
