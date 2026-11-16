-- Fonctionnalité 7 : statistiques web par site avec GoAccess.
-- Voir conception/08-stats-web.md et 08-stats-web-contrats.md (B-1).
--
-- Une ligne par site déjà calculé : `updated_at` = dernière réussite,
-- `attempted_at` = dernière tentative (ordre de passage de l'ordonnanceur),
-- `error` = erreur de la dernière tentative.

CREATE TABLE IF NOT EXISTS site_web_stats (
  site_id uuid PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
  updated_at timestamptz NULL,
  attempted_at timestamptz NOT NULL DEFAULT now(),
  error text NULL);
