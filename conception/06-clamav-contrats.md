# Fonctionnalité 5 - Contrats d'interface (ClamAV)

Référence : `06-clamav.md`. Debian/Ubuntu seulement ; RHEL : `supported:false`, « Not supported on this server ».
Trois chantiers parallèles : **A** agent, **B** backend, **C** interface. Règle : un fichier = un propriétaire.
Libellés d'interface en anglais, jamais de tiret cadratin. Aucun secret dans les journaux.

Précision par rapport à `06-clamav.md` §4 : on **ne renomme pas** `migration_jobs` ; A ajoute seulement une route
neutre `GET /jobs/{job_id}` qui appelle `migration_jobs::get` (même JSON que `GET /migration/jobs/{id}`).

## 0. Propriété des fichiers
### Agent (`panel/agent/`) : A
- nouveaux : `src/services/clamav.rs` (install, config clamd, état, client socket `INSTREAM`/`PING`/`VERSION`),
  `src/services/av_scan.rs` (parcours + scan, tâche), `src/services/quarantine.rs`, `src/routes/antivirus.rs`.
- modifiés : `src/routes/mod.rs`, `src/services/mod.rs`, `src/routes/service_installer.rs` (entrée `clamav` dans
  `install-status`), `src/services/security.rs` (`quarantine_file` passe par `quarantine::quarantine`),
  `dockpanel-agent.service` + `src/services/agent_unit.rs` (ReadWritePaths `-/etc/clamav -/etc/rspamd`),
  `src/services/hestia_mail.rs` (lire `ANTIVIRUS=` du domaine mail Hestia et l'exposer, voir A-H).
### Backend (`panel/backend/`) : B
- nouveaux : `migrations/20261120000000_antivirus.sql`, `src/services/av_scanner.rs`, `src/routes/antivirus.rs`.
- modifiés : `src/routes/mod.rs`, `src/services/mod.rs`, `src/main.rs` (`spawn_supervised("av_scanner")`),
  `src/services/import_mail.rs` (action manuelle, voir A-H).
### Interface (`panel/frontend/src/`) : C
- nouveau : `components/AntivirusTab.tsx`, `components/ClamavCard.tsx` (carte Services + carte mail réutilisables).
- modifiés : `pages/Security.tsx` (onglet « Antivirus »), `pages/Settings.tsx` (carte ClamAV dans Services),
  `pages/Mail.tsx` (interrupteur dans « Spam Filter »), `pages/SiteDetail.tsx` (« Scan now » + badge).

## A. Agent (toutes les routes sous le jeton agent habituel)
Erreurs : `{ "error": "message lisible en anglais" }` avec 400/404/409/412/500.

### A-1 `GET /antivirus/status`
```json
{ "supported": true, "unsupported_reason": null,
  "installed": true, "running": true, "responding": true,
  "version": "ClamAV 1.4.3", "signatures": { "version": 27450, "updated_at": "2026-11-15T03:12:00Z" },
  "memory_bytes": 1450000000, "total_ram_bytes": 8325000000,
  "mail": { "enabled": false, "rspamd_installed": true, "mail_installed": true },
  "install_job": null }
```
`responding` = `PING` → `PONG` sur `/run/clamav/clamd.ctl` (délai 3 s). `signatures` et `version` viennent de
`VERSION` (format `ClamAV 1.4.3/27450/Sat Nov 15 03:12:00 2026`), `null` si clamd ne répond pas.
`memory_bytes` = `MemoryCurrent` de `clamav-daemon` (systemctl show), `null` si arrêté.
`install_job` = id de la tâche d'installation en cours, sinon `null`. `install-status` reçoit
`"clamav": {"installed","running","supported"}`.

### A-2 `POST /antivirus/install` → `{ "job_id": "..." }`
- 412 si RAM totale < 2 Go (`"ClamAV needs at least 2 GB of RAM"`), 412 si non supporté, 409 si une installation tourne.
- Tâche `migration_jobs::spawn("clamav_install", "server", …)` ; phases `packages`, `signatures`, `configure`,
  `start`, `verify` ; `warn("Less than 4 GB of RAM: ClamAV uses about 1.5 GB")` sous 4 Go.
- Réglages : remplacer sur place (ou ajouter) dans `/etc/clamav/clamd.conf` : `MaxThreads 2`, `MaxFileSize 25M`,
  `MaxScanSize 100M`, `StreamMaxLength 26M`, `ConcurrentDatabaseReload no`, `LocalSocketMode 660`,
  `LocalSocketGroup clamav`. Si l'unité `clamav-daemon.socket` existe, le mode du socket y est réglé par un
  drop-in. Attendre que `clamav-freshclam` ait produit `main.c[lv]d`, `daily.c[lv]d`, `bytecode.c[lv]d` dans
  `/var/lib/clamav` (jusqu'à 15 min, progression), sans lancer `freshclam` à la main.
- Fin : `PING` OK. Rapport de tâche : `{ "version": "...", "signatures_version": 27450 }`.

### A-3 `POST /antivirus/uninstall` → `{ "ok": true }`
Désactive d'abord l'antivirus mail (A-4 `enable:false`), puis `pkg::remove(["clamav-daemon","clamav-freshclam","clamav"])`.
La quarantaine (`/var/lib/dockpanel/quarantine`) est conservée.

### A-4 `POST /antivirus/mail` `{ "enable": true }` → `{ "ok": true, "enabled": true }`
- 412 si mail non installé, Rspamd non installé, ou (pour `enable:true`) clamd ne répond pas.
- Activer : utilisateur `_rspamd` ajouté au groupe `clamav` (redémarrage de Rspamd si ajouté), écriture atomique de
  `/etc/rspamd/local.d/antivirus.conf` (contenu de `06-clamav.md` §3), `rspamadm configtest` (retour arrière si échec),
  `systemctl reload rspamd`. Désactiver : retrait du fichier + reload. `enabled` = présence du fichier.

### A-5 `POST /antivirus/scan` `{ "domain": "x.tld" }` → `{ "job_id": "..." }`
- 404 si `/var/www/<domain>` absent, 412 si clamd ne répond pas, 409 si un `av_scan` tourne déjà sur ce serveur.
- Tâche `spawn("av_scan", domain, …)`, phase `scanning`, `progress(done=fichiers traités, total=fichiers comptés)`.
- Parcours sans suivre les liens, exclut `/var/www/.dockpanel-canary` et tout ce qui n'est pas un fichier normal ;
  fichiers > 25 Mo comptés `files_skipped`. Contenu envoyé par `zINSTREAM` (blocs de 64 Kio), une connexion à la fois.
  Réponse clamd `stream: <Sig> FOUND` → détection ; `... ERROR` → compté `files_errors` + `warn`.
  Lecture séquentielle, un seul fichier ouvert à la fois.
- Rapport : `{ "domain", "files_scanned", "files_skipped", "files_errors", "signatures_version", "duration_ms",
  "infected": [{ "path": "/var/www/x.tld/public/a.php", "signature": "Php.Malware.X", "size": 1234, "sha256": "..." }] }`
  (500 détections au plus, `truncated: true` au-delà).

### A-6 `GET /jobs/{job_id}` : JSON de `migration_jobs::get`, 404 si inconnu.

### A-7 Quarantaine (`services/quarantine.rs`, réutilisé par `security::apply_fix`)
- `POST /antivirus/quarantine` `{ "domain", "path", "signature"? }` → `{ "quarantine_id", "item": <Item> }`.
  Le chemin canonique doit être un fichier normal sous `/var/www/<domain>/` (sinon 400). Déplacement vers
  `/var/lib/dockpanel/quarantine/<uuid>/file` (dossier 0700 root, fichier 0000), `meta.json` écrit avant.
  Repli copie + suppression si `rename` échoue (autre système de fichiers).
- `POST /antivirus/restore` `{ "quarantine_id" }` → `{ "ok": true, "path" }` ; 409 si le chemin d'origine existe,
  409 si le sha256 a changé ; remet uid, gid, mode, puis supprime le dossier de quarantaine.
- `POST /antivirus/delete` `{ "domain", "path" }` → `{ "ok": true }` (mêmes contrôles de chemin).
- `POST /antivirus/quarantine/delete` `{ "quarantine_id" }` → `{ "ok": true }` (purge définitive).
- `GET /antivirus/quarantine` → `[<Item>]` avec
  `Item = { "quarantine_id", "domain", "original_path", "signature"|null, "sha256", "size", "uid", "gid", "mode",
  "quarantined_at" }`.
- Les anciens fichiers `<ts>_<nom>` à la racine de la quarantaine sont listés avec `quarantine_id = "legacy:<nom>"`,
  sans restauration (409 « No metadata for this file »).

### A-H Import Hestia
L'inventaire mail de chaque domaine expose `"antivirus": true|false` (clé `ANTIVIRUS='yes'` du `mail.conf` Hestia).
B ajoute dans `import_mail.rs` une seule action manuelle par import si au moins un domaine l'a :
`"Enable mail antivirus (Mail > Spam Filter): HestiaCP scanned mail for <n> domain(s)"`.

## B. Backend
Toutes les routes exigent une session ; **admin seulement** sauf mention « propriétaire ». Activité journalisée
(`antivirus.install`, `.uninstall`, `.mail`, `.schedule`, `.scan`, `.quarantine`, `.restore`, `.delete`, `.ignore`).

### B-M Migration `20261120000000_antivirus.sql`
```sql
CREATE TABLE av_scans (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  server_id UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  site_id UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  trigger TEXT NOT NULL CHECK (trigger IN ('manual','scheduled')),
  status TEXT NOT NULL CHECK (status IN ('queued','running','completed','failed')),
  agent_job_id TEXT, files_scanned BIGINT NOT NULL DEFAULT 0, files_skipped BIGINT NOT NULL DEFAULT 0,
  files_errors BIGINT NOT NULL DEFAULT 0, infected_count INT NOT NULL DEFAULT 0,
  progress_done BIGINT, progress_total BIGINT, signatures_version BIGINT, error TEXT,
  requested_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), started_at TIMESTAMPTZ, completed_at TIMESTAMPTZ);
CREATE TABLE av_detections (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID NOT NULL REFERENCES av_scans(id) ON DELETE CASCADE,
  site_id UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
  file_path TEXT NOT NULL, signature TEXT NOT NULL, size BIGINT NOT NULL, sha256 TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','quarantined','deleted','ignored','restored')),
  quarantine_id TEXT, handled_by UUID REFERENCES users(id) ON DELETE SET NULL, handled_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now());
CREATE TABLE av_ignored (
  site_id UUID NOT NULL REFERENCES sites(id) ON DELETE CASCADE, sha256 TEXT NOT NULL,
  signature TEXT NOT NULL, note TEXT, created_by UUID REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(), PRIMARY KEY (site_id, sha256));
CREATE TABLE av_schedules (
  server_id UUID PRIMARY KEY REFERENCES servers(id) ON DELETE CASCADE,
  enabled BOOLEAN NOT NULL DEFAULT true, hour SMALLINT NOT NULL DEFAULT 3 CHECK (hour BETWEEN 0 AND 23),
  interval_days SMALLINT NOT NULL DEFAULT 1 CHECK (interval_days BETWEEN 1 AND 30),
  last_run_at TIMESTAMPTZ);
```
(adapter les noms de tables `servers`/`users`/`sites` et le type d'id à ceux réellement utilisés dans le dépôt.)

Règles : une détection ouverte (`open`) unique par `(site_id, file_path, sha256)` : un nouveau scan met à jour
`last_seen_at`/`scan_id` au lieu d'en créer une autre. Les fichiers dont le `sha256` est dans `av_ignored` du site
ne créent pas de détection. Conservation 90 jours des scans terminés (pas des détections ouvertes).

### B-R Routes (`/api/antivirus/...`)
| Méthode | Chemin | Accès | Corps / réponse |
|---|---|---|---|
| GET | `/status?server_id=` | admin | A-1 tel quel + `"schedule": {enabled,hour,interval_days,last_run_at,next_run_at}` |
| POST | `/install` | admin | `{server_id}` → `{job_id}` |
| GET | `/jobs/{job_id}?server_id=` | admin | A-6 tel quel |
| POST | `/uninstall` | admin | `{server_id}` → `{ok}` |
| POST | `/mail` | admin | `{server_id, enable}` → `{ok, enabled}` |
| PUT | `/schedule` | admin | `{server_id, enabled, hour, interval_days}` → schedule |
| GET | `/site-status?site_id=` | propriétaire | `{installed, responding, last_scan: <Scan>|null, open_detections}` (pour SiteDetail) |
| POST | `/scan` | propriétaire | `{server_id, site_id?}` ; sans `site_id` (admin) = tous les sites du serveur → `{scan_ids:[...]}` |
| GET | `/scans?server_id=&site_id=&limit=50` | propriétaire (ses sites) | `[<Scan>]`, `Scan = {id, server_id, site_id, domain, trigger, status, files_scanned, files_skipped, files_errors, infected_count, progress_done, progress_total, signatures_version, error, created_at, started_at, completed_at}` |
| GET | `/detections?server_id=&site_id=&status=` | propriétaire | `[{id, scan_id, site_id, domain, file_path, signature, size, sha256, status, quarantine_id, handled_by, handled_at, created_at, last_seen_at}]` |
| POST | `/detections/{id}/quarantine` `/restore` `/delete` `/ignore` | propriétaire | `ignore` : `{note?}` → détection mise à jour |
| GET | `/quarantine?server_id=` | admin | A-7 tel quel |
| POST | `/quarantine/{quarantine_id}/delete?server_id=` | admin | `{ok}` |

Les proxys longs (`install`) utilisent `post_long` comme l'installation de Rspamd.

### B-S Service `av_scanner` (forme de `wp_vuln_scanner`)
- File : les scans `queued` d'un serveur sont exécutés un par un (A-5), suivis par `poll_job`
  (`import_types.rs`), progression écrite dans `progress_done/total`. 409 de l'agent = on réessaie plus tard.
- Planning : toutes les 5 min, pour chaque serveur en ligne avec ClamAV installé et `av_schedules.enabled`
  (ligne créée à la volée avec les défauts), si l'heure courante ≥ `hour` et `last_run_at` plus vieux que
  `interval_days` (à 1 h près) : met en file un scan `scheduled` par site. Heure : UTC si le serveur ne fournit pas son
  fuseau par une route existante (l'interface affiche alors « UTC »).
- Après chaque scan : `fire_alert_deduped` (type `malware`, sévérité critique, clé `av:<site_id>`) s'il reste des
  détections ouvertes sur le site, `resolve_alert` sinon. Alerte `av_signatures` (warning) si
  `signatures.updated_at` > 3 jours, alerte `av_down` si clamd installé ne répond pas 10 min de suite (mail non analysé).
- Au démarrage : les scans `running` d'un démarrage précédent passent en `failed` (« Panel restarted »).

## C. Interface
- **Settings → Services** : carte ClamAV (`ClamavCard`) : état, version, date des signatures, mémoire, bouton
  Install (avertissement RAM avant, progression de la tâche) / Uninstall (confirmation). « Not supported on this server »
  si `supported:false`.
- **Mail → Spam Filter** : interrupteur « Antivirus » ; désactivé avec raison si ClamAV ou Rspamd absent ; bandeau
  « ClamAV is not responding: mail is delivered without virus scanning » si `installed && !responding && mail.enabled`.
- **Security → Antivirus** (`AntivirusTab`) : état + planning (enabled, hour, interval_days),
  « Scan all sites now », tableau des scans (rafraîchissement 3 s tant qu'un scan tourne),
  détections ouvertes avec Quarantine / Delete (confirmation) / Ignore (note facultative), sous-onglet
  Quarantine (Restore, Delete permanently).
- **SiteDetail** : bouton « Scan now » + badge du dernier scan (`Clean`, `<n> threats`, `Scanning 42%`, `Never scanned`)
  via `/site-status`, avec lien vers Security → Antivirus. Masqué si ClamAV non installé sur le serveur du site.
