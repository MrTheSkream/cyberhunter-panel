# Fonctionnalité 6 - Contrats d'interface (FTP + quotas disque)

Référence : `07-ftp-quotas.md`. vsftpd est pris en charge sur Debian et Ubuntu seulement ; sur RHEL,
`supported:false` et le message « Not supported on this server ».

Organisation :
- **Trois chantiers parallèles** : **A** agent, **B** backend, **C** interface.
- **Propriété** : un fichier appartient à un seul chantier.
- **Libellés d'interface** : en anglais, jamais de tiret cadratin.
- **Journaux** : aucun secret (ni hash, ni mot de passe).

## 0. Propriété des fichiers
### Agent (`panel/agent/`) : A
- **Nouveaux fichiers :**
  - `src/services/ftp.rs` : installation, configuration, PAM, certificat, liste blanche, état.
  - `src/routes/ftp.rs`.
  - `src/services/site_owner.rs`.
  - `src/services/disk_usage.rs`.
  - `src/routes/disk_usage.rs`.
- **Fichiers modifiés :**
  - `src/main.rs` (fusion des routeurs), `src/services/mod.rs`, `src/routes/mod.rs` si besoin.
  - `src/services/firewall.rs` : `allow_tcp_range` et `remove_tcp_range`.
  - `src/routes/service_installer.rs` : entrée `vsftpd` dans `install-status`. Les installeurs UFW et
    fail2ban ajoutent les ports FTP et la prison si vsftpd est installé. La désinstallation de fail2ban
    reste inchangée.
  - `dockpanel-agent.service` et `src/services/agent_unit.rs` : `ReadWritePaths` reçoit
    `-/etc/vsftpd.conf -/etc/pam.d`, et le test de réparation de l'unité est mis à jour.
  - Les fichiers qui font `chown -R www-data:www-data` sur `/var/www/<domaine>` (voir A-7) :
    `routes/backups.rs`, `routes/nginx.rs`, `services/app_process.rs`, `services/cms.rs`,
    `services/deploy.rs`, `services/diagnostics.rs`, `services/migration.rs`, `services/staging.rs`,
    `services/wordpress.rs`, `services/wp_vulnerability.rs`.
    - Exception : `sftp_accounts.rs::deprovision` garde son `www-data` volontaire.
### Backend (`panel/backend/`) : B
- **Nouveaux fichiers :**
  - `migrations/20261121000000_ftp_disk_quota.sql`.
  - `src/services/disk_usage.rs` : ordonnanceur et alertes.
  - `src/routes/ftp.rs`.
- **Fichiers modifiés :**
  - `src/routes/mod.rs`, `src/services/mod.rs`.
  - `src/main.rs` : `spawn_supervised("disk_usage")`.
  - `src/routes/sites.rs` :
    - nouvelles routes FTP et quota ;
    - `disable_sftp` et la suppression de site retirent le FTP ;
    - le JSON du site s'enrichit.
  - `src/models.rs`.
  - `src/services/import_sftp.rs` : le FTP est coché à l'import.
  - `src/services/migration_ledger.rs` : action manuelle « install the FTP server ».
  - `src/services/notifications.rs` : `disk_quota` ajouté à `SUPPRESSIBLE_ALERT_TYPES`.
  - `src/routes/resellers.rs` : somme de l'espace mesuré.
### Interface (`panel/frontend/src/`) : C
- **Nouveaux fichiers :**
  - `components/FtpServerCard.tsx` : carte de Settings → Services.
  - `components/DiskUsageCard.tsx`.
- **Fichiers modifiés :**
  - `pages/Settings.tsx` : carte FTP et libellé d'alerte.
  - `pages/SiteDetail.tsx` : carte « SFTP / FTP Access » et carte « Disk usage ».
  - `pages/Sites.tsx` : colonne « Disk ».
  - `pages/Alerts.tsx` : libellé.
  - `pages/Resellers.tsx` : usage mesuré.

## A. Agent (toutes les routes sous le jeton agent habituel)
Erreurs : `{ "error": "message lisible en anglais" }` avec les codes 400, 404, 409, 412 ou 500.

### A-1 `GET /ftp/status`
```json
{ "supported": true, "unsupported_reason": null,
  "installed": true, "running": true,
  "cert": { "kind": "letsencrypt", "subject": "panel.example.com", "expires_at": "2027-02-10T00:00:00Z" },
  "ports": { "control": 21, "passive_min": 12000, "passive_max": 12100 },
  "firewall": "open", "fail2ban_jail": true, "users": 28 }
```
- **`cert.kind`** vaut `letsencrypt` ou `self_signed`. Tout est `null` si vsftpd n'est pas installé.
- **`firewall`** vaut `open`, `closed` ou `none` (aucun pare-feu géré).
- **`users`** : nombre de lignes de la liste blanche.
- **`install-status`** reçoit `"vsftpd": {"installed","running","supported"}`.

### A-2 `POST /ftp/install` `{ "users": ["adm-jim_jeuxx", ...], "pasv_address": null }` → `{ "ok": true, "warnings": [] }`
- **Refus** : 412 si le serveur n'est pas pris en charge, 409 si une installation ou une désinstallation tourne déjà.
  Délai total de 5 min.
- **Étapes, dans l'ordre :**
  1. `pkg::install(["vsftpd"])`.
  2. Écrire `/etc/pam.d/dockpanel-ftp` :
     ```
     auth    required pam_listfile.so item=user sense=deny file=/etc/ftpusers onerr=succeed
     @include common-auth
     @include common-account
     session required pam_loginuid.so
     ```
     Pas de `pam_shells`. Le `session` est à confirmer dans la VM.
  3. Préparer le certificat :
     - Si `panel_tls_paths()` existe (logique reprise de `routes/mail.rs:1234`, à déplacer dans un
       module partagé), vsftpd pointe directement sur `/etc/letsencrypt/live/<hôte>/{fullchain,privkey}.pem`.
     - Sinon, générer `/etc/dockpanel/ftp/{cert,key}.pem` : RSA 2048 auto-signé valable 10 ans,
       CN = nom d'hôte, clé en 0600 root.
  4. Écrire `/etc/vsftpd.conf` (contenu de `07-ftp-quotas.md` §2, avec les chemins de certificat retenus,
     plus `pasv_address` s'il est fourni). Écriture atomique ; l'ancien fichier est sauvegardé en
     `.dockpanel.bak` une seule fois.
  5. Écrire la liste blanche `/etc/dockpanel/ftp-users` (voir A-4).
  6. Lancer `systemctl enable --now vsftpd`, puis vérifier que le service est actif et qu'il écoute sur
     `:21`. En cas d'échec : `systemctl stop`, puis restauration de la configuration et 500 avec la fin
     du journal de l'unité.
  7. Pare-feu : `allow_tcp("21")` et `allow_tcp_range(12000, 12100)`. Un échec devient un warning,
     pas une erreur.
  8. Si fail2ban est installé : écrire `/etc/fail2ban/jail.d/dockpanel-vsftpd.conf` puis
     `fail2ban-client reload`.
     ```
     [vsftpd]
     enabled = true
     port = 21,12000:12100
     filter = vsftpd
     logpath = /var/log/vsftpd.log
     maxretry = 5
     findtime = 600
     bantime = 3600
     ```
- **Réexécution** : la route peut être rappelée sur un serveur déjà installé, ce qui revient à une
  réparation idempotente.

### A-3 `POST /ftp/uninstall` → `{ "ok": true }`
- Arrête vsftpd, puis lance `pkg::remove(["vsftpd"])`.
- Retire les ports 21 et 12000-12100, la prison fail2ban (suivie d'un reload), `/etc/pam.d/dockpanel-ftp`,
  `/etc/dockpanel/ftp/` et la liste blanche.

### A-4 `PUT /ftp/users` `{ "users": ["..."] }` → `{ "ok": true, "written": 28, "kicked": ["..."] }`
- **Source de vérité** : la liste envoyée est complète ; c'est le backend qui la tient. L'agent réécrit
  le fichier en entier, de façon atomique, en 0600 root.
- **Contrôle de chaque nom** :
  - l'utilisateur existe, son uid est ≥ 30000, il appartient au groupe `sftp_sites` et le marqueur
    `/etc/dockpanel/sftp-owners/<uid>.owner` existe ;
  - sinon : 400 avec le nom fautif, et le fichier n'est pas modifié.
- **Liste vide** : acceptée.
- **Retraits** : chaque nom retiré par rapport au fichier précédent est déconnecté avec
  `pkill -u <nom> -x vsftpd`. La route renvoie la liste `kicked`.
- **vsftpd absent** : 412 `"FTP server not installed"`. Le backend garde alors la case et resynchronise
  à l'installation.

### A-5 `POST /disk-usage` `{ "domains": ["x.tld", ...] }` → `{ "results": [ ... ] }`
- **Format d'un résultat** : `{ "domain", "bytes", "files", "error": null }`. Si le dossier
  `/var/www/<domaine>` est absent, `bytes` et `files` valent `null` et `error` vaut `"Site directory not found"`.
- **Refus** : 400 si plus de 500 domaines ou si un nom est invalide (mêmes règles que les autres routes).
- **Parcours** :
  - un seul thread `spawn_blocking` (`walkdir`) ;
  - pas de suivi des liens symboliques, pas de sortie du système de fichiers (`same_file_system`) ;
  - octets = somme de `st_blocks × 512` ;
  - liens durs comptés une fois (ensemble `(dev, ino)` quand `nlink > 1`) ;
  - `files` = nombre d'entrées hors dossiers.
- **Priorité** : en début de thread, `setpriority(PRIO_PROCESS, tid, 19)` puis `ioprio_set` en classe
  idle.
- **Délai** : 10 min pour l'appel entier ; un domaine en erreur ne fait pas échouer les autres.
- **Une seule mesure à la fois** par agent : un second appel attend son tour (mutex).

### A-6 Installeurs existants
- **`install_ufw`** : si vsftpd est installé, ouvrir aussi 21 et 12000:12100.
- **`install_fail2ban`** : si vsftpd est installé, écrire la prison de A-2.

### A-7 Propriétaire des fichiers d'un site (`services/site_owner.rs`)
```rust
pub fn site_owner(domain: &str) -> (u32, u32)                // stat de /var/www/<domain>, (33,33) www-data si absent
pub async fn chown_site_tree(domain: &str, path: &Path) -> Result<(), String>  // chown -R uid:gid via l'échappement
```
- Chaque `chown -R www-data:www-data` visant l'arborescence d'un site passe par `chown_site_tree`.
- **Garde** : `path` doit rester sous `/var/www/<domain>`.
- **Lecture au bon moment** : le propriétaire est lu avant toute opération qui pourrait recréer la racine
  du site. Par exemple, une restauration qui remplace `/var/www/<domain>` lit d'abord, puis applique.
- **Tests unitaires** : garde de chemin, et repli sur www-data quand le dossier est absent.

## B. Backend
### B-1 Migration `20261121000000_ftp_disk_quota.sql`
```sql
ALTER TABLE sites ADD COLUMN IF NOT EXISTS ftp_enabled boolean NOT NULL DEFAULT false;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS disk_quota_mb integer NULL CHECK (disk_quota_mb IS NULL OR disk_quota_mb > 0);
CREATE TABLE IF NOT EXISTS site_disk_usage (
  site_id uuid PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
  bytes bigint NULL, files bigint NULL,
  measured_at timestamptz NOT NULL DEFAULT now(),
  error text NULL);
```

### B-2 Routes FTP
- **`GET /api/ftp/status?server_id=`** (admin) : relaie A-1. Le serveur par défaut est le serveur local.
- **`POST /api/ftp/install` `{ "server_id"? }`** (admin) :
  - envoie à A-2 la liste des `sftp_username` réels (`sftp_account_name()`) des sites du serveur qui ont
    `ftp_enabled AND sftp_enabled` ;
  - ajoute `pasv_address` quand l'IP par défaut du serveur a une IP publique distincte (fonctionnalité 1).
- **`POST /api/ftp/uninstall` `{ "server_id"? }`** (admin) : relaie A-3. Les cases `ftp_enabled` sont
  conservées.
- **`POST /api/sites/{id}/ftp` `{ "enabled": bool }`** → `{ "ftp_enabled": bool }`. Mêmes droits et même
  contrôle de verrouillage que `enable_sftp`.
  - **Refus** : 412 `"Enable SFTP first"` si `!sftp_enabled`, 412 `"FTP server not installed"` si A-4
    répond 412.
  - **Écriture** : la colonne est mise à jour, puis A-4 reçoit la liste complète du serveur. Si l'agent
    échoue, la colonne reprend sa valeur et l'erreur est relayée.
- **Fonction partagée** : `sync_ftp_users(pool, agents, server_id)` est utilisée par la route, par
  `disable_sftp`, par la suppression de site et par l'import.
- **`disable_sftp` et suppression de site** :
  - `ftp_enabled = false`, puis `sync_ftp_users`, avant le retrait du compte ;
  - un 412 (vsftpd absent) est ignoré.

### B-3 Quotas et mesure
- **`PUT /api/sites/{id}/disk-quota` `{ "quota_mb": 2048 | null }`** :
  - autorisé à l'admin, et au revendeur propriétaire du compte client ; sinon 403 ;
  - après l'écriture, l'alerte est recalculée (B-4) à partir de la dernière mesure.
- **`POST /api/sites/{id}/disk-usage/refresh`** :
  - mesure synchrone de ce site par A-5 ; renvoie `disk_usage` (format ci-dessous) puis recalcule
    l'alerte ;
  - 429 `"A measurement is already running for this site"` si une mesure de ce site est en cours ;
  - autorisé à l'admin, au propriétaire et à son revendeur.
- **JSON du site** (détail et liste) : ajout de `"ftp_enabled"`, `"disk_quota_mb"` et
  `"disk_usage": { "bytes", "files", "measured_at", "error" } | null`.
- **Ordonnanceur `services/disk_usage.rs`** :
  - au démarrage, puis toutes les 6 h, il groupe les sites par serveur et fait un appel A-5 par serveur ;
  - il écrit `site_disk_usage` par upsert (`error` renseigné, `bytes` conservé à la dernière valeur
    connue si la mesure échoue) ;
  - il recalcule ensuite les alertes ;
  - si un serveur est injoignable, il est sauté sans erreur bloquante, et on retente au cycle suivant.
- **Revendeurs** : `GET` de la liste et du détail ajoute `"disk_used_bytes"`, la somme des
  `site_disk_usage.bytes` des sites de ses clients.

### B-4 Alerte `disk_quota`
- **Calcul** : `pct = bytes / (quota_mb × 1048576)`, avec la clé `disk_quota:<site_id>`.
- **Quand la résoudre** : si `quota_mb` est nul, si `bytes` est nul ou si `pct < 0.90`.
- **Warning** si `0.90 ≤ pct < 1.0`. Titre : `Disk usage of x.tld at 92% of quota`.
- **Critical** si `pct ≥ 1.0`. Titre : `Disk quota exceeded on x.tld (2.3 GB of 2 GB)`.
- **Changement de gravité** : on résout l'ancienne alerte et on émet la nouvelle. Si l'état ne change
  pas, rien n'est renvoyé (même schéma que `av_scanner::refresh_site_alert`).
- **Destinataire** : le propriétaire du site. L'admin la reçoit selon les règles existantes.

### B-5 Import Hestia (`import_sftp.rs`)
- **Quand le site importé avait `ftp_user`** :
  - `ftp_enabled = true`, puis `sync_ftp_users`, une fois le hash posé ;
  - si A-4 répond 412, on ajoute dans le journal l'action manuelle
    `"Install the FTP server (Settings → Services) to restore FTP access"`, sous le code `ftp_server_missing`.
- **Si `user.conf` contient un `DISK_QUOTA` chiffré** : une note dans le journal, sans action.
  - Le chantier B ne lit que l'inventaire existant. Si `DISK_QUOTA` n'y figure pas, on ne l'ajoute pas :
    rien n'est fait dans ce cas.

## C. Interface
- **`FtpServerCard`** (Settings → Services) :
  - état « Running » ou « Stopped », boutons « Install » et « Uninstall » (le second avec confirmation) ;
  - certificat : « Let's Encrypt (panel.example.com), expires 2027-02-10 », ou un avertissement
    « Self-signed certificate: FTP clients will ask to trust it » ;
  - ports « 21, passive 12000-12100 », pare-feu, présence de la prison fail2ban ;
  - si le serveur n'est pas pris en charge : « Not supported on this server ».
- **Carte « SFTP / FTP Access »** de SiteDetail :
  - interrupteur « Enable FTP (FTPS) », désactivé avec une infobulle « Enable SFTP first » ou
    « Install the FTP server in Settings → Services » ;
  - bloc « Connection details » : Host (nom d'hôte du panel), Port 21, Encryption « Require explicit FTP
    over TLS », Mode « Passive », Username ;
  - indication « Same password as SFTP ».
- **`DiskUsageCard`** :
  - barre `used / quota` : verte, orange à partir de 90 %, rouge au-delà de 100 % ; sans quota, la valeur
    seule et « Unlimited » ;
  - « Measured 2 h ago », bouton « Refresh » et `error` affichée s'il y en a une ;
  - champ « Quota (GB) » (décimales acceptées, envoyé en Mo ; vide = illimité) et bouton « Save »,
    seulement si l'utilisateur est admin ou revendeur.
- **Liste des sites** : colonne « Disk » au format `1.2 GB` ou `1.2 / 2 GB`, en rouge si le quota est
  dépassé.
- **Alertes** : libellé `disk_quota` → « Disk quota ».
- **Resellers** : « Disk: 3.4 GB used of 10 GB », ou « of unlimited ».
- **Formats** : tailles en base 1024, avec une décimale.
