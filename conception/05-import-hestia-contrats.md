# Fonctionnalité 5 - Contrats d'interface (import HestiaCP complet)

Référence : écrit `05-import-hestia.md` (décisions D1-D12). Debian/Ubuntu ; RHEL refuse proprement (PHP legacy, MariaDB local, mail).
Cinq chantiers parallèles : écrit **W1** agent (archive, staging, fichiers, SSL), **W2** bases (MariaDB local), **W3** web
(vhost, PHP legacy, SSL multi-noms), **W4** mail + SFTP, **W5** orchestration backend + assistant.
Ce fichier fixe ce qu'ils s'échangent et qui possède quoi. Règle : écrit un fichier = un propriétaire ; les autres
demandent la modification par ce contrat, jamais en y touchant. Libellés d'interface en anglais, jamais de tiret cadratin.

## 0. Propriété des fichiers (`panel/`)

### Agent (`panel/agent/`)
| Fichier | Propriétaire | Remarque |
|---|---|---|
| `src/services/migration.rs`, `src/routes/migration.rs` | W1 | staging, analyse, import-site, ssl, cleanup |
| `src/services/hestia.rs` (nouveau), `migration_jobs.rs` (nouveau), `migration_files.rs` (nouveau) | W1 | |
| `src/routes/mod.rs`, `src/services/mod.rs`, `src/main.rs` | W1 | bloc `// --- import-hestia (05) ---` écrit à l'étape 0 pour tous |
| `dockpanel-agent.service`, `src/services/agent_unit.rs`, `scripts/setup.sh`, `scripts/update.sh` | W1 | voir W1-S |
| `src/services/local_mariadb.rs` (nouveau), `src/routes/local_db.rs` (nouveau), `src/services/database_backup.rs`, `src/routes/database_backup.rs` | W2 | |
| `src/routes/nginx.rs`, `src/templates/nginx/*.conf`, `src/services/nginx.rs`, `src/services/apache.rs`, `src/services/vhost_extras.rs` (nouveau) | W3 | |
| `src/services/ssl.rs`, `src/routes/ssl.rs` | W3 | |
| `src/routes/php.rs`, `src/services/php_pool.rs`, `src/services/pkg.rs`, `src/routes/iac.rs`, `src/routes/service_installer.rs` | W3 | listes de versions PHP |
| `src/routes/mail.rs`, `src/services/hestia_mail.rs` (nouveau) | W4 | |
| `src/routes/sftp.rs`, `src/services/sftp_accounts.rs`, `src/services/ownership.rs` | W4 | W4 remplace aussi le littéral `["8.1",...]` ligne ~297 par `php_pool::PHP_VERSIONS` |
| `src/routes/database.rs`, `src/services/database.rs` | personne | conteneurs inchangés |

### Backend (`panel/backend/`)
| Fichier | Propriétaire | Remarque |
|---|---|---|
| `src/routes/migration.rs`, `src/services/import_types.rs`, `import_site.rs`, `migration_ledger.rs` (nouveaux) | W5 | boucle d'import = un seul propriétaire |
| `src/routes/mod.rs`, `src/services/mod.rs`, `src/main.rs` | W5 | écrit TOUTES les routes ci-dessous à l'étape 0 |
| `migrations/20261119020000_migration_items.sql` | W5 | |
| `src/routes/databases.rs`, `src/services/import_db.rs` (nouveau), `src/routes/backups.rs`, `src/routes/backup_orchestrator.rs`, `src/services/backup_policy_executor.rs`, `migrations/20261119000000_local_databases.sql` | W2 | |
| `src/routes/sites.rs`, `src/routes/ssl.rs`, `src/routes/php_settings.rs`, `src/helpers.rs` (renouvellement), `src/services/auto_healer.rs`, `src/models.rs`, `migrations/20261119010000_site_aliases_canonical.sql` | W3 | |
| `src/routes/mail.rs`, `src/services/import_mail.rs` (nouveau), `src/services/import_sftp.rs` (nouveau) | W4 | |

### Frontend (`panel/frontend/src/`)
| Fichier | Propriétaire |
|---|---|
| `pages/Migration.tsx` | W5 |
| `pages/Databases.tsx` (et composants propres aux bases) | W2 |
| `pages/SiteDetail.tsx`, `components/PhpVersionPicker.tsx` | W3 |
| `pages/Mail.tsx` (bascule « keep a copy ») | W4 |

La carte SFTP (champ « username ») vit dans `SiteDetail.tsx` : écrit W3 l'implémente selon la spec W4-S.

## 1. Étape 0 (W1 agent + W5 backend, une heure, fusionnée AVANT le reste)
- W1 écrit dans l'agent : écrit le bloc de déclarations `mod`/`.merge(...)` pour `local_db` (routeur vide) et les squelettes compilables de
  `local_mariadb.rs`, `hestia_mail.rs`, `vhost_extras.rs`, `migration_jobs.rs`, `hestia.rs`, avec les signatures de W1-H ci-dessous
  (corps `Err("not implemented".into())`). Chaque propriétaire REMPLACE son squelette en entier.
- W5 écrit dans le backend : écrit `import_types.rs` (types W5-T), squelettes `import_db.rs`, `import_mail.rs`, `import_sftp.rs` (signatures W2/W4,
  retour `Failed("not implemented")`), la migration `migration_items`, et TOUTES les lignes de routes de §W5-R (handlers squelettes dans les
  fichiers des propriétaires : écrit retour 501 jusqu'à implémentation, noms de fonctions imposés).
- Horodatages de migration réservés : écrit `20261119000000` (W2), `20261119010000` (W3), `20261119020000` (W5), `20261119030000` (W4 : `sites.sftp_username`, `mail_accounts.keep_copy`). Le plus récent existant est `20261118000000`.
- Exception unique et bornée à l'étape 0 : écrit W5 peut ajouter dans les fichiers des autres une fonction handler squelette marquée
  `// STUB(Wn)` (501) pour que `routes/mod.rs` compile ; le propriétaire la remplace. Plus aucune autre édition croisée ensuite.

## W1. Agent : écrit archive, staging, fichiers, SSL

### W1-S. Système
- Staging : écrit `STAGING_ROOT = /var/lib/dockpanel/migration`, `<root>/<migration_uuid>/` en 0700 root. Remplace `/tmp/dockpanel-migration-*` pour TOUS les panels.
  `FETCH_DIR` inchangé. `cleanup` supprime le staging et les jobs de la migration.
- `scripts/setup.sh` / `update.sh` : écrit paquets `zstd` et `rsync` ajoutés à la liste de base ; `a2dismod -f cgi cgid || true` (W3 en dépend, D9) ;
  vérifier que `/var/lib/dockpanel`, `/var/vmail`, `/var/www` sont dans `ReadWritePaths` de l'unité du dépôt (`panel/agent/dockpanel-agent.service`,
  pas la copie sous `.claude/worktrees`) et mettre à jour les tests de chemins de `agent_unit.rs` si l'unité change.
- `zstd` absent alors qu'un blob `.zst` existe : écrit l'analyse échoue avec « install zstd ».

### W1-A. `POST /migration/analyze` (corps `{path, source}`, `source` accepte `auto`)
- `auto` : écrit `hestiacp` si `hestia/user.conf` existe (avec ou sans `./`), `cpanel` si `homedir/` ou `cp/`, `plesk` si `domains/`, sinon 400 « Unknown backup format ».
- Hestia, archive tar simple : écrit mode `lazy` (D8) ; compressée : mode `full`. Écrit `<staging>/meta.json` `{"mode","archive","hestia_user"}`.
- Réponse (inventaire, AUCUN secret, aucune valeur de hash/clé) : écrit
```json
{ "id": "<uuid agent>", "source": "hestiacp", "mode": "lazy", "hestia_user": "adm-jim", "archive_bytes": 9674659840,
  "disk": { "staging_free": 0, "www_free": 0, "www_needed_estimate": 0, "ok": true, "reason": null },
  "sites": [{ "domain": "x.tld", "doc_root": "web/x.tld/domain_data", "size_bytes": 123, "file_count": 0, "runtime": "php",
              "web_server": "apache", "php_version": "5.6", "php_version_source": "BACKEND:PHP-5_6",
              "aliases": ["www.x.tld"], "canonical_host": "www",
              "ssl": { "present": true, "issuer": "LE", "not_after": "2027-01-01T00:00:00Z", "covers": ["x.tld","www.x.tld"], "expired": false },
              "force_ssl": true, "hsts": true, "ftp_user": "adm-jim_x", "suspended": false,
              "doc_root_dir": "public_html", "custom_nginx_template": null,
              "paths_to_fix": [{ "file": ".user.ini", "occurrences": 1 }], "upload_php_files": 0 }],
  "databases": [{ "name": "adm-jim_x", "file": "db/adm-jim_x/adm-jim_x.mysql.sql.gz", "size_bytes": 1, "engine": "mariadb",
                  "charset": "utf8mb4", "db_user": "adm-jim_x", "suggested_site": "x.tld", "suggested_via": "wp-config.php" }],
  "mail_domains": [{ "domain": "d.be", "selector": "mail", "dkim": true, "catch_all": null, "accounts": 3, "aliases": 1, "maildir_bytes": 1 }],
  "mail_accounts": [{ "email": "a@d.be", "domain": "d.be", "quota_mb": null, "forward_to": null, "forward_only": false,
                      "hash_scheme": "BLF-CRYPT", "suspended": false }],
  "ftp_accounts": [{ "user": "adm-jim_x", "domain": "x.tld", "hash_scheme": "yescrypt" }],
  "cron_jobs": 0, "dns_domains": 0, "warnings": ["..."] }
```
  `runtime` Hestia : écrit `php` si `BACKEND` non vide, sinon `static`. `php_version` : `PHP-X_Y` donne `X.Y`, `default` donne `null`. `mail_accounts` (cPanel) garde la forme `{email, domain}`.
  `web_server` : écrit `hestia_web_server` existant. `canonical_host` : `hestia::canonical_from_redirect` sur `conf/nginx.ssl.conf_redirect` puis `nginx.conf_redirect`.
  Avertissements : écrit `PROXY` personnalisé (nom du gabarit), `SSL_FORCE=no`, `SSL_HSTS=no`, suspendu, `public_html` absent, plusieurs `FTP_USER`.
- `file_count` : écrit 0 en mode lazy. `size_bytes` : taille du blob compressé. Indices base vers site (D12), `paths_to_fix`, `upload_php_files` : une passe de lecture
  par `domain_data` (décompression en flux, extraction ciblée des petits fichiers, jamais d'arbre complet sur disque), avec job de progression.
- `disk.ok=false` : écrit `reason` explicite ; l'analyse réussit quand même (le backend affiche, l'import refuse).

### W1-J. Jobs (`services/migration_jobs.rs`)
```rust
pub struct JobHandle { .. }  // Clone
impl JobHandle { pub fn progress(&self, phase:&str, done:u64, total:u64, msg:&str); pub fn warn(&self, w:String); }
pub fn spawn<F, Fut>(kind:&str, key:&str, f:F) -> String   // job_id ; même (kind,key) déjà en cours : écrit renvoie l'id existant
  where F: FnOnce(JobHandle) -> Fut, Fut: Future<Output=Result<serde_json::Value,String>> + Send + 'static;
pub fn get(job_id:&str) -> Option<serde_json::Value>
```
`GET /migration/jobs/{job_id}` (route W1) : écrit
`{ "job_id", "kind", "key", "state": "running|done|failed", "phase", "bytes_done", "bytes_total", "message", "warnings": [], "report": {}|null, "error": null|"..", "updated_at": 0 }`.
En mémoire, conservé 6 h après la fin. Agent redémarré : écrit 404, traité par le backend comme un échec relançable.

### W1-H. Aides publiques pour W2/W4 (`services/migration.rs`, `services/hestia.rs`)
```rust
pub fn staging_dir(migration_id:&str) -> Result<PathBuf,String>;                // valide l'id (UUID)
pub async fn spawn_member_reader(migration_id:&str, member:&str) -> Result<tokio::process::Child,String>;
   // stdout = contenu du membre, décompressé selon .gz/.zst ; kill_on_drop ; membre relatif, sans "..", sans "/" initial
pub async fn extract_tar_member(migration_id:&str, member:&str, dest:&Path, include:&[String], strip:u32,
                                job:Option<&JobHandle>) -> Result<(),String>;   // flux -> tar x --no-same-owner
// hestia.rs
pub fn parse_pairs(line:&str) -> Vec<(String,String)>;                           // ex-hestia_pairs
pub fn php_version_from_backend(b:&str) -> Option<String>;
pub fn canonical_from_redirect(domain:&str, conf:&str) -> Option<&'static str>;  // "www" | "apex"
pub struct DbCred { pub db:String, pub user:String, pub mysql_hash:String, pub charset:String }  // Debug masque mysql_hash
pub fn db_credentials(migration_id:&str, db:&str) -> Result<DbCred,String>;      // lit db/<db>/hestia/db.conf (ligne DB=<db>)
pub fn ftp_hash(migration_id:&str, domain:&str) -> Option<(String,String)>;      // (ftp_user, hash crypt(3)) ; jamais journalisé
```
Tests purs exigés : écrit `parse_pairs`, `php_version_from_backend`, `canonical_from_redirect` (www, apex, absent), détection `auto`, calcul `disk`, rejet des chemins de membres.

### W1-I. Import de site : écrit `POST /migration/import-site`
Corps `{ "migration_id", "domain", "runtime", "mode": "initial"|"force" }` -> **202** `{ "job_id" }` (validation en 400 immédiat).
Phases : écrit `space` (libre >= 2,5 x blob + 1 Gio, sinon échec `insufficient_disk`), `extract` dans `/var/www/<d>/.import-<job>/`, `place` (`public_html` vers la racine
de `document_root_for(runtime)` ; `public_html0` si seul ; `private/` vers `/var/www/<d>/private` ; exclusions D7) par `rsync -a` (`--delete` seulement si `mode=force`),
`fix` (propriétaire `www-data` hors `.git`, retrait setuid/setgid, réécriture bornée D7, liens sortants), suppression de `.import-<job>`. Rapport du job : écrit
```json
{ "doc_root_used": "public_html", "private_copied": true, "files_bytes": 0, "rewritten": [".user.ini"], "paths_to_fix": [{"file":"wp-config.php","occurrences":2}],
  "symlinks_out": ["x -> /etc"], "upload_php_files": 0, "custom_nginx_saved": "/var/www/x.tld/private/.hestia-import/custom-nginx/custom-lmj.stpl", "warnings": [] }
```
Autres panels : écrit comportement actuel (rsync depuis le staging), nouveau staging, sans `--delete` en `initial`. L'ancien `POST /migration/import-database` (conteneurs) est conservé.

### W1-C. `POST /migration/hestia/import-ssl`
Corps `{ "migration_id", "domain" }`. Lit `web/<d>/hestia/<d>.{crt,ca,key}`, construit `fullchain = crt + ca`, vérifie `ssl::cert_covers_domain`, correspondance clé/certificat, `not_after`,
écrit `/etc/dockpanel/ssl/<d>/{fullchain,privkey}.pem` (clé 0600 à la création, `ssl::write_key_file`). Réponse 200
`{ "cert_path", "key_path", "expiry": "RFC3339", "covers": ["x.tld","www.x.tld"], "issuer": "..", "warnings": [] }` ; 422 `{"error", "code": "expired|mismatch|not_covering|missing"}`.
Ne modifie PAS le vhost (W5 le refait via `build_nginx_body`). Aucune clé dans la réponse ni dans les journaux.

**Fait quand** : écrit analyse d'un tar de 9,6 Go sans extraction des blobs ; tous les avertissements de l'audit produits ; import de site de plusieurs Go avec progression ;
`conf/`, `hestia/`, `template/` jamais présents sous `/var/www` ; tests purs verts ; `cargo test` agent vert.

## W2. Bases : écrit MariaDB local (`kind='local'`)

### W2-D. Données (`migrations/20261119000000_local_databases.sql`)
```sql
ALTER TABLE databases ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'container' CHECK (kind IN ('container','local'));
ALTER TABLE databases ADD COLUMN IF NOT EXISTS imported_hash BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE databases ADD CONSTRAINT chk_databases_local_shape CHECK
  (kind = 'container' OR (port IS NULL AND container_id IS NULL AND stack_id IS NULL AND site_id IS NOT NULL AND engine = 'mariadb'));
```
`Database` (dans `routes/databases.rs`) gagne `kind: String` (sérialisé). Les requêtes de colonnes explicites sont complétées. Unicité du nom d'une base `local` par serveur : écrit
vérifiée dans le code (join `sites.server_id`), pas par index.

### W2-A. Routes agent (`routes/local_db.rs`, `services/local_mariadb.rs`)
Toutes en root par le socket `/run/mysqld/mysqld.sock` ; identifiants entre backticks ; chaînes SQL jamais construites à partir de texte non validé.
| Route | Corps / réponse |
|---|---|
| `GET /localdb/status` | `{installed, running, version, socket, bind: "127.0.0.1:3306", supports_uca1400, databases: n}` |
| `POST /localdb/install` | idempotent, `post_long` 900 s ; dépôt mariadb.org 11.4 (Debian/Ubuntu) ou repli distribution ; écrit `/etc/mysql/mariadb.conf.d/99-cyberhunter.cnf` (`bind-address=127.0.0.1`, `port=3306`, `character-set-server=utf8mb4`, `max_allowed_packet=256M`, `local_infile=0`) ; `{success, message, version}` |
| `POST /localdb/databases` | `{name, db_user, charset?, password?: string, password_hash?: string}` (exactement un des deux) : écrit crée base, `'u'@'localhost'` et `'u'@'127.0.0.1'`, `GRANT ALL ON \`base\`.*` (`_` `%` échappés) -> `{created_db, created_user}` |
| `POST /localdb/databases/{name}/drop` | `{db_user, drop_user_if_unused: true}` |
| `POST /localdb/databases/{name}/password` | `{db_user, new_password}` |
| `POST /localdb/query` | `{database, sql}` -> même forme que `POST /databases/query` ; compte temporaire `ch_tmp_<aléa>` limité à la base, supprimé en fin et au démarrage de l'agent (balayage `ch_tmp_%`) |
| `POST /localdb/config` | `{sql_mode: string ou null}` : écrit `sql_mode` dans `99-cyberhunter.cnf` (motif `^[A-Z0-9_,]*$`, null = défauts MariaDB 11.4), redémarre MariaDB ; `/localdb/status` renvoie `sql_mode` |
| `POST /localdb/hestia/import` | `{migration_id, db_name, replace: bool}` -> **202** `{job_id}` |

Validation du nom local : écrit `^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`, utilisateur <= 80 car., même motif. `password_hash` : `^\*[0-9A-Fa-f]{40}$`.
Job d'import : écrit `hestia::db_credentials` ; base présente avec des tables et `replace=false` -> échec `code: "exists_not_ours"` ; `replace=true` -> `DROP DATABASE` puis recréation ;
`CREATE DATABASE` avec le jeu de caractères de `DbCred.charset` ; utilisateur existant avec un autre hash : écrit conservé + avertissement ; flux `spawn_member_reader` vers
`mariadb --binary-mode --init-command="SET foreign_key_checks=0, unique_checks=0"` sur la base (filtre `uca1400` -> `utf8mb4_unicode_ci` seulement si `!supports_uca1400`) ;
progression en octets lus du blob ; contrôle final (nombre de tables > 0 si le dump en créait). Rapport `{tables, created_db, created_user, collation_rewritten, warnings}`.
Aucun hash ni mot de passe dans le rapport, la progression ou les journaux.

Sauvegardes (`database_backup.rs`, endpoints `/db-backups/{name}/...` existants) : écrit `container_name == "local"` -> `mariadb-dump --single-transaction --routines --events` de la base
seule (root par le socket) ; restauration en flux ; `user`/`password` du corps ignorés. Pas de PITR ni instantané pour `local` (400).

### W2-B. Backend (`routes/databases.rs`, `services/import_db.rs`, appelants de sauvegarde)
- `pub(crate) fn container_ref(kind:&str, name:&str) -> String` (`"local"` ou `dockpanel-db-<name>`) utilisé par `backups.rs:114`, `backup_orchestrator.rs:950,1126`, `backup_policy_executor.rs:552`.
- `create` : écrit champ optionnel `kind` (`container` défaut ; `local` exige engine `mariadb`/`mysql`, site, MariaDB local installé -> 409 `{"code":"local_db_not_installed"}`) ; mot de passe généré affiché une fois comme aujourd'hui.
- `credentials` pour `local` : écrit `{host:"localhost", port:3306, socket:"/run/mysqld/mysqld.sock", user, password: null|"..", password_known: bool, kind:"local", note}`.
- `remove`, `reset_password` (ALTER USER, remet `imported_hash=false`, stocke le nouveau mot de passe chiffré), `query`, `tables`, `table_schema`, `indexes`, `foreign_keys`, `schema_overview`, `dumps`, `import`
  branchent sur `kind` (agent `/localdb/*`). `pitr_*` : écrit 400 « not available for local databases ». Le plafond de 25 ne compte que `kind='container'`.
- `GET /api/databases/local/status` -> `local_status`, `POST /api/databases/local/install` -> `local_install` (admin).
- `services/import_db.rs` : écrit `pub async fn import_hestia_db(ctx:&ImportCtx, db_name:&str, site_id:Uuid) -> ItemOutcome`. Ordre : ligne `databases` (kind local, `imported_hash=true`, `db_password_enc=''`,
  `db_user` = `DbCred.user` fourni par l'inventaire, port/conteneur NULL) créée d'abord, puis job agent (`replace` = état du grand livre `running|failed`), suivi par sondage, ligne supprimée si le job échoue
  et que la base n'existait pas avant. Détail du grand livre : écrit `{tables, collation_rewritten, db_user}`, jamais de hash.

**Fait quand** : écrit 30 bases (dont 10 avec point, une avec majuscule) importées en VM avec l'ancien mot de passe valide sur socket et TCP ; l'interface « Databases » fonctionne pour `local` (liste, identifiants, tables,
requête, sauvegarde/restauration, reset, suppression) ; aucun `ch_tmp_%` résiduel ; conteneurs existants intacts ; tests purs (validation de nom, hash, échappement GRANT, filtre collation) verts.

## W3. Web : écrit vhost (alias, canonique, no-exec), PHP legacy, SSL multi-noms

### W3-P. PHP 5.6 / 7.4
- Source unique : écrit `agent/src/services/php_pool.rs` : `PHP_VERSIONS = ["5.6","7.4","8.1","8.2","8.3","8.4","8.5"]` et `LEGACY_PHP_VERSIONS = ["5.6","7.4"]`.
  `routes/php.rs::ALLOWED_VERSIONS` en dérive. Remplacer les littéraux `["8.1",...]` : écrit `routes/nginx.rs` (~827, ~1278), `routes/iac.rs:327`, `services/pkg.rs` (~947, ~988) ;
  `routes/service_installer.rs:~1716` (ordre de repli descendant) reste SANS legacy. `sftp_accounts.rs` est à W4.
- `GET /php/versions` : écrit chaque entrée gagne `"legacy": bool`. `POST /php/install` : message `warning` pour legacy (« PHP 5.6 reached end of life ... no security updates »).
  `COMMON_EXTENSIONS` : écrit ajouter `json`, `mcrypt`, `soap` (filtre « candidat existe » déjà en place). RHEL : 501 pour 5.6/7.4 (déjà : flux `php_streams`).
- Le pool 5.6/7.4 rendu par `php_pool.rs` doit être accepté par `php-fpm5.6 -t` / `php-fpm7.4 -t` (VM) ; toute directive inconnue d'un FPM ancien est filtrée par version (test pur).
- Backend `routes/sites.rs` : écrit `PHP_VERSIONS` identique + `pub(crate) const LEGACY_PHP_VERSIONS`. `PUT /api/sites/{id}/php-version` (et création) répondent `warning` si legacy.
- Frontend : écrit `PhpVersionPicker.tsx` ajoute 5.6 et 7.4 avec badge « Legacy, no security updates » ; `SiteDetail.tsx` bandeau permanent pour un site legacy.

### W3-V. Modèle de vhost (`SiteConfig`, `nginx.rs`, gabarits, `apache.rs`, `vhost_extras.rs`)
Nouveaux champs optionnels (`#[serde(default)]`) ajoutés à TOUS les littéraux `SiteConfig` (comme `web_server`) : écrit
- `aliases: Option<Vec<String>>` : écrit `Some` fait foi, rendu `server_name <domain> <a1> <a2>;` dans TOUS les blocs `server` (http, https, proxy) et `ServerAlias` Apache ; `None` : conserve ceux
  du vhost sur disque (`aliases_in_nginx_config`). Chaque alias validé `is_valid_domain`, <= 20, ni le domaine, ni doublon.
- `canonical_host: Option<String>` (`"www"|"apex"`, absent = aucun) : écrit cible = `www.<domain>` ou `<domain>`, doit figurer dans les noms servis sinon 400.
  Rendu : écrit HTTP seul (sans SSL) : `location / { return 301 $scheme://<cible>$request_uri; }` quand `$host != <cible>` (par `if` dans le `location /`) ; avec SSL, bloc `:80` :
  `location / { return 301 https://<cible>$request_uri; }` (une seule redirection) ; bloc `:443` : écrit `if ($host != "<cible>") { return 301 https://<cible>$request_uri; }` en tête du `server`.
  `/.well-known/acme-challenge/` reste servi sur `:80` pour tous les noms. Modes nginx et Apache identiques (la redirection est dans nginx).
- `php_no_exec_dirs: Option<Vec<String>>` : écrit absent ou `[]` = aucun, rendu inchangé (la liste par défaut D9 est écrite en base à la création d'un site PHP et à l'import, et proposée aux sites existants par « apply defaults ») ; chaque entrée `^/[A-Za-z0-9_./-]*$`, sans `..`. nginx : bloc regex D9 placé AVANT le bloc `\.php$` (et avant les presets) ;
  Apache : écrit `<LocationMatch>` + `Require all denied`. Fonction pure `vhost_extras::no_exec_block(dirs)` testée (chemins `/uploads/x.php`, `/uploads/x.jpg/x.php`, `/Uploads/x.PHP`).
- `apache.rs` : écrit `ExecCGI` ajouté à la liste `Options=` d'`AllowOverride` (rien d'autre) ; mise à jour idempotente des vhosts Apache gérés au démarrage de l'agent ; test du vhost rendu (`apachectl configtest`).
- Rendu octet pour octet inchangé quand aucun nouveau champ n'est fourni et qu'aucun alias n'existe (les tests `absent_*_renders_byte_identically_*` restent verts ; aucun test existant ne change).

Backend (`migrations/20261119010000_site_aliases_canonical.sql`) : écrit
```sql
ALTER TABLE sites ADD COLUMN IF NOT EXISTS aliases TEXT[];                -- NULL = non géré par la base
ALTER TABLE sites ADD COLUMN IF NOT EXISTS canonical_host TEXT CHECK (canonical_host IN ('www','apex'));
ALTER TABLE sites ADD COLUMN IF NOT EXISTS php_no_exec_dirs TEXT[];       -- NULL = aucun
ALTER TABLE sites ADD COLUMN IF NOT EXISTS force_ssl BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS hsts BOOLEAN NOT NULL DEFAULT true;
```
`models.rs::Site` : écrit `aliases: Option<Vec<String>>`, `canonical_host: Option<String>`, `php_no_exec_dirs: Option<Vec<String>>`. `build_nginx_body` envoie `aliases` seulement si `Some`, `canonical_host` si `Some`,
`php_no_exec_dirs` si `Some`. Les endpoints d'alias existants (`add_alias`, `remove_alias`) lisent la liste agent, mettent la colonne à jour après succès (elle devient gérée). Nouveaux : écrit
`PUT /api/sites/{id}/canonical-host` `{canonical_host: "www"|"apex"|string ou null}` : écrit` -> handler `sites::set_canonical_host` ; `PUT /api/sites/{id}/php-no-exec` `{dirs: ["/..."]|null}` -> `sites::set_php_no_exec`
(propriétaire ou admin ; transaction : écrit UPDATE, rebuild du vhost, commit si l'agent accepte ; journal d'activité). `POST /api/sites` écrit la liste par défaut pour tout nouveau site PHP ; `{dirs: "defaults"}` applique la liste par défaut. Frontend `SiteDetail.tsx` : carte alias avec choix canonique (None / www / apex),
carte « Block PHP execution in upload folders » (liste éditable, défaut affiché).
Aides pour W5 : écrit `pub(crate) async fn record_uploaded_ssl(db:&PgPool, site_id:Uuid, cert_path:Option<&str>, key_path:Option<&str>, expiry:Option<DateTime<Utc>>)` (extrait de `upload_ssl`, même UPDATE), et `build_nginx_body` reste `pub(crate)`.

### W3-F. Force SSL / HSTS par site, nom SFTP
- `SiteConfig.force_ssl: Option<bool>` et `hsts: Option<bool>` (absent = vrai = rendu actuel octet pour octet). `force_ssl=false` : écrit le bloc `:80` sert le site (plus de `return 301 https`) tout en gardant l'ACME ; `hsts=false` : pas d'en-tête `Strict-Transport-Security`.
  `Site` : écrit `force_ssl: bool`, `hsts: bool` (`#[sqlx(default)]` à vrai) ; `build_nginx_body` les envoie toujours. `PUT /api/sites/{id}/ssl-options` `{force_ssl, hsts}` -> `sites::set_ssl_options` ; carte SSL de `SiteDetail.tsx` : deux bascules ; l'import les prend de l'inventaire (`force_ssl`, `hsts`).
- SFTP (fichiers W3 car `sites.rs`, `models.rs`, `SiteDetail.tsx`) : écrit `Site.sftp_username: Option<String>` (colonne créée par la migration W4) ; `build_nginx_body` : `pool_user = site.sftp_username` sinon `sftp<uid>` ; `enable_sftp` accepte `{username?}`, la valide (motif et unicité de W4-S) et l'envoie à `POST /sftp/sites/{d}/enable` ;
  carte SFTP : écrit champ username à l'activation, nom affiché ensuite. Fonction partagée `pub(crate) fn sftp_account_name(site:&Site)->String` (utilisée par W4).

### W3-S. SSL : écrit noms supplémentaires
- Agent `routes/ssl.rs::ProvisionRequest` : écrit `extra_names: Option<Vec<String>>` (SAN HTTP-01 en plus du domaine, validés, <= 10) et `fallback_apex_only: bool` (défaut false).
  `services/ssl.rs` : écrit la commande ACME (`ssl.rs:457`) ajoute les identifiants ; si elle échoue et `fallback_apex_only` : nouvelle tentative sans les noms supplémentaires, réponse avec `warnings: ["www.x.tld not included: ..."]`.
- Backend : écrit toutes les portes d'émission/renouvellement (`routes/ssl.rs` provision/renew, `helpers.rs` `renewal_plan`/exécuteurs HTTP-01, `auto_healer::auto_renew_ssl`) passent `extra_names = site.aliases`
  (ou `["www.<domain>"]` si `aliases` NULL et que le vhost sur disque le sert) avec `fallback_apex_only: true`. Un certificat importé (`ssl_challenge` NULL, émetteur Let's Encrypt) est renouvelable ; émetteur autre : écrit refus existant.
  Pas de SAN pour DNS-01/joker (inchangé).
- **Garde DNS** (`auto_healer::auto_renew_ssl`, avant l'ARI et tout ordre) : écrit un domaine dont les A/AAAA (résolveur système) ne contiennent aucune IP du serveur (primaire + déclarées) est ignoré pour cette passe
  (log `info` au plus une fois par jour et par site), sans toucher au certificat ni aux compteurs d'échec ; l'alerte d'expiration existante est inchangée. Réutiliser la logique de `GET /api/preflight/dns`. Le bouton « Renew » manuel n'est pas concerné.

**Fait quand** : écrit site 5.6 et 7.4 servis en VM ; alias et canonique conservés après un nouveau rendu (changement de version PHP, SSL, bascule Apache) ; redirection unique, ACME joignable ; `example.be`-like 200 ;
PHP dans `uploads` : écrit 403 nginx seul et Apache ; renouvellement de test couvre `www.` ; tests purs verts.

## W4. Mail + SFTP

### W4-A. Routes agent (`routes/mail.rs`, `services/hestia_mail.rs`)
| Route | Corps / réponse |
|---|---|
| `POST /mail/hestia/secrets` | `{migration_id, domain}` -> `{selector, dkim_private_pem: null\|"..", catch_all: null\|"addr", accounts: [{email, hash, scheme, quota_mb: null\|n, forward_to: null\|"..", forward_only, suspended}], aliases: [{source, destination}]}`. **Seule route qui renvoie des secrets mail**, réservée au backend, jamais journalisée. Sources : écrit `hestia/<d>.conf` (`ACCOUNT ALIAS FWD FWD_ONLY MD5 QUOTA SUSPENDED`), `conf/passwd`, `conf/aliases`, `conf/dkim.pem` (ou `hestia/<d>.pem`), `hestia/mail.conf` (`DKIM_SELECTOR`, `CATCHALL`). `QUOTA='unlimited'` donne `null`. |
| `POST /mail/dkim/import` | `{domain, selector, private_key_pem}` : écrit valide RSA >= 1024 bits, écrit `/etc/dockpanel/dkim/<d>/<selector>.private` (0600, `opendkim`), `rebuild_dkim_tables`, renvoie `{public_key}` |
| `POST /mail/hestia/import-maildir` | `{migration_id, domain, account}` -> **202** `{job_id}` : écrit extrait `<account>/` de `mail/<d>/accounts.tar.{gz,zst}` (`extract_tar_member`, `strip=1`, `--keep-newer-files`) vers `/var/vmail/<d>/<account>/`, `chown -R vmail:vmail`, puis `doveadm force-resync -u <account>@<d> '*'` (échec non fatal). Rapport `{bytes, messages_estimate}` |

Les adresses et sélecteurs sont validés comme dans `sync_config`/`dkim_generate`. `account` : écrit `[A-Za-z0-9._+-]+`, sans `..`.

### W4-B. Backend (`services/import_mail.rs`, `routes/mail.rs`)
- **Redirection + copie locale** : écrit colonne `mail_accounts.keep_copy BOOLEAN NOT NULL DEFAULT false` (migration `20261119030000`) ; `SyncAccount.keep_copy` (`#[serde(default)]`) côté agent : avec `forward_to` et `keep_copy`, la ligne `virtual_alias_maps` devient `email<TAB>email,forward_to` (la boîte reçoit ET redirige) ; sans `keep_copy`, comportement actuel. `build_sync_payload`, `update_account` (champ `keep_copy`) et `MailAccount` (sérialisé, `#[sqlx(default)]`) l'exposent ; `Mail.tsx` : bascule « Keep a copy in this mailbox » sous « Forward to ». Tests purs : ligne d'alias avec/sans copie.
- `routes/mail.rs` : écrit `sync_mail_config` devient `pub(crate)` (aucun autre changement de comportement).
- `pub async fn import_mail_domain(ctx:&ImportCtx, domain:&str) -> Vec<(String, ItemOutcome)>` : écrit clés `mail_domain:<d>`, `mailbox:<email>`, `mail_alias:<src>`, `maildir:<email>`.
  Pas d'appel à `create_domain`, ni DNS automatique, ni certificat `mail.<d>`. Étapes : écrit (1) `/mail/status` : Dovecot absent -> `Failed("mail server not installed")` pour tout le domaine
  (le préalable de W5 le signale avant) ; (2) `POST /mail/hestia/secrets` ; (3) `INSERT mail_domains (domain, dkim_selector, dkim_private_key chiffré, dkim_public_key, catch_all, server_id)` ;
  (4) `POST /mail/dkim/import` ; (5) boîtes : écrit `password_hash` = hash tel quel si son schéma figure dans les schémas de `agent_password_schemes` (sinon `enabled=false` + Warning « password scheme X not supported, set a new password »),
  `quota_mb` = valeur, ou 1048576 (maximum du panel, illimité en pratique) pour `null` ; jamais 1024 par défaut, `forward_to` si présent avec `keep_copy = !forward_only`, `suspended` donne `enabled=false` ; (6) alias ; (7) `sync_mail_config` ;
  (8) maildirs en jobs, un par boîte, sondés ; ligne `maildir:<email>` par boîte. Un domaine/boîte existant dans le panel et absent du grand livre : écrit jamais modifié (Warning `exists_not_ours`).
  Aucun hash ni clé dans `details`.
- Tests purs : écrit mapping des champs `ACCOUNT`/`FWD`/`QUOTA`, choix `enabled`, formats d'alias.

### W4-S. SFTP (`routes/sftp.rs`, `services/sftp_accounts.rs`, `services/import_sftp.rs`)
- Agent : écrit `pub async fn set_password_hash(uid:i32, crypt_hash:&str) -> Result<(),String>` : format `^\$(y|gy|7|6|5|2[abxy]|1)\$[A-Za-z0-9./$,=-]+$`, longueur <= 255, sans `:`/espace/saut de ligne ;
  appliqué par `chpasswd -e` avec `<username>:<hash>` sur stdin (jamais en argument). Route `POST /sftp/sites/{domain}/password-hash` `{uid, migration_id}` : écrit l'agent lit lui-même `hestia::ftp_hash(migration_id, domain)`.
  Réponse `{ok, scheme}` ; 422 `{"code":"unsupported_scheme"}` si le verrou échoue (le compte reste verrouillé : écrit `usermod -L`).
- Backend : écrit `pub async fn import_sftp(ctx:&ImportCtx, site_id:Uuid, domain:&str) -> ItemOutcome` : site déjà `sftp_enabled` -> Skipped ; sinon `nextval('sftp_id_seq')`, `POST /sftp/sites/{d}/enable`,
  `UPDATE sites SET sftp_enabled, sftp_uid, sftp_gid`, nouveau rendu du vhost (`build_nginx_body`, pool utilisateur `sftp<uid>`), `password-hash`. À appeler APRÈS la copie des fichiers. `details` : écrit
  `{sftp_username:"adm-jim_x", hestia_user:"adm-jim_x", password:"kept"|"locked"}`. Plusieurs `FTP_USER` : écrit seul le premier, avertissement. `locked` : Warning avec l'action « Generate password » = « Reset password » de la carte SFTP existante (génère et n'affiche qu'une fois, sans stockage).
- **Nom SFTP personnalisé** (D6) : écrit migration `20261119030000_sftp_username_keep_copy.sql` : `ALTER TABLE sites ADD COLUMN IF NOT EXISTS sftp_username TEXT; CREATE UNIQUE INDEX IF NOT EXISTS idx_sites_sftp_username ON sites(sftp_username) WHERE sftp_username IS NOT NULL;`
  Agent : écrit `POST /sftp/sites/{domain}/enable` accepte `{uid, gid, username?}` ; validation `^[a-z_][a-z0-9_.-]{0,31}$`, absent de `getent passwd/group`, non réservé (root, daemon, www-data, nginx, postfix, dovecot, vmail, opendkim, mysql...), ni de la forme `sftp<chiffres>` d'un autre uid ; 409 `{"code":"username_taken"}` sinon.
  `useradd` utilise ce nom (groupe `sftpg<gid>` inchangé) ; le nom est écrit dans le marqueur `/etc/dockpanel/sftp-owners/<uid>.owner` (lu par `ownership.rs`, `set_password`, `password-hash`, désactivation : écrit routes existantes résolues par `uid`, jamais par nom reçu). Le backend vérifie aussi l'unicité (index) avant l'appel agent.
- `import_sftp` : écrit nom = `FTP_USER` de Hestia ; conflit ou nom invalide : repli `sftp<uid>` + Warning.
- `sftp_accounts.rs` : écrit la boucle de versions PHP (~297) utilise `php_pool::PHP_VERSIONS`.

**Fait quand** : écrit sur 7 domaines / 14 boîtes : `doveadm auth test` avec les anciens mots de passe, IMAP identique à la source, DKIM `mail` valide, aucune création DNS/certificat ; 28 comptes SFTP ouvrent avec le mot de passe Hestia
(ou sont signalés `locked`) ; chroot et écriture PHP vérifiés ; tests purs et `cargo test` verts.

## W5. Orchestration backend + assistant

### W5-T. Types partagés (`services/import_types.rs`, écrits à l'étape 0)
```rust
#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize)] #[serde(rename_all = "lowercase")]
pub enum ItemStatus { Done, Skipped, Warning, Failed }
pub struct ItemOutcome { pub status: ItemStatus, pub message: String, pub details: serde_json::Value }  // details : écrit sans secret
pub type ProgressFn = std::sync::Arc<dyn Fn(&str /*step*/, &str /*label*/, &str /*pending|in_progress|done|error*/, Option<String>) + Send + Sync>;
pub struct ImportCtx { pub db: sqlx::PgPool, pub agent: crate::services::agent::AgentHandle, pub server_id: uuid::Uuid, pub user_id: uuid::Uuid,
    pub migration_id: uuid::Uuid, pub agent_migration_id: String, pub jwt_secret: String, pub force: bool, pub progress: ProgressFn }
pub async fn wait_job(ctx:&ImportCtx, job_id:&str, step:&str, label:&str) -> Result<serde_json::Value, String>;
   // sonde GET /migration/jobs/{id} toutes les 3 s, émet la progression (1 évt / 2 s), échec après 15 min sans progrès ou sur 404
```
Signatures fixées pour les exécuteurs des autres : écrit `import_db::import_hestia_db`, `import_mail::import_mail_domain`, `import_sftp::import_sftp` (voir W2, W4).

### W5-D. Grand livre (`migrations/20261119020000_migration_items.sql`)
```sql
CREATE TABLE IF NOT EXISTS migration_items (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  migration_id UUID NOT NULL REFERENCES migrations(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,   -- site | files | ssl | php | sftp | db | mail_domain | mailbox | mail_alias | maildir | preflight
  key TEXT NOT NULL,    -- domaine, nom de base, adresse
  status TEXT NOT NULL CHECK (status IN ('pending','running','done','skipped','warning','failed')),
  message TEXT NOT NULL DEFAULT '',
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  attempts INT NOT NULL DEFAULT 0,
  started_at TIMESTAMPTZ, finished_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (migration_id, kind, key));
CREATE INDEX IF NOT EXISTS idx_migration_items_migration ON migration_items(migration_id);
```
`migrations.status` : écrit relance permise depuis `analyzed|done|failed`. `finalize_analyzing_on_startup` : le message `importing` devient « relancez : les éléments terminés sont conservés » ; les lignes `running` sont reprises.

### W5-R. API backend (toutes écrites dans `routes/mod.rs` à l'étape 0)
| Route | Handler | Propriétaire |
|---|---|---|
| `POST /api/migration/analyze`, `GET /api/migration`, `GET/DELETE /api/migration/{id}`, `GET /api/migration/{id}/progress` | existants (`auto` accepté et transmis) | W5 |
| `POST /api/migration/{id}/import` | `migration::import` | W5 |
| `GET /api/migration/{id}/report` | `migration::report` | W5 |
| `GET /api/migration/{id}/preflight` | `migration::preflight` | W5 |
| `GET /api/databases/local/status`, `POST /api/databases/local/install` | `databases::local_status`, `databases::local_install` | W2 |
| `PUT /api/sites/{id}/canonical-host`, `PUT /api/sites/{id}/php-no-exec`, `PUT /api/sites/{id}/ssl-options` | `sites::set_canonical_host`, `sites::set_php_no_exec`, `sites::set_ssl_options` | W3 |
| `PUT /api/databases/local/config` | `databases::local_set_config` | W2 |

`POST /api/migration/{id}/import` (admin, 202 `{migration_id}`) : écrit
```json
{ "default_php_version": "8.3",
  "sites": [{ "domain": "x.tld", "runtime": "php", "php_version": "5.6",
              "options": { "ssl": true, "aliases": true, "canonical": true, "sftp": true, "force_ssl": true, "hsts": true } }],
  "databases": [{ "name": "adm-jim_x", "site_domain": "x.tld", "engine": "mariadb" }],
  "mail_domains": ["d.be"],
  "force_items": ["db:adm-jim_x"], "retry": false }
```
`runtime`, `doc_root`, `web_server`, `aliases`, `canonical_host`, `php_version` par défaut viennent de l'INVENTAIRE stocké (jamais du corps, comme `imported_web_server` aujourd'hui) ; le corps ne fait que choisir
et surcharger `php_version` (liste blanche `PHP_VERSIONS`). `retry:true` sans éléments : écrit rejoue la dernière sélection (`migrations.selected_items`). `force_items` : `"<kind>:<key>"`.
`GET /api/migration/{id}/preflight` : écrit `{ "mariadb_local": {installed, running, version}, "mail": {installed, schemes: []}, "php": {installed: ["8.3"], missing_for_selection: ["5.6"]}, "apache": {installed}, "disk": {} }`.
`GET /api/migration/{id}/report` : écrit `{ "summary": {"done":0,"skipped":0,"warning":0,"failed":0}, "items": [{kind,key,status,message,details,attempts,updated_at}], "manual_actions": ["..."] }`
(`manual_actions` calculé : écrit DNS à basculer, boîtes verrouillées, FTP verrouillé, chemins à corriger, gabarit nginx sauvegardé, PHP legacy, Force SSL/HSTS imposés). `migrations.result` garde les clés historiques (compteurs seulement).

### W5-F. Boucle d'import (`routes/migration.rs`, `services/import_site.rs`, `services/migration_ledger.rs`)
Une seule tâche tokio ; `register_provision_log` capacité **512**. Chaque élément : écrit lecture du grand livre ; `done` et hors `force_items` = `Skipped("already imported")` sans écriture ; sinon `running` (attempts+1), exécution, résultat écrit.
Ordre : écrit `preflight` (MariaDB locale si bases, Dovecot si mail : absent = éléments `failed` explicites ; Apache absent : repli nginx existant), puis par site :
1. `ensure_claimable` pour le domaine ET pour chaque alias importé (garde anti-détournement d'`add_alias` ; alias non revendicable = omis avec Warning) ; ligne `sites` déjà créée par ce même grand livre = reprise ; autre ligne existante = `skipped` (inchangé).
2. `php` : écrit version = surcharge > inventaire > `default_php_version` ; absente de `GET /php/versions` : `POST /php/install` (`post_long` 700 s) ; échec = `failed` (site non créé).
3. `INSERT sites` (web_server, php_version, `aliases`, `canonical_host`), puis `PUT /nginx/sites/{d}` avec `build_nginx_body` rechargé depuis la ligne ; sans SSL à ce stade.
4. `files` : écrit `POST /migration/import-site` (`mode=force` seulement si forcé), puis `wait_job`.
5. `ssl` (option cochée, certificat valide) : écrit `POST /migration/hestia/import-ssl`, `record_uploaded_ssl`, nouveau `PUT` du vhost ; expiré ou échec = Warning, site servi en HTTP.
6. `sftp` : écrit `import_sftp`.
Puis bases : écrit site cible = `site_domain` > `suggested_site` > unique site importé, sinon `failed` avec message clair ; `import_hestia_db`. Puis mail : `import_mail_domain`.
Fin : écrit statut `done` (erreurs dans le rapport) ; `cleanup` agent seulement par DELETE. Plus de plafond 300 s/600 s (durées gouvernées par `wait_job`). Les événements SSE ne portent jamais de valeur sensible.

### W5-U. Interface (`pages/Migration.tsx`)
Anglais, sans tiret cadratin. Étape 2 : écrit bandeau disque, préalables (MariaDB locale, mail, PHP manquants avec bouton d'installation), tableau des sites (version PHP à choisir, `default` visible, alias, canonique, SSL et échéance, FTP, avertissements),
bases avec site proposé prérempli, domaines mail et boîtes (schéma inconnu signalé). Étape 3 : écrit progression par élément (octets, phase). Étape 4 : rapport par élément (statut, message), actions manuelles, « Retry failed »,
« Force re-import » par élément avec confirmation saisie (« this overwrites data written since the first import »). Mots de passe et hashes : écrit jamais affichés.

**Fait quand** : écrit import complet de l'archive de 9,6 Go en VM avec rapport ; relance immédiate = 100 % `skipped` sans écriture ; reprise après arrêt du backend ou de l'agent ; aucun secret dans `migrations`, `migration_items`, SSE, journaux (grep) ; `cargo test` et `tsc` verts.

## 6. Ordre de construction
1. Étape 0 (W1 + W5) : écrit squelettes, types, migrations, routes, bloc de modules ; fusion.
2. En parallèle : écrit W1, W2, W3, W4 (agent d'abord, puis backend et interface de chacun) et W5 (boucle contre les squelettes, tests avec agent simulé).
3. Dépendances réelles : écrit W2 (job d'import) et W4 (secrets, maildirs, hash FTP) lisent `staging_dir`, `spawn_member_reader`, `extract_tar_member`, `hestia::*` de W1 ; W5 appelle `build_nginx_body`, `record_uploaded_ssl` (W3) et les exécuteurs (W2, W4).
   Les squelettes de l'étape 0 suffisent pour compiler ; l'intégration réelle se fait dans l'ordre W1, W3, W2, W4, W5.
4. Intégration : écrit chaque chantier fusionne sur `main` après `cargo test`, `cargo clippy`, `npm run build` ; puis plan de test VM (`05-import-hestia.md` section 4) sur l'archive réduite, puis complète.
