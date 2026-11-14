# Réglages PHP — contrats d'interface (figés pour l'implémentation)

Référence : `conception/02-php-par-domaine.md` (décisions D1–D3 au §6). Formats échangés entre
**agent** (`panel/agent`), **API** (`panel/backend`) et **frontend** (`panel/frontend`).
Dossier d'un site : `/var/www/<domaine>` (docroot `.../public`, déjà en place).

## A. Agent ← API

### A1. `PUT /nginx/sites/{domain}` — `SiteConfig` gagne `php_pool: Option<PhpPool>`
```json
"php_pool": {
  "values":  { "memory_limit": "256M", "upload_max_filesize": "128M", "post_max_size": "136M",
               "max_execution_time": "60", "max_input_time": "60", "max_input_vars": "4000",
               "display_errors": "Off", "error_reporting": "E_ALL & ~E_DEPRECATED & ~E_STRICT",
               "date.timezone": "Europe/Paris", "short_open_tag": "Off", "allow_url_fopen": "On",
               "session.gc_maxlifetime": "1440" },
  "isolation": true,
  "disable_shell": true,
  "pm": "ondemand",
  "max_children": 8,
  "max_requests": 4000,
  "idle_timeout_s": 10,
  "request_terminate_timeout_s": 90,
  "extra": [ ["opcache.memory_consumption", "256"] ]
}
```
- L'API envoie **toutes** les valeurs effectives (défauts compris) : l'agent ne connaît pas de défauts PHP.
- Absent (`null`) → comportement actuel inchangé (`php_memory_mb` / `php_max_workers`, 64M, etc.).
  Présent → `php_memory_mb` / `php_max_workers` sont ignorés.
- **Défense en profondeur côté agent** (400 `{error}` sinon) : clé `^[a-z][a-z0-9_.]{0,63}$`, valeur
  ≤ 256 caractères sans `\n \r [ ] ;` ni `"` ; `pm` ∈ {ondemand, dynamic, static} ; entiers 1–1000
  (max_children), 0–100000 (max_requests), 1–3600 (idle), 0–86400 (terminate) ; clés de `extra`
  interdites : `extension`, `zend_extension`, `open_basedir`, `disable_functions`,
  `disable_classes`, `auto_prepend_file`, `auto_append_file`, `sendmail_path`, `error_log`,
  `upload_tmp_dir`, `session.save_path`, `user_ini.filename`, `doc_root`, `include_path`.
- Rendu (fonction **pure** testée) :
  - `values` et `extra` → `php_value[k] = v` ;
  - `isolation` → `php_admin_value[open_basedir] = /var/www/<d>/:/tmp/:/usr/share/php/`,
    `php_admin_value[upload_tmp_dir]` et `php_admin_value[session.save_path] = /var/www/<d>/tmp`
    (dossier créé 0700, propriétaire = utilisateur du pool), `php_admin_value[sendmail_path] =
    /usr/sbin/sendmail -t -i -f noreply@<d>` ;
  - **toujours** `php_admin_value[error_log] = /var/log/php-fpm/<pool>.error.log` +
    `php_admin_flag[log_errors] = on` (dossier créé si absent) ;
  - `disable_shell` → `php_admin_value[disable_functions] = exec,system,passthru,shell_exec,proc_open,popen` ;
  - `pm = ondemand` → `pm.process_idle_timeout = <idle>s` ; `dynamic` → start/min/max spare dérivés de
    max_children comme aujourd'hui ; `static` → rien de plus ;
  - `request_terminate_timeout = <n>s` ; vhost : `fastcgi_read_timeout <n>s;` dans le bloc PHP.
- Application : copie de l'ancien fichier → écriture atomique → `php-fpm<ver> -t` → si échec, ancien
  fichier remis (ou supprimé s'il n'existait pas), **400** `{error: "<sortie de -t>"}`, vhost non
  modifié ; sinon reload (nom d'unité via `pkg::service_name` si dispo) puis vhost comme aujourd'hui.
- Après écriture réussie : suppression des pools du même nom dans **les autres versions**
  (`/etc/php/*/fpm/pool.d/<pool>.conf`) + reload de ces versions.

### A2. `GET /php/ini/{version}` → `{ "version": "8.3", "path": "/etc/php/8.3/fpm/php.ini", "content": "...", "values": { "memory_limit": "128M", ... } }`
- `version` doit être une version installée autorisée (8.1–8.5), sinon 400/404.
- `values` = lecture des 8 clés : memory_limit, max_execution_time, max_input_time,
  upload_max_filesize, post_max_size, display_errors, error_reporting, date.timezone (null si absente/commentée).

### A3. `PUT /php/ini/{version}` — `{ "content": "..." }` **ou** `{ "values": { "memory_limit": "512M" } }`
- `values` : remplace la ligne active de la clé (ou décommente / ajoute en fin de section `[PHP]`)
  — fonction **pure** testée `set_ini_values(content, map) -> String` ; mêmes règles de caractères que A1,
  clés limitées aux 8 de A2.
- `content` : ≤ 512 Kio, UTF-8.
- Séquence : copie `php.ini.dockpanel.bak` → écriture atomique → `php-fpm<ver> -t` → restart
  `php<ver>-fpm` → `systemctl is-active`. Échec à n'importe quelle étape → ancien fichier remis,
  restart, **400** `{error}`. Succès → réponse au format A2.
- Le php.ini CLI n'est jamais touché.

## B. Frontend ← API

### B1. `GET /api/sites/{id}/php-settings` (propriétaire ou admin)
```ts
interface PhpSettingsResponse {
  php_version: string | null;
  can_admin: boolean;                       // l'appelant peut modifier isolation/pool/extra
  values: Record<string, string>;           // valeurs propres au site (surcharges)
  effective: Record<string, string>;        // valeurs appliquées (surcharges + défauts)
  defaults: Record<string, string>;
  fields: PhpField[];                       // description des 12 réglages (ordre d'affichage)
  isolation: boolean;
  disable_shell: boolean;
  pool: { pm: "ondemand" | "dynamic" | "static"; max_children: number; max_requests: number;
          idle_timeout_s: number; request_terminate_timeout_s: number };
  extra: [string, string][];
}
interface PhpField {
  key: string; label: string;
  kind: "size" | "int" | "bool" | "choice";   // size = "256M" ; bool = "On"/"Off"
  min?: number; max?: number;                 // size : en Mo ; int : valeur brute
  choices?: { value: string; label: string }[];
}
```
Les 12 clés : memory_limit (size 32–4096), upload_max_filesize (size 1–2048), post_max_size
(size 1–2048, ≥ upload), max_execution_time (int 0–3600), max_input_time (int -1–3600),
max_input_vars (int 1000–100000), display_errors (bool), error_reporting (choice : production
`E_ALL & ~E_DEPRECATED & ~E_STRICT`, développement `E_ALL`, silencieux `E_ERROR | E_PARSE`),
date.timezone (choice : liste IANA courante, défaut Europe/Paris), short_open_tag (bool),
allow_url_fopen (bool), session.gc_maxlifetime (int 60–604800).

Défauts : memory_limit = `php_memory_mb`M ; upload_max_filesize = `max_upload_mb`M (min 1) ;
post_max_size = upload + 8M ; max_execution_time 60 ; max_input_time 60 ; max_input_vars 4000 ;
display_errors Off ; error_reporting production ; date.timezone Europe/Paris ; short_open_tag Off ;
allow_url_fopen On ; session.gc_maxlifetime 1440. Pool : ondemand, max_children = `php_max_workers`,
max_requests 4000, idle 10, terminate = max_execution_time effectif + 30.

### B2. `PUT /api/sites/{id}/php-settings`
```ts
{ values?: Record<string, string | null>;   // null = revenir au défaut
  isolation?: boolean; disable_shell?: boolean;
  pool?: Partial<PhpSettingsResponse["pool"]>; extra?: [string, string][] }
```
- Propriétaire : `values` seulement ; présence d'un autre champ → 403. Admin : tout.
- 400 `{error, field?}` si validation (bornes B1, règles A1). Site non PHP → 400.
- `memory_limit` écrit aussi `php_memory_mb` ; `pool.max_children` écrit `php_max_workers`.
- Appliqué tout de suite (vhost + pool). Échec agent (dont 400 de `-t`) → base inchangée
  (transaction), erreur relayée. Réponse : `PhpSettingsResponse` à jour. Journal d'activité.

### B3. Admin — php.ini global
- `GET /api/php/ini/{version}` → format A2.
- `PUT /api/php/ini/{version}` → corps A3, réponse A2 ; erreurs agent relayées (400 lisible).

### B4. Création de site
Nouveaux sites : `php_isolation = true`, `php_disable_shell = true` (défauts de colonne).
Le clonage copie `php_settings`, `php_isolation`, `php_disable_shell`.

## C. Migration
`panel/backend/migrations/20261115000000_php_settings.sql` :
```sql
ALTER TABLE sites ADD COLUMN IF NOT EXISTS php_settings JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS php_isolation BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE sites ADD COLUMN IF NOT EXISTS php_disable_shell BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE sites ALTER COLUMN php_isolation SET DEFAULT true;
ALTER TABLE sites ALTER COLUMN php_disable_shell SET DEFAULT true;
```
`php_settings` = `{ "values": {...}, "pool": {...}, "extra": [[k,v],...] }` (surcharges seulement).
**Tout** envoi de `SiteConfig` pour un site PHP (création, changement de version, SSL, IP, limites…)
passe `php_pool` construit depuis ces colonnes — un seul constructeur côté API.

### C bis (ajouté à l'implémentation)
La migration enregistre, pour chaque site PHP existant, les valeurs de l'ancien pool comme
surcharges (`max_execution_time 300`, `upload/post 64M`, `pm dynamic`, `max_requests 500`,
`request_terminate_timeout_s 0`) : D1 respecté, aucun changement de comportement à la mise à jour.
`memory_limit` et `max_children` ne sont jamais stockés dans le JSONB (colonnes `php_memory_mb` /
`php_max_workers` seules), pour que la carte « Resource Limits » et la carte PHP ne se contredisent pas.

**Drapeau `legacy` (D1 strict).** La migration écrit aussi `"legacy": true` dans le JSONB de ces
sites. Pour une ligne `legacy` :
- **A1** : par exception à « toutes les valeurs effectives », `php_pool.values` ne contient que
  `memory_limit` (depuis `php_memory_mb`, que l'ancien pool posait toujours) + les clés surchargées
  dans `values` (+ `post_max_size` dérivé = upload + 8M si seul `upload_max_filesize` est surchargé).
  Les autres clés sont **absentes** → héritées du php.ini global, comme avant la mise à jour.
  L'agent écrit un `php_value` par clé présente (aucune clé obligatoire). Le `request_terminate_timeout`
  dérivé (si non surchargé) prend `max_execution_time` = 0 → 3630 s quand celui-ci est hérité.
- **B1** : la réponse gagne `legacy: boolean` et `inherits_global: string[]` (clés prises dans le
  php.ini global ; `[]` hors legacy). Ces clés sont absentes de `effective` ; `defaults` ne contient
  que `memory_limit` (remettre une autre clé « au défaut » = la ré-hériter du php.ini).
- **B2** : le drapeau est conservé à chaque PUT (propriétaire comme admin) ; le propriétaire ne peut
  pas le modifier (`legacy` présent → 403). Admin : `{ "legacy": false }` (« Utiliser les défauts du
  panel ») retire le drapeau — les surcharges stockées restent, les autres clés prennent les défauts
  B1. Toute autre valeur (`true`, non booléen) → 400 `field: "legacy"` ; le drapeau ne se pose jamais
  par l'API. Contrôle post ≥ upload : ignoré si l'upload est hérité (inconnu).
