# Fonctionnalité 7 - Contrats d'interface (statistiques web GoAccess)

Référence : `08-stats-web.md`. GoAccess est pris en charge sur Debian et Ubuntu seulement ; sur RHEL,
`supported:false` et le message « Not supported on this server ».

Organisation :
- **Trois chantiers parallèles** : **A** agent, **B** backend, **C** interface.
- **Propriété** : un fichier appartient à un seul chantier.
- **Libellés d'interface** : en anglais, jamais de tiret cadratin.
- **Journaux** : aucun contenu de log de visiteur dans les journaux de l'agent ou du backend (au plus le
  domaine, la durée et le message d'erreur de GoAccess tronqué à 500 caractères).

## 0. Propriété des fichiers
### Agent (`panel/agent/`) : A
- **Nouveaux fichiers :**
  - `src/services/web_stats.rs` : installation, calcul, GeoIP, état, purge, renommage, suppression.
  - `src/routes/web_stats.rs`.
- **Fichiers modifiés :**
  - `src/main.rs` (fusion du routeur, appel de la reconciliation A-8 au démarrage), `src/services/mod.rs`,
    `src/routes/mod.rs` si besoin.
  - `src/routes/service_installer.rs` : entrée `goaccess` dans `install-status`.
  - `src/templates/nginx/http.conf` et `src/templates/nginx/https.conf` : retrait des `access_log off;`.
  - `src/services/nginx.rs` : fonction de reconciliation A-8 et tests associés.
  - `src/routes/nginx.rs` : `delete_site` et `rename_site` appellent A-9.
### Backend (`panel/backend/`) : B
- **Nouveaux fichiers :**
  - `migrations/20261122000000_web_stats.sql`.
  - `src/services/web_stats.rs` : ordonnanceur horaire.
  - `src/routes/web_stats.rs` : routes serveur et routes par site.
- **Fichiers modifiés :**
  - `src/routes/mod.rs`, `src/services/mod.rs`.
  - `src/main.rs` : `spawn_supervised("web_stats")`.
  - `src/services/uptime.rs` : User-Agent `DockPanel-Uptime` (B-5).
### Interface (`panel/frontend/src/`) : C
- **Nouveaux fichiers :**
  - `components/WebStatsServerCard.tsx` : carte de Settings → Services.
  - `components/WebStatsSection.tsx` : section de la fiche du site.
- **Fichiers modifiés :**
  - `pages/Settings.tsx` : carte GoAccess, et alignement des cartes ClamAV, FTP et GoAccess sur la grille
    à deux colonnes (C-3).
  - `pages/SiteDetail.tsx` : section « Web statistics », et « Traffic Stats » renommé « Recent traffic ».

## A. Agent (toutes les routes sous le jeton agent habituel)
Erreurs : `{ "error": "message lisible en anglais" }` avec les codes 400, 404, 409, 412 ou 500.

Constantes :
- `STATS_ROOT = /var/lib/dockpanel/stats` (0700 root), un dossier par domaine `<STATS_ROOT>/<domaine>/`
  (0700) contenant `db/`, `report.html` (0600) et `state.json` (0600).
- `GEOIP_PATH = /var/lib/dockpanel/geoip/dbip-country-lite.mmdb` (0644), `GEOIP_META = .../geoip/meta.json`.
- `BROWSERS_FILE = <STATS_ROOT>/browsers.list` : une ligne `DockPanel-Uptime\tCrawlers` (séparateur
  tabulation, format `--browsers-file` de GoAccess).
- Tous les noms de domaine passent par `routes::is_valid_domain` avant de toucher au disque.

### A-1 `GET /stats/status`
```json
{ "supported": true, "unsupported_reason": null,
  "installed": true, "version": "1.8.1",
  "geoip": { "present": true, "updated_at": "2026-11-01T03:00:00Z", "error": null },
  "running": "jeuxx.org", "sites": 31, "data_bytes": 52428800 }
```
- **`running`** : domaine en cours de calcul, ou `null`.
- **`sites`** : nombre de dossiers sous `STATS_ROOT`. **`data_bytes`** : taille de `STATS_ROOT`
  (`st_blocks × 512`).
- **`install-status`** reçoit `"goaccess": {"installed","supported"}`.

### A-2 `POST /stats/install` → `{ "ok": true, "warnings": [] }`
- **Refus** : 412 si non pris en charge, 409 si une installation, une désinstallation ou une purge tourne.
  Délai total de 5 min.
- **Étapes :**
  1. `pkg::install(["goaccess"])`, puis contrôle de `goaccess --version`.
  2. Créer `STATS_ROOT` (0700) et le dossier GeoIP, écrire `BROWSERS_FILE`.
  3. Télécharger la base GeoIP (A-7). Un échec devient un warning, pas une erreur.
- **Réexécution** : idempotente, vaut réparation.

### A-3 `POST /stats/uninstall` → `{ "ok": true }`
- `pkg::remove(["goaccess"])`. `STATS_ROOT` et la base GeoIP sont **conservés**.
- 409 si un calcul tourne (l'interface affiche l'erreur, on réessaie plus tard).

### A-4 `POST /stats/purge` → `{ "ok": true, "removed": 31 }`
- Supprime les dossiers de domaines sous `STATS_ROOT`, garde `BROWSERS_FILE`. 409 si un calcul tourne.
  Utilisable que GoAccess soit installé ou non.

### A-5 `POST /stats/run` `{ "domain": "x.tld" }`
→ `{ "domain", "ok": true, "updated_at": "2026-11-16T10:00:03Z", "duration_ms": 4200, "initialized": false, "error": null }`
- **Refus** : 412 `"Web statistics not installed"`, 400 si domaine invalide, 404 `"No access log for this site"`
  si ni `<d>.access.log` ni `<d>.access.log.1` n'existe.
- **Un seul calcul à la fois par agent** (mutex) : un second appel attend son tour, au plus 10 min, puis
  409 `"Another statistics run is in progress"`.
- **Priorité** : `nice -n 19 ionice -c 3 goaccess ...` (ou `setpriority`/`ioprio_set` sur le processus
  fils). Délai de 15 min par appel ; au-delà le processus est tué et `error` le dit.
- **Initialisation** (le dossier `db/` n'existe pas ou est vide) :
  1. `zcat` des `<d>.access.log.N.gz` du plus ancien au plus récent, envoyé sur l'entrée standard de
     `goaccess - --persist --db-path=<dir>/db ...` (sans `--restore`), sortie `-o` vers un fichier
     temporaire jeté ;
  2. puis le passage normal ci-dessous, avec `--restore`. `initialized: true` dans la réponse.
- **Passage normal** :
  ```
  goaccess /var/log/nginx/<d>.access.log.1 /var/log/nginx/<d>.access.log \
    --log-format=COMBINED --persist --restore --db-path=<dir>/db --keep-last=365 \
    [--geoip-database=<GEOIP_PATH>] --browsers-file=<BROWSERS_FILE> \
    --no-global-config --html-report-title=<d> -o <dir>/report.tmp.html
  ```
  - les fichiers absents sont retirés de la ligne ;
  - en cas de succès, `report.tmp.html` est renommé en `report.html` (atomique) ;
  - en cas d'échec, `report.html` est laissé tel quel ;
  - `state.json` = `{ "updated_at", "error", "duration_ms" }` est réécrit dans les deux cas
    (`updated_at` garde la dernière réussite).
- **Tests unitaires** : construction de la ligne de commande (fichiers présents ou absents, avec ou sans
  GeoIP), ordre des `.gz`, rejet des domaines invalides.

### A-6 Lecture
- **`GET /stats/{domain}/report`** : le contenu de `report.html` en `text/html; charset=utf-8`, ou 404
  `"No report yet"`.
- **`GET /stats/{domain}/state`** : le contenu de `state.json`, ou `{ "updated_at": null, "error": null }`.

### A-7 Base GeoIP DB-IP
- **Source** : `https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.mmdb.gz`, mois courant, puis
  mois précédent si le premier répond 404.
- **Contrôles avant remplacement** : décompression gzip réussie, taille entre 1 Mo et 200 Mo, présence du
  marqueur de métadonnées mmdb `\xAB\xCD\xEFMaxMind.com`. Écriture dans un fichier temporaire puis
  renommage atomique.
- **Rythme** : au début de chaque A-5, si la base a plus de 31 jours et que la dernière tentative a plus de
  24 h (`meta.json` : `{ "updated_at", "attempted_at", "error" }`), une mise à jour est tentée. Un échec
  ne bloque pas le calcul.

### A-8 Journaliser les fichiers statiques
- **Templates** : retirer les 10 lignes `access_log off;` de `http.conf` et `https.conf`. La ligne
  `access_log /var/log/nginx/{domain}.access.log;` et le format restent strictement inchangés.
- **Reconciliation au démarrage** `reconcile_static_access_logs()` dans `services/nginx.rs`, appelée
  depuis `main.rs` après les reconciliations existantes :
  - candidats : les `.conf` de `sites-enabled` gérés par le panel (même filtre que
    `retrofit_static_denies`, jamais `dockpanel-panel.conf`) qui contiennent la ligne d'accès du site et
    au moins une ligne `access_log off;` ;
  - retrait des seules lignes dont le contenu, espaces exclus, est exactement `access_log off;` ;
  - ne s'exécute pas si `nginx -t` échoue déjà avant modification ;
  - après modification, `nginx -t` : succès, un seul reload ; échec, chaque fichier est remis à
    l'identique ;
  - idempotente ; journal : nombre de vhosts modifiés.
- **Tests unitaires** : fonction pure de patch (retire les bonnes lignes, laisse intact un vhost sans
  `access_log off;`, ne touche ni la ligne d'accès du site ni les autres directives), rendu des templates
  sans `access_log off`.

### A-9 Cycle de vie
- `delete_site` : supprime `<STATS_ROOT>/<domaine>/` (au mieux, avertissement en cas d'échec).
- `rename_site` : renomme `<STATS_ROOT>/<ancien>/` en `<STATS_ROOT>/<nouveau>/` si le second n'existe pas.
- Fonctions dans `services/web_stats.rs`, appelées depuis `routes/nginx.rs`.

## B. Backend
### B-1 Migration `20261122000000_web_stats.sql`
```sql
CREATE TABLE IF NOT EXISTS site_web_stats (
  site_id uuid PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
  updated_at timestamptz NULL,
  attempted_at timestamptz NOT NULL DEFAULT now(),
  error text NULL);
```

### B-2 Routes serveur (admin)
- **`GET /api/web-stats/status?server_id=`** : relaie A-1. Le serveur par défaut est le serveur local.
- **`POST /api/web-stats/install` `{ "server_id"? }`** : relaie A-2, puis réveille l'ordonnanceur pour ce
  serveur (premier calcul tout de suite).
- **`POST /api/web-stats/uninstall` `{ "server_id"? }`** : relaie A-3.
- **`POST /api/web-stats/purge` `{ "server_id"? }`** : relaie A-4, puis supprime les lignes
  `site_web_stats` des sites de ce serveur.

### B-3 Routes par site
Droits : ceux de la fiche du site (admin, revendeur du propriétaire, propriétaire). Sans droit : **404**,
comme un site inexistant.
- **`GET /api/sites/{id}/stats`** →
  `{ "installed": bool, "updated_at": ts|null, "error": str|null, "running": bool }`. `installed` vient de
  A-1 (mis en cache 60 s par serveur) ; `updated_at` et `error` de `site_web_stats`.
- **`POST /api/sites/{id}/stats/refresh`** : A-5 synchrone pour ce site, met à jour `site_web_stats`,
  renvoie le même format que le `GET`. 429 `"A statistics run is already running for this site"` si un
  calcul de ce site est en cours côté backend. 412 relayé si GoAccess n'est pas installé.
- **`GET /api/sites/{id}/stats/report`** : relaie A-6 et renvoie le HTML avec ces en-têtes :
  - `Content-Type: text/html; charset=utf-8`
  - `Content-Security-Policy: sandbox allow-scripts; default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; font-src data:`
  - `Content-Disposition: attachment; filename="<domaine>-stats.html"`
  - `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`, `Referrer-Policy: no-referrer`
  - 404 `"No report yet"` relayé.

### B-4 Ordonnanceur `services/web_stats.rs`
- Au démarrage (après 2 min), puis **toutes les heures**, et à chaque réveil par B-2 install.
- Par serveur en ligne : A-1 ; si `installed` est faux, serveur sauté.
- Sites du serveur, dans l'ordre : `ORDER BY w.attempted_at ASC NULLS FIRST, s.domain` (jointure gauche
  sur `site_web_stats`).
- **Un appel A-5 par site**, l'un après l'autre (l'agent sérialise de toute façon). Upsert dans
  `site_web_stats` : `attempted_at = now()`, `updated_at` et `error` d'après la réponse. Une erreur
  réseau ou un 404 « No access log » est notée dans `error` sans bloquer les sites suivants.
- Les serveurs différents sont traités en parallèle. Un serveur injoignable est sauté jusqu'au cycle
  suivant.
- Le verrou « calcul en cours pour ce site » (B-3 refresh) est partagé avec l'ordonnanceur.
- **Tests unitaires** : ordre des sites, upsert en succès et en échec.

### B-5 User-Agent des vérifications de disponibilité
- `http_check_client_builder()` dans `services/uptime.rs` : `.user_agent("DockPanel-Uptime")`.
- Test unitaire : l'en-tête est bien envoyé.

## C. Interface
### C-1 `WebStatsServerCard` (Settings → Services)
- Titre « Web statistics (GoAccess) », état « Installed » ou « Not installed », version.
- Boutons « Install » et « Uninstall » (le second avec confirmation : « Statistics data is kept »).
- Ligne GeoIP : « Country database: updated 2026-11-01 » ou l'erreur, avec « IP Geolocation by DB-IP ».
- Ligne données : « 31 sites, 50.0 MB of statistics data », bouton « Delete statistics data » (rouge,
  confirmation : « This deletes the history of every site. It cannot be undone. »).
- « Running: jeuxx.org » quand un calcul tourne. Non pris en charge : « Not supported on this server ».

### C-2 `WebStatsSection` (fiche du site)
- **En-tête** : « Web statistics », « Updated 23 min ago », boutons « Refresh », « Full screen » et
  « Download », et l'erreur éventuelle en rouge.
- **Rapport** : `fetch("/api/sites/{id}/stats/report", { credentials: "same-origin" })` (avec
  `X-Server-Id` comme `api.ts`), texte placé dans
  `<iframe sandbox="allow-scripts" srcdoc={html} title="Web statistics" />` de 900 px de haut.
  - **Jamais** `allow-same-origin`, jamais `src` vers l'API, jamais de blob ouvert en onglet ni de
    `window.open`.
  - « Full screen » : le même `iframe` dans une superposition plein écran, fermée par Échap ou un bouton
    « Close ».
  - « Download » : le texte déjà chargé enregistré en fichier `<domaine>-stats.html` (lien `download` sur
    un blob, sans navigation).
- **Sous le cadre** : « IP Geolocation by DB-IP » (lien `https://db-ip.com`, `rel="noopener noreferrer"`).
- **États vides** :
  - GoAccess absent : « Install Web statistics in Settings → Services » (lien pour l'admin, texte simple
    sinon) ;
  - pas encore de rapport : « Statistics are being prepared », avec « Refresh ».
- **Bloc existant** « Traffic Stats » renommé « Recent traffic », sans autre changement.

### C-3 Alignement des cartes de Settings → Services
- ClamAV, FTP et GoAccess occupent chacun une colonne de la grille à deux colonnes (retrait des
  `sm:col-span-2`), en gardant un rendu lisible à cette largeur.

### Formats
- Tailles en base 1024 avec une décimale ; dates relatives comme dans `DiskUsageCard`.
