# Fonctionnalité 4 - Contrats d'interface (Apache + .htaccess)

Référence : `04-apache-htaccess.md` (décisions D1-D4). Ubuntu/Debian seulement ; RHEL refusé proprement.
Trois chantiers parallèles : **agent** (panel/agent + scripts), **backend** (panel/backend),
**frontend** (panel/frontend). Ce fichier fixe ce qu'ils s'échangent.

## A. Agent

### A1. `SiteConfig.web_server: Option<String>` (`routes/nginx.rs`)
- Valeurs `"nginx"` (défaut si absent) ou `"apache"` ; autre valeur → 400.
- N'a d'effet que pour `runtime == "php"` ; ignoré (traité comme nginx) pour les autres runtimes.
- Ajouté à **tous** les littéraux `SiteConfig` (docker_apps, git_build, ssl routes, `enable_ssl_for_site`
  qui doit le recopier).
- Absent ou `"nginx"` → rendu nginx **octet pour octet identique** à aujourd'hui (le test
  `absent_pool_renders_byte_identically_to_the_old_templates` et ses semblables doivent rester verts).

### A2. vhost nginx en mode Apache (branche nouvelle dans `http.conf` et `https.conf`, runtime php)
Remplace les presets et le bloc `\.php$` ; tout le reste (listen/IP, SSL, ACME, limites, WAF,
anti-bots, en-têtes, gzip, `custom_nginx`, journaux d'accès) est inchangé :
```nginx
location ~ /\.(?!well-known) { deny all; }
location ~* \.(?:jpe?g|png|gif|webp|avif|svg|ico|css|js|mjs|map|woff2?|ttf|otf|eot|txt|xml|pdf|mp4|webm|mp3|ogg|zip|gz)$ {
    try_files $uri @apache;
    expires 30d;
}
location / { try_files /nonexistent @apache; }
location @apache {
    proxy_pass http://127.0.0.1:8081;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_read_timeout <fastcgi_read_timeout ou 300>s;
}
```
- Pas d'`access_log off` : le journal d'accès nginx sert aux statistiques, à la bande passante et à fail2ban.
- Ne doit **pas** contenir la ligne `index index.html index.htm;` (la retouche « static deny » au
  démarrage de l'agent et `update.sh` s'en servent comme repère).

### A3. vhost Apache `/etc/apache2/sites-enabled/<domaine>.conf` (fonction pure `render_apache_vhost`)
```apache
# Managed by CyberHunter - Panel. Do not edit by hand.
<VirtualHost 127.0.0.1:8081>
    ServerName <domaine>
    ServerAlias <alias...>            # mêmes alias que le server_name nginx
    DocumentRoot <document_root_for(site)>
    <Directory <document_root>>
        AllowOverride All
        Options +FollowSymLinks -Indexes -ExecCGI -Includes
        Require all granted
    </Directory>
    <FilesMatch "^\.(ht|user\.ini)">
        Require all denied
    </FilesMatch>
    <FilesMatch "\.php$">
        SetHandler "proxy:unix:<socket du pool du site>|fcgi://localhost"
    </FilesMatch>
    ProxyTimeout <request_terminate_timeout ou max_execution_time ou 300>
    LimitRequestBody <max_upload_mb * 1048576>
    ErrorLog /var/log/apache2/<domaine>.error.log
    CustomLog /dev/null common
</VirtualHost>
```
- Le socket est celui que `put_site` a résolu pour le pool du site (après l'attente du socket).
- Écriture atomique ; `apachectl configtest` ; puis `systemctl reload apache2`.

### A4. Configuration globale Apache (écrite par l'installeur, idempotente)
- `/etc/apache2/ports.conf` : `Listen 127.0.0.1:8081` uniquement.
- `a2dissite 000-default` ; `a2dismod mpm_prefork php*` ; `a2enmod mpm_event proxy proxy_fcgi
  rewrite remoteip headers expires setenvif`.
- `/etc/apache2/conf-available/cyberhunter.conf` (activée) :
  `RemoteIPHeader X-Real-IP`, `RemoteIPInternalProxy 127.0.0.1`,
  `SetEnvIf X-Forwarded-Proto "^https$" HTTPS=on`, `ServerTokens Prod`, `ServerSignature Off`.
- **Apache ne doit jamais prendre le port 80** : avant `apt install apache2`,
  `systemctl mask --runtime apache2.service` (le démarrage automatique du paquet est empêché),
  écriture de la config ci-dessus, `configtest`, `systemctl unmask --runtime`, `enable --now`.
  À vérifier en VM.

### A5. Routes agent
- Installeur `POST /services/install/apache` (et uninstall), sur le modèle de `install_redis` ;
  `install_status` inclut `"apache"` ; RHEL → message « Apache mode is not supported on RHEL yet ».
- `/services/health` inclut `apache2` s'il est installé.
- `PUT /nginx/sites/{domain}` (put_site) avec `web_server = "apache"` :
  - Apache absent → **409** `{"error":"Apache is not installed","code":"apache_not_installed"}`, rien n'est modifié ;
  - ordre : pool PHP → vhost Apache (écrit, `configtest`, reload) → vhost nginx (`nginx -t`, reload) ;
    échec nginx → vhost Apache précédent restauré (ou supprimé s'il n'existait pas) + reload ;
  - avec `web_server = "nginx"` et un vhost Apache existant pour ce domaine : après le succès nginx,
    le vhost Apache est supprimé et Apache rechargé.
- Suppression / renommage du site : vhost Apache et `/var/log/apache2/<domaine>.error.log` traités
  comme leurs équivalents nginx. Désactivation : rien à faire côté Apache (nginx sert le 503).
- Journaux du site : type `apache_error` lisant `/var/log/apache2/<domaine>.error.log`.
- Import HestiaCP (`parse_hestiacp`) : `MigrationSite.web_server: Option<String>` = `"apache"` si le
  `web.conf` du domaine (`web/<d>/hestia/web.conf` ou `web/<d>/web.conf`) a une clé `PROXY` non vide,
  sinon `"nginx"` ; absent pour les autres panels.

### A6. Système
- `dockpanel-agent.service` : `ReadWritePaths` + `-/etc/apache2` (`/var/log` y est déjà) ; mettre à
  jour les tests pin de chemins sandbox si besoin.
- `scripts/setup.sh` (Debian/Ubuntu) : installer et configurer Apache comme A4 (D1 : défaut pour
  les nouveaux serveurs). RHEL : ne rien installer.

## B. Backend

### B1. Données
Migration `20261118000000_web_server.sql` :
```sql
ALTER TABLE sites ADD COLUMN IF NOT EXISTS web_server TEXT NOT NULL DEFAULT 'nginx'
  CHECK (web_server IN ('nginx','apache'));
```
Champ `web_server: String` dans `Site`. Les sites existants restent `nginx`.

### B2. Corps vers l'agent
`build_nginx_body` et **tous** les corps faits à la main (création, auto-SSL, clonage, préproduction,
import) envoient `"web_server"`.

### B3. Création `POST /api/sites`
- Nouveau champ optionnel `web_server` ; pour `runtime == "php"`, défaut **`"apache"`** (D1) ;
  pour les autres runtimes, forcé à `"nginx"` ; valeur inconnue → 400.
- 409 `apache_not_installed` de l'agent → relayé tel quel (code inclus), rien en base.

### B4. Bascule `PUT /api/sites/{id}/web-server` `{ "web_server": "nginx" | "apache" }`
- Propriétaire du site ou admin ; site PHP seulement (sinon 400).
- Transaction : UPDATE, appel agent (vhost reconstruit), commit seulement si l'agent accepte.
- Réponse `{ "web_server": ... }` ; journal d'activité `site.web_server`.
- Cache FastCGI : en mode Apache, `fastcgi_cache` est ignoré par le rendu ; la valeur reste en base
  (aucune perte quand on revient en nginx).

### B5. Import
Le `web_server` renvoyé par l'agent pour chaque domaine HestiaCP est utilisé à la création (D3).

### B6. Services
- `POST /api/services/install/apache` (même flux SSE que redis) et `install-status` inclut `apache`.
- Désinstallation d'Apache refusée (409) tant qu'un site est en `web_server = 'apache'`.

## C. Frontend
- **Création de site** (`Sites.tsx`) : pour PHP, choix « Web server » : `nginx + Apache (.htaccess)`
  (présélectionné) / `nginx only`. Si Apache est choisi et pas installé (`/services/install-status`) :
  message + installation via le flux d'installation existant (journal visible), puis création.
  Erreur `apache_not_installed` → même proposition.
- **Fiche du site** (`SiteDetail.tsx`) : carte « Web server » (sites PHP) : mode actuel, bascule avec
  confirmation, mentions :
  - « .htaccess files are read. `php_value` / `php_flag` in .htaccess do not work with PHP-FPM: use
    PHP settings or .user.ini. » ;
  - la carte cache FastCGI indique qu'il n'est pas utilisé en mode Apache.
- **Paramètres → Services** : entrée Apache (installer / état).
- **Journaux du site** : choix « Apache error log » pour les sites en mode Apache.
- Libellés en anglais (comme le reste de l'interface), jamais de tiret cadratin.
