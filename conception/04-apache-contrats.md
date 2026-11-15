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
    proxy_pass http://127.0.0.1:8091;   # bloc qui ne sert que HTTP (voir ci-dessous pour HTTPS)
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_read_timeout <fastcgi_read_timeout ou 300>s;
}
```
- **HTTPS vers le port TLS d'Apache.** Le bloc qui sert HTTPS (443 avec Force SSL) envoie à
  `https://127.0.0.1:8092` avec `proxy_ssl_server_name on; proxy_ssl_name $host; proxy_ssl_verify off;`
  (SNI = Host du visiteur, pour qu'Apache choisisse le vhost du site et non le catch-all ; certificat
  de boucle locale auto-signé, d'où pas de vérification). Le bloc unique 80+443 (Force SSL désactivé)
  choisit par requête, au niveau `server` (aucun `if` dans une `location`) :
  `set $apache_upstream http://127.0.0.1:8091; if ($scheme = https) { set $apache_upstream https://127.0.0.1:8092; }`
  puis `proxy_pass $apache_upstream;` (variable sans partie URI : l'URI est transmise telle quelle,
  adresse IP littérale : pas de `resolver`). Un bloc qui ne sert que HTTP garde `http://127.0.0.1:8091`.
  Raison : `%{HTTPS}` de mod_rewrite vient de mod_ssl, jamais d'une variable d'environnement ;
  derrière un saut en HTTP clair il valait toujours `off`, et la règle `.htaccess` très répandue
  `RewriteCond %{HTTPS} off` + `RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]` bouclait
  sans fin (constaté au premier import HestiaCP réel). HestiaCP fait de même (nginx vers Apache en TLS
  sur un port local). `X-Forwarded-Proto` et le `SetEnvIf ... HTTPS=on` restent (sans effet nuisible).
  Port vu par l'application : le port réel de la connexion est `8092` (même classe de comportement
  que le `8443` de Hestia : `UseCanonicalPhysicalPort On`, `%{SERVER_ADDR}`/le port local le
  montreraient). Avec la valeur par défaut `UseCanonicalName Off`, `%{SERVER_PORT}` vient du `Host`
  envoyé par nginx (sans port, donc le port par défaut du schéma) : mesuré en conteneur
  (Debian 12, Apache 2.4 + nginx), `%{SERVER_PORT}` vaut `443` en HTTPS et la boucle disparaît
  (l'ancien saut HTTP redirigeait vers lui-même en 301).
- Pas d'`access_log off` : le journal d'accès nginx sert aux statistiques, à la bande passante et à fail2ban.
- Ne doit **pas** contenir la ligne `index index.html index.htm;` (la retouche « static deny » au
  démarrage de l'agent et `update.sh` s'en servent comme repère).

### A3. vhost Apache `/etc/apache2/sites-enabled/<domaine>.conf` (fonction pure `render_apache_vhost`)
```apache
# Managed by CyberHunter - Panel. Do not edit by hand.
<VirtualHost 127.0.0.1:8091>
    ServerName <domaine>
    ServerAlias <alias...>            # mêmes alias que le server_name nginx
    DocumentRoot <document_root_for(site)>
    <Directory <document_root>>
        AllowOverride AuthConfig Limit Indexes Options=FollowSymLinks,SymLinksIfOwnerMatch,Indexes,MultiViews Nonfatal=Override
        AllowOverrideList RewriteEngine RewriteBase RewriteCond RewriteRule RewriteOptions Redirect RedirectMatch RedirectPermanent RedirectTemp ErrorDocument Header RequestHeader AddType ForceType RemoveType RemoveHandler AddDefaultCharset AddCharset RemoveCharset AddEncoding RemoveEncoding AddLanguage RemoveLanguage LanguagePriority FileETag MultiviewsMatch SetEnv SetEnvIf SetEnvIfNoCase BrowserMatch BrowserMatchNoCase UnsetEnv PassEnv SetOutputFilter AddOutputFilter AddOutputFilterByType
        Options +SymLinksIfOwnerMatch -FollowSymLinks -Indexes -ExecCGI -Includes
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
- **Deux blocs, même contenu** : le bloc ci-dessus sur `127.0.0.1:8091`, puis le même corps (mêmes
  ServerName/ServerAlias/DocumentRoot/Directory/FilesMatch/LocationMatch/ProxyTimeout/LimitRequestBody/
  ErrorLog) dans `<VirtualHost 127.0.0.1:8092>` précédé de `SSLEngine on`,
  `SSLCertificateFile /etc/apache2/ssl/cyberhunter-loopback.crt`,
  `SSLCertificateKeyFile /etc/apache2/ssl/cyberhunter-loopback.key` (voir A2 pour la raison). Les
  retouches (alias ajouté ou retiré, renommage, mise à jour `AllowOverride`) portent sur les deux blocs.
  Un vhost géré à un seul bloc (écrit avant) reçoit son second bloc au prochain rendu, et au démarrage
  de l'agent (configuration globale appliquée d'abord ; en cas d'échec, le vhost reste en HTTP seul et
  le démarrage suivant réessaie).
- Le socket est celui que `put_site` a résolu pour le pool du site (après l'attente du socket).
- Écriture atomique ; `apachectl configtest` ; puis `systemctl reload apache2`.
- **Isolation des sockets (durcissement)** : un `.htaccess` ne doit jamais pouvoir viser le socket
  d'un autre site. `AllowOverride All` le permettait (`SetHandler`/`AddHandler
  "proxy:unix:<autre>.sock|fcgi://localhost"`, aussi dans `<Files>`/`<If>`). Le vhost n'accorde donc
  plus la catégorie `FileInfo` (qui regroupe SetHandler/AddHandler) : il accorde `AuthConfig Limit
  Indexes Options=...` en entier et ré-autorise une à une les directives FileInfo utiles
  (`AllowOverrideList` : Rewrite*, Redirect*, ErrorDocument, Header, AddType, AddDefaultCharset,
  SetEnvIf...). `SetHandler`, `AddHandler`, `Action`, `SetInputFilter` restent refusés dans tous les
  contextes (le `SetHandler` du vhost, lui, n'est pas soumis à AllowOverride). `Nonfatal=Override`
  transforme une directive refusée en avertissement dans le journal d'erreurs au lieu d'une erreur 500
  (un `.htaccess` cPanel avec `AddHandler ...php74...`, ou le `SetHandler Drupal_Security_...` de
  Drupal, continue de fonctionner, la ligne étant ignorée). Les conteneurs (`<IfModule>`, `<Files>`,
  `<FilesMatch>`, `<If>`, `<Limit>`) restent permis ; avec `AllowOverride None` + liste seule ils
  seraient refusés et casseraient tout `.htaccess` WordPress.
- Une règle `<Proxy>`/`<ProxyMatch>` « refuser tout sauf le worker du site » a été **essayée et ne
  convient pas** : mesuré sur Apache 2.4.58, ces sections ne sont pas appliquées aux handlers forcés
  (`SetHandler`, `AddHandler`, `RewriteRule [H=]`), seulement aux requêtes déjà proxy dès la
  traduction (`ProxyPass`). Aucune n'est émise.
- **Limite connue** : `RewriteRule ... [H=proxy:unix:<autre>.sock|fcgi://localhost]` (et `[P]` vers une
  URL `fcgi://` TCP) ne peut pas être refusé par la configuration Apache tant que `RewriteRule` est
  permis. En pratique, le pool visé refuse le script (chemin dans l'arbre du site appelant, hors de
  son `open_basedir` : « No input file specified »). Le contournement par lien symbolique vers un
  fichier de l'autre site est refusé par défaut par `Options +SymLinksIfOwnerMatch -FollowSymLinks` (lien et
  cible de propriétaires différents : 403 ; `mod_rewrite` accepte l'une ou l'autre option). Un `.htaccess`
  PEUT réactiver `FollowSymLinks` (présent dans la liste `Options=`) : Drupal et beaucoup de sites migrés
  contiennent `Options +FollowSymLinks`, et une erreur 500 n'est pas acceptable. Risque résiduel : un
  locataire qui fait cela plus `[H=]` ne peut exécuter que des scripts déjà présents dans l'arbre de
  l'autre site, sous le `open_basedir` de cet autre site. Sans réactivation, un lien symbolique dont le
  propriétaire diffère de celui de sa cible (ex. lien de déploiement créé par root) est refusé.
- **`open_basedir` sur tous les pools** : chaque pool PHP-FPM reçoit toujours
  `php_admin_value[open_basedir] = /var/www/<domaine>/:/tmp/:/usr/share/php/`, quel que soit
  l'utilisateur du pool (`www-data` ou dédié) et l'option `isolation` (une seule ligne ; une valeur
  `open_basedir` explicite du pool l'emporte). Raison : constaté en VM, un `RewriteRule ... [H=proxy:unix:<autre>.sock|...]`
  exécutait le script d'un site dans le pool d'un autre (pool `www-data` sans `open_basedir`), hors des
  limites du site appelant. Avec `open_basedir`, le pool visé refuse tout script hors de son propre
  arbre. Les pools existants sont complétés au démarrage de l'agent (pools gérés par le panel sans
  ligne `open_basedir` : ligne ajoutée, `php-fpm -t`, rechargement par version ; idempotent, `www.conf`
  et fichiers non gérés jamais touchés).
- Écriture atomique ; `apachectl configtest` ; puis `systemctl reload apache2`.

### A4. Configuration globale Apache (écrite par l'installeur, idempotente)
- `/etc/apache2/ports.conf` : `Listen 127.0.0.1:8091` et `Listen 127.0.0.1:8092 https` uniquement
  (boucle locale, jamais `0.0.0.0`) ; le contrôle « port déjà pris par un autre programme » couvre les deux.
- `a2dissite 000-default` ; `a2dismod mpm_prefork php*` ; `a2enmod mpm_event proxy proxy_fcgi
  rewrite remoteip headers expires setenvif alias ssl`.
- Certificat de boucle locale auto-signé `/etc/apache2/ssl/cyberhunter-loopback.{crt,key}` (CN=localhost,
  RSA 2048, 10 ans, clé root 0600), créé par la même fonction shell dans `configure_script` et
  `setup.sh` (test de parité) : recréé seulement si la clé manque ou si le certificat manque ou expire
  dans moins de 30 jours ; sinon seuls propriétaire et modes sont réaffirmés. `global_config_ok`
  exige les deux fichiers. `/etc/apache2` est déjà dans `ReadWritePaths`.
- `/etc/apache2/conf-available/cyberhunter.conf` (activée) :
  `RemoteIPHeader X-Real-IP`, `RemoteIPInternalProxy 127.0.0.1`,
  `SetEnvIf X-Forwarded-Proto "^https$" HTTPS=on`, `ServerTokens Prod`, `ServerSignature Off`, et un
  vhost catch-all `default.invalid` (`Redirect 404 /`) sur chacun des deux ports (TLS avec le
  certificat de boucle locale sur 8092).
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
