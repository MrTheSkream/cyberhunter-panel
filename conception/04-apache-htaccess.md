# Fonctionnalité 4 - Apache + .htaccess, nginx devant (validée)

## 1. Point de départ

**CyberHunter - Panel aujourd'hui** :
- nginx seul : chaque site PHP a un vhost nginx qui envoie les `.php` au pool PHP-FPM du site ;
  les fichiers `.htaccess` sont **ignorés** (nginx ne les lit pas) ;
- les besoins couverts par `.htaccess` passent par des « presets » (WordPress, Laravel, Drupal,
  Joomla…), des directives nginx personnalisées (admin) et les écrans redirections / mot de passe ;
- **conséquence pour une migration depuis HestiaCP** : un site qui compte sur son `.htaccess`
  (réécritures maison, `Deny from all` sur un dossier, protections de plugins WordPress, anciens
  CMS) perd ces règles en arrivant ; l'import actuel ne lit même pas le type de serveur web d'Hestia ;
- tout le reste repose sur nginx et doit continuer à marcher : SSL/ACME, IP par site, WAF
  (ModSecurity), anti-bots, limite de débit, journaux d'accès (statistiques, bande passante,
  fail2ban), page « site désactivé ».

**HestiaCP** (installation nginx + Apache, la plus courante) :
- nginx écoute sur 80/443, termine le SSL, **sert les fichiers statiques** (images, css, js…) et
  **transmet le reste à Apache** (ports locaux 8080/8443) ;
- Apache (mpm_event) exécute le PHP via PHP-FPM, lit les `.htaccess` (`AllowOverride All`) ;
- choix par domaine via deux modèles : « Proxy template » (nginx) et « Backend template » (PHP).

## 2. Ce qu'on fait

### 2.1 Un mode par site : « nginx » ou « nginx + Apache (.htaccess) »
- Nouveau réglage de site **Serveur web** pour les sites PHP : `nginx` (comportement actuel,
  inchangé octet pour octet) ou `apache`.
- Choix à la création (formulaire de site) et bascule à tout moment dans la fiche du site
  (comme le changement de version PHP). Bascule = nouveaux fichiers testés, puis rechargement ;
  échec → retour automatique à l'état précédent.
- Sites statiques, Node, Python, proxy, Docker : non concernés.

### 2.2 Ce qui se passe en mode Apache
- **nginx reste devant**, sans changement pour : écoute 80/443 et IP du site, certificats et ACME,
  WAF, anti-bots, limite de débit, en-têtes de sécurité, gzip, journaux d'accès (donc statistiques,
  bande passante, fail2ban, page « désactivé » : rien à refaire).
- nginx sert lui-même les fichiers statiques (décision D2) et transmet le reste à Apache sur
  **`127.0.0.1:8081`** (8080, 8443 et 8880 sont déjà pris par le panel et Traefik), avec
  `Host`, `X-Real-IP`, `X-Forwarded-For`, `X-Forwarded-Proto`.
- nginx refuse toujours `.htaccess`, `.htpasswd` et les fichiers cachés.
- **Apache** (un vhost par site, `/etc/apache2/sites-enabled/<domaine>.conf`) :
  - écoute **uniquement** `127.0.0.1:8081` (jamais exposé) ; MPM event ; modules `proxy_fcgi`,
    `rewrite`, `remoteip`, `headers`, `expires`, `setenvif` ; pas de mod_php ; site par défaut
    désactivé (une requête sans vhost connu → 404) ;
  - `DocumentRoot` = le même dossier `public` que nginx ;
  - `AllowOverride All` (compatibilité maximale, comme HestiaCP), `Options +FollowSymLinks
    -Indexes -ExecCGI -Includes` ;
  - PHP envoyé **au même pool PHP-FPM du site** que la fonctionnalité 2 : les réglages PHP par
    site, l'isolation et les fonctions bloquées restent exactement les mêmes ;
  - `mod_remoteip` : le PHP voit la **vraie IP du visiteur** (pas 127.0.0.1) ; `HTTPS=on` quand
    nginx a reçu la requête en HTTPS (WordPress, redirections « force https » des `.htaccess`) ;
  - délais et taille d'envoi alignés sur ceux du site (`max_execution_time`, `max_upload_mb`) ;
  - journal d'erreurs Apache par site `/var/log/apache2/<domaine>.error.log`, visible dans le
    visualiseur de journaux du site ; pas de journal d'accès Apache (nginx a déjà le vrai).
- **Limite connue** (aussi chez HestiaCP) : `php_value` / `php_flag` dans un `.htaccess` ne marchent
  pas avec PHP-FPM (erreur 500). Les réglages PHP se font dans la carte « PHP settings » ou un
  `.user.ini`. L'interface l'indique à côté du réglage.
- Le cache FastCGI nginx n'existe pas en mode Apache (la carte l'indique).

### 2.3 Installation d'Apache
- Apache n'est **pas** installé par défaut. Il s'installe :
  - depuis Paramètres → Services (comme Redis), ou
  - automatiquement au premier site passé en mode Apache (avec le journal d'installation).
- L'installation écrit sa configuration (`ports.conf` sur 127.0.0.1:8081, modules, site par défaut
  désactivé) **avant** de démarrer Apache, pour qu'il ne prenne jamais le port 80 à nginx.
- Désinstallation refusée tant qu'un site est en mode Apache.
- Le service apparaît dans la santé des services.

### 2.4 Fiabilité
- Rendu du vhost Apache = fonction pure testée ; écriture atomique ; `apachectl configtest` avant
  rechargement ; échec → ancien fichier remis, nginx inchangé.
- Ordre de bascule nginx → Apache : vhost Apache écrit et testé, Apache rechargé, **puis** vhost nginx
  (le site n'est jamais servi par un Apache qui ne le connaît pas). Inverse pour revenir.
- Suppression, renommage, désactivation et changement d'IP d'un site gèrent aussi le vhost Apache.
- Agent : ajout de `/etc/apache2` aux chemins modifiables du service (sandbox systemd).

### 2.5 Import depuis HestiaCP
- L'import lit le `web.conf` d'Hestia : un domaine qui y utilisait Apache est créé directement en
  mode Apache (décision D3), pour que son `.htaccess` continue de marcher dès l'arrivée.

## 3. Données
- Migration : `ALTER TABLE sites ADD COLUMN web_server TEXT NOT NULL DEFAULT 'nginx'
  CHECK (web_server IN ('nginx','apache'))` ; tous les sites existants restent `nginx`.
- Le champ part dans le corps envoyé à l'agent (création, bascule, clonage, préproduction, import,
  reconstruction SSL…).

## 4. Hors périmètre
- RHEL / AlmaLinux (httpd) : refusé proprement pour l'instant (le panel n'y a pas de pool PHP par site).
- Apache pour les sites statiques / Node / Python / proxy.
- Cache côté nginx pour le mode Apache (proxy_cache) : plus tard si besoin.
- **Défaut existant repéré, à traiter à part** : une reconstruction du vhost nginx (changement de
  version PHP, SSL, IP…) **efface** les redirections et la protection par mot de passe du site
  (leurs `include` ne sont pas dans les modèles). Je propose de le corriger juste après cette
  fonctionnalité.

## 5. Tests en VM
1. Installation d'Apache : il n'écoute que 127.0.0.1:8081 ; nginx garde 80/443 ; l'IP par site marche.
2. Site en mode Apache avec un `.htaccess` de type WordPress (permaliens) : `/un-article/` répond via
   `index.php` ; un dossier avec `Deny from all` → 403 ; une redirection 301 du `.htaccess` marche.
3. `phpinfo()` : vraie IP du visiteur, `HTTPS=on` en https, réglages PHP du site appliqués,
   isolation (open_basedir) toujours active.
4. Fichier statique servi par nginx (en-tête), `.php` exécuté par Apache ; `.htaccess` illisible.
5. Envoi de 100 Mo et script long : mêmes limites qu'en mode nginx.
6. Bascule Apache → nginx → Apache : aucune coupure observable, aucun fichier résiduel.
7. vhost Apache invalide simulé → `configtest` échoue, ancien état remis, site toujours en ligne.
8. Désactivation / suppression / renommage du site : vhost Apache traité.
9. WAF, journal d'accès, statistiques et fail2ban : inchangés en mode Apache.
10. Import d'un domaine Hestia en Apache → arrive en mode Apache.

## 6. Décisions (validées le 2026-11-14)
- **D1 - Apache par défaut pour les nouveaux sites PHP** (comme HestiaCP). Conséquences :
  - les sites existants restent en nginx (rien ne change sans action) ;
  - le formulaire de création propose « nginx + Apache » présélectionné, « nginx seul » possible ;
  - Apache est installé par le script d'installation du panel sur les nouveaux serveurs ; sur un
    serveur existant, la première création en mode Apache l'installe (journal d'installation) ;
  - si Apache ne peut pas être utilisé (RHEL, installation en échec), la création le dit clairement
    et propose nginx seul - jamais de bascule silencieuse.
- **D2 - Fichiers statiques servis par nginx** (comme HestiaCP).
- **D3 - Import HestiaCP** : les domaines qui utilisaient Apache arrivent en mode Apache.
- **D4 - Défaut existant** (redirections / mot de passe effacés par une reconstruction du vhost) :
  corrigé juste après cette fonctionnalité, avant la fonctionnalité 5.
