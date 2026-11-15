# Fonctionnalité 5 - Import complet d'une sauvegarde utilisateur HestiaCP

Objectif : sortir tous les sites d'un HestiaCP en important une archive `v-backup-user` (tar simple, blobs
internes en `.tar.gz` ou `.tar.zst`) : sites, certificats, bases, mails, comptes FTP, avec les mêmes
identifiants, de façon relançable et avec un rapport par élément. Contrats d'interface :
`05-import-hestia-contrats.md`.

## 1. Constats (audit de `lab/adm-jim.2026-11-15_05-32-36.tar`, 9,6 Go)

- Disposition : `web/<d>/{domain_data.tar.gz, hestia/{web.conf,<d>.crt|key|ca|pem}, conf/, template/}`,
  `db/<n>/{<n>.mysql.sql.gz, hestia/}`, `mail/<d>/{accounts.tar.gz, conf/{passwd,accounts,aliases,dkim.pem,...},
  hestia/{mail.conf,<d>.conf,<d>.pem,<d>.pub}}`, `hestia/{user.conf,ssl/}`, `cron/`, `user_dir/`.
  `domain_data` contient `public_html/ private/ logs/ stats/ cgi-bin/ document_errors/`.
- `web.conf` : clés `ALIAS`, `SSL`, `SSL_FORCE`, `SSL_HSTS`, `BACKEND` (`PHP-5_6`, `PHP-8_4`, `default`), `PROXY`
  (Apache), `FTP_USER`, `FTP_MD5` (hash crypt(3) yescrypt `$y$`), `SUSPENDED`. Le `default` ne donne pas la version
  (le gabarit `template/php-fpm/default.tpl` garde le marqueur `%backend_version%`).
- La redirection d'hôte canonique n'est PAS dans `web.conf` : c'est `web/<d>/conf/nginx.conf_redirect` et
  `nginx.ssl.conf_redirect` (`if ($host != "www.d") { return 301 $scheme://www.d$request_uri; }`), 10 domaines.
- `db.conf` : `DB`, `DBUSER`, `MD5` (hash `mysql_native_password` `*HEX40`), `HOST`, `TYPE`, `CHARSET`.
- Mail : `hestia/<d>.conf` = une ligne `ACCOUNT= ALIAS= FWD= FWD_ONLY= MD5= QUOTA=` par boîte ; `conf/passwd` = ligne
  Dovecot `user:{BLF-CRYPT}$2y$...:uid:gid::home:0:userdb_quota_rule=...` ; `accounts.tar.gz` = maildirs
  (`<user>/cur,new,tmp,.Spam/`, `dovecot-uidlist`, index). Le schéma du panel (`/var/vmail/%d/%n`, `BLF-CRYPT`
  toujours accepté) est compatible tel quel.
- Aucune tâche cron, DNS vide.
- Dans le code actuel, les alias n'existent que dans le fichier vhost (`server_name` modifié par chaîne) : un
  nouveau rendu les perd ; et la commande ACME ne demande que `domain` (`agent/src/services/ssl.rs:457`).

## 2. Décisions

**D1. Bases : un serveur MariaDB local partagé, `kind='local'`.** Une instance par hôte (`mariadb-server` 11.4 LTS
du dépôt mariadb.org ; à défaut paquet de la distribution avec réécriture `uca1400` vers `utf8mb4_unicode_ci` si une sonde
`information_schema.COLLATIONS` ne connaît pas `utf8mb4_uca1400_ai_ci`, avertissement). Écoute `127.0.0.1:3306` et socket `/run/mysqld/mysqld.sock` : `localhost`
fonctionne comme sous Hestia. Dans le modèle du panel, une ligne `databases` garde `engine='mariadb'` et gagne `kind`
(`container` par défaut, `local`) :
- `local` : `port` NULL, `container_id` NULL, `stack_id` NULL, `db_password_enc=''` + `imported_hash=true` tant que le
  mot de passe n'est connu que sous forme de hash. Le panel agit en root par le socket (l'agent est root) via un compte
  temporaire limité à la base (`ch_tmp_<aléa>`, `GRANT ALL ON <base>.*`, supprimé après usage, balayage au démarrage) :
  un locataire ne voit jamais les autres bases.
- Utilisateurs créés pour `'u'@'localhost'` ET `'u'@'127.0.0.1'` avec `IDENTIFIED VIA mysql_native_password USING '<hash>'`
  (hash validé `^\*[0-9A-Fa-f]{40}$`). Les `GRANT` sur `base.*` échappent `_` et `%` (sinon `adm-jim_x` couvre `adm-jimXx`).
- Noms : l'agent valide un motif propre au local, `^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$` (points, tirets, majuscules ;
  identifiants toujours entre backticks, backtick/NUL/`/`/`\` refusés). `is_valid_name` (agent) et les validateurs de
  création du backend ne bougent pas (ils servent aux conteneurs) ; les lignes importées ne passent pas par `create`.
- Quota : `MAX_DATABASES_PER_USER` (25) ne compte que `kind='container'` (les 30 bases importées ne le heurtent pas).
- PITR et instantané de volume : refusés (400) pour `local`. Sauvegardes : la convention `container_name = "local"` fait
  basculer l'agent (`database_backup.rs`) sur `mariadb-dump` ; les appelants backend passent par un helper `container_ref`.
- Les conteneurs existants (`mariadb:11`, ports 3307+) continuent tels quels ; l'import Hestia ne crée que du `local`.
- `sql_mode` du serveur partagé : défauts MariaDB 11.4, mais configurable (`PUT /api/databases/local/config`, fichier `99-cyberhunter.cnf`, redémarrage) pour les sites PHP 5.6 qui exigeraient un mode non strict.
- Import SQL en flux (`gzip|zstd -dc | mariadb`), jamais de copie décompressée sur disque (le code actuel fait `gunzip -k`).

**D2. PHP 5.6 et 7.4.** Ajoutés à la liste unique `php_pool::PHP_VERSIONS` (PPA ondrej / sury, mécanisme existant),
marqués `legacy` : bandeau « no security updates » (sélecteur, fiche du site, rapport). La version Hestia est respectée
(`PHP-5_6` donne 5.6). Pour `default`, la version est lue dans `web/<d>/conf/nginx.conf` ou `apache2.conf` (socket `php8.3-fpm-<d>.sock`, vérifié sur les 28 domaines : 17 en 8.3, 8 en 5.6, 3 en 8.4) ; à défaut, version choisie dans l'assistant (`default_php_version`). Si la version
n'est pas installée, l'import l'installe (`/php/install`, jusqu'à 10 min) avant de créer le vhost. RHEL : refus avec message.

**D3. SSL.** Le certificat Hestia (`web/<d>/hestia/<d>.crt` + `.ca` en chaîne + `.key`) est installé par l'agent depuis le
staging (la clé ne transite jamais par le backend ni la base), après `cert_covers_domain`, correspondance clé/certificat et
date. Expiré : site importé en HTTP + avertissement. `ssl_challenge=NULL` : le renouvellement automatique existant le prend en
charge (HTTP-01) à l'approche de l'échéance ; émetteur Let's Encrypt donc non « étranger ». **Défaut à corriger** : un
renouvellement ferait perdre `www.` à tous ces sites ; les commandes ACME incluent désormais les alias (`extra_names`), avec
repli apex seul + avertissement. **Garde DNS** : avant cela (et avant la bascule DNS), l'auto-renouvellement pour un domaine qui ne pointe pas ici (A/AAAA du résolveur système absent des IP du serveur) est ignoré sans commande ACME, pour ne pas épuiser les limites d'échecs de Let's Encrypt avec 28 domaines dont le certificat importé est déjà dans la fenêtre de 45 jours ; l'alerte d'expiration existante reste active. Force SSL et HSTS deviennent des options par site (`sites.force_ssl`, `sites.hsts`, défaut vrai = rendu actuel octet pour octet), importées de `SSL_FORCE` / `SSL_HSTS` (donc fidèles aux 1 et 2 sites qui ne les avaient pas), basculables dans la fiche du site.

**D4. Alias et hôte canonique : modèle persistant.** `SiteConfig.aliases` (liste faisant foi) et `SiteConfig.canonical_host`
(`www`/`apex`), colonnes `sites.aliases` (NULL = jamais géré par la base : l'agent conserve ceux du disque) et
`sites.canonical_host`. La redirection canonique est rendue par les gabarits : bloc `:80` DANS `location /` (un `return` au
niveau `server` casserait `/.well-known/acme-challenge/`), bloc `:443` par `if ($host != "<cible>") { return 301 https://<cible>$request_uri; }`.
Jamais dans l'include des redirections (ses analyseurs supposent des lignes `location =`).

**D5. Mail.** Domaines, boîtes avec hash tel quel (`{BLF-CRYPT}...`), alias, redirections, fourre-tout, clés DKIM (sélecteur
`mail` conservé, pas `dockpanel`), maildirs. N'appelle PAS `create_domain` (génération DKIM, DNS automatique, certificat `mail.<d>` :
effets de bord à ne pas déclencher avant la bascule DNS). Schéma de hash non géré par le Dovecot cible : boîte importée
`enabled=false` + action manuelle (aucun mot de passe généré ni stocké). Redirection avec copie locale (`FWD` sans `FWD_ONLY`) : le modèle de boîte gagne `keep_copy` (redirection + copie conservée), importé tel quel, avec bascule dans l'interface Mail. Seuls hashes mail et clés DKIM passent de l'agent au
backend (le panel les stocke) ; ils ne sont écrits ni dans `inventory`, `result`, `migration_items`, ni dans le SSE.

**D6. FTP vers SFTP.** Un compte SFTP du panel par site (chroot `/var/www/<d>`) : le nom Hestia
(`adm-jim_x`) EST gardé : le panel accepte désormais un nom SFTP personnalisé (`sites.sftp_username`, motif `^[a-z_][a-z0-9_.-]{0,31}$`, unique dans le panel, absent de `/etc/passwd`, des noms réservés et des comptes `sftp<uid>`), utilisé par l'import et saisissable dans l'interface SFTP ; le nom par défaut reste `sftp<uid>`. En cas de conflit à l'import : repli `sftp<uid>` + avertissement. Mot de passe : le hash yescrypt est appliqué par `chpasswd -e`
(stdin, jamais argv) ; l'agent le lit lui-même dans le staging (par référence). Hash refusé par la plateforme : compte verrouillé
+ action manuelle « Generate password » du rapport = le « Reset password » existant, qui génère un mot de passe et ne l'affiche qu'une fois (la demande « générer et montrer une fois », sans jamais le stocker). SFTP activé APRÈS la copie des fichiers (l'activation change propriétaire et pool PHP).

**D7. Fichiers.** `domain_data` décompressé (gz/zst) dans `/var/www/<d>/.import-<job>/` (même système de fichiers) puis placé par renommage (`mv`, pas de double occupation) quand la cible est vide ou absente, par `rsync -a` puis suppression du temporaire sinon : `public_html` vers `public`
(`public_html0` s'il est seul à exister, avertissement), `private/` vers `/var/www/<d>/private` (sous `open_basedir`, hors racine web).
Jamais copiés : `conf/`, `hestia/`, `template/`, `logs/`, `stats/`, `cgi-bin/`, `document_errors/`. Le gabarit nginx personnalisé
(`PROXY` = `custom-lmj`, `template/nginx/*.stpl`) n'est pas traduit : copié dans `/var/www/<d>/private/.hestia-import/custom-nginx/`
(hors web) et cité dans l'avertissement. Chemins absolus : seule la chaîne exacte `/home/<user>/web/<d>/public_html` (resp. `/private`)
est réécrite en `/var/www/<d>/public` (resp. `/private`) dans `.user.ini`, `php.ini`, `.htaccess` à la racine web (cas courant Wordfence
`auto_prepend_file`, qui sinon met le site en erreur fatale sous `open_basedir`), originaux gardés dans `private/.hestia-import/orig/` ;
les autres fichiers contenant le préfixe (`wp-config.php`, `.env`, profondeur <= 3) sont listés sans modification. Liens symboliques
sortant de l'arbre du site : listés. Bits setuid/setgid retirés.

**D8. Staging et espace disque.** Plus de `/tmp` (`PrivateTmp`, perdu au redémarrage de l'agent) :
`/var/lib/dockpanel/migration/<id>/` (déjà dans `ReadWritePaths`). Archive tar simple (cas Hestia) : mode `lazy`, seules les petites
métadonnées (<= 4 Mio, hors blobs `*.tar.*` et `*.sql.*`) sont extraites ; chaque blob est lu en flux depuis l'archive d'origine
(`tar xOf` sur fichier seekable : saut direct) à l'import. Archive compressée ou autre panel : extraction complète avec contrôle d'espace.
L'archive doit rester en place jusqu'à la fin de l'import. Contrôle à l'analyse (`disk` dans l'inventaire) et avant chaque site
(libre >= 2,5 x blob compressé + 1 Gio), refus net sinon.

**D9. Apache et `.htaccess`.**
- Mode Apache par `PROXY` (existant).
- `Options -Indexes -ExecCGI` donne 500 car `ExecCGI` n'est pas dans la liste `Options=` d'`AllowOverride`. Décision : autoriser
  `ExecCGI` (et rien de plus) dans cette liste et garantir `mod_cgi`/`cgid` désactivés : `+ExecCGI` ne fait alors rien (aucun handler,
  `AddHandler` refusé). Préféré à une réécriture à l'import : fidèle au fichier du client et valable pour les futurs `.htaccess`. Les vhosts
  Apache gérés existants sont mis à jour au démarrage de l'agent (idempotent, comme `open_basedir`).
- Protection `SetHandler` des dossiers d'upload ignorée (Nonfatal) : le **blocage d'exécution PHP est porté par le vhost**, pas par les
  `.htaccess` : `SiteConfig.php_no_exec_dirs` (absent ou `[]` = aucun, rendu octet pour octet inchangé pour les sites existants ; liste par défaut proposée : `/wp-content/uploads`, `/sites/default/files`, `/storage/app/public`,
  `/uploads`, `/upload`, écrite en base à la création de tout nouveau site PHP et à l'import, avec bouton « apply defaults » pour les sites existants ; colonne `sites.php_no_exec_dirs`, NULL = aucun). nginx (passage obligatoire des deux modes) :
  `location ~* ^<dir>/.*\.(?:php[0-9]?|phtml|pht|phps|phar)(/|$) { return 403; }` avant le bloc `\.php$` ; Apache, en défense en
  profondeur : `<LocationMatch>` + `Require all denied` (non annulable par `.htaccess`). L'analyse compte les `.php` déjà présents.

**D10. Relançable, par élément.** Table `migration_items` (grand livre + rapport) : une ligne par `(migration, kind, key)`. Un élément `done` est
SAUTÉ à la relance (`rsync --delete` ou réimport de dump détruirait les données écrites après la bascule) ; refait seulement par `force_items`
explicite (confirmation dans l'interface). `running`/`failed` sont refaits entièrement (jamais terminés : base partielle supprimée puis recréée).
Une base existante non créée par cette migration n'est jamais touchée. Progression : jobs agent sondés toutes les 3 s (octets, phase), SSE limité à
1 événement / 2 s par élément, capacité du journal 64 portée à 512, plus de plafond 300 s (blocage = 15 min sans progrès).

**D11. Secrets.** `migrations.inventory`, `result`, `migration_items.details`, SSE, journaux : aucun hash, clé ni mot de passe. Les secrets
MySQL/FTP/SSL sont appliqués par l'agent depuis le staging (par référence : `migration_id` + nom). Staging en 0700 root, supprimé par `cleanup`.

**D12. Rattachement base vers site.** Indices à l'analyse (noms seulement) : extraction ciblée de `wp-config.php`, `.env`, `configuration.php`,
`app/etc/env.php`, `config.php`, `includes/config.php` des `domain_data` : `suggested_site` + `suggested_via` ; repli sur le nom
(`<user>_<domaine>`). Non résolu : choix obligatoire dans l'assistant.

## 3. Flux
1. Analyse : `POST /api/migration/analyze` (source `hestiacp` ou `auto`) : staging + inventaire sans secret + `disk` + avertissements.
2. Assistant : sites (version PHP, alias, canonique, SSL, FTP), bases (site proposé), domaines mail ; contrôle préalable (MariaDB local, mail, PHP installés ?).
3. Import : par site (revendication, PHP, ligne `sites`, vhost, fichiers [job], SSL, FTP), puis bases [job], puis mail (domaine, boîtes, alias, DKIM, `sync`, maildirs [jobs]).
4. Rapport : `GET /api/migration/{id}/report` ; actions manuelles listées (DNS, boîtes verrouillées, FTP verrouillé, chemins à corriger, gabarit nginx, PHP hérité).

## 4. Plan de test VM (labo Ubuntu 24.04 ; les tests unitaires purs sont à la charge de chaque chantier)
Archive réduite (3 domaines : WP PHP 8.3 www canonique, un PHP 5.6, `example.be`) puis archive complète.
1. Analyse : quelques minutes, aucun fichier > 4 Mio dans le staging ; inventaire exact (28 sites, 30 bases, 7 domaines mail, 14 boîtes, 28 FTP) ; recherche des valeurs de hash dans `migrations`, `migration_items`, journaux : vide.
2. Disque : refus propre avec un staging artificiellement plein.
3. Site : `curl --resolve` HTTP et HTTPS (certificat Hestia servi, `www` vers canonique en un seul 301, ACME joignable en `:80`), HSTS ; PHP 5.6 : version du pool, page phpinfo ; `private/` lisible par PHP (include `../private`), 404 en HTTP.
4. Sécurité fichiers : `/private`, `/conf`, `/hestia` : 404 ; PHP déposé dans `uploads` : 403 (nginx seul et Apache) ; un `.htaccess` `SetHandler none` d'uploads ne change rien ; `example.be` : 200 ; `+ExecCGI` sans effet ; `.user.ini` Wordfence réécrit, site sans erreur fatale.
5. Bases : connexion `mariadb -u <dbuser>` avec l'ancien mot de passe, par socket ET par `-h127.0.0.1` ; base à point/tiret/majuscule ; `wp-config` inchangé ; nombre de tables = source ; collation `uca1400` ; MyISAM+InnoDB ; aucun `ch_tmp_%` résiduel ; interface (tables, requête, sauvegarde, reset mot de passe, suppression) OK pour `local`.
6. Mail : `doveadm auth test` avec le mot de passe d'origine ; IMAP : dossiers et nombre de messages = source ; `opendkim-testkey -d <d> -s mail` ; envoi signé ; aucun enregistrement DNS ni certificat `mail.<d>` créé ; boîte à schéma inconnu désactivée.
7. SFTP : connexion `sftp<uid>` avec le mot de passe Hestia ; chroot ; fichiers modifiables par PHP.
8. Relance : import terminé relancé : tout `skipped`, rien d'écrit (somme de contrôle de `/var/www`, dump d'une base inchangés) ; agent tué en plein site : la relance reprend ; `force_items` d'une base : recréée.
9. Renouvellement : `ssl_expiry` forcé à J+10, DNS non pointé : échec journalisé sans perte du certificat ; DNS pointé : certificat couvre `www.`.
10. Gros site (plusieurs Go) : progression visible, pas de coupure à 300 s, rechargement de la page sans perdre le suivi.
11. Sites PHP 5.6 : si une erreur SQL liée au mode strict apparaît, répéter avec `sql_mode` non strict (réglage du serveur local) et noter la valeur retenue ; l'utilisateur confrontera plus tard avec `@@sql_mode` de la source.
12. Force SSL / HSTS par site : les 3 sites concernés sans redirection / sans en-tête ; un site existant reste identique octet pour octet.
13. Mail : boîte `FWD` sans `FWD_ONLY` reçoit ET redirige ; SFTP : connexion avec `adm-jim_x`.

## 5. Questions ouvertes
Tranchées par l'utilisateur : noms SFTP conservés, redirection + copie locale ajoutée, Force SSL/HSTS par site, archive laissée en place pendant l'import. Reste, à son rythme : `SELECT @@version, @@sql_mode, @@character_set_server, @@collation_server;` sur le Hestia source (le `sql_mode` du serveur local est configurable, voir D1 et test 11).
