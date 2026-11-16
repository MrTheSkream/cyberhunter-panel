# 6 - FTP (FTPS) et quotas disque par site (validée le 2026-11-16)

Choix validés :
- **Comptes FTP** : le FTP réutilise le compte du site (même utilisateur Linux et même mot de passe
  que le SFTP), avec une case « FTP » en plus par site.
- **Chiffrement** : FTPS obligatoire, aucune connexion en clair.
- **Quotas** : mesure de l'espace + alertes, sans quota noyau.
- **Périmètre du quota** : les fichiers du site seulement (`/var/www/<domaine>`).

## 1. Constat (code actuel)
- **Aucun serveur FTP** : 0 occurrence de vsftpd, proftpd ou pure-ftpd. « ftp » est déjà un nom de compte
  réservé (`sftp_accounts.rs:53`).
- **SFTP** : un compte au plus par site, porté par des colonnes de `sites`.
  - Colonnes : `sftp_enabled`, `sftp_uid` = `sftp_gid` (séquence à partir de 30000), `sftp_username`.
  - Utilisateur et groupe : `sftp<uid>` (ou le nom choisi), groupe `sftpg<gid>`, shell `/usr/sbin/nologin`.
  - Prison et montage : la prison `/var/dockpanel-sftp/<domaine>` (root:root 0755) contient
    `content/`, monté en bind sur `/var/www/<domaine>` par une unité systemd `.mount`.
  - Propriétaire : quand SFTP est actif, les fichiers et le pool PHP appartiennent à ce compte. Sinon,
    c'est `www-data:www-data`.
  - Mot de passe : SHA-512-crypt dans `/etc/shadow`, jamais stocké par le panel. L'import Hestia garde
    le hash d'origine.
- **Import Hestia** : chaque domaine a un compte FTP à la racine du site (28 domaines, `FTP_PATH`
  vide). Le premier compte est déjà importé comme compte SFTP, avec son hash. Le quota disque Hestia
  (`DISK_QUOTA='unlimited'`) n'est pas lu.
- **Pas de quota disque** :
  - `max_disk_mb` du revendeur est enregistré mais jamais mesuré ni appliqué.
  - L'espace d'un site n'est mesuré que pour le staging (`staging.rs:127`, `du -sb`).
- **VM et VPS** : la racine `/` est en ext4, sans option de quota et sans les outils `quota`.
- **Pare-feu** : `firewall::allow_tcp_ports`, en ufw ou firewalld, ne gère pas les plages de ports.
  L'installeur UFW n'ouvre que 22, 80, 443, 587 et 993.
- **Fail2ban** : le panel écrit déjà ses propres prisons (`security.rs:993`, `nginx.rs:694`). Il n'y
  en a pas pour le FTP.
- **Défaut existant qui gênerait le FTP** : plusieurs routines font `chown -R www-data:www-data` sans
  tenir compte du compte du site. C'est le cas de la mise à jour WordPress, de l'installation de CMS,
  du deploy, de la restauration de sauvegarde et du staging. Après l'une d'elles, le compte FTP/SFTP
  ne peut plus écrire dans ses propres fichiers.

## 2. Serveur FTP : vsftpd (Settings → Services)
vsftpd est le serveur qu'utilise HestiaCP. Il est simple, s'authentifie par PAM sur `/etc/shadow`,
sait chrooter et parle FTPS. Il n'est pris en charge que sur Debian et Ubuntu ; sur RHEL, le panel
affiche « Not supported on this server ».

### Configuration
Le fichier `/etc/vsftpd.conf` est écrit en entier par le panel :
```
listen=NO
listen_ipv6=YES                 # écoute IPv4 + IPv6
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
chroot_local_user=YES           # prison = home du compte = /var/dockpanel-sftp/<domaine>
allow_writeable_chroot=NO       # la prison est root:root 0755, on écrit dans content/
userlist_enable=YES
userlist_deny=NO                # liste blanche : seuls les sites avec FTP coché
userlist_file=/etc/dockpanel/ftp-users
pam_service_name=dockpanel-ftp
ssl_enable=YES
force_local_logins_ssl=YES      # FTPS obligatoire (AUTH TLS explicite, port 21)
force_local_data_ssl=YES
ssl_tlsv1=NO
ssl_sslv2=NO
ssl_sslv3=NO
require_ssl_reuse=NO            # sinon FileZilla échoue souvent
ssl_ciphers=HIGH
rsa_cert_file=/etc/dockpanel/ftp/cert.pem
rsa_private_key_file=/etc/dockpanel/ftp/key.pem
pasv_enable=YES
pasv_min_port=12000             # mêmes ports que HestiaCP
pasv_max_port=12100
# pasv_address=<IP publique>    seulement si le serveur est derrière du NAT (IP publique de l'IP par défaut, fonctionnalité 1)
xferlog_enable=YES
dual_log_enable=YES
vsftpd_log_file=/var/log/vsftpd.log
seccomp_sandbox=NO              # plantages connus de vsftpd 3.0.5 avec TLS sur les noyaux récents (à vérifier)
```

### PAM
Le panel écrit un fichier PAM dédié, `/etc/pam.d/dockpanel-ftp`. Celui de Debian (`vsftpd`) passe par
`pam_shells`, qui refuserait nos comptes : leur shell `/usr/sbin/nologin` ne figure pas dans
`/etc/shells`. Le fichier dédié se limite donc à `pam_unix` pour l'authentification et le compte,
plus `pam_listfile` sur `/etc/ftpusers` (root et les comptes système restent interdits).

### Certificat
- Le panel copie le certificat Let's Encrypt du nom d'hôte du panel dans `/etc/dockpanel/ftp/` et
  recharge vsftpd quand ce certificat est renouvelé.
- S'il n'y en a pas, il génère un certificat auto-signé (10 ans) et l'interface affiche « Self-signed
  certificate: FTP clients will ask to trust it ».

### Pare-feu
- Ports à ouvrir : 21/tcp et la plage 12000-12100/tcp.
- Nouvelle fonction `firewall::allow_tcp_range(min, max)` : `12000:12100/tcp` pour ufw,
  `12000-12100/tcp` pour firewalld.
- L'installeur UFW ajoute ces ports quand vsftpd est déjà installé.

### Fail2ban
- Si fail2ban est installé, le panel crée la prison `jail.d/dockpanel-vsftpd.conf` : filtre `vsftpd`
  de la distribution, `logpath=/var/log/vsftpd.log`, 5 essais en 10 min, 1 h de bannissement.
- Elle apparaît dans Security → Fail2ban comme les autres.

### Service et désinstallation
- **Agent** : ajout de `-/etc/vsftpd.conf -/etc/dockpanel` (déjà présent) et `-/etc/pam.d` dans
  `ReadWritePaths`, ou passage par l'échappement non sandboxé (à choisir en implémentant ; le test de
  réparation de l'unité est mis à jour).
- **Désinstallation** : arrêt du service, retrait du paquet, puis suppression des règles de pare-feu, de
  la prison fail2ban, de `/etc/pam.d/dockpanel-ftp` et du certificat copié.
- **Cases FTP des sites** : conservées en base. Une réinstallation les remet en service, et
  l'interface affiche « FTP server not installed » en attendant.

## 3. FTP par site (fiche du site → carte « SFTP / FTP Access »)
### Activation
- **Nouvelle colonne** : `sites.ftp_enabled boolean NOT NULL DEFAULT false`, migration additive.
- **Prérequis** : la case « FTP » n'est active que si le compte SFTP du site existe et que vsftpd est
  installé. Sinon, elle est désactivée avec la raison.
- **Cocher / décocher** : la case ajoute ou retire le nom du compte dans `/etc/dockpanel/ftp-users`.
  - Le fichier est réécrit en entier à partir de la base (écriture atomique). vsftpd le relit à chaque
    connexion, donc aucun rechargement n'est nécessaire.
  - Décocher coupe aussi les sessions FTP en cours de ce compte : on tue les processus vsftpd
    du compte, pas ses sessions SFTP.
- **Désactiver le SFTP** (ou supprimer le site) décoche le FTP avant de supprimer le compte.
- **Mot de passe** : c'est le même. « Reset password » vaut donc pour SFTP et FTP. Le durcissement SSH
  (`PasswordAuthentication no`) ne touche pas le FTP.

### Ce que voit l'utilisateur
- Le FTP montre la même arborescence que le SFTP : on arrive à la racine de la prison et on travaille
  dans `content/`.
- La carte affiche les paramètres de connexion à recopier dans FileZilla : hôte, port 21,
  « Require explicit FTP over TLS », mode passif et nom d'utilisateur.

### Corriger d'abord les propriétaires de fichiers
- Nouvelle fonction de l'agent `site_owner(domain)` : elle renvoie l'uid et le gid du dossier
  `/var/www/<domaine>`, que `provision()` fixe et qu'aucune routine ne modifie avant d'appeler cette
  fonction.
- Les `chown -R www-data:www-data` en dur l'utilisent à la place. Cela touche wordpress.rs, cms.rs,
  deploy.rs, staging.rs, la restauration de sauvegarde, migration.rs, app_process.rs et
  wp_vulnerability.rs.
- Le correctif est livré avec cette fonctionnalité parce qu'il conditionne l'écriture en FTP comme en
  SFTP.

### Import Hestia
- **Si le domaine avait un `FTP_USER`** :
  - le compte SFTP importé reçoit `ftp_enabled = true` ;
  - si vsftpd n'est pas installé, la case est quand même posée, et le journal d'import ajoute l'action
    manuelle « Install the FTP server (Settings → Services) to restore FTP access ».
- **Comptes FTP en plus du premier** : toujours ignorés, avec un avertissement comme aujourd'hui.
  Ce n'est pas le cas pour ton serveur.

## 4. Quotas disque (mesure + alerte)
### Données
- **Nouvelle colonne** `sites.disk_quota_mb integer NULL` : vide = illimité.
- **Nouvelle table** `site_disk_usage` :
  `site_id` (clé primaire, cascade à la suppression), `bytes bigint`, `files bigint`,
  `measured_at timestamptz`, `error text NULL`.

### Mesure
- **Route de l'agent** `POST /disk-usage` : elle prend `{ domains: [...] }` et renvoie
  `{ domain, bytes, files, error }` pour chaque domaine.
- **Méthode** :
  - L'agent parcourt `/var/www/<domaine>` sans suivre les liens symboliques et sans changer de
    système de fichiers.
  - Il compte l'espace réellement alloué sur le disque (`st_blocks × 512`, comme `du`), pas la taille
    apparente.
  - Un fichier présent plusieurs fois (liens durs) n'est compté qu'une fois.
  - Le parcours se fait avec `nice` / `ionice` (classe idle).
- **Fréquence** : un ordonnanceur du backend mesure tous les sites toutes les 6 h. Le bouton
  « Refresh » sur la fiche du site lance une mesure immédiate (une à la fois par site).
- **Ordre de grandeur** : environ 110 000 fichiers pour 31 sites (vu lors des scans ClamAV), soit
  quelques secondes.

### Alertes
- **Type** : `disk_quota`, avec la clé `disk_quota:<site_id>`. Il est ajouté à
  `SUPPRESSIBLE_ALERT_TYPES`.
- **Seuils** :
  - **Warning** à 90 % du quota.
  - **Critical** au dépassement. L'alerte est résolue quand l'usage repasse sous 90 %.
  - Pas de nouvel envoi tant que l'état ne change pas.
- **Destinataires** : l'admin et le propriétaire du site, par les canaux de notification existants.
- **Aucun blocage** : le site continue de fonctionner et le FTP d'écrire. C'est une limite d'alerte.

### Qui règle quoi
- L'admin fixe le quota de chaque site ; un revendeur le fixe pour les sites de ses clients.
- Le propriétaire voit l'usage et le quota, sans pouvoir les modifier.
- **Revendeurs** : le `max_disk_mb` existant reste hors périmètre, avec une seule exception. La page
  Resellers affiche la somme mesurée des sites du revendeur à côté de sa limite, sans alerte.

### Import Hestia
`DISK_QUOTA` est un quota par utilisateur Hestia, pas par domaine :
- `unlimited` (ton cas) : rien.
- valeur chiffrée : une note dans le journal d'import, sans quota appliqué automatiquement.

## 5. Interface (libellés en anglais)
- **Settings → Services** : ligne « FTP server (vsftpd) » avec Install / Uninstall, l'état
  (running ou stopped), le certificat utilisé et les ports ouverts.
- **Fiche du site** :
  - la carte « SFTP Access » devient « SFTP / FTP Access » : case « Enable FTP (FTPS) » et bloc
    « Connection details » ;
  - nouvelle carte « Disk usage » : barre usage / quota (verte, orange à 90 %, rouge au dépassement),
    « Measured 2 h ago », bouton « Refresh » et champ « Quota (GB) » pour l'admin (vide =
    « Unlimited ») ;
  - la carte affiche aussi la taille des bases du site, à titre indicatif.
- **Liste des sites** : nouvelle colonne « Disk » (usage, et quota s'il y en a un).
- **Alerts / Settings → Notifications** : libellés du type `disk_quota`.

## 6. À vérifier en premier dans la VM (pièges probables)
1. **PAM** : connexion d'un compte au shell nologin via `dockpanel-ftp` (pas de `pam_shells`), et
   refus de root et d'un compte système.
2. **Chroot** : vsftpd accepte la prison root:root 0755 sans `allow_writeable_chroot`, et l'écriture
   dans `content/` fonctionne à travers le montage bind.
3. **TLS** : `seccomp_sandbox` avec TLS sur le noyau 6.8. Connexion FileZilla en « explicit TLS » et
   transferts en mode passif.
4. **Liste blanche** : un compte SFTP sans la case FTP est refusé dès l'étape `USER`.
5. **Pare-feu** : la plage passive est bien ouverte en ufw.
6. **Fail2ban** : le filtre `vsftpd` de la distribution reconnaît les échecs écrits dans
   `/var/log/vsftpd.log` (format avec `dual_log_enable`).
7. **Certificat** : vsftpd relit-il le certificat à chaque connexion ou faut-il un rechargement après
   renouvellement ?
8. **Propriétaires** : après une mise à jour WordPress, une restauration et une installation de CMS
   sur un site SFTP, les fichiers appartiennent toujours au compte du site.

## 7. Tests en VM (instantané avant)
- Installer vsftpd, puis cocher FTP sur jeuxx.org.
- Avec FileZilla ou `lftp` (`set ftp:ssl-force true`) :
  - connexion, envoi, téléchargement, renommage et suppression ;
  - le fichier envoyé appartient bien au compte du site ;
  - la connexion en clair est refusée ;
  - un mauvais mot de passe 5 fois de suite mène au bannissement fail2ban.
- Après « Reset password », le nouveau mot de passe vaut pour SFTP et pour FTP.
- Décocher FTP coupe la session ouverte ; désactiver SFTP retire aussi l'accès FTP.
- Lancer un réimport Hestia d'un domaine : `ftp_enabled` est coché et le hash d'origine permet de
  se connecter.
- Quotas :
  - mesurer les 31 sites et comparer avec `du -sx` ;
  - avec un quota de 1 Go sur un site de 1,2 Go, l'alerte critical part ;
  - après une baisse du quota sous 90 %, l'alerte est résolue ;
  - aucune écriture n'est bloquée.
- Désinstaller vsftpd : ports fermés, prison fail2ban retirée, cases conservées ; tout revient à la
  réinstallation.
