# 5 - Antivirus ClamAV : messagerie et fichiers des sites (à valider)

Choix validés : mail **et** fichiers web, branchement mail par le **module antivirus de Rspamd**,
détection web = **signaler + quarantaine en 1 clic** (rien n'est déplacé tout seul), scan web
**chaque nuit, réglable**, scan manuel par site à tout moment.

## 1. Constat (code actuel)
- **Aucune trace de ClamAV** dans l'agent, le backend ou l'interface (ni clamd, ni freshclam, ni milter).
- Le « malware check » du scanner de sécurité (`agent/services/security_scanner.rs:165`) n'a pas de
  signatures : nom de fichier en liste noire + 10 regex `grep` sur les `*.php` seulement. On le garde
  tel quel (complémentaire, très rapide), ClamAV s'ajoute à côté.
- Mail : Postfix + OpenDKIM (milter 8891), Rspamd optionnel (milter 11332, config d'origine, aucun
  fichier `local.d` écrit). `milter_default_action = accept`.
- Quarantaine existante (`security.rs:1067`) : simple `rename` vers `/var/lib/dockpanel/quarantine/`,
  **sans métadonnées ni restauration**.
- L'agent tourne avec `ProtectSystem=strict` ; `/etc/clamav` et `/etc/rspamd` ne sont pas dans
  `ReadWritePaths`.

## 2. Installation (Settings → Services, comme les autres services)
- Paquets `clamav-daemon` + `clamav-freshclam` (Debian/Ubuntu). Sur RHEL : « Not supported on this
  server » (même règle que pour Apache).
- **Mémoire** : clamd garde toute la base de signatures en RAM (~1,2-1,5 Go en 2026).
  - Refus si RAM totale < 2 Go, avertissement en dessous de 4 Go.
  - `ConcurrentDatabaseReload no` : sinon la mise à jour des signatures double la mémoire pendant
    le rechargement (risque d'OOM). Contrepartie : clamd ne répond plus ~20-40 s à chaque
    rechargement ; les mails passent alors sans analyse (voir §3), un scan web en cours attend.
  - clamd est son propre service systemd : il n'entre pas dans le `MemoryMax=512M` de l'agent.
- Ordre : installation → premier `freshclam` attendu (clamd ne démarre pas sans base) → réglages
  clamd → démarrage → test `PING` sur `/run/clamav/clamd.ctl`. Installation longue (base ~300 Mo à
  télécharger) : tâche avec progression, comme l'import.
- Réglages clamd écrits par le panel (bloc délimité dans `/etc/clamav/clamd.conf`) :
  `MaxThreads 2`, `MaxFileSize 25M`, `MaxScanSize 100M`, `ConcurrentDatabaseReload no`,
  `LocalSocketMode 660` + groupe `clamav` (Rspamd ajouté au groupe).
- `ReadWritePaths` de l'agent : ajout de `-/etc/clamav` et `-/etc/rspamd` (le test de
  réparation de l'unité est mis à jour).
- Désinstallation : coupe d'abord l'antivirus mail (retrait du fichier Rspamd, rechargement),
  arrête les scans planifiés de ce serveur, retire les paquets. **La quarantaine est conservée.**

## 3. Antivirus de la messagerie (Mail → carte « Spam Filter », interrupteur « Antivirus »)
- Exige ClamAV **et** Rspamd installés (sinon bouton désactivé avec la raison ; on propose
  d'installer Rspamd comme aujourd'hui).
- Activer = écrire `/etc/rspamd/local.d/antivirus.conf` puis `rspamadm configtest` puis reload :
  ```
  clamav {
    type = "clamav";
    servers = "/run/clamav/clamd.ctl";
    action = "reject";          # refus SMTP 5xx, l'expéditeur est prévenu
    scan_mime_parts = true;
    max_size = 26214400;
    symbol = "CLAM_VIRUS";
    message = '${SCANNER}: virus found: "${VIRUS}"';
  }
  ```
  Désactiver = retirer le fichier + reload. Retour arrière si `configtest` échoue.
- S'applique aux mails **entrants et sortants** (le milter Rspamd est déjà sur `smtpd_milters`
  et `non_smtpd_milters`). Réglage par serveur, pas par domaine.
- **Si clamd est arrêté ou en rechargement, les mails passent sans analyse** (Rspamd ajoute
  `CLAM_VIRUS_FAIL`, Postfix accepte) : on privilégie la livraison. La page Mail le signale
  quand clamd ne répond pas, et une alerte part après 10 min d'indisponibilité.
- Import Hestia : si un domaine avait `ANTIVIRUS=yes`, ajout d'une action manuelle
  « Enable mail antivirus ».

## 4. Scan des fichiers des sites
- **Moteur** : l'agent (root) parcourt lui-même `/var/www/<domaine>` et **envoie le contenu de
  chaque fichier à clamd par le socket** (commande `INSTREAM`, celle qu'utilise Rspamd). Pourquoi :
  - clamd (utilisateur `clamav`, profil AppArmor d'Ubuntu) n'a pas besoin d'accéder à `/var/www` :
    aucun droit ni profil AppArmor à modifier, les sites SFTP en `750` sont lus quand même ;
  - le parcours étant fait par l'agent, on a le vrai décompte pour la progression et
    `files_scanned`, les liens symboliques ne sont pas suivis, les fichiers > 25 Mo sont comptés
    « non analysés » au lieu d'être ignorés en silence.
  Lecture à faible priorité (`ionice` idle) et une seule connexion clamd à la fois.
- **Tâche longue** : réutilise le cadre de tâches de l'import (`migration_jobs`), renommé en module
  générique (`jobs`) avec une route neutre `GET /jobs/{id}` (l'ancienne reste en alias). Une seule
  analyse à la fois par serveur ; progression « fichiers traités / total ».
- **Planification** (backend, service supervisé `av_scanner`, même forme que `wp_vuln_scanner`) :
  par serveur, activé par défaut une fois ClamAV installé, **chaque nuit à 03:00** (heure du
  serveur), fréquence et heure réglables, sites analysés l'un après l'autre.
- **Base** :
  - `av_scans` (id, server_id, site_id nul = tout le serveur, trigger manual|scheduled, status,
    files_scanned, infected_count, signatures_version, started_at, completed_at, error).
  - `av_detections` (id, scan_id, site_id, file_path, signature, size, sha256, status
    open|quarantined|deleted|ignored|restored, handled_by, handled_at).
  - `av_ignored` (site_id, sha256, signature, note) : « faux positif », ce fichier précis
    (même contenu) n'est plus signalé **sur ce site** ; s'il change, il est réanalysé. Limité au
    site pour qu'un client ne puisse pas masquer une détection chez un autre.
  - Conservation 90 jours, comme les scans de sécurité.
- **Alertes** : `fire_alert_deduped` par site infecté (type `malware`, critique, canaux habituels :
  email, Slack, Discord…), résolue automatiquement quand un scan repasse propre. Alerte aussi si
  les signatures ont plus de 3 jours.
- **Actions** sur une détection (admin et propriétaire du site, journalisées) :
  - **Quarantine** : déplacement vers `/var/lib/dockpanel/quarantine/<id>/` (dossier root 700,
    fichier en 000) + `meta.json` (chemin d'origine, uid/gid, mode, sha256, signature).
  - **Restore** : remet le fichier à sa place avec ses droits, seulement si le chemin est libre et
    que le sha256 correspond.
  - **Delete** : suppression définitive (confirmation dans l'interface).
  - **Ignore** : faux positif (voir `av_ignored`).
  - Toute action vérifie que le chemin canonique reste sous `/var/www/<domaine>` du site concerné.
  - La quarantaine existante du scanner de sécurité passe par la même fonction (elle gagne la
    restauration).
- **Fichiers-pièges** (`docs/guides/security-hardening.md`) : celui du web est
  `/var/www/.dockpanel-canary`, hors des dossiers de sites ; un scan par site ne le lit jamais.
  Le parcours l'exclut quand même explicitement.

## 5. Interface (libellés en anglais)
- **Settings → Services** : ClamAV (install/uninstall, état, version et date des signatures,
  mémoire utilisée).
- **Mail** : interrupteur « Antivirus » dans la carte Spam Filter.
- **Security → nouvel onglet « Antivirus »** : planning (on/off, heure, fréquence), « Scan all
  now », historique des scans, liste des détections avec Quarantine / Delete / Ignore / Restore,
  liste de la quarantaine.
- **Fiche site** : bouton « Scan now » + badge du dernier résultat.

## 6. À vérifier en premier dans la VM (pièges probables)
- `-/etc/clamav` dans `ReadWritePaths` : si le dossier n'existe pas au démarrage de l'agent,
  l'entrée est ignorée jusqu'au redémarrage. Reprendre la solution déjà utilisée pour
  `-/etc/postfix` et Apache.
- `clamd.conf` d'origine contient déjà `MaxThreads`, `MaxFileSize`… : remplacer les lignes sur
  place plutôt qu'ajouter un bloc (clés en double).
- Mode du socket : s'il vient de `clamav-daemon.socket` (activation systemd), le régler là.
- Premier téléchargement : le service `clamav-freshclam` démarre seul et tient le verrou ; on
  attend les fichiers de base au lieu de lancer `freshclam` à la main.
- Ajout de Rspamd au groupe `clamav` : demande un redémarrage de Rspamd, pas un reload.
- VM : 8 Go de RAM, ~6,3 Go disponibles : assez pour clamd (~1,5 Go) en plus du reste.

## 7. Tests en VM (instantané avant)
1. Installation : refus sous 2 Go simulé, puis installation réelle, signatures téléchargées,
   clamd répond, mémoire relevée.
2. Mail : EICAR envoyé de l'extérieur → refus 5xx ; EICAR envoyé par une boîte locale → refus ;
   mail normal → livré ; clamd arrêté → mail livré + avertissement dans la page Mail.
3. Web : EICAR déposé dans un site SFTP (fichier 640 propriétaire SFTP) → détecté par le scan
   manuel ; alerte reçue ; Quarantine → site intact, fichier absent ; Restore → fichier revenu
   avec ses droits ; Ignore → plus signalé au scan suivant ; Delete.
4. Scan planifié avancé à « dans 2 min » : tous les sites analysés, aucun impact sur le site
   servi pendant ce temps.
5. Sur la copie des 28 sites importés : durée du scan complet, faux positifs relevés.
6. Désinstallation : antivirus mail retiré proprement, mails toujours livrés, quarantaine conservée.
