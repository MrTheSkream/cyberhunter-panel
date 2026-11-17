# 11 - Mise en production (checklist)

But : remplacer HestiaCP par CyberHunter - Panel sur le serveur de production, sans perte de données et
avec un retour arrière possible à chaque étape. Cocher au fil de l'eau ; une case non cochée dans une
section **bloquante** interdit de passer à la section suivante.

## 0. Point de départ (17/11/2026)

Validé dans la VM de lab (Ubuntu 24.04, panel installé depuis DockPanel puis binaires déposés par
`lab/deploy.ps1`) :
- fonctionnalités 1 à 9 (multi-IP, PHP par domaine, login-as-user, Apache/.htaccess, import HestiaCP sur
  une vraie archive, ClamAV, FTP et quotas, stats web, terminal utilisateur) ;
- fonctionnalité 10 (mises à jour signées) : scénarios 1 à 6 et 9 de `10-mises-a-jour-contrats.md` §V.

Jamais fait :
- installation à neuf par `scripts/install.sh` ;
- exécution sur Ubuntu 22.04 (cible de production) ;
- release signée avec la clé de **production** ;
- agent distant (scénarios 7, 8, 10 de la fonctionnalité 10) ;
- import HestiaCP suivi d'une vraie bascule (DNS, mail entrant).

## 1. Décisions à prendre avant tout (bloquant)

- [ ] Serveur(s) cible : nouveau serveur à côté de HestiaCP (recommandé : bascule réversible) ou
      réinstallation du serveur HestiaCP (pas de retour arrière simple). Taille disque/RAM.
- [ ] Un seul serveur ou plusieurs ? Si plusieurs, les scénarios 7, 8, 10 (agent distant) deviennent
      bloquants (section 4).
- [ ] DNS : qui sert les zones après la bascule ? Le cluster DNS est reporté ; si HestiaCP sert
      aujourd'hui les zones (ou fait partie d'un cluster), décider : DNS du panel sur un seul serveur,
      DNS externe (registrar, Cloudflare), ou garder l'existant le temps de la transition.
- [ ] Nom d'hôte du panel et certificat reconnu (Let's Encrypt) : indispensable pour les agents
      distants et pour éviter `curl -k`.
- [ ] Fenêtre de bascule et liste des sites/boîtes mail par ordre de criticité.

## 2. Clé de production et première release (bloquant)

- [ ] Générer la paire de **production** sur la machine de release, distincte de la clé de test :
      `minisign -G -p "$HOME\.minisign\cyberhunter.pub" -s "$HOME\.minisign\cyberhunter.key"`.
- [ ] Phrase de passe forte, stockée dans le gestionnaire de mots de passe.
- [ ] Copie hors ligne de `cyberhunter.key` (clé USB chiffrée ou coffre) : perdre la clé = plus aucune
      mise à jour possible pour les serveurs installés, il faudrait les réinstaller.
- [ ] Noter l'ID de clé (affiché par `release.sh`) dans ce document : `________________`.
- [ ] Version `3.0.0-rc.N` cohérente dans les 4 `Cargo.toml`, `Cargo.lock` et `package.json`.
- [ ] `bash scripts/release.sh --dry-run` depuis Git Bash : résumé avec la bonne clé, `GLIBC_` ≤ 2.35
      pour chaque binaire ; signature lancée dans PowerShell à l'invite du script.
- [ ] `bash scripts/release.sh` : publication de la pre-release sur `MrTheSkream/cyberhunter-panel`.
- [ ] Jeton GitHub fine-grained de **production** : ce dépôt seulement, Contents: read-only, expiration
      notée ici `__________` (rappel de renouvellement dans l'agenda).
- [ ] Révoquer le jeton de test du 17/11/2026 s'il ne l'est pas déjà.

## 3. Recette sur une VM Ubuntu 22.04 vierge (bloquant)

Instantané Hyper-V avant chaque étape.

- [ ] VM Ubuntu 22.04 à jour, aucune installation préalable.
- [ ] Release de la section 2 téléchargée dans un dossier, puis
      `CYBERHUNTER_REPO_URL=<url git> CYBERHUNTER_RELEASE_DIR=<dossier> DOCKPANEL_VERSION=v3.0.0-rc.N sudo -E bash install.sh` :
      fin sans erreur, `setup.sh` a vérifié chaque fichier contre `checksums.txt`.
- [ ] `systemctl is-active dockpanel-api dockpanel-agent` ; `ldd /usr/local/bin/dockpanel-agent` sans
      version manquante ; `/api/health` renvoie la bonne version.
- [ ] Compte admin créé, 2FA activée, codes de secours rangés.
- [ ] Telemetry, Updates : « Signing key ID » = ID de la section 2 ; jeton enregistré.
- [ ] Mise à jour depuis l'interface : publier `rc.N+1`, l'installer (canal Beta), vérifier la version
      et le journal ; puis un « Roll back » vers l'instantané : le jeton reste tel quel.
- [ ] Test rapide par fonctionnalité :
  - [ ] 1. multi-IP : IP par site, IP d'envoi mail ;
  - [ ] 2. PHP par domaine et php.ini global ;
  - [ ] 3. se connecter en tant qu'utilisateur ;
  - [ ] 4. site en mode nginx + Apache avec un `.htaccess` ;
  - [ ] 5. import HestiaCP d'une archive réelle (voir section 5) ;
  - [ ] 6. ClamAV : installation, scan d'un site, quarantaine ;
  - [ ] 7. FTPS par site, quota disque ; stats web GoAccess (affichage, 404 pour un non-admin, dossier
        supprimé avec le site) ;
  - [ ] 8. stats web : génération horaire ;
  - [ ] 9. terminal utilisateur : session persistante, `sudo` avec mot de passe ;
  - [ ] 10. mises à jour (ci-dessus).
- [ ] Sauvegarde : `/opt/dockpanel/scripts/db-backup.sh` tourne (cron 3 h), un dump est restaurable.
- [ ] Canal de notification configuré (e-mail ou autre) : les alertes ne partent nulle part sinon
      (journal « No notification channels configured » vu en lab).

## 4. Points ouverts à trancher

- [ ] **Agent distant** (bloquant si plusieurs serveurs) : scénarios 7, 8, 10 avec une seconde VM
      Ubuntu 22.04 et le certificat reconnu de la section 1.
- [ ] Shell root (Terminal) refusé à un second administrateur qui ne possède pas la ligne du serveur
      (hérité de DockPanel, `auth.rs`) : corriger ou accepter et documenter.
- [ ] Tri de la quarantaine de tests shell qui échouaient déjà avant la fonctionnalité 10 : chacun
      classé « faux positif Windows/lab » ou « vrai défaut ».
- [ ] Revue de sécurité de la surface héritée (l'agent tourne en root) : ports exposés, pare-feu,
      fail2ban/limitation des connexions, accès SSH, mots de passe par défaut éventuels.

## 5. Migration depuis HestiaCP

- [ ] Inventaire : utilisateurs, domaines web, bases, boîtes et alias mail, zones DNS, tâches cron,
      certificats, comptes FTP.
- [ ] Sauvegarde complète HestiaCP (`v-backup-users` ou équivalent) copiée **hors du serveur**, et
      vérification qu'une archive se lit.
- [ ] TTL des enregistrements DNS concernés abaissés (300 s) au moins 48 h avant la bascule.
- [ ] Site pilote non critique : import, puis contrôle site, base, SSL, FTP, cron ; bascule DNS ;
      quelques jours d'observation.
- [ ] Mail pilote : envoi et réception, SPF, DKIM, DMARC, rDNS de l'IP d'envoi, absence de blacklist.
- [ ] Puis les autres sites par lots, du moins au plus critique, avec la même vérification.
- [ ] HestiaCP gardé intact (ou son serveur conservé) N jours après la dernière bascule : `N = ____`.

## 6. Bascule (go / no-go)

Go seulement si :
- [ ] sections 1, 2 et 3 entièrement cochées, et 4 tranchée ;
- [ ] site et mail pilotes stables depuis au moins quelques jours ;
- [ ] sauvegarde HestiaCP hors serveur vérifiée ;
- [ ] instantané (ou sauvegarde) du nouveau serveur juste avant.

## 7. Retour arrière

- Avant la bascule DNS d'un site : rien à défaire, HestiaCP sert toujours.
- Après : remettre les enregistrements DNS vers HestiaCP (TTL bas = effet en quelques minutes) ; le
  mail reçu entre-temps sur le nouveau serveur doit être récupéré (noter la méthode retenue).
- Mise à jour du panel ratée : retour automatique, puis « Roll back » d'un instantané depuis
  Telemetry, Updates.

## 8. Après la mise en production

- [ ] Canal de mise à jour « Stable » ; les pre-releases restent pour la VM de recette.
- [ ] Sauvegardes du panel et des sites copiées hors serveur, restauration testée une fois.
- [ ] Rappels : expiration du jeton GitHub, renouvellement des certificats, mises à jour Ubuntu.
- [ ] Procédure de release écrite (clé, `release.sh`, test sur la VM de recette avant le canal Stable).
