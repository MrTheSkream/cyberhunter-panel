# 14. Certificats `mail.<domaine>` présentés par SNI, et port 465

Branche : `feat/mail-sni-certs`, partie de `main`. Domaines de test : `.example.test` uniquement.

## 1. Constats (code de `main`, rc.4)

- Postfix (`smtpd_tls_cert_file`) et Dovecot (`ssl_cert`) ne présentent qu'un seul certificat : celui du panel,
  dans `/etc/letsencrypt/live/<hôte du panel>/`, posé par `mail_install` via `panel_tls_paths()`
  (`agent/src/routes/mail.rs:652` et `:693`). Il n'y a aucun SNI. Un client configuré sur `mail.<d>`
  (c'est le cas de tous les clients venus de Hestia) reçoit donc un certificat dont le nom ne correspond pas.
- Le port 465 est ouvert dans le pare-feu (`MAIL_PORTS`), mais `master.cf` ne déclare que `submission` (587).
  Le test `starts_with("submission")` (`:666`) reconnaîtrait aussi une entrée `submissions`. Il faut le rendre exact.
- `provision_mail_host_cert` (backend `routes/mail.rs:1413`) émet un certificat pour **l'apex**, par
  `/ssl/provision/{domain}`. Cette route réécrit toujours un vhost nginx, et l'appel se fait **sans** `issuance_lock`.
  Rien ne renouvelle ce certificat sans une ligne `sites` du même nom.
- `mail_domains` n'a aucune colonne de certificat.
- L'archive Hestia contient `mail/<d>/conf/ssl/<d>.{crt,key,ca}`. Le certificat couvre `mail.<d>` et `webmail.<d>`
  (vérifié sur l'archive du labo : SAN = mail.<d>, webmail.<d>, émetteur Let's Encrypt). L'import ne le lit pas.
- L'émission ACME de l'agent (`ssl::order_http01`) sait commander un nom sans vhost. Le vhost par défaut
  `:80` (`services/default_vhost.rs`) sert `/.well-known/acme-challenge/` pour tout hôte inconnu.
- `helpers::dns_gate_for(pool, server_id, domain)` décide déjà si un nom pointe ici, pour les renouvellements de sites.
- Le renouvellement des sites (`auto_healer::auto_renew_ssl`) n'a lieu que si l'auto-heal est activé.

## 2. Décisions

**D1. Nom couvert.** Un certificat par domaine mail, pour `mail.<d>` seul. `webmail.<d>` est hors périmètre
(voir Q2). Le certificat du panel reste le certificat **par défaut** : il est présenté sans SNI ou pour un nom inconnu.

**D2. Stockage, sans collision avec les sites.** Les fichiers vont dans `/etc/dockpanel/mail-tls/mail.<d>/{fullchain.pem,privkey.pem}`
(clé en 0600 root ; le chemin est couvert par `ReadWritePaths=/etc/dockpanel`). Pas dans `/etc/dockpanel/ssl/` :
ce répertoire est indexé par nom de site, et les routes SSL le listent et le suppriment.

**D3. Émission, côté agent.** Nouvelle route `POST /mail/tls/issue { domain, email }` :
- elle appelle `ssl::order_http01` pour `mail.<d>` ;
- elle ne touche à **aucun** vhost ;
- elle tient `site_lock` sur la clé `mail.<d>`.

En cas de succès, elle reconstruit la configuration SNI (D6). La réponse contient `expiry`.
Pour l'import (D8), la route est `POST /mail/hestia/import-host-cert` (section 6).

**D4. État en base.** Migration sur `mail_domains` :
- `host_cert_status TEXT NOT NULL DEFAULT 'none'`, parmi `none`, `pending_dns`, `active`, `imported`, `failed` ;
- `host_cert_expiry TIMESTAMPTZ` ;
- `host_cert_checked_at TIMESTAMPTZ` ;
- `host_cert_error TEXT` (message court, sans secret).

**D5. Verrou.** Côté backend, `issuance_lock::begin(mail_domain.id, …)` : l'id du domaine mail sert de clé, dans le même espace
d'UUID que les sites, sans collision. Côté agent, `site_lock("mail.<d>")`.

Correctif au passage : `provision_mail_host_cert` (apex) prend aussi `issuance_lock` sur l'id du site du même nom
quand il en existe un.

**D6. Présentation par SNI.** Reconstruite depuis le disque à chaque `POST /mail/sync`, après chaque émission ou installation,
et au démarrage de l'agent (soin pour les installations existantes). Seuls les domaines **actifs** de la liste de sync,
dont le certificat sur disque est lisible, non expiré et couvre `mail.<d>`, sont présentés.

- **Postfix**
  - Fichier `/etc/postfix/tls_server_sni` : une ligne `mail.<d> <privkey> <fullchain>` par domaine.
  - `postmap -F hash:/etc/postfix/tls_server_sni`. Le `.db` **embarque les clés** : il est en 0600 root. Il embarque aussi
    le contenu des fichiers, donc chaque renouvellement relance `postmap`.
  - `postconf tls_server_sni_maps=hash:/etc/postfix/tls_server_sni` (Postfix 3.4 et plus).
  - Liste vide : le paramètre est retiré.
  - Ce réglage vaut pour 25, 587 et 465.
- **Dovecot** : `/etc/dovecot/conf.d/99-dockpanel-sni.conf`, avec un bloc par domaine :
  - Dovecot 2.3 : `local_name mail.<d> { ssl_cert = <… ; ssl_key = <… }` ;
  - Dovecot 2.4 : `local_name mail.<d> { ssl_server_cert_file = … ; ssl_server_key_file = … }`.
- **Sûreté**
  - Avant le rechargement : `postfix check` et `doveconf -n`. En cas d'échec, les fichiers précédents sont restaurés
    (même schéma que `apply_ip_transports`), l'erreur est journalisée et remontée, et le courrier n'est pas coupé.
  - Le rechargement n'a lieu que si le contenu a changé.

**D7. Port 465.**
- Un bloc `submissions inet n - y - - smtpd` est ajouté à `master.cf`, avec les options suivantes :
  - `syslog_name=postfix/submissions` ;
  - `smtpd_tls_wrappermode=yes` ;
  - `smtpd_sasl_auth_enable=yes` ;
  - `smtpd_recipient_restrictions=permit_sasl_authenticated,reject`.
- Ce bloc est identique à 587, au mode TLS près. La liaison expéditeur et identifiant (`smtpd_sender_restrictions`)
  et les limites de débit sont globales dans `main.cf` : 465 en hérite, sans contournement.
- Il est posé à l'installation et par le soin au démarrage, si aucune entrée **active** dont le premier jeton est exactement
  `submissions` (ou `465`) n'existe.
- Le test 587 devient lui aussi exact sur le jeton.
- Si `/etc/services` ne connaît pas `submissions`, le bloc commence par `465`. La validation passe par `postfix check`,
  avec retour arrière.

**D8. Import Hestia.**
- L'agent lit `mail/<d>/conf/ssl/<d>.{crt,ca,key}` dans le staging, **par référence**. La clé ne transite ni par le backend,
  ni par `inventory`, `result` ou SSE (même règle que D5 du chantier 05).
- Si le certificat couvre `mail.<d>` et n'est pas expiré, il est installé dans `/etc/dockpanel/mail-tls/mail.<d>/`
  (fullchain = crt + ca), avec l'état `imported` et son expiration. Il est présenté par SNI **dès l'import**, sans aucune
  commande ACME.
- Sinon, l'état passe à `pending_dns`.
- Dans les deux cas, le renouvellement (D9) prend le relais avec Let's Encrypt une fois que `mail.<d>` pointe ici.
- **Amendement de 05** : D5 et la ligne de test 135 (« aucun certificat `mail.<d>` créé ») deviennent « aucune commande ACME
  à l'import ; le certificat `mail.<d>` de l'archive est installé s'il est valide ».

**D9. Émission et renouvellement automatiques.** Nouvelle étape `auto_renew_mail_host_certs` dans la boucle de l'auto-healer,
**soumise au même interrupteur auto-heal que les sites**. Elle traite tout domaine mail actif dans l'un de ces cas :
- état `none` ou `pending_dns`, ou `failed` dont le dernier essai date de plus de 6 h ;
- état `active` ou `imported` dont l'expiration est à moins de 30 jours.

Pour chacun :
- elle applique `dns_gate_for(server, "mail.<d>")`. Si le nom ne pointe pas ici, l'état passe à `pending_dns`,
  sans commande ACME, ce qui ménage les limites d'échec de Let's Encrypt ;
- sinon, elle prend le verrou D5 et appelle `/mail/tls/issue`. Le résultat est inscrit en base, et une alerte dédoublonnée
  (`ssl_renewal_failure`) est levée sur échec ;
- vérification au plus une fois par heure et par domaine (`host_cert_checked_at`).

Ce mécanisme couvre aussi, sans action, **les serveurs déjà importés en rc.4**, dont l'archive a pu disparaître.
La création manuelle d'un domaine mail passe aussi par là : aucun appel de plus dans `create_domain`.

**D10. Suppression ou désactivation.** Domaine supprimé : les fichiers `mail-tls/mail.<d>` sont supprimés, et le SNI est reconstruit
(au sync qui suit). Domaine désactivé : le certificat est retiré du SNI, les fichiers sont gardés, aucun renouvellement n'a lieu.

**D11. Interface (libellés en anglais).** Dans la liste et la fiche des domaines mail :
- badge `mail.<d>` : `Active until <date>`, `Imported, until <date>`, `Waiting for DNS`, `Failed: <message>` ;
- bouton `Retry now`, qui force D9 pour ce domaine.

## 3. Tests

- **Rust (purs)**
  - Rendu de la table SNI Postfix et du drop-in Dovecot 2.3 et 2.4. La branche 2.4 est couverte **par ces tests seulement** :
    la VM tourne en 2.3.
  - Détection exacte de `submission` et `submissions`.
  - Ajout idempotent du bloc 465.
  - Sélection des certificats présentables : expiré, mauvais nom, fichiers manquants.
  - Choix des domaines à traiter en D9.
  - Lecture du certificat Hestia.
- **Pins** : les épingles existantes restent vertes, et une épingle par fichier de configuration généré est ajoutée.
- **Recette en VM**
  - Partir d'un snapshot **rc.4 avec le mail installé et un domaine Hestia importé**, puis mettre à jour, pour exercer le soin.
  - Utiliser Pebble derrière un proxy nginx, et des domaines `*.example.test`.
  - Pour chaque port :
    - `openssl s_client -connect <ip>:993 -servername mail.a.example.test` ;
    - `-starttls smtp` sur 587 ;
    - direct sur 465.
  - Attendu : sujet `mail.a.example.test`, chaîne valide.
  - Sans SNI ou avec un nom inconnu : le certificat du panel.
  - Un second domaine mail obtient son propre certificat.
  - Renouvellement forcé : le numéro de série change sur les 3 ports.
  - Un drop-in volontairement cassé : retour arrière, et le courrier continue.
  - AUTH et envoi réels sur 465, et refus d'un expéditeur non lié.

## 4. Questions ouvertes

- **Q1.** Le panel doit-il publier `A mail.<d>` dans le DNS automatique (`mail_records_for`) ? Aujourd'hui, la topologie
  conseillée est l'apex (MX vers `<d>`). Recommandation : non dans ce lot (cela change le contrôle des prérequis de tous les domaines).
- **Q2.** Ajouter `webmail.<d>` au certificat, comme Hestia le faisait ? Recommandation : plus tard, avec le webmail par domaine.
- **Q3.** Présenter aussi l'apex `<d>` par SNI quand son certificat existe ? Recommandation : non dans ce lot.

## 5. Décisions validées (2026-11-20)

- Q1 : non, pas de `A mail.<d>` dans ce lot.
- Import : amendement de 05 validé (le certificat de l'archive est installé, aucune commande ACME).
- Renouvellement : même interrupteur auto-heal que les sites.

## 6. Contrats entre agent, backend et interface

**Agent** (`panel/agent`)
- `POST /mail/tls/issue` `{ "domain": "<d>", "email": "<acme>" }`
  - Succès, 200 : `{ "ok": true, "host": "mail.<d>", "expiry": "<RFC 3339>" }`.
  - Échec : statut 4xx ou 5xx, `{ "error": "<message court>", "code": "<code>" }`.
  - `code` vaut `invalid_domain`, `acme_failed` ou `sni_apply_failed`. Avec `sni_apply_failed`, le certificat a bien
    été émis, mais la configuration a été restaurée.
- `POST /mail/hestia/import-host-cert` `{ "migration_id": "...", "domain": "<d>" }` (même forme que `HestiaDomainRequest`)
  - Réponse, 200 : `{ "installed": bool, "expiry": "<RFC 3339>"|null, "reason": "<missing|expired|wrong_name|unreadable>"|null }`.
- `POST /mail/domains/remove` (existant) : supprime aussi `/etc/dockpanel/mail-tls/mail.<d>/` et reconstruit le SNI.
- `POST /mail/sync` (existant) : reconstruit le SNI depuis `virtual_domains`, croisé avec les certificats présents sur disque.
  Ajout dans la réponse : `"host_tls": { "presented": [..hosts], "error": null|"..." }`.
- Au démarrage : `heal_mail_tls()` pose 465 si absent et reconstruit le SNI, seulement si le mail est installé.
- Source de vérité du SNI : le fichier `virtual_domains`, qui ne contient que les domaines actifs, croisé avec les
  certificats valides présents sur disque.

**Backend** (`panel/backend`)
- Migration : les 4 colonnes `host_cert_*` de D4, avec une contrainte CHECK sur le vocabulaire de `host_cert_status`.
- `GET` sur les domaines mail (liste et fiche) : expose `host_cert_status`, `host_cert_expiry`, `host_cert_error`.
- `POST /api/mail/domains/{id}/host-cert/retry` : mêmes droits que les autres écritures sur le domaine. Lance D9 tout de suite
  pour ce domaine, en ignorant le délai entre deux essais mais **pas** le contrôle DNS. Renvoie
  `{ host_cert_status, host_cert_expiry, host_cert_error }`.

## 7. Écarts d'implémentation

- **Port 465.**
  - Une entrée `smtps` ou `hôte:465` active compte comme déjà présente.
  - Une entrée active est en colonne 0, avec un premier jeton exact et `inet` en deuxième.
  - Si `postfix check` refuse le bloc à l'installation, seul 587 est gardé.
- **Fichiers.**
  - Une clé qui ne correspond pas à son certificat est classée `unreadable`.
  - Sans aucun nom à présenter, la table, le `.db` et le drop-in sont supprimés.
  - `mail_uninstall` ne supprime pas `/etc/dockpanel/mail-tls`.
- **Réglage administrateur.** Une valeur `tls_server_sni_maps` posée par l'administrateur est gardée tant que rien n'est à présenter.
- **Alerte d'échec.**
  - Sa clé est `ssl_renewal_failure` / `mail_host_failed:<id du domaine mail>`.
  - Elle n'est résolue que par un succès ultérieur.
  - Elle reste active si le domaine est supprimé ou passe en `pending_dns`.
- **Erreurs de transport et expiration illisible.**
  - Une erreur de transport vers l'agent ne passe pas l'état à `failed`.
  - Une expiration illisible est revérifiée une fois par jour.
- **Retry.**
  - `Retry now` force aussi la réémission d'un certificat valide. L'interface masque alors le bouton.
  - Le bouton n'est visible que pour les admins, qui sont les seuls à avoir les droits d'écriture sur un domaine mail.
- **Import.**
  - Un domaine déjà `active` n'est pas remplacé à la réimportation.
  - Une réimportation dans une nouvelle migration est refusée (`exists_not_ours`), comme avant.
- **`provision_mail_host_cert` (apex).** La clôture du verrou vaut « déjà émis » seulement si le site n'était pas en TLS avant l'attente.
- **Migration.** Elle est numérotée `20261130000200`, car `20261130000000` était déjà prise sur `main`. Sans ce changement, l'API refusait de démarrer (vu en VM). L'épingle g6 vérifie désormais l'unicité des versions.

## 8. Recette (2026-11-20, VM Ubuntu 24.04 : Postfix 3.8.6, Dovecot 2.3.21, CA Pebble derrière nginx)

**Scénario 1 : rc.4 avec le mail installé, et domaines `a` et `b.example.test` importés en rc.4, puis mise à jour vers la branche.**
- Soin au démarrage : 465 écoute, le bloc `submissions` est posé.
- Les deux domaines sont à `none`. Le contrôle DNS donne `pending_dns` tant que l'IP de la VM n'est pas déclarée dans les IP du serveur.
- `Retry now` émet le certificat de `mail.a`. L'auto-heal, une fois activé, émet celui de `mail.b` en environ 80 s.
- `openssl s_client`, sur 993, 587 (`-starttls smtp`) et 465 :
  - avec SNI `mail.a.example.test` : bon certificat, code de vérification 0 ;
  - sans SNI ou avec un nom inconnu : certificat par défaut.
- Renouvellement forcé : le numéro de série change sur les 3 ports.
- Drop-in Dovecot cassé :
  - `sni_apply_failed`, et les fichiers SNI sont restaurés (md5 identiques) ;
  - Postfix et Dovecot restent actifs ;
  - après correction, `Retry now` rétablit l'état `active`.
- Port 465 :
  - AUTH et envoi depuis l'adresse liée : message remis ;
  - expéditeur non lié : 553 ;
  - envoi sans AUTH : 554.

**Scénario 2 : installation neuve avec la branche, puis import Hestia.**
- `mail_install` pose 465.
- Le certificat `mail.a` de l'archive passe à `imported` et il est présenté tout de suite sur les 3 ports. Aucune commande ACME n'a lieu à l'import.
- `b`, sans certificat dans l'archive, passe à `pending_dns`, puis l'auto-heal le fait passer à `active`.
- `.db` et table SNI : 0600 root.
- Désactiver `b` le retire du SNI et garde ses fichiers ; le réactiver le remet.
- Supprimer `a` supprime son dossier et sa ligne SNI.
- Archive avec un certificat valable 10 jours : `imported`, puis l'auto-heal le remplace par Let's Encrypt (Pebble) en environ 40 s, sur les 3 ports.

**Non vérifié en VM**
- Le badge et le bouton dans le navigateur.
- Le repli sur un certificat Let's Encrypt du panel (le serveur de test n'en a pas : c'est le snakeoil qui est servi).
- Dovecot 2.4 (tests unitaires seulement).

**À savoir.** L'auto-heal est désactivé par défaut (`auto_heal_enabled = false`, migration `20260314000001`). Sans lui, rien n'est émis ni renouvelé automatiquement : il reste `Retry now`.
