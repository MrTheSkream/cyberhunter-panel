# Terminal utilisateur : Claude Code dans le navigateur (validée le 2026-11-16)

Objectif : depuis n'importe quel navigateur, ouvrir un shell en tant qu'utilisateur Linux non root (par
exemple `bastien`), rattaché à une session tmux persistante où tourne `claude`. Fermer l'onglet, changer
d'appareil ou perdre le WebSocket ne coupe pas la session : on la retrouve à la reconnexion.

Hors périmètre :
- les portées des clés d'API ;
- le shell root `@server` et les shells de site, qui restent inchangés (voir §9) ;
- le retrait de Guacamole et de XFCE.

## 1. Constat (code actuel)
- **Ticket** (`backend/src/routes/terminal.rs:100`, `GET /api/terminal/token`) :
  - JWT HS256 signé avec le jeton de l'agent, valable 60 s, réutilisable jusqu'à expiration (pas de
    `jti`) ;
  - claims : `sub`, `purpose:"terminal"`, `exp`, `record`, `scope` (`@server` ou domaine du site) ;
  - contrôles, dans l'ordre : verrouillage (`terminals_locked_down`), serveur local seulement, admin pour
    `@server`, interrupteur `server_terminal_disabled`, propriété du site ;
  - **aucun contrôle de clé `dp_` ni de double authentification**, aucune entrée d'audit.
- **Chemin du WebSocket** : le navigateur parle directement à l'agent par nginx
  (`/agent/terminal/ws?token=…` → `agent.sock:/terminal/ws`). Le backend n'est pas sur le chemin. Aucune
  vérification d'`Origin`, ni dans l'agent ni dans nginx.
- **Agent** (`agent/src/routes/terminal.rs`) :
  - `open_pty_shell` fait un `fork` direct. Le shell hérite donc de l'espace de noms de l'agent
    (`ProtectHome=yes`, `ProtectSystem=strict`, `PrivateTmp=yes`). Il hérite aussi de
    **`NoNewPrivileges=yes`** posé par l'unité : `sudo` ne peut pas marcher dans un shell lancé ainsi,
    même sans le `prctl`.
  - Les sorties partent en trames texte via `from_utf8_lossy` sur chaque lecture. Un caractère
    multi-octets (emoji, accent) coupé entre deux lectures est corrompu.
  - Limite dure de 30 min par session, 20 sessions au plus, une connexion par seconde.
  - Le « panic » (`POST /security/kill-terminals`) tue le pid direct de chaque shell et lance
    `pkill -u www-data -f bash`.
- **Session navigateur** : les claims ne disent pas comment la session a été ouverte (mot de passe seul,
  TOTP ou passkey). `key_id` n'est renseigné que pour une clé `dp_`.
- **Correspondance de comptes** : rien ne relie un compte panel à un utilisateur Linux. Il n'y a aucun
  usage de tmux, de `loginctl` ou d'unités `systemd --user`.
- **Interface** :
  - xterm.js 6 avec les seules extensions fit et search (ni unicode11, ni webgl, ni clipboard) ;
  - pas de gestion d'OSC 52 ;
  - toutes les pages sont dans le layout, aucune page plein écran.

## 2. Lancer le shell hors de l'espace de noms de l'agent
### Choix : unité systemd transitoire via `systemd-run --pty --uid=<login>`
L'agent ouvre son pty comme aujourd'hui. Le processus fils exécute ensuite, sans abandon de privilèges :
```
systemd-run --quiet --collect --pty --uid=<login> \
  --unit=dockpanel-uterm-<login>-<8 hex> --slice=dockpanel-uterm.slice \
  --working-directory=<home> \
  --setenv=HOME=<home> --setenv=USER=<login> --setenv=LOGNAME=<login> --setenv=SHELL=<shell> \
  --setenv=XDG_RUNTIME_DIR=/run/user/<uid> --setenv=TERM=xterm-256color --setenv=COLORTERM=truecolor \
  --setenv=LANG=C.UTF-8 --setenv=PATH=/usr/local/bin:/usr/bin:/bin \
  -- /etc/dockpanel/bin/uterm-attach
```
- **Pourquoi ça marche** :
  - l'unité est créée par PID 1, donc hors de l'espace de noms de l'agent : elle voit le vrai `/home` ;
  - elle n'hérite pas de `NoNewPrivileges`, donc `sudo` fonctionne ;
  - `systemd-run --pty` relaie le pty de l'unité vers le sien. Le redimensionnement passe tout seul :
    quand l'agent règle la taille de son pty, `systemd-run` reçoit `SIGWINCH` et la recopie.
  - Le pty de l'unité est désigné par son chemin (`TTYPath`), sans passage de descripteur par D-Bus. Le
    problème RHEL connu de `safe_command_unsandboxed` (refus SELinux de `file_receive`) ne se pose pas.
- **Le bac à sable de l'agent n'est pas affaibli** : seul `-/etc/systemd/user` est ajouté à
  `ReadWritePaths` pour l'unité tmux (§3). `ProtectHome=yes` reste.
- **Pas de démon supplémentaire** : `systemd-run` est déjà utilisé par l'agent et présent partout.
- **Échappement** : systemd développe les `$` des arguments de `ExecStart`. Les arguments sont donc
  échappés (`$` en `$$`), comme le fait déjà `safe_command_unsandboxed`.

### Pistes écartées
- **`machinectl shell user@`** : il demande le paquet `systemd-container` et ouvre une session de
  connexion PAM complète. On contrôle moins bien le nom de l'unité, l'arrêt par le panic et
  l'environnement. C'est une couche de plus sans rien gagner sur la piste retenue.
- **API D-Bus `StartTransientUnit` directe** : même résultat que `systemd-run`, mais il faudrait ajouter
  zbus et réécrire le relais du pty, que `systemd-run --pty` fournit déjà.
- **Service compagnon par utilisateur avec un socket Unix** : un démon de plus par utilisateur et un
  protocole pty à écrire et à sécuriser. Le socket devrait en plus être visible depuis l'agent, donc
  hors de `/home`.
- **ttyd** : il ferait double emploi avec xterm.js et le WebSocket de l'agent, et ouvrirait un serveur de
  plus. **Pas de ttyd.**

## 3. Persistance : tmux dans le gestionnaire utilisateur (`systemd --user`, linger)
- **Linger** : `loginctl enable-linger <login>`, posé quand l'admin enregistre la correspondance (§5).
  `user@<uid>.service` tourne alors en permanence, même sans connexion, et redémarre au boot.
- **Unité utilisateur** `/etc/systemd/user/dockpanel-tmux.service` :
  - commune à tous, mais activée seulement pour les utilisateurs liés à un compte du panel
    (`systemctl --user -M <login>@ enable`) ;
  - grâce à cette activation, la session est recréée au démarrage du serveur.
  ```
  [Unit]
  Description=DockPanel persistent tmux session
  [Service]
  Type=forking
  ExecStart=/usr/bin/tmux -f /etc/dockpanel/tmux.conf -S %t/dockpanel-tmux.sock new-session -d -s claude -c %h
  ExecStartPost=/etc/dockpanel/bin/uterm-autostart
  ExecStop=/usr/bin/tmux -S %t/dockpanel-tmux.sock kill-server
  Restart=on-failure
  [Install]
  WantedBy=default.target
  ```
  - **Démarrage** : la fenêtre ouvre le shell de connexion de l'utilisateur.
  - **Commande de démarrage** : `uterm-autostart` tape la commande réglée dans la correspondance (par
    défaut `claude`) avec `tmux send-keys`. Si `claude` se termine, on retombe sur le shell et la session
    tmux reste ouverte.
- **Script `uterm-attach`**, lancé dans l'unité transitoire :
  ```
  systemctl --user start dockpanel-tmux.service   # démarre la session si elle n'existe pas
  exec tmux -S "$XDG_RUNTIME_DIR/dockpanel-tmux.sock" attach -t claude
  ```
- **Ce qui se passe à la coupure** :
  - le WebSocket tombe ou l'agent redémarre : le client `systemd-run` meurt et le pty de l'unité
    raccroche. `tmux attach` se termine et l'unité transitoire est nettoyée (`--collect`).
  - **Le serveur tmux, `claude` et tout ce qui tourne dans la session continuent.** Ils vivent dans
    `user@<uid>.service`, pas dans l'unité de la connexion.
  - « Détacher » tmux (préfixe puis `d`) ferme proprement la connexion web.
- **Plusieurs appareils en même temps** : ils voient la même session, et la taille suit le dernier actif
  (`window-size latest`).
- **`/etc/dockpanel/tmux.conf`** charge ensuite `~/.tmux.conf` pour les réglages personnels
  (`source-file -q`) :
  ```
  set -g default-terminal "tmux-256color"
  set -as terminal-features ",xterm-256color:RGB:clipboard:usstyle"
  set -g set-clipboard on        # copie de tmux → OSC 52 → presse-papiers du navigateur
  set -g mouse on
  set -g window-size latest
  set -g history-limit 50000
  set -g escape-time 10
  set -g focus-events on
  ```

## 4. Sécurité
### 4.1 Qui peut ouvrir un terminal utilisateur
Nouvelle route `GET /api/terminal/user/token`. La route existante n'est pas modifiée.

Contrôles, dans l'ordre (toute réponse négative est journalisée, §4.5) :
1. **Verrouillage d'urgence** (`terminals_locked_down`) : 503, comme aujourd'hui.
2. **Interrupteur** `user_terminal_disabled = "true"` : 403 `"User terminal is disabled"`.
3. **Serveur local seulement** (`require_local_agent_scope`).
4. **Session navigateur obligatoire** :
   - `key_id` présent (clé `dp_`) : 403 ;
   - pas de cookie de session : 403 ;
   - session d'emprunt d'identité (`imp_by`) : 403.

   Une clé `dp_` volée, même celle du compte admin de Claude, ne peut donc jamais obtenir de ticket.
5. **Rôle `admin`** au moment de la demande, relu en base et pas seulement dans le JWT : sinon 403.
6. **Double authentification prouvée dans cette session** : nouveau claim de session `amr`.
   - **Où il est posé** : `issue_session_pub` reçoit la méthode. `"mfa"` après `/auth/2fa/verify`, après
     une connexion par passkey, ou après le renouvellement d'une session qui l'avait déjà. Sinon `"pwd"`.
   - **Sans `amr: "mfa"`** : 403 avec le code `mfa_required`, et l'interface demande de se reconnecter
     avec la double authentification.
   - **Sessions déjà ouvertes** : elles n'ont pas ce claim, il faudra se reconnecter une fois.
7. **Correspondance** : le compte doit avoir une correspondance active (§5), sinon 404
   `"No Linux account is linked to your panel account"`.
   - Le login Linux vient **uniquement de la base**. La requête n'a aucun paramètre d'utilisateur.

### 4.2 Le ticket
- **Claims** : `scope: "@user:<login>"`, `uid`, `record` (réglage de la correspondance, faux par défaut)
  et un `jti` aléatoire. Validité 60 s.
- **Usage unique** : l'agent garde les `jti` déjà vus jusqu'à leur expiration et refuse un second usage.
- **Agent ancien** : le scope `@user:…` y tomberait dans la branche site, où `/var/www/@user:…` n'existe
  pas, donc refus. Il n'y a rien à protéger de plus côté ancien agent.

### 4.3 Contrôles de l'agent avant chaque ouverture
Fonction pure `validate_login(passwd_entry, shells, groups)`, testée unitairement. Refus si :
- `uid` vaut 0, ou est inférieur à 1000, ou vaut au moins 60000 (`nobody` et les plages système hautes) ;
- l'`uid` diffère de celui du ticket ;
- le compte appartient au groupe `sftp_sites` (les comptes de site créés par le panel) ;
- le shell n'est pas dans `/etc/shells`, ou se termine par `nologin` ou `false` ;
- le dossier personnel est absent.

Le même contrôle sert à la vérification lors de l'enregistrement de la correspondance (§5).

### 4.4 Interrupteurs, verrouillage et panic
- **Interrupteur dédié** « User terminal » dans Settings → Account → Security Hardening, à côté de
  « Server terminal » (même modèle de réglage inversé, `user_terminal_disabled`). Le désactiver coupe
  aussi les connexions en cours.
- **Verrouillage d'urgence** :
  - refuse les nouveaux tickets (§4.1, point 1) ;
  - **coupe les connexions en cours** : à l'activation, le backend appelle la nouvelle route agent
    `POST /terminal/user/kill { "stop_sessions": false }`, qui arrête les unités `dockpanel-uterm-*` ;
  - **la session tmux et `claude` continuent**, mais personne ne peut s'y rattacher tant que le
    verrouillage est actif.
- **Panic** :
  - fait tout ce qui précède avec `stop_sessions: true` : arrêt des unités de connexion, puis de
    `dockpanel-tmux.service` de chaque utilisateur correspondant (`systemctl --user -M <login>@ stop`) ;
  - **cela tue `claude` et tout ce qui tourne dans la session** ;
  - l'agent garde la liste des logins concernés dans `/var/lib/dockpanel/user-terminals.json` ;
  - le résultat du panic ajoute `user_terminals_killed`.
- **Arrêt par unité systemd** : il tue tout le groupe de processus (cgroup), contrairement au kill du pid
  direct utilisé pour les autres shells.
- **Durée** : la limite dure de 30 min ne s'applique pas à ce terminal. Elle est remplacée par 12 h par
  connexion. La reconnexion est automatique et la session tmux survit.

### 4.5 Journal d'audit
- **Backend** (`security_audit_log`, auteur et IP), pour chaque demande de ticket :
  - `user_terminal.ticket` en succès ;
  - `user_terminal.denied` en refus, avec la raison.
- **Agent** (journal d'audit existant `/var/lib/dockpanel/audit/`), avec l'auteur (`sub`), l'IP
  (`X-Real-IP`) et le login :
  - `user_terminal.session_created` quand la connexion démarre la session tmux ;
  - `user_terminal.attach` à chaque rattachement à une session existante ;
  - `user_terminal.detach` à la fermeture, avec la durée et la cause : fermeture, coupure, panic,
    verrouillage, limite de 12 h.
- **Consultation** : les événements de l'agent remontent dans Security → Audit par une route de lecture
  du backend.
- **Enregistrement asciicast** : désactivé par défaut, réglable par correspondance. Le réglage global
  « Session recording » ne s'applique pas, car Claude affiche du code et des secrets.
- **`observe_input` n'est pas appliqué**, ni en blocage ni en observation :
  - dans tmux et `claude`, la reconstruction de lignes à partir des touches n'a pas de sens : invite de
    Claude, éditeurs, mode copie ;
  - elle écrirait les invites, et donc des secrets, dans `suspicious-events.jsonl`.

### 4.6 `NO_NEW_PRIVS` désactivé : `sudo` disponible
- **Choix** : l'unité transitoire ne pose pas `NoNewPrivileges`, donc `sudo` marche.
- **Garde-fou** : `sudo` demande toujours le mot de passe Linux de l'utilisateur, qui n'est jamais stocké
  par le panel. Une session panel volée ne donne donc pas root à elle seule.
- **Limite à connaître** : si l'utilisateur a une règle `NOPASSWD` dans sudoers, une session panel avec
  double authentification suffit pour être root.
  - La vérification de la correspondance (§5) affiche un avertissement si `sudo -l -n` réussit sans mot
    de passe.
  - Le test d'acceptation `sudo -n true` doit échouer.

### 4.7 Exposition réseau
- **Aucun nouveau port** : même chemin `/agent/terminal/ws` derrière le domaine HTTPS du panel.
- **Vérification d'`Origin`**, pour le scope `@user` seulement : l'hôte de l'`Origin` doit être celui de
  l'en-tête `Host` transmis par nginx, sinon 403. Les autres scopes restent inchangés (§9).
- **Ticket** : il s'obtient avec le cookie de session (même origine), et le WebSocket le reçoit en
  paramètre.

## 5. Correspondance compte panel ↔ utilisateur Linux
- **Table**
  ```sql
  CREATE TABLE user_linux_accounts (
    user_id uuid PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    linux_user text NOT NULL UNIQUE,
    uid integer NOT NULL CHECK (uid >= 1000 AND uid < 60000),
    autostart_command text NULL DEFAULT 'claude',
    record boolean NOT NULL DEFAULT false,
    created_by uuid NULL REFERENCES users(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now());
  ```
- **Réglée par un admin** dans Settings → Account → « User terminal », qui affiche la liste des comptes
  admin.
- **Enregistrement** :
  - seul un compte de rôle `admin` peut recevoir une correspondance ;
  - l'enregistrement demande une preuve récente (mot de passe ou code TOTP, `require_enrolment_proof`) ;
  - l'agent vérifie le login (§4.3) et l'enregistrement échoue si la vérification échoue ;
  - l'agent prépare ensuite le compte, de façon idempotente : linger, unité tmux activée pour ce login,
    `tmux.conf` et scripts présents ;
  - l'opération est journalisée.
- **Bouton « Check »** : il affiche l'uid, le dossier personnel, le shell, l'état du linger et de la
  session tmux, et l'avertissement `NOPASSWD` éventuel.
- **Si le compte perd son rôle admin** : la correspondance reste en base mais n'ouvre plus rien (§4.1,
  point 5).

## 6. Interface
- **Accès** :
  - entrée « My session » sous Terminal dans le menu, visible seulement pour un admin qui a une
    correspondance ;
  - page **plein écran `/terminal/me`**, une URL stable à mettre en favori. Elle est déclarée hors du
    layout, avec sa propre redirection vers `/login` puis le retour à la page.
- **xterm.js** :
  - ajout des extensions `@xterm/addon-unicode11` (largeur des emoji et du CJK), `@xterm/addon-webgl`
    (avec retour au rendu DOM en cas d'échec) et `@xterm/addon-clipboard` ;
  - truecolor natif, `TERM=xterm-256color` et `COLORTERM=truecolor`.
- **Copier** :
  - la sélection dans tmux en mode souris envoie un **OSC 52**, que l'extension clipboard écrit dans le
    presse-papiers du navigateur ;
  - la **lecture** du presse-papiers par OSC 52 est **refusée** : un programme distant ne peut pas lire le
    presse-papiers local ;
  - Maj + glisser donne la sélection native de xterm, et Ctrl+Maj+C la copie ;
  - un bouton « Copy » est aussi présent.
- **Coller** :
  - Ctrl+Maj+V, Ctrl+V, clic droit ou bouton « Paste » ;
  - le texte part en mode paste encadré (bracketed paste), compris par tmux et Claude ;
  - il est découpé en trames de 16 Kio ; l'agent écrit tout, en gérant les écritures partielles.
  - **200 lignes collées arrivent intactes** : c'est un critère d'acceptation.
- **Raccourcis** :
  - Ctrl+C, Ctrl+D, Ctrl+R, Ctrl+L et Ctrl+Z vont au shell, et la page n'en intercepte aucun ;
  - Ctrl+W, Ctrl+T et Ctrl+N sont réservés par les navigateurs et ne peuvent pas être capturés. Une
    fermeture accidentelle ne coûte rien, la session tmux survit.
- **Redimensionnement** :
  - `ResizeObserver` et `visualViewport`, pour le clavier mobile ;
  - un message `resize` seulement si la taille change.
- **Mobile** : barre de touches (Esc, Tab, Ctrl, flèches, préfixe tmux, Paste).
- **Reconnexion** :
  - automatique, sans limite de tentatives (délai croissant jusqu'à 30 s), avec un **nouveau ticket**
    à chaque fois ;
  - bandeau « Reconnecting… » puis « Reattached » ;
  - **pas de délai d'inactivité** côté page.
- **Sorties de l'agent** : décodage UTF-8 qui garde en réserve un caractère coupé entre deux lectures (pour
  ce scope seulement), pour que les emoji ne soient plus corrompus.

## 7. Paquets et installation
- **Paquet** : `tmux` seulement. Pas de ttyd ni de `systemd-container`.
- **`scripts/setup.sh`** (installation neuve, idempotente) :
  - `run "Installing tmux" pkg_install tmux` dans `install_dependencies` ;
  - écriture de `/etc/dockpanel/tmux.conf`, de `/etc/systemd/user/dockpanel-tmux.service` et des scripts
    `/etc/dockpanel/bin/uterm-attach` et `uterm-autostart`, chacun réécrit seulement s'il diffère.
- **Serveurs existants** (la VM, ton VPS après mise à jour) :
  - l'agent pose les mêmes fichiers et installe `tmux` s'il manque, lors de l'enregistrement d'une
    correspondance ;
  - ajout de `-/etc/systemd/user` aux `ReadWritePaths` de l'unité de l'agent, avec la réparation
    `agent_unit.rs` et son test mis à jour ;
  - `/etc/dockpanel` est déjà inscriptible par l'agent. Les scripts y sont placés plutôt que sous
    `/usr/local`, qui est en lecture seule pour l'agent (`ProtectSystem=strict`).
- **Linger** : `loginctl enable-linger <login>` par l'agent, via `safe_command_unsandboxed`.

## 8. Tests
### Unitaires
- **Backend** : fonction pure de décision du ticket. Elle refuse :
  - un non-admin, une clé `dp_`, un emprunt d'identité, une session sans `amr` ;
  - un compte sans correspondance, l'interrupteur coupé, le verrouillage.

  Elle teste aussi :
  - le claim `amr` à chaque chemin de connexion (mot de passe, TOTP, passkey, renouvellement) ;
  - la contrainte `uid` en base ;
  - le contenu du ticket (`scope`, `jti`, `record` faux par défaut).
- **Agent** :
  - `validate_login` refuse root, un uid inférieur à 1000, `nobody`, un shell `nologin`, le groupe
    `sftp_sites` et un uid différent de celui du ticket ;
  - construction de la ligne `systemd-run`, échappement des `$` compris ;
  - `jti` à usage unique ;
  - vérification d'`Origin` ;
  - décodeur UTF-8 avec réserve (emoji coupé après 1, 2 ou 3 octets) ;
  - découpage et écriture des collages longs.

### De bout en bout dans la VM (scripts `tests/*-e2e.sh`, comme les existants)
- **Refus** : clé `dp_`, compte non-admin, admin sans correspondance, correspondance vers `root` ou un uid
  inférieur à 1000, session sans double authentification, ticket rejoué.
- **Verrouillage** : il refuse les nouveaux tickets et coupe la connexion en cours, la session tmux
  survit. Le **panic** tue la connexion **et** la session tmux.
- **Dans le shell** :
  - `id -u` égal à l'uid de l'utilisateur, `ls /home/<user>` et `~/.claude` visibles ;
  - `sudo -n true` échoue proprement avec un code non nul, sans planter le terminal ;
  - `sudo` avec mot de passe réussit.
- **Persistance** :
  - lancer un compteur dans tmux, couper le WebSocket, se reconnecter : le compteur a continué ;
  - même scénario après `systemctl restart dockpanel-agent`.
- **Collage** : 200 lignes envoyées en mode paste encadré arrivent intactes (somme de contrôle dans un
  fichier).
- **Comptes de test** : ces tests demandent dans la VM un compte admin de test avec TOTP, un compte
  non-admin et un utilisateur Linux de test. Je te demanderai l'accord avant de les créer.

## 9. Non-régression du shell root `@server` et des shells de site
- `open_pty_shell` et la route `GET /api/terminal/token` restent **inchangés octet pour octet**.
  - Le nouveau code vit dans de nouveaux fichiers : `routes/user_terminal.rs` côté backend,
    `services/user_terminal.rs` côté agent.
  - La branche ajoutée dans `ws_handler` intercepte seulement les scopes qui commencent par `@user:`.
- **Tests de non-régression** :
  - un test unitaire épingle l'empreinte SHA-256 du corps de `open_pty_shell` et de `ws_token`, relevée
    avant le changement ;
  - un script e2e vérifie dans la VM, pour `@server` : `id -u` = 0, `cd ..` permis, enregistrement selon
    le réglage global, limite de 30 min ;
  - le même script vérifie, pour un site : `www-data`, `bash --restricted`, blocage des commandes et
    `NO_NEW_PRIVS` (`sudo` refusé).

## 10. À vérifier en premier dans la VM
1. `systemd-run --pty --uid=` lancé depuis l'agent (dans son espace de noms) relaie bien le pty et la
   taille de fenêtre, et voit `/home`.
2. `tmux attach` dans l'unité transitoire rejoint bien le serveur tmux de `user@<uid>.service` (socket
   dans `/run/user/<uid>`).
3. OSC 52 de tmux jusqu'au presse-papiers, dans Chrome et dans Firefox. Firefox exige une action de
   l'utilisateur ; la copie suit un relâchement de souris, ce qui devrait suffire.
4. `claude` survit à la coupure du WebSocket et à `systemctl restart dockpanel-agent`.

## 11. Remarques hors périmètre (constatées, non modifiées)
Le ticket des terminaux existants (`@server` et sites) a trois faiblesses :
- il peut être obtenu avec une clé `dp_` ;
- il n'exige pas la double authentification ;
- il est réutilisable pendant 60 s, et le WebSocket ne vérifie pas l'`Origin`.

Tu as demandé que ces terminaux restent strictement identiques, je n'y touche donc pas ici. Les
protections de §4.1 et §4.7 pourront leur être appliquées dans une fonctionnalité séparée.
