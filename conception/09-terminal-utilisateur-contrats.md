# Terminal utilisateur - Contrats d'interface

Référence : `09-terminal-utilisateur.md` (validée).

Prise en charge : Debian et Ubuntu avec systemd ≥ 248 (Ubuntu 24.04 : 255). Ailleurs, `supported:false`
et « Not supported on this server ».

Organisation :
- **Trois chantiers parallèles** : **A** agent (avec `scripts/setup.sh`), **B** backend, **C** interface.
- **Propriété** : un fichier appartient à un seul chantier.
- **Libellés d'interface** : en anglais, jamais de tiret cadratin.
- **Journaux** : jamais de contenu de terminal, de ticket ni de secret.
- **Règle absolue** : `open_pty_shell` (agent) et `ws_token` (backend) ne changent pas d'un octet.
  - Le seul ajout dans `ws_handler` est une branche placée **après** la vérification du ticket.
  - Elle n'est prise que si `scope` commence par `@user:`.

## 0. Propriété des fichiers
### Agent : A
- **Nouveaux fichiers** :
  - `panel/agent/src/services/user_terminal.rs` : `validate_login`, préparation du compte, ligne
    `systemd-run`, `jti`, décodeur UTF-8, kill, registre des logins, audit.
  - `panel/agent/src/routes/user_terminal.rs` : routes A-2 à A-4 et la route d'événements de B-6.
  - `tests/user-terminal-*-e2e.sh` : scripts e2e (A-8).
- **Fichiers modifiés** :
  - `panel/agent/src/routes/terminal.rs` : uniquement la branche `@user:` dans `ws_handler`, l'aiguillage
    vers `services::user_terminal::handle` et le test d'empreinte (A-7).
  - `panel/agent/src/routes/security.rs` : `kill-terminals` arrête aussi les terminaux utilisateur (A-4).
  - `panel/agent/src/main.rs`, `src/routes/mod.rs` et `src/services/mod.rs` : enregistrement du module
    et des routes.
  - `panel/agent/dockpanel-agent.service` et `src/services/agent_unit.rs` : `-/etc/systemd/user` dans
    `ReadWritePaths`, test mis à jour.
  - `scripts/setup.sh` : `tmux` et les fichiers de §3 de la conception (A-6).
### Backend : B
- **Nouveaux fichiers** :
  - `panel/backend/migrations/20261123000000_user_terminal.sql`.
  - `panel/backend/src/routes/user_terminal.rs` : ticket, correspondances, événements, kill.
- **Fichiers modifiés** :
  - `src/auth.rs` : claim `amr` dans `Claims`.
  - `src/routes/auth.rs` : `issue_session_pub` reçoit la méthode, passée par la connexion par mot de
    passe (l. 348) et par `/auth/2fa/verify` (l. 1611).
  - `src/routes/passkeys.rs` (l. 972) et `src/routes/oauth.rs` (l. 586) : la méthode est passée.
  - `src/routes/security.rs` : le panic et l'activation du verrouillage appellent A-4.
  - `src/routes/settings.rs` : `user_terminal_disabled` dans la liste autorisée, et l'appel B-5.
  - `src/routes/mod.rs`.
### Interface : C
- **Nouveaux fichiers** :
  - `panel/frontend/src/pages/UserTerminal.tsx` : page plein écran `/terminal/me`.
  - `panel/frontend/src/components/UserTerminalSettings.tsx` : correspondances et vérification.
- **Fichiers modifiés** :
  - `src/main.tsx` : route hors layout.
  - `src/data/navItems.ts` : « My session ».
  - `src/pages/Settings.tsx` : interrupteur « User terminal » et carte des correspondances.
  - `src/components/PanicReport.tsx` : `user_terminals_killed`.
  - Page de connexion : retour à `?next=`.
  - `package.json` et `package-lock.json` : `@xterm/addon-unicode11`, `@xterm/addon-webgl`,
    `@xterm/addon-clipboard`, en versions compatibles avec `@xterm/xterm` 6.0.0.
- **Inchangé** : `src/pages/Terminal.tsx`.

## A. Agent
- **Erreurs** : `{ "error": "message" }` avec les codes 400, 403, 404, 409, 412 ou 500.
- **Authentification** : les routes A-2 à A-4 et la route d'événements de B-6 sont sous le jeton agent
  habituel. A-1 est sous ticket, comme `/terminal/ws`.

### A-1 Branche `@user:` du WebSocket `/terminal/ws`
- **Ticket** : mêmes claims que l'existant, plus `uid: u32` et `jti: String`. `purpose` vaut
  `"terminal"` et `scope` vaut `"@user:<login>"`.
  - Absence de `uid` ou de `jti` : 401.
  - `jti` déjà vu : 401. Les `jti` sont gardés en mémoire jusqu'à leur `exp`, avec au plus 10 000
    entrées.
- **Origin** : l'en-tête `Origin` est obligatoire, et son hôte (port compris) doit égaler l'en-tête
  `Host`. Sinon 403.
- **Contrôle du compte** : à chaque ouverture, `validate_login` (A-5) sur l'entrée `getpwnam(login)`,
  avec l'uid du ticket. Un refus renvoie 403 et la raison.
- **Préparation** : si les fichiers de A-6 manquent, 412 `"User terminal is not prepared for this
  account"`. La préparation ne se fait jamais à la volée.
- **Ouverture** :
  - nouveau pty (`openpt`), puis `fork` ;
  - le fils fait `setsid`, `TIOCSCTTY`, `dup2`, ferme les fd et vide l'environnement (`clearenv`) ;
  - il exécute ensuite la ligne `systemd-run` de §2 de la conception, avec l'unité
    `dockpanel-uterm-<login>-<8 hex>` et les arguments échappés (`$` → `$$`) ;
  - pas de `setuid`, pas de `prctl`.
- **Avant l'ouverture** : `systemctl --user -M <login>@ is-active dockpanel-tmux.service` décide de
  l'événement d'audit, `session_created` ou `attach`.
- **Protocole** : identique à l'existant (`{"type":"input"}`, `{"type":"resize"}`, texte brut).
  - **Sortie** : trames texte après décodage UTF-8 **avec réserve**.
    - Une séquence incomplète en fin de lecture est gardée pour la lecture suivante.
    - Une séquence invalide devient U+FFFD.
  - **Entrée** : écriture complète sur le maître, avec gestion de `EAGAIN` et des écritures partielles.
    Une trame d'entrée fait au plus 64 Kio.
- **Enregistrement** : seulement si `record: true`, au même format asciicast que l'existant.
- **Pas d'`observe_input`.**
- **Limites** :
  - durée de 12 h par connexion, au lieu de 30 min ;
  - au plus 4 connexions simultanées par login ;
  - les compteurs globaux existants (20 sessions, une connexion par seconde) s'appliquent.
- **Fin de connexion** : SIGTERM au fils (`systemd-run`), puis `systemctl stop <unité>` si l'unité est
  encore active après 2 s.
  - Audit `detach` avec la durée et la cause : `closed`, `ws_lost`, `killed` ou `timeout`.
- **Registre** : `register_terminal` existant (avec `is_root` à faux), plus un registre propre
  `(unité, login)`.

### A-2 `GET /terminal/user/check?login=<login>`
```json
{ "supported": true, "ok": true, "reasons": [],
  "uid": 1000, "home": "/home/bastien", "shell": "/bin/bash",
  "tmux_installed": true, "prepared": true, "linger": true,
  "session_running": true, "sudo_nopasswd": false }
```
- **`reasons`** : les refus de `validate_login`, en anglais.
- **`sudo_nopasswd`** : vrai si une règle `NOPASSWD` s'applique. Calculé avec `sudo -l -n -U <login>`
  lancé en root via `safe_command_unsandboxed`.
- **Login invalide** (hors de `^[a-z_][a-z0-9_-]{0,31}$`) : 400.

### A-3 `POST /terminal/user/prepare` `{ "login", "uid", "autostart_command": "claude" | null }` → `{ "ok": true, "warnings": [] }`
- **Contrôle** : `validate_login` avec l'uid. Refus : 403 et les raisons.
- **Étapes idempotentes** :
  1. installer `tmux` s'il manque ;
  2. écrire `/etc/dockpanel/tmux.conf`, `/etc/systemd/user/dockpanel-tmux.service` et
     `/etc/dockpanel/bin/{uterm-attach,uterm-autostart}` (0755), seulement si leur contenu diffère ;
  3. écrire la commande de démarrage dans `/etc/dockpanel/uterm/<login>.autostart` (0644) :
     - une seule ligne, ou pas de fichier si la commande vaut `null` ;
     - au plus 200 caractères, sans saut de ligne ni caractère de contrôle, sinon 400 ;
  4. `loginctl enable-linger <login>`, puis attendre l'apparition de `/run/user/<uid>` (10 s au plus) ;
  5. `systemctl --user -M <login>@ daemon-reload`, puis `enable dockpanel-tmux.service` ;
  6. ajouter le login à `/var/lib/dockpanel/user-terminals.json`.
- **Pas de `start`** : la session démarre à la première connexion ou au boot.

### A-4 `POST /terminal/user/kill` `{ "stop_sessions": bool, "login": null | "<login>" }` → `{ "ok": true, "connections_killed": 2, "sessions_stopped": 1 }`
- **Connexions** : arrête les unités `dockpanel-uterm-*`, ou celles du login donné, avec
  `systemctl stop 'dockpanel-uterm-<…>-*.service'`.
- **`stop_sessions: true`** : arrête aussi la session tmux de chaque login du registre (ou du login
  donné), avec `systemctl --user -M <login>@ stop dockpanel-tmux.service`.
- **`POST /security/kill-terminals`** existant : son traitement actuel est inchangé. Il appelle ensuite
  l'équivalent de A-4 avec `stop_sessions: true` et ajoute `user_terminals_killed` à sa réponse JSON.

### A-5 `validate_login(entry, shells, groups, expected_uid) -> Result<(), Vec<String>>` (fonction pure)
Raisons possibles :
- `"Linux user not found"` ;
- `"root is not allowed"` ;
- `"UID below 1000 is a system account"` ;
- `"UID 60000 and above is not allowed"` ;
- `"UID does not match the linked account"` ;
- `"Site accounts (sftp_sites) are not allowed"` ;
- `"Login shell is not valid"` : shell absent de `/etc/shells`, ou qui se termine par `nologin` ou
  `false` ;
- `"Home directory does not exist"`.

`/home` est caché à l'agent. Le dossier personnel est donc vérifié hors de son espace de noms, avec
`test -d` via `safe_command_unsandboxed`.

### A-6 Fichiers hôte (contenu de §3 de la conception), communs à `setup.sh` et A-3
- **`uterm-autostart`** lit `/etc/dockpanel/uterm/$USER.autostart`.
  - S'il existe, il envoie la ligne avec
    `tmux -S "$XDG_RUNTIME_DIR/dockpanel-tmux.sock" send-keys -t claude -l -- "<ligne>"`, puis
    `send-keys -t claude Enter`.
  - Sinon, il ne fait rien.
- **Contenu unique** : il est défini une seule fois, en constantes Rust dans `services/user_terminal.rs`.
  `setup.sh` écrit le même contenu, et un test lit `scripts/setup.sh` pour comparer.

### A-7 Tests unitaires de l'agent
- **`validate_login`** : toutes les raisons.
- **Ligne `systemd-run`** : nom de l'unité, échappement des `$`, variables d'environnement.
- **`jti`** : rejeu refusé, purge à l'expiration.
- **Origin** : même hôte accepté ; absent, autre hôte ou autre port refusés.
- **Décodeur UTF-8** : un emoji de 4 octets coupé après 1, 2 et 3 octets, et une séquence invalide.
- **Longues entrées** : 200 lignes écrites en entier, malgré des écritures partielles simulées.
- **Empreintes SHA-256** du texte source de `open_pty_shell` et de `observe_input`, relevées sur `main`
  avant le changement. Le test lit `routes/terminal.rs` avec `include_str!` et compare.
- **`agent_unit`** : `ReadWritePaths` contient `-/etc/systemd/user`, et `ProtectHome=yes` est toujours là.

### A-8 Scripts e2e (`tests/user-terminal-*-e2e.sh`, lancés depuis l'hôte Windows contre la VM)
- **Couverture** : tout le §8 de la conception.
  - Refus, verrouillage, panic.
  - Uid, `/home`, `sudo -n true`, `sudo` avec mot de passe.
  - Persistance après coupure et après redémarrage de l'agent.
  - Collage de 200 lignes.
  - Non-régression de `@server` et des sites.
- **Client WebSocket** : script Python (bibliothèque `websockets`). Il lit les secrets de test dans des
  fichiers et ne les affiche jamais.

## B. Backend
### B-1 Migration `20261123000000_user_terminal.sql`
- La table `user_linux_accounts` de §5 de la conception.
- Le réglage par défaut :
  `INSERT INTO settings (key, value) VALUES ('user_terminal_disabled','false') ON CONFLICT DO NOTHING`
  (à adapter aux colonnes réelles de `settings`).

### B-2 Claim `amr`
- **Champ** : `Claims.amr: Option<String>`, avec `#[serde(default, skip_serializing_if = "Option::is_none")]`.
- **Valeurs** :
  - `"mfa"` après `/auth/2fa/verify` et la connexion par passkey ;
  - `"pwd"` après une connexion par mot de passe sans TOTP ;
  - `"oauth"` après OAuth ;
  - non renseigné pour une clé `dp_` ou un emprunt d'identité.
- **Sessions existantes** : elles se décodent toujours, avec `None`.
- **Tests** : un test par chemin de connexion.

### B-3 `GET /api/terminal/user/token` → `{ "token", "login" }`
- **Fonction pure** `user_ticket_decision(ctx) -> Result<(), Denial>`, testée unitairement. Ordre et
  codes :
  1. verrouillage : 503 ;
  2. interrupteur : 403 `"User terminal is disabled"` ;
  3. serveur non local : 501 ;
  4. `key_id` présent, pas de cookie de session, ou `imp_by` présent : 403
     `"A browser session is required"` ;
  5. rôle relu en base différent d'`admin` : 403 ;
  6. `amr` différent de `"mfa"` : 403 avec le code `mfa_required` ;
  7. pas de correspondance : 404.
- **Ticket** : signé comme celui de `ws_token`. Claims :
  - `sub` (email), `purpose:"terminal"`, `scope:"@user:<login>"` ;
  - `uid`, `record` (de la correspondance) ;
  - `jti` (UUID v4) et `exp` à 60 s.
- **Audit** (`security_hardening::audit_log`) : `user_terminal.ticket` en succès, `user_terminal.denied`
  en refus, avec l'auteur, l'IP et la raison. Jamais le ticket.

### B-4 Correspondances
Routes admin, ouvertes seulement à une session navigateur : mêmes points 4 et 6 que B-3.
- **`GET /api/terminal/user/accounts`** : la liste des comptes admin. Chaque compte porte
  `{ user_id, email, linux_user, uid, autostart_command, record, updated_at }`, ou `null` sans
  correspondance.
- **`PUT /api/terminal/user/accounts/{user_id}`**
  `{ "linux_user", "autostart_command", "record", "proof": {...} }` :
  - `require_enrolment_proof` sur `proof` ;
  - le compte cible doit être admin ;
  - appel de A-2 : si `ok` est faux, refus 400 avec les `reasons` ; sinon appel de A-3 ;
  - upsert avec l'`uid` renvoyé par A-2 ;
  - audit `user_terminal.mapping_set`.
- **`DELETE /api/terminal/user/accounts/{user_id}`** :
  - même preuve ;
  - appel de A-4 avec ce login et `stop_sessions: false` ;
  - suppression de la ligne, audit `user_terminal.mapping_removed` ;
  - le linger et la session tmux ne sont pas retirés.
- **`GET /api/terminal/user/accounts/{user_id}/check`** : relaie A-2 pour le login enregistré.
- **`GET /api/terminal/user/me`** → `{ "linked": bool, "login": str|null, "available": bool, "reason": str|null }` :
  - sert au menu et à la page, et toute session y a accès ;
  - `available` reprend la décision de B-3, sans émettre de ticket.

### B-5 Coupures
- **Activation du verrouillage** (sa route et le panic) : appel de A-4 avec `stop_sessions: false`, sans
  bloquer si l'agent ne répond pas.
- **Panic** : appel de A-4 avec `stop_sessions: true`. `kill-terminals` le fait déjà sur un agent récent,
  l'appel couvre les autres. La réponse ajoute `user_terminals_killed`.
- **`PUT /api/settings`** : quand `user_terminal_disabled` passe à `"true"`, appel de A-4 avec
  `stop_sessions: false`.

### B-6 Événements de l'agent
- **Route backend** `GET /api/security/user-terminal-events?limit=` (admin) : elle lit les lignes
  `user_terminal.*` du journal d'audit de l'agent.
- **Route agent** `GET /terminal/user/events?limit=` : fournie par le chantier A dans
  `routes/user_terminal.rs`.

## C. Interface
### C-1 Page `/terminal/me` (`UserTerminal.tsx`, hors layout)
- **Garde** :
  - sans session : redirection vers `/login?next=/terminal/me` ;
  - `GET /api/terminal/user/me` avec `available` faux : écran explicatif avec la raison ;
  - cas `mfa_required` : « Sign in again with two-factor authentication », avec un bouton qui déconnecte
    puis ramène à la connexion.
- **xterm** :
  - `allowProposedApi: true` et `unicode11` actif ;
  - WebGL, avec retour au rendu DOM sur `onContextLoss` ou en cas d'échec ;
  - fit, `scrollback` 10000, mêmes police et thèmes que `Terminal.tsx`.
- **Presse-papiers** :
  - extension `@xterm/addon-clipboard` avec un fournisseur maison ;
  - **écriture seulement** : `writeText` passe à `navigator.clipboard.writeText`, et `readText` renvoie
    toujours `""` ;
  - Ctrl+Maj+C copie la sélection xterm. Ctrl+Maj+V et Ctrl+V collent ;
  - le collage passe par `term.paste()` (paste encadré), et l'envoi est découpé en trames de 16 Kio.
- **Clavier** : `attachCustomKeyEventHandler` ne retient que Ctrl+Maj+C et Ctrl+Maj+V. Tout le reste va au
  terminal, y compris Ctrl+C, D, R, L et Z.
- **Taille** : `ResizeObserver` et `window.visualViewport`, puis `fit`. Un message `resize` part
  seulement si les colonnes ou les lignes changent.
- **Connexion** :
  - nouveau ticket à chaque tentative ;
  - URL `/agent/terminal/ws?token=<encodeURIComponent>&cols&rows`, sans `domain` ;
  - reconnexion sans fin : premier délai d'1 s, doublé à chaque essai jusqu'à 30 s, avec une part
    aléatoire ;
  - arrêt sur un 401, 403 ou 404 du ticket, avec affichage de la raison ;
  - bandeau « Reconnecting… », puis « Reattached » pendant 2 s ;
  - pas de délai d'inactivité.
- **Barre fine** : état de la connexion, « Copy », « Paste », taille de police, « Reconnect » et « Exit »
  (retour au panel).
- **Mobile** : barre de touches avec Esc, Tab, Ctrl (verrouillable), les flèches, `Ctrl+B` (préfixe
  tmux) et Paste.

### C-2 Menu
- « My session » sous Terminal, vers `/terminal/me`. L'entrée n'apparaît que si
  `GET /api/terminal/user/me` renvoie `linked: true`.

### C-3 Settings → Account → Security Hardening
- **Interrupteur « User terminal »** (`user_terminal_disabled`), réglage inversé comme « Server
  terminal ». Texte d'aide : « Disabling it also closes open user terminal connections. »
- **`UserTerminalSettings`** : une ligne par compte admin.
  - Champs « Linux user » et « Start command » (par défaut `claude`), case « Record sessions »
    (décochée).
  - Boutons « Save » et « Unlink » : une boîte de dialogue demande la preuve (mot de passe ou code TOTP).
  - Bouton « Check » : affiche le résultat de B-4. Si `sudo_nopasswd` est vrai, il affiche
    l'avertissement « This user can run sudo without a password: a panel session alone gives root ».

### C-4 Panic
- `PanicReport` affiche `user_terminals_killed`.

### C-5 Connexion
- La page de connexion respecte `?next=`, mais seulement pour un chemin interne : il commence par `/` et
  pas par `//`.
