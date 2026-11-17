# Mises à jour depuis l'interface - Contrats d'interface

Référence : `10-mises-a-jour.md` (validée). Choix du propriétaire (§11) : signature minisign obligatoire,
nouvelle série 3.0.0, jeton GitHub *fine-grained* en lecture seule stocké sur le serveur, publication
depuis la machine Windows (compilation Docker), sans GitHub Actions.

Organisation :
- **Étape 0 (orchestrateur, avant de créer les worktrees)** : commit de version, voir §0.
- **Trois chantiers parallèles** : **A** backend, **B** agent et scripts, **C** interface.
- **Propriété** : un fichier appartient à un seul chantier (§1). Un chantier qui a besoin d'un changement
  dans un fichier d'un autre le signale dans son compte rendu, sans le faire.
- **Libellés et messages d'API** : en anglais, jamais de tiret cadratin. Les messages de §2.6 sont à
  reprendre **au caractère près**.
- **Secrets** : le jeton GitHub n'apparaît jamais dans une réponse, un log, le journal d'activité, une
  ligne de commande, une variable d'environnement d'un processus enfant ni une requête vers un agent.
  Une URL signée de GitHub (redirection) n'est jamais journalisée en entier : seulement l'hôte.
- **Principe de sécurité** : rien ne s'installe sans (1) la signature minisign de `checksums.txt`
  vérifiée avec la clé publique compilée, (2) le tag lié par le commentaire de confiance, (3) le SHA-256
  de chaque fichier. Celui qui vérifie la signature est **le binaire Rust** (backend pour le panel,
  agent pour lui-même). Les scripts shell ne reçoivent que des fichiers déjà vérifiés, dans un dossier
  root 0700, et revérifient seulement leur SHA-256.

## 0. Étape préalable : version 3.0.0-rc.1 (orchestrateur, un seul commit)
- **Pourquoi l'orchestrateur** : A et B modifient chacun leur `Cargo.toml` et leur `Cargo.lock` (nouvelle
  dépendance). Aucun des trois chantiers ne peut faire le changement de version sans toucher un fichier
  d'un autre. Le commit est donc fait **avant** de créer les worktrees, et les chantiers partent de lui.
- **Fichiers** (`2.242.1` → `3.0.0-rc.1`) :
  - `panel/agent/Cargo.toml`, `panel/backend/Cargo.toml`, `panel/cli/Cargo.toml`, `panel/mcp/Cargo.toml` ;
  - l'entrée du paquet dans chacun des quatre `Cargo.lock` ;
  - `panel/frontend/package.json` et les deux occurrences de `panel/frontend/package-lock.json`.
- **Hors commit** : `FEATURES.md`, `docs/testing.md`, `CHANGELOG.md` (tampons historiques), et
  `panel/frontend/tsconfig.tsbuildinfo` (ne pas toucher).
- **Série** : le code est en `3.0.0-rc.1` pendant le développement. Les releases de test en VM sont
  `v3.0.0-rc.2` et suivantes, publiées depuis une branche jetable (§V). La première vraie release est
  `v3.0.0`, signée avec la clé de production.
- **Format de tag** : `vX.Y.Z` ou `vX.Y.Z-rc.N` uniquement (`validate_target_version` et `release_key`
  existants). `v3.0.0-rc1` (sans point) est refusé : on écrit `v3.0.0-rc.1`.
- **Comparaison** : `telemetry_collector::is_newer_release` reste la seule règle. `3.0.0-rc.1 > 2.242.1`,
  `3.0.0 > 3.0.0-rc.2 > 3.0.0-rc.1`.

## 1. Propriété des fichiers
### Backend : A
- **Nouveaux fichiers** :
  - `panel/backend/build.rs` : `cargo:rerun-if-env-changed=CYBERHUNTER_UPDATE_PUBKEY` (§2.3).
  - `panel/backend/src/services/update_source.rs` : `update.conf`, fichier jeton, prédicat
    « configuré », clé publique compilée et son identifiant.
  - `panel/backend/src/services/release_fetch.rs` : client GitHub, politique de redirection, cache des
    releases, vérification minisign et SHA-256, extraction de l'archive source.
  - `panel/backend/src/services/testdata/release/*` : fixtures de test (§A-11).
  - `panel/backend/migrations/20261124000000_update_source.sql` (§A-9).
- **Fichiers modifiés** :
  - `panel/backend/Cargo.toml` : ajout de `minisign-verify = "0.3.0"`, **sans toucher la ligne `version`** ;
    `panel/backend/Cargo.lock`.
  - `src/services/mod.rs`, `src/services/telemetry_collector.rs`, `src/services/panel_update.rs`.
  - `src/routes/update.rs`, `src/routes/telemetry.rs`, `src/routes/agent_updates.rs`, `src/routes/mod.rs`.
  - `src/routes/sites.rs` : uniquement le commentaire de la ligne 711 (§2.8).
  - `src/main.rs` : seulement si nécessaire (log de démarrage de la clé, voir A-2).
### Agent et scripts : B
- **Nouveaux fichiers** :
  - `panel/agent/build.rs` : identique à celui du backend.
  - `panel/agent/src/services/release_verify.rs` : clé compilée, analyse de `checksums.txt`, vérification
    minisign et SHA-256, téléchargement depuis le panel.
  - `panel/agent/src/services/testdata/release/*` : fixtures (générées par B, indépendantes de celles de A).
  - `tests/no-upstream-repo-pin.sh`, `tests/update-release-dir-pin.sh`, `tests/release-format-pin.sh`.
  - `scripts/release-build/Dockerfile` : image de compilation des releases (§B-5bis).
  - `scripts/release-build/build-in-container.sh` : compilation et contrôle glibc, lancés dans l'image.
  - `scripts/release-build/check-glibc.sh` : contrôle des symboles versionnés (§B-5bis), utilisable seul.
- **Fichiers modifiés** :
  - `panel/agent/Cargo.toml` (ajout de `minisign-verify = "0.3.0"`, sans la ligne `version`) et
    `panel/agent/Cargo.lock`.
  - `panel/agent/src/routes/panel_update.rs`, `src/services/phone_home.rs` (si besoin),
    `src/services/mod.rs`.
  - `scripts/update.sh`, `scripts/agent-self-update.sh`, `scripts/release.sh`, `scripts/install.sh`,
    `scripts/install-agent.sh`, `scripts/setup.sh`, `scripts/deploy-demo.sh`.
  - **Tout `tests/*.sh`** qui épingle un de ces scripts ou les anciens noms d'assets
    (`dockpanel-*-linux-*`, par exemple `tests/install-integrity-pin-e2e.sh`). Le dossier `tests/`
    appartient entièrement à B.
### Interface : C
- **Fichiers modifiés** : `panel/frontend/src/pages/Telemetry.tsx` (onglet « Updates »),
  `panel/frontend/src/pages/Dashboard.tsx` (bandeau).
- **Nouveau fichier possible** : `panel/frontend/src/components/UpdateSourceCard.tsx`.
- **Interdit** : `package.json`, `package-lock.json`, `tsconfig.tsbuildinfo`. Aucune dépendance ajoutée.
- `panel/frontend/public/install-agent.sh` est un artefact ignoré par git (copié par
  `scripts/stage-install-agent.mjs`) : personne ne le modifie.

## 2. Constantes partagées
### 2.1 Fichiers d'une release
Tag `vX.Y.Z[-rc.N]` sur `MrTheSkream/cyberhunter-panel`. Fichiers attachés, **et rien d'autre** :

| Nom exact | Contenu | Obligatoire |
|---|---|---|
| `cyberhunter-agent-linux-amd64` | binaire `dockpanel-agent` (ELF brut, pas d'archive) | oui |
| `cyberhunter-api-linux-amd64` | binaire `dockpanel-api` | oui |
| `cyberhunter-cli-linux-amd64` | binaire `dockpanel` | oui |
| `cyberhunter-mcp-linux-amd64` | binaire `dockpanel-mcp` | oui |
| `cyberhunter-{agent,api,cli,mcp}-linux-arm64` | idem ARM64 | les quatre ou aucun |
| `cyberhunter-frontend.tar.gz` | `dist/` à la racine de l'archive (comme aujourd'hui) | oui |
| `cyberhunter-source.tar.gz` | `git -c core.autocrlf=false archive --format=tar.gz --prefix=cyberhunter-source/ HEAD -- scripts panel` (le commit qui reçoit le tag), en LF | oui |
| `checksums.txt` | §2.2 | oui |
| `checksums.txt.minisig` | signature minisign de `checksums.txt` (§2.3) | oui |

- **Noms internes inchangés** : sur le serveur, les binaires gardent leurs chemins actuels
  (`/usr/local/bin/dockpanel-agent`, `dockpanel-api`, `dockpanel`, `dockpanel-mcp`) et les services leurs
  noms. Seuls les noms d'assets changent.
- **Architecture** : `uname -m` `x86_64` → `amd64`, `aarch64`/`arm64` → `arm64`. En Rust :
  `std::env::consts::ARCH` `"x86_64"` → `amd64`, `"aarch64"` → `arm64`.
- **Plus de SBOM** dans les releases (hors périmètre).

### 2.2 Format de `checksums.txt`
- UTF-8 sans BOM, fins de ligne **LF**, une ligne par fichier de la release sauf `checksums.txt` et
  `checksums.txt.minisig`, triées par nom (ordre C).
- Ligne : `^[0-9a-f]{64}  [A-Za-z0-9._-]{1,128}$` (64 hexadécimaux minuscules, **deux espaces**, nom
  sans `/`). C'est la sortie de `sha256sum` en mode texte.
- Lecteur (A et B, même règles) : taille max 64 Kio, 32 lignes max, dernière ligne vide tolérée, aucune
  autre ligne vide, `\r` refusé, nom en double refusé, tout écart refusé (pas de ligne ignorée).
- Généré par `release.sh` dans le conteneur Linux (`sha256sum cyberhunter-* | LC_ALL=C sort -k2`), et
  signé **octet pour octet** tel qu'il est publié.

### 2.3 Signature minisign
- **Crate** : `minisign-verify = "0.3.0"` (jedisct1, auteur de minisign ; aucune dépendance ; 0.3.0
  publiée en septembre 2026 ; API identique à 0.2.5 : `PublicKey::from_base64`, `Signature::decode`,
  `Signature::trusted_comment`, `PublicKey::verify(bin, &sig, allow_legacy)`). La signature globale, que
  `verify` contrôle, couvre le commentaire de confiance.
- **Appel** : `verify(&checksums_bytes, &sig, false)`. `allow_legacy = false` : seules les signatures
  pré-hachées (algorithme `ED`, défaut de minisign ≥ 0.10) sont acceptées.
- **Commentaire de confiance** : exactement `cyberhunter-release <tag>` (ex.
  `cyberhunter-release v3.0.0-rc.2`), égal au tag demandé, sinon refus. Cela lie la signature à la
  version : un détenteur du jeton ne peut pas republier un ancien jeu signé sous un nouveau tag.
- **Clé publique compilée** :
  - variable d'environnement **de compilation** `CYBERHUNTER_UPDATE_PUBKEY` = la ligne base64 du fichier
    `.pub` de minisign (2ᵉ ligne, commence par `RW`) ;
  - lue par `option_env!("CYBERHUNTER_UPDATE_PUBKEY")` dans `update_source.rs` (A) et
    `release_verify.rs` (B) ; `build.rs` émet `cargo:rerun-if-env-changed=CYBERHUNTER_UPDATE_PUBKEY` pour
    que changer la clé recompile ;
  - absente ou vide → `None` → mises à jour « not configured » (raison `no_signing_key`). Mal formée →
    `None` aussi, plus un `tracing::error!("CYBERHUNTER_UPDATE_PUBKEY is not a valid minisign public key")`
    au démarrage ;
  - **identifiant affiché** : `format!("{:016X}", u64::from_le_bytes(key_id))`, où `key_id` = octets
    2 à 9 de la clé décodée. C'est l'ID que minisign imprime (`untrusted comment: minisign public key <ID>`).
- **Pourquoi une variable de compilation** :
  - aucune clé dans le dépôt, donc ni la clé de test ni celle de production n'y fuitent ;
  - un build de développement (`lab/build.sh` sans `-e`) a les mises à jour désactivées : l'échec est
    fermé par défaut ;
  - la clé de test et celle de production ne diffèrent que par l'option `-e` de `docker run` ;
  - un fichier de configuration lu à l'exécution pourrait être remplacé par quiconque écrit dans
    `/etc/dockpanel` ; une constante compilée ne change qu'avec un binaire signé ;
  - rotation : une nouvelle clé n'arrive que dans une release signée par l'ancienne (§4 de la conception).
- **Côté shell** : aucune vérification minisign, et donc pas de copie de la clé dans `update.sh`
  (écart assumé par rapport au §4 de la conception) : `update.sh` et `agent-self-update.sh` ne
  téléchargent plus rien et ne reçoivent que des fichiers vérifiés par le binaire Rust, qu'ils
  revérifient au SHA-256. Une copie shell de la clé serait un second point de vérité à garder synchrone,
  sans gain de sécurité : celui qui contrôle le processus root qui lance le script contrôle déjà le script.

### 2.4 `/etc/dockpanel/update.conf` et le fichier jeton
- **`update.conf`** (root, 0600) :
  ```
  # Managed by CyberHunter - Panel (Telemetry, Updates)
  UPDATE_REPO=MrTheSkream/cyberhunter-panel
  UPDATE_TOKEN_FILE=/etc/dockpanel/update-token
  ```
  - format `CLE=valeur`, sans guillemets, lignes `#` et vides ignorées, clés inconnues ignorées, `\r`
    final toléré ;
  - **lu et écrit uniquement par le backend** (écart par rapport à la conception, voir §2.3 : les scripts
    ne contactent plus GitHub). Jamais `source` ;
  - écrit par `PUT /api/update/source` (A-6.2), par écriture dans un fichier temporaire puis `rename` ;
  - `UPDATE_REPO` doit respecter `^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}$` et ne pas être
    `.` ou `..` après le `/` ;
  - `UPDATE_TOKEN_FILE` : chemin absolu sous `/etc/dockpanel/`, sinon la config est invalide ;
  - **dépôt par défaut** (constante backend `DEFAULT_UPDATE_REPO`) : `MrTheSkream/cyberhunter-panel`,
    utilisé quand `PUT` ne précise pas `repo` et qu'aucun `update.conf` n'existe.
- **Fichier jeton** `/etc/dockpanel/update-token` (root, 0600) : une ligne, le jeton, suivie de `\n`.
  Le lecteur enlève les espaces autour ; vide = pas de jeton.
- **Format du jeton accepté** : `^github_pat_[A-Za-z0-9_]{20,255}$` (fine-grained uniquement).
- **Prédicat « configuré »** : clé compilée présente **et** `update.conf` valide **et** jeton non vide.
  Raison, dans cet ordre : `no_signing_key`, puis `no_source` (fichier absent ou invalide), puis `no_token`.

### 2.5 Chemins sur le serveur
- **Cache du panel** : `/var/lib/dockpanel/releases/` (root, 0700). Pas `/tmp` : `dockpanel-api` a
  `PrivateTmp=yes`, et l'unité transitoire de `update.sh` ne verrait pas ses fichiers.
  - `/var/lib/dockpanel/releases/.partial-<tag>-<uuid>/` : téléchargement en cours, supprimé en cas d'échec.
  - `/var/lib/dockpanel/releases/<tag>/` : `checksums.txt` et `checksums.txt.minisig` vérifiés, plus les
    fichiers déjà demandés. **Un fichier présent dans ce dossier a passé sa vérification SHA-256** : il est
    écrit sous un nom temporaire puis renommé après contrôle.
  - `/var/lib/dockpanel/releases/<tag>/cyberhunter-source/` : l'archive source extraite par A.
  - Rétention : on garde le tag courant, le tag annoncé et les cibles de flotte non terminées ; les autres
    sont supprimés au démarrage et après chaque préparation réussie.
- **Staging de l'agent** : `/var/lib/dockpanel/agent-release/` (root, 0700), fichier
  `cyberhunter-agent-<tag>`, supprimé par `agent-self-update.sh` à la sortie.
- **Verdicts inchangés** : `/var/lib/dockpanel/last-panel-update.json` et
  `/var/lib/dockpanel/last-agent-update.json` (mêmes champs qu'aujourd'hui).

### 2.6 Erreurs (corps `{ "error": "<message>", "code": "<code>" }`, via `err_coded`)
| Code | Statut | Message exact |
|---|---|---|
| `updates_not_configured` | 409 | `Updates are not configured` |
| `token_invalid` | 409 (400 sur `PUT /api/update/source`) | `The update token is missing or expired` |
| `repo_unreadable` | 409 (400 sur `PUT /api/update/source`) | `The update token cannot read this repository` |
| `github_rate_limited` | 503 | `GitHub rate limit reached, try again later` |
| `release_not_found` | 404 | `Release not found` |
| `release_incomplete` | 422 | `The release is missing required files, nothing was installed` |
| `signature_failed` | 422 | `Signature check failed, nothing was installed` |
| `checksum_failed` | 422 | `Checksum check failed, nothing was installed` |
| `download_failed` | 502 | `Download failed` |
| `token_format` | 400 | `Token format is not valid (expected a fine-grained token starting with github_pat_)` |
| `repo_format` | 400 | `Repository must look like owner/name` |
| `update_in_flight` | 409 | message existant de `OrchestratorError::AlreadyInFlight` |
| `fleet_target` | 400 | `Fleet target must be this panel's version (v<courante>) or, with include_panel, the advertised update` |
| `release_not_offered` | 403 | `This release is not offered to agents` |
| `release_file_unknown` | 404 | `Release file not available` |

- **Correspondance GitHub** : 401 → `token_invalid` ; 403 avec `x-ratelimit-remaining: 0` ou 429 →
  `github_rate_limited` ; autre 403 ou 404 sur la liste des releases → `repo_unreadable` ; 404 sur
  `releases/tags/<tag>` ou release en brouillon → `release_not_found` ; erreur réseau, délai, 5xx, taille
  dépassée, hôte refusé → `download_failed`.
- **Signature** : `checksums.txt.minisig` absent, illisible, d'une autre clé, signature invalide,
  algorithme non pré-haché, commentaire de confiance différent → `signature_failed`.
- **Contenu** : `checksums.txt` mal formé ou sans entrée pour un fichier requis, fichier requis absent
  de la release → `release_incomplete` ; SHA-256 différent, taille différente de celle annoncée par
  GitHub → `checksum_failed`.
- La cause précise (hôte, statut, nom du fichier) va dans le log `tracing` et le journal d'activité,
  jamais l'URL complète ni le jeton.

### 2.7 Canaux
- Valeurs stockées **inchangées** : `stable`, `candidate`, `hold` (`update_channel`, `UpdateChannel`).
  L'interface affiche `candidate` comme « Beta (pre-releases) ».
- Une release est une **pre-release** si GitHub la marque `prerelease: true` **ou** si son tag porte un
  suffixe `-rc.N`.
- Sélection : liste `GET /repos/{repo}/releases?per_page=30`, on écarte les brouillons (`draft: true`) et
  les tags refusés par `validate_target_version`, et sur `stable` les pre-releases ; on garde le
  **maximum selon `release_key`** (pas l'ordre de GitHub, pas `/releases/latest`).
- `hold` : pas de vérification automatique ; « Check now » vérifie comme `stable` (comportement actuel).

### 2.8 Nettoyage `ovexro` (sans recouvrement)
- **A** : `panel/backend/src/services/telemetry_collector.rs` (constantes l. 20-22, supprimées) et
  `panel/backend/src/routes/sites.rs` l. 711 (commentaire : remplacer la ligne `See: ...` par rien).
  Le `User-Agent` `DockPanel/<ver>` devient `CyberHunter-Panel/<ver>`.
- **B** : `scripts/update.sh`, `scripts/agent-self-update.sh`, `scripts/install-agent.sh`,
  `scripts/install.sh`, `scripts/setup.sh` (l. 34 et 165), `scripts/deploy-demo.sh` (l. 34).
- **C** : rien. Aucune mention suivie par git dans `panel/frontend` (vérifié avec `git grep`).
- **Test** : `tests/no-upstream-repo-pin.sh` (B), sur l'arbre fusionné uniquement (§B-8).

## A. Backend
### A-1 `update_source.rs`
- `pub struct UpdateSource { repo: String, token_file: PathBuf }`, `pub fn read_conf(text) -> Result<..>`
  (fonction pure), `pub fn load() -> SourceStatus`.
- `pub struct SourceStatus { configured: bool, reason: Option<&'static str>, repo: Option<String>,
  token_set: bool, signing_key_id: Option<String> }`. Le jeton lui-même n'est **jamais** un champ d'une
  structure `Serialize` ni `Debug` : il est lu juste avant la requête GitHub, dans
  `release_fetch::github_auth_header`, qui renvoie un `HeaderValue` marqué `set_sensitive(true)`.
- `write_source(repo, token)` : écrit le jeton puis `update.conf` (temporaire + `rename`, 0600).
- `clear_token()` : supprime le fichier jeton, garde `update.conf`.

### A-2 Clé publique
- `pub fn signing_key() -> Option<&'static minisign_verify::PublicKey>` (`OnceLock`), et
  `pub fn signing_key_id() -> Option<String>` (§2.3).
- Au démarrage : `info!` avec l'ID de la clé, ou `warn!("No update signing key compiled in; updates are disabled")`.

### A-3 Client GitHub (`release_fetch.rs`)
- Client `reqwest` dédié : `redirect(Policy::none())`, `connect_timeout` 10 s, HTTPS seulement.
- En-têtes de la première requête (hôte `api.github.com` obligatoire) : `Authorization: Bearer <jeton>`,
  `Accept` (voir plus bas), `X-GitHub-Api-Version: 2022-11-28`,
  `User-Agent: CyberHunter-Panel/<version>`.
- **Appels** :
  - liste : `GET https://api.github.com/repos/{repo}/releases?per_page=30`, `Accept: application/vnd.github+json`,
    15 s, réponse ≤ 2 Mio ;
  - release : `GET https://api.github.com/repos/{repo}/releases/tags/{tag}`, même en-tête ;
  - fichier : `GET https://api.github.com/repos/{repo}/releases/assets/{id}`,
    `Accept: application/octet-stream`.
- **Redirections** (suivies à la main) :
  - au plus 3 ; statuts 301, 302, 303, 307, 308 ; `Location` relative résolue contre l'URL courante ;
  - chaque cible : schéma `https`, port absent ou 443, hôte dans la constante
    `ALLOWED_DOWNLOAD_HOSTS = ["api.github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com"]` ;
  - les requêtes après la première ne portent **que** `User-Agent` et `Accept` : jamais `Authorization`,
    même si la cible est `api.github.com` ;
  - au premier téléchargement, `info!` de l'hôte final (pour le relever en VM), sans chemin ni requête.
- **Fonctions pures testables** : `next_hop(current: &Url, location: &str, hop: u8, allowed: &[&str]) -> Result<Url, FetchError>`
  et `request_headers(hop: u8, auth: Option<HeaderValue>) -> HeaderMap`.
- **Tailles et délais** : `checksums.txt` ≤ 64 Kio et `.minisig` ≤ 4 Kio (30 s chacun) ; un fichier ≤
  200 Mio (209 715 200 octets) et égal au `size` annoncé par GitHub, sinon arrêt du flux ; 300 s par
  fichier ; 900 s pour toute une préparation.

### A-4 Cache vérifié
- `pub async fn prepare(tag, names: &[&str]) -> Result<PathBuf, FetchError>` :
  1. si `<tag>/checksums.txt` et `.minisig` manquent : les télécharger dans `.partial-*`, vérifier
     (§2.3), analyser (§2.2), puis renommer le dossier en `<tag>/` ;
  2. pour chaque nom manquant : télécharger, comparer taille et SHA-256 au manifeste, renommer ;
  3. un verrou par tag (`tokio::sync::Mutex` dans une table) sérialise les préparations concurrentes.
- Requiert « configuré » (sinon `updates_not_configured`), même si des fichiers sont déjà en cache :
  effacer le jeton coupe tout, sauf le retour arrière par instantané.
- **Fichiers requis** : panel = les 4 binaires de l'architecture du panel, `cyberhunter-frontend.tar.gz`,
  `cyberhunter-source.tar.gz` ; agents = `cyberhunter-agent-linux-amd64`, plus `-arm64` s'il figure au
  manifeste.
- **Extraction** : après vérification, `tar -xzf cyberhunter-source.tar.gz -C <tag>/ --no-same-owner`
  (processus `tar`), ce qui donne `<tag>/cyberhunter-source/scripts/update.sh`.

### A-5 Vérification (poller et « Check now »)
- Point unique : `check_for_updates_inner`. **Sans configuration, il ne fait aucune requête** : il efface
  l'annonce (`update_available_version`, `update_release_notes`, `update_release_url`,
  `update_available_prerelease`) et renvoie `Err(NotConfigured)`.
- Le poller toutes les 6 h saute silencieusement (`debug!`) quand ce n'est pas configuré ;
  `reconcile_stored_update` au démarrage efface aussi l'annonce dans ce cas.
- Résultat stocké dans `settings` : clés existantes, plus `update_available_prerelease` (`"true"`/`"false"`)
  et `update_check_error` (message de §2.6, effacé après une vérification réussie).
- Notes de version : `body` de la release, 4000 caractères max, stocké tel quel (l'interface l'affiche en
  texte brut).

### A-6 Endpoints (tous admin, `AdminUser`, sauf A-6.8 et A-6.9)
#### A-6.1 `GET /api/update/status`
Champs existants (état aplati, `current_version`, `available_version`, `channel`, `last_restore`,
`last_panel_update`) plus :
```json
{ "configured": true, "not_configured_reason": null,
  "repo": "MrTheSkream/cyberhunter-panel", "token_set": true,
  "signing_key_id": "1A2B3C4D5E6F7089",
  "available_prerelease": true, "release_notes": "…", "release_url": "https://github.com/…",
  "checked_at": "2026-11-20T10:00:00Z", "last_check_error": null }
```
- `not_configured_reason` : `"no_signing_key" | "no_source" | "no_token" | null`.
- Non configuré : `available_version`, `release_notes`, `release_url` à `null`, `available_prerelease`
  à `false`, quel que soit le contenu de la base.
- `available_version` n'est renvoyé que s'il est plus récent que la version courante (règle actuelle).

#### A-6.2 `PUT /api/update/source` `{ "token": "github_pat_…", "repo": "owner/name" }`
- `repo` facultatif : valeur actuelle de `update.conf`, sinon `DEFAULT_UPDATE_REPO`.
- Contrôles : format du jeton (`token_format`), format du dépôt (`repo_format`), puis test réel
  `GET /repos/{repo}/releases?per_page=1` : 401 → 400 `token_invalid`, 403/404 → 400 `repo_unreadable`,
  réseau → 502 `download_failed`. Rien n'est écrit en cas d'échec.
- Succès : écriture (A-1), effacement de `update_check_error`, réponse 200
  `{ "configured": bool, "not_configured_reason": …, "repo": "…", "token_set": true }`
  (`configured` reste faux sans clé compilée).
- Journal : `update.source_set`.

#### A-6.3 `DELETE /api/update/source/token`
- Supprime le fichier jeton et efface l'annonce. 200 `{ "configured": false, "not_configured_reason": "no_token", "token_set": false }`.
- Journal : `update.token_cleared`.

#### A-6.4 `POST /api/update/manual-check` et `POST /api/telemetry/check-updates`
- Non configuré : 409 `updates_not_configured`, **aucune requête sortante**.
- Échec GitHub : codes de §2.6, et `update_check_error` est enregistré.
- Succès, `manual-check` : 200 `{ "checked_at", "available_version": str|null, "prerelease": bool }`.
- Succès, `check-updates` : forme actuelle `{ "success": true, "message", "available_version" }`.
- Journal : `update.check` (manuel et automatique).

#### A-6.5 `GET /api/telemetry/update-status` et `GET /api/telemetry/config`
- Ajout de `"configured": bool`. Non configuré : `update_available: false`, et les clés `update_*`
  (sauf `update_checked_at`) sont retirées de la réponse. Le bandeau du tableau de bord disparaît donc.

#### A-6.6 `POST /api/update/apply` `{ "target_version": "v3.0.0-rc.2" }`
Contrôles synchrones, dans cet ordre :
1. non configuré → 409 `updates_not_configured` (avant toute autre chose, aucune requête) ;
2. `validate_target_version` et `reject_apply_target` → 400, messages existants inchangés ;
3. réservation « en cours » (code existant) → 409 `update_in_flight`.

Puis 202 `{ "accepted": true, "state": … }` (forme actuelle), et la suite **en tâche de fond** (le vhost
du panel coupe `/api` à 300 s, `proxy_read_timeout` de `setup.sh`, et un téléchargement plus l'instantané
peuvent dépasser) :
4. `prepare(tag, fichiers du panel)`, avec `last_log_line` = `Downloading and verifying release` ; en
   cas d'échec, état `Failed { reason, at, code }` (`reason` = message de §2.6, nouveau champ facultatif
   `code`), **aucun instantané n'est créé**, journal `update.apply_failed` ;
5. instantané, puis lancement de `update.sh` **extrait de la release vérifiée** (A-7) ; journal
   `update.apply_started`. Les échecs de l'instantané passent aussi par `Failed`.

#### A-6.7 `POST /api/update/rollback`
- Inchangé, et **pas** soumis à la configuration. Journal : `update.rollback_started`.

#### A-6.8 `POST /api/update/fleet` (« apply-fleet »), corps inchangé
1. non configuré → 409 `updates_not_configured` ;
2. `validate_target_version` → 400 (message actuel) ;
3. la cible doit être `v<version courante>` ou, avec `include_panel: true`, la version annoncée (et
   `reject_apply_target` passe) → sinon 400 `fleet_target` ;
4. `prepare(tag, fichiers agents)` → codes de §2.6, synchrone, avec un budget de 240 s (deux binaires
   agent) ;
5. création du plan (inchangée) → 202 `{ run_id, plan_size }` ; journal `update.fleet_started`.
- Dans `update_one_server`, avant le `POST /panel/update` : si `servers.agent_version` est inconnu ou
  `release_key` < `3.0.0-rc.1` (constante `MIN_SIGNED_AGENT_VERSION`), échec de ce serveur sans requête,
  avec : `This agent runs v<version>, older than 3.0.0-rc.1, and cannot verify signed releases. Reinstall it with install-agent.sh.`
  Un agent hérité contacterait sinon `ovexro/dockpanel` lui-même.
- Avec `include_panel`, la mise à jour du panel en fin de flotte réutilise la release préparée.
- Fin de flotte : journal `update.fleet_finished`.

#### A-6.9 `GET /api/agent/release/{tag}/{name}` (nouveau, côté agents)
- Authentification : `authenticate_agent` + `agent_rate_limit`, comme `/api/agent/version`. Jamais de
  jeton GitHub vers l'agent.
- `tag` : `vX.Y.Z[-rc.N]` ou l'alias `current` (= `v<version du panel>`).
- Tags autorisés : `v<version du panel>`, ou la `target_version` d'une ligne de `fleet_update_runs` avec
  `finished_at IS NULL`. Sinon 403 `release_not_offered`.
- `name` autorisés : `checksums.txt`, `checksums.txt.minisig`, `cyberhunter-agent-linux-amd64`,
  `cyberhunter-agent-linux-arm64`. Sinon, ou absent du manifeste, 404 `release_file_unknown`.
- Sert depuis le cache, en appelant `prepare` à la demande (codes de §2.6).
- 200 : `Content-Type: application/octet-stream`, `Content-Length`, en-tête `X-Release-Tag: <tag réel>`.

#### A-6.10 `GET /api/agent/version` (existant)
- Réponse inchangée `{ "target_version": str|null }`. `null` en plus quand ce n'est pas configuré, ou
  quand l'`agent_version` du serveur appelant est inconnue ou < `3.0.0-rc.1`.

### A-7 Lancement de `update.sh`
- Script : `/var/lib/dockpanel/releases/<tag>/cyberhunter-source/scripts/update.sh`, lancé par
  `bash <chemin>` (plus `/opt/dockpanel/scripts/update.sh`). `ScriptMissing` vise ce chemin.
- Environnement (exactement) : `INSTALL_FROM_RELEASE=1`, `DOCKPANEL_VERSION=<tag avec v>`,
  `CYBERHUNTER_RELEASE_DIR=/var/lib/dockpanel/releases/<tag>`. `DOCKPANEL_NO_SELF_REFRESH` n'est plus
  passé. Le reste (groupe de processus, lecture du verdict) est inchangé.
- Au démarrage suivant, `finalize_pending_on_startup` écrit le journal du résultat (A-8).

### A-8 Journal d'activité
- `log_activity` pour les actions issues d'une requête (auteur, `client_ip(&headers)`), et
  `log_activity_system` pour les résultats constatés sans requête (après redémarrage, poller), avec
  `user_email` = l'opérateur de l'instantané, ou `"system"`.
- `target_type = "panel_update"`, `target_name` = tag (ou `null`), `details` = JSON :

| `action` | `details` |
|---|---|
| `update.source_set` | `{ "repo" }` |
| `update.token_cleared` | `{}` |
| `update.check` | `{ "channel", "manual": bool, "result": "available"\|"up_to_date"\|"error", "available_version", "error" }` |
| `update.apply_started` | `{ "from_version", "to_version", "snapshot_id" }` |
| `update.apply_failed` | `{ "from_version", "to_version", "stage": "verify"\|"download"\|"updater", "code", "reason" }` |
| `update.apply_succeeded` | `{ "from_version", "to_version" }` |
| `update.rolled_back` | `{ "from_version", "attempted_version", "reason" }` (retour arrière automatique de `update.sh`) |
| `update.rollback_started` | `{ "snapshot_id", "from_version", "to_version" }` |
| `update.fleet_started` | `{ "target_version", "plan_size", "include_panel" }` |
| `update.fleet_finished` | `{ "target_version", "outcome" }` |

- Jamais le jeton, jamais une URL de téléchargement.

### A-9 Migration `20261124000000_update_source.sql`
```sql
-- L'annonce stockée vient peut-être du dépôt amont : on l'efface.
DELETE FROM settings WHERE key IN
  ('update_available_version', 'update_release_notes', 'update_release_url');
```
- Le commentaire SQL ne doit pas contenir le nom du dépôt amont (§B-8).

### A-10 Compatibilité et tests de A qui lisent des fichiers de B
- `panel/mcp/src/tools.rs` lit `GET /api/update/status` : on n'y fait que des ajouts de champs, aucun
  renommage ni suppression.
- A et C listent dans leur compte rendu les épingles de `tests/` qui visent leurs fichiers et qu'ils ont
  cassées ; B ou l'orchestrateur les corrige.
- Les épingles existantes de `panel_update.rs` sur `scripts/update.sh` restent (B garantit les chaînes,
  §B-4). A n'en ajoute pas de nouvelles sur les scripts : c'est le rôle de `tests/update-release-dir-pin.sh`.

### A-11 Tests unitaires de A
- **`update.conf`** : fichier valide, commentaires, clé inconnue, dépôt invalide, chemin de jeton hors
  `/etc/dockpanel`, `\r` final.
- **Prédicat** : chaque raison, et leur ordre.
- **Jeton** : formats acceptés et refusés ; sérialisation de `StatusResponse`, de la réponse de `PUT`, et
  des `details` du journal, avec un jeton connu en place : la chaîne n'apparaît nulle part. Même
  contrôle sur `Display` et `Debug` de `FetchError` et sur le texte journalisé après un échec simulé
  d'une requête portant ce jeton.
- **`checksums.txt`** : valide, sans dernière ligne vide, doublon, un seul espace, majuscules, `/` dans le
  nom, `\r`, 33 lignes, 64 Kio dépassés.
- **Signature** (fixtures de §A-12) : valide → OK ; `checksums.txt` modifié d'un octet → refus ;
  `.minisig` absent → refus ; signature d'une autre clé → refus ; commentaire de confiance d'un autre tag
  → refus ; signature non pré-hachée (si `minisign -l` est disponible) → refus.
- **ID de clé** : égal à l'ID imprimé par minisign dans le `.pub` de la fixture.
- **Redirections** : `Authorization` seulement au saut 0 ; hôte hors liste refusé ; `http` refusé ;
  port 8443 refusé ; 4ᵉ redirection refusée ; `Location` relative résolue puis contrôlée.
- **Taille** : `Content-Length` > 200 Mio refusé ; flux plus long que le `size` annoncé coupé.
- **Aucune requête sans configuration** : `check_for_updates_inner` et `prepare` prennent le client par
  un trait (`ReleaseApi`) ; avec un faux qui compte, 0 appel ; `apply` non configuré donne 409
  `updates_not_configured` avant tout autre contrôle (fonction de décision pure).
- **Versions** : `3.0.0-rc.1 > 2.242.1` ; `3.0.0 > 3.0.0-rc.2` ; sélection : brouillon ignoré,
  pre-release seulement sur `candidate`, tag `-rc.N` non marqué traité comme pre-release, maximum par
  `release_key` même si GitHub renvoie un ordre différent.
- **Agents** : noms et tags autorisés pour A-6.9, alias `current` ; seuil `MIN_SIGNED_AGENT_VERSION` ;
  règle de cible de flotte.
- **Migration** : `sqlx` la charge (test existant des migrations, s'il y en a un).

### A-12 Fixtures
- Générées une fois avec minisign (paquet Debian, dans un conteneur `debian:bookworm-slim`), clé de test
  **sans phrase de passe** (`minisign -G -W`), commentaire de confiance `cyberhunter-release v9.9.9`.
- Commitées : `test.pub`, `checksums.txt`, `checksums.txt.minisig`, une variante signée par une autre clé.
  **La clé privée de test n'est pas commitée.**

## B. Agent et scripts
### B-1 Clé et vérification (`release_verify.rs`)
- Même lecture de `CYBERHUNTER_UPDATE_PUBKEY` et même `build.rs` que A (§2.3).
- Même analyseur de `checksums.txt` (§2.2) et même vérification (§2.3), écrits par B (pas de crate
  partagée entre agent et backend).

### B-2 `POST /panel/update` (agent)
- Corps et réponse inchangés (`{ target_version }` → 200 `{ accepted, target_version }`).
- Refus synchrones (texte brut, comme aujourd'hui) :
  - cible invalide → 400 (existant) ; déjà en cours → 409 (existant) ;
  - binaire `/usr/local/bin/dockpanel-api` présent → 409
    `This server is a full panel install, update it from its own panel` (le mode `FullPanel`, qui lançait
    `/opt/dockpanel/scripts/update.sh`, disparaît) ;
  - pas de `DOCKPANEL_CENTRAL_URL`/`DOCKPANEL_SERVER_TOKEN` → 412 `This agent has no panel URL (DOCKPANEL_CENTRAL_URL)` ;
  - pas de clé compilée → 412 `This agent build has no update signing key`.
- Puis tâche de fond, état `InFlight` :
  1. `GET {central}/api/agent/release/{tag}/checksums.txt.minisig`, puis `checksums.txt`, avec
     `Authorization: Bearer <DOCKPANEL_SERVER_TOKEN>`, sans suivre de redirection, 30 s chacun, ≤ 4 Kio et
     ≤ 64 Kio ;
  2. vérification minisign, commentaire `cyberhunter-release <tag>`, analyse ;
  3. `GET …/cyberhunter-agent-linux-<arch>`, ≤ 200 Mio, 600 s (le panel peut d'abord le chercher chez
     GitHub), SHA-256 égal au manifeste, magie ELF `7f454c46` ;
  4. écriture dans `/var/lib/dockpanel/agent-release/cyberhunter-agent-<tag>` (0700) ;
  5. `systemd-run` (comme aujourd'hui) de `agent-self-update.sh` avec
     `--setenv=DOCKPANEL_VERSION=<tag>`, `--setenv=DOCKPANEL_AGENT_STAGED_BIN=<chemin>`,
     `--setenv=DOCKPANEL_AGENT_STAGED_SHA256=<hex>`, `--setenv=DOCKPANEL_AGENT_UPDATE_DETACHED=1`.
- Échecs de la tâche → `Failed { reason }`, lus par le backend via `/panel/update/status` :
  - 409 du panel avec `updates_not_configured` → `Updates are not configured` ;
  - signature → `Signature check failed, nothing was installed` ;
  - SHA-256 ou ELF → `Checksum check failed, nothing was installed` ;
  - réseau ou autre statut → `Download failed (<statut>)`.
- La boucle `auto_update_loop` passe par la même fonction (inchangée sur ce point).

### B-3 `scripts/agent-self-update.sh`
- **Entrées** : `DOCKPANEL_VERSION` (obligatoire), `DOCKPANEL_AGENT_STAGED_BIN` et
  `DOCKPANEL_AGENT_STAGED_SHA256` (obligatoires ; sinon `fail verify "no verified agent binary was staged; start the update from the panel"`).
  `DOCKPANEL_GITHUB_REPO` et `dp_fetch` disparaissent : **aucun `curl` hors de la socket unix locale**.
- Étape `verify` : SHA-256 du fichier préparé égal à `DOCKPANEL_AGENT_STAGED_SHA256` (sinon sortie 99),
  magie ELF, taille > 1 Mo. Puis `swap`, `unit`, `restart`, `verify-running`, `rollback`, `complete`
  comme aujourd'hui (noms d'étapes et `POST_SWAP_STAGES` inchangés, verdict au même format).
- Le bloc de ré-exécution transmet les trois nouvelles variables. Le fichier préparé est supprimé à la
  sortie, sur tous les chemins.

### B-4 `scripts/update.sh`
- **Supprimés** : `GITHUB_REPO`, l'auto-rafraîchissement (`raw.githubusercontent.com`), la
  synchronisation `git fetch origin main` + `reset --hard` (sur les serveurs existants, `origin` pointe
  vers le dépôt amont), et tout téléchargement.
- **Mode release** (`INSTALL_FROM_RELEASE=1`) :
  - exige `CYBERHUNTER_RELEASE_DIR` ; sinon `error "Release updates are started from the panel (Telemetry, Updates). To update by hand, build from source."` et sortie 1 ;
  - `REPO_DIR` = dossier parent du script, donc `<release>/cyberhunter-source` : les unités, les modèles
    nginx et `install-agent.sh` viennent de la release vérifiée ;
  - avant toute modification, revérifie le SHA-256 de **chaque** fichier utilisé contre
    `$CYBERHUNTER_RELEASE_DIR/checksums.txt` (étape de verdict `verify`, échec fermé) ;
  - copie les binaires depuis le dossier de release (noms de §2.1), extrait
    `cyberhunter-frontend.tar.gz` comme aujourd'hui ;
  - recopie `<release>/cyberhunter-source/scripts/` vers `/opt/dockpanel/scripts/` (pour les usages SSH),
    **seulement après** le contrôle de santé réussi, juste avant le verdict `complete` ;
  - transmet `CYBERHUNTER_RELEASE_DIR` dans la liste `--setenv` de la ré-exécution `systemd-run`.
- **Mode source** (`BUILD_FROM_SOURCE=1` ou cargo présent) : inchangé, sans la synchronisation git.
- **Chaînes que B doit garder** (épinglées par les tests de A) : `last-panel-update.json`,
  `trap _dockpanel_on_exit EXIT`, `_dockpanel_write_result true "complete"`,
  `_dockpanel_write_result false "rollback"`, `exec systemd-run`, et aucun `--wait` ni `--pipe` sur une
  ligne non commentée. Format du verdict inchangé.

### B-5 `scripts/release.sh` (machine Windows, Git Bash, Docker, `gh`)
- **Usage** : `bash scripts/release.sh [--arm64] [--dry-run] [--notes-file <fichier>]`.
- **Variables** : `CYBERHUNTER_MINISIGN_KEY` (défaut `$HOME/.minisign/cyberhunter.key`),
  `CYBERHUNTER_MINISIGN_PUB` (défaut `$HOME/.minisign/cyberhunter.pub`), `CYBERHUNTER_RELEASE_REPO`
  (défaut `MrTheSkream/cyberhunter-panel`). Clés de test : mêmes variables vers d'autres fichiers, hors
  du dépôt.
- **Étapes** :
  1. versions identiques (agent, backend, cli, mcp, frontend) ; tag absent en local et sur GitHub ; dépôt
     propre (`git status --porcelain`, en ignorant seulement `panel/frontend/tsconfig.tsbuildinfo`) ;
  2. source = `git -c core.autocrlf=false archive --format=tar HEAD`, passée par stdin aux conteneurs
     (pas de fichiers Windows en CRLF, pas de conversion de chemins) ;
  3. compilation des quatre crates en release dans l'image `cyberhunter-release-build:<version de l'image>`
     (§B-5bis, construite par `docker build scripts/release-build` si elle manque), avec
     `-e CYBERHUNTER_UPDATE_PUBKEY=<2ᵉ ligne du .pub>` ; ARM64 seulement avec `--arm64` ;
     **jamais `rust:1-bookworm`** (glibc 2.36) ;
  4. frontend dans `node:22-bookworm` (`npm ci && npm run build`) ;
  5. assemblage des noms de §2.1, `cyberhunter-source.tar.gz` (§2.1), puis `checksums.txt` (§2.2), le
     tout dans `dist/release-<version>/` (`/dist/` est dans `.gitignore`, un second lancement reste possible) ;
  6. contrôles : `check-glibc.sh` sur chacun des binaires (§B-5bis, arrêt au premier refus) ; la clé
     base64 figure dans les binaires api et agent (`grep -c`) ; le résumé affiche l'ID de clé et, par
     binaire, la plus haute version `GLIBC_` requise ;
  7. signature : `minisign -S -s <key> -m checksums.txt -x checksums.txt.minisig -t "cyberhunter-release <tag>"`
     (phrase de passe demandée, jamais stockée) ; `minisign` natif s'il existe, sinon conteneur avec `-it`
     (`winpty` sous MSYS). **Sous Git Bash (MSYS) avec un `minisign` Windows natif**, le script ne le lance
     pas lui-même : la console ne lui transmet pas la phrase de passe (constaté en VM le 17/11/2026). Il
     affiche la ligne PowerShell exacte à lancer dans un autre terminal, puis attend Entrée jusqu'à ce que
     `checksums.txt.minisig` existe ; `CYBERHUNTER_SIGN_INLINE=1` force la signature directe. Dans tous les
     cas, puis `minisign -V` avec la clé publique ; puis contrôle que la signature est
     pré-hachée (les deux premiers octets du base64 décodé de la 2ᵉ ligne du `.minisig` valent `ED`, pas
     `Ed`), sinon arrêt : un minisign trop ancien publierait une release que tous les serveurs refusent ;
  8. résumé, puis `Publish <tag>? [y/N]` ; `--dry-run` s'arrête avant ;
  9. `git tag -a <tag> -m "CyberHunter <tag>"`, `git push origin <tag>`, puis
     `gh release create <tag> --repo <repo> --verify-tag --title "CyberHunter <tag>" [--prerelease] --notes-file <f> <fichiers>`
     (`--prerelease` si le tag contient `-rc.`).
- Les commentaires sur GitHub Actions, cosign et musl sont retirés.

### B-5bis Compilation compatible Ubuntu 22.04 (glibc 2.35)
- **Cible** : Ubuntu 22.04+ et Debian 12+, donc **glibc ≤ 2.35** pour tous les binaires de release.
- **Méthode : compiler sur la glibc la plus ancienne visée.** `scripts/release-build/Dockerfile` :
  - `FROM ubuntu:22.04@sha256:<empreinte>` (empreinte relevée par B au moment de l'écriture, avec
    `docker buildx imagetools inspect ubuntu:22.04`) ;
  - `apt-get install --no-install-recommends build-essential cmake pkg-config ca-certificates curl` (plus
    `gcc-aarch64-linux-gnu libc6-dev-arm64-cross` pour `--arm64`, chaîne croisée de 22.04, glibc 2.35
    aussi) ;
  - rustup en `--profile minimal`, toolchain **épinglée** `1.100.0` (celle de `rust:1-bookworm`
    aujourd'hui, mesurée : `rustc 1.100.0 (0ef1bc386 2026-11-09)`), cibles `x86_64-unknown-linux-gnu`
    et, en option, `aarch64-unknown-linux-gnu` ;
  - un `LABEL org.cyberhunter.release-build=<n>` versionné. `release.sh` construit l'image si l'étiquette
    manque, et ne la reconstruit que si `n` change.
- **Pourquoi pas cargo-zigbuild** : il ajoute deux outils à épingler (zig et cargo-zigbuild), et les
  dépendances C (`aws-lc-sys`, `tikv-jemalloc-sys`) passeraient par `zig cc`, ce qui se casse plus
  souvent qu'avec gcc. Compiler sur 22.04 garantit le plafond 2.35 par construction, sans aucune
  option ; le contrôle ci-dessous attrape le reste.
- **Dépendances natives** (relevées dans les quatre `Cargo.lock`) :
  - `aws-lc-sys` 0.44 (agent, backend ; via `jsonwebtoken` `aws_lc_rs` et rustls) : C et assembleur,
    compilé avec gcc ; `cmake` est installé par précaution. Pas de bindgen nécessaire sur x86_64 et
    aarch64 Linux (liaisons pré-générées) ;
  - `ring` (cli, mcp, et via rustls) : C compilé par `cc` ;
  - `tikv-jemalloc-sys` (agent, backend) : `configure` et `make`, fournis par `build-essential` ;
  - **pas d'OpenSSL** : `reqwest` et `sqlx` sont en rustls ; `openssl-probe` n'est que du Rust (recherche
    des certificats) ;
  - `libsqlite3-sys` figure dans le `Cargo.lock` du backend mais n'est pas lié (sqlx sans `sqlite`).
  - Mesure sur les binaires actuels du lab (compilés dans bookworm) : ils ne dépendent que de
    `libc.so.6`, `libm.so.6` et `libgcc_s.so.1`, et demandent au plus `GLIBC_2.34`. Rien n'oblige donc
    une version de glibc plus récente aujourd'hui. Le contrôle garde ce plafond pour les versions futures.
  - **Recette de B** : une compilation complète des quatre crates dans l'image est la preuve attendue
    (sortie de `check-glibc.sh` jointe au compte rendu).
- **`check-glibc.sh <binaire> [max=2.35]`**, lancé **dans l'image** (binutils de 22.04) :
  - `readelf --version-info --wide` → toutes les versions `GLIBC_2.N` demandées (section
    `.gnu.version_r`), `GLIBC_PRIVATE` refusé, maximum comparé numériquement (`sort -V`). Au-dessus de
    `2.35` : `ERROR: <binaire> requires GLIBC_<v> (max 2.35)` et sortie 1 ;
  - `readelf -d` : les `NEEDED` doivent être dans `libc.so.6`, `libm.so.6`, `libgcc_s.so.1`,
    `libpthread.so.0`, `libdl.so.2`, `librt.so.1`, `ld-linux-x86-64.so.2`, `ld-linux-aarch64.so.1`.
    Toute autre bibliothèque (ex. `libssl.so.3`, `libsqlite3.so.0`) : `ERROR: <binaire> needs <lib>`,
    sortie 1 ;
  - binaire non ELF : sortie 1.
- **Lab** : `lab/build.sh` (hors périmètre, à personne) reste sur `rust:1-bookworm` pour les tests ;
  seuls les binaires de release sont soumis au plafond.
- **Refus explicites d'Ubuntu 22.04 ailleurs** (relevé seulement, rien à changer) :
  - aucun test de version d'Ubuntu ou de Debian dans `panel/agent/src`, `panel/backend/src`,
    `scripts/setup.sh`, `scripts/install-agent.sh` ou `scripts/update.sh` ; `setup.sh` accepte
    `ubuntu|debian` sans version (l. 469) ;
  - le terminal utilisateur (09) exige systemd ≥ 248 (`user_terminal::is_supported`) : 22.04 a
    systemd 249, il est donc pris en charge ;
  - à vérifier en VM 22.04 (pas un refus explicite) : la PHP par défaut est 8.1 (`setup.sh` ajoute
    `ppa:ondrej/php` si besoin), et `curl` 7.81 (`--retry-all-errors` disponible).

### B-6 Installation et autres scripts
- **`install-agent.sh`** : télécharge depuis le panel, plus depuis GitHub :
  `curl -fsSL -H "Authorization: Bearer $TOKEN" "$PANEL_URL/api/agent/release/current/<nom>"` pour
  `checksums.txt` et `cyberhunter-agent-linux-<arch>`. Le SHA-256 est **obligatoire** (manifeste ou
  entrée absente = arrêt). Pas de minisign en shell : l'ancre de confiance de ce script est le panel
  lui-même (l'opérateur exécute le script servi par le panel), et l'agent installé vérifie ensuite seul
  les signatures. Message d'échec : `Could not download the agent from the panel. Check that updates are configured on the panel (Telemetry, Updates) and that the token is valid.`
- **`setup.sh`** : plus de `GITHUB_REPO` ni de téléchargement GitHub. `INSTALL_FROM_RELEASE=1` exige
  `CYBERHUNTER_RELEASE_DIR` (une release téléchargée à la main), avec vérification SHA-256 obligatoire
  contre son `checksums.txt` et les noms de §2.1. La ligne « Open an issue » est retirée.
- **`install.sh`** : URL de clonage via `CYBERHUNTER_REPO_URL`, obligatoire, sans valeur par défaut
  (dépôt privé : l'authentification git est à la charge de l'opérateur). Ligne `Usage` mise à jour.
- **`deploy-demo.sh`** : `GITHUB_REPO="${GITHUB_REPO:?GITHUB_REPO is required}"`, sans défaut.
- **Premier passage en 3.0.0** : un serveur en 2.242.1 ne sait pas vérifier une signature. On installe
  donc la première 3.0.0 à la main (SSH), panel et agents ; ensuite tout passe par l'interface.

### B-7 Tests unitaires de l'agent
- `checksums.txt` et signature : mêmes cas que A-11 (fixtures propres à B).
- SHA-256 différent, magie ELF absente, taille > 200 Mio : refus, rien n'est préparé.
- URL construite : `{central}/api/agent/release/{tag}/{nom}` avec l'architecture de la machine.
- Refus `FullPanel`, refus sans URL du panel, refus sans clé.
- Épingles de `agent-self-update.sh` (embarqué) : aucun `curl` sauf `--unix-socket` ; variables
  `DOCKPANEL_AGENT_STAGED_*` exigées ; revérification SHA-256 ; `systemd-run`, `--collect`, pas de
  `--scope` ; étapes et `POST_SWAP_STAGES` inchangés. Mettre à jour les épingles existantes qui citaient
  `dp_fetch` ou `checksums.txt` téléchargé.

### B-8 Tests shell (`tests/`, lancés sur l'arbre fusionné)
- **`tests/no-upstream-repo-pin.sh`** :
  - `git grep -n -i -e "<mot interdit>" -- panel scripts` doit être vide (fichiers suivis seulement) ; le
    mot est assemblé dans le script (`"ovex""ro"`) pour qu'il ne se trouve pas lui-même ;
  - `git grep -n -e "api.github.com" -e "releases/download" -e "raw.githubusercontent" --` sur la liste
    fermée suivante est vide : `scripts/update.sh`, `scripts/agent-self-update.sh`,
    `scripts/install-agent.sh`, `scripts/install.sh`, `scripts/setup.sh`,
    `panel/backend/src/services/telemetry_collector.rs`, `panel/backend/src/services/panel_update.rs`,
    `panel/agent/src/routes/panel_update.rs`, `panel/agent/src/services/phone_home.rs`,
    `panel/agent/src/services/release_verify.rs`. La liste est fermée exprès : d'autres fonctions
    légitimes appellent GitHub (OAuth, statuts git, Joomla, nixpacks, typst) et ne sont pas concernées ;
    `deploy-demo.sh` garde ses URL mais sans dépôt par défaut. A reformule donc les deux commentaires
    de `panel_update.rs` qui citent `releases/download` (l. 442 et 1054).
  - Il échoue tant que A et B ne sont pas tous deux fusionnés : c'est attendu.
- **`tests/update-release-dir-pin.sh`** : `update.sh` exige `CYBERHUNTER_RELEASE_DIR` en mode release,
  revérifie le SHA-256, ne contient ni `git fetch` ni `raw.githubusercontent` ; les chaînes de §B-4 sont
  présentes ; `bash -n` de tous les scripts modifiés (et `shellcheck` s'il est installé).
- **`tests/release-format-pin.sh`** : `release.sh` cite exactement les noms de §2.1, le commentaire
  `cyberhunter-release`, `core.autocrlf=false` ; exécution de l'étape de sommes sur des fichiers factices
  et contrôle du format de §2.2 ; le `Dockerfile` part de `ubuntu:22.04@sha256:` et épingle une
  toolchain `x.y.z` exacte ; `release.sh` ne cite pas `rust:1-bookworm` ; `check-glibc.sh` refuse une
  sortie `readelf` factice qui demande `GLIBC_2.36` ou un `NEEDED` `libssl.so.3`, et accepte
  `GLIBC_2.34`.
- Les épingles existantes de `tests/` cassées par les nouveaux noms sont mises à jour.

## C. Interface (onglet « Updates » de `/telemetry`, conservé à sa place)
### C-1 Données
- Source unique : `GET /api/update/status` (A-6.1). Le type `UpdateStateView` reçoit les nouveaux champs.
- « Check now » appelle `POST /api/update/manual-check` (plus `/telemetry/check-updates`), puis recharge
  le statut.
- Les erreurs s'affichent avec `ApiError.message` tel quel. `code === "updates_not_configured"` →
  recharger le statut.

### C-2 Non configuré
- Titre : « Updates are not configured ».
- Raison :
  - `no_signing_key` : « This build has no update signing key. Install a signed CyberHunter release by hand to enable updates. »
  - `no_source` ou `no_token` : « Add a GitHub fine-grained token with read-only access to Contents of the release repository. »
- « Check now » désactivé, aucun bouton d'installation, carte de la source (C-3) visible.

### C-3 Carte « Update source »
- « Release repository » : champ texte prérempli avec `repo` (vide si `null` ; le backend applique son
  défaut). Pas de nom de dépôt codé en dur dans l'interface.
- « GitHub token » : champ `type="password"`, `autocomplete="off"`, placeholder `github_pat_...`, jamais
  prérempli. État : « Token set » ou « No token ».
- Boutons « Save token » (« Replace token » si `token_set`) → `PUT /api/update/source` ; le champ est
  vidé après la réponse, réussie ou non. « Clear token » → confirmation « Clear the update token? Updates
  will be disabled until a new token is saved. » → `DELETE /api/update/source/token`.
- « Signing key ID: <id> », ou « No signing key in this build ».

### C-4 Configuré
- Version installée, « Last checked » (`checked_at`), canal, `last_check_error` en rouge s'il existe.
- Canal : « Stable », « Beta (pre-releases) », « Hold (no automatic checks) » → `PUT /api/update/channel`
  avec `stable`, `candidate`, `hold`.
- Mise à jour disponible : « v<version> » avec un badge « Pre-release » si `available_prerelease`, les
  notes en **texte brut** (`whitespace-pre-wrap`, nœud texte React ; ni `marked` ni
  `dangerouslySetInnerHTML`), le lien « View on GitHub » (`release_url`), et le bouton
  « Install v<version> ».
- Confirmation : « Install v<version>? A snapshot is taken first. » → `POST /api/update/apply`.
- Après le 202, l'interface suit `GET /api/update/status` comme aujourd'hui : `in_flight` affiche
  `last_log_line` (d'abord `Downloading and verifying release`) ; `failed` affiche `reason` en rouge (par
  exemple « Signature check failed, nothing was installed »).
- Instantanés, retour arrière, verdicts : inchangés.

### C-5 Flotte
- Cible préremplie avec `v<current_version>`. Aide : « Agents can only move to this panel's version, or
  to the advertised update when the panel is included. »
- Section désactivée si non configuré. Les erreurs par serveur s'affichent telles quelles.

### C-6 Tableau de bord
- Bandeau seulement si `configured && update_available` (`/api/telemetry/update-status`).

### C-7 Contrôles de C
- Pas de lanceur de tests dans le frontend, et on n'en ajoute pas. Contrôles :
  - `npm run build` (`tsc -b` + `vite build`) passe ;
  - `git grep -n "dangerouslySetInnerHTML\|marked" -- panel/frontend/src/pages/Telemetry.tsx` ne
    trouve rien de nouveau ;
  - aucun tiret cadratin dans les libellés ajoutés ;
  - vérification visuelle en VM (§V).

## V. Plan de test en VM (instantané Hyper-V avant chaque série)
**Préparation (propriétaire)** :
- paire de clés de **test** hors du dépôt :
  `minisign -G -p ~/.minisign/cyberhunter-test.pub -s ~/.minisign/cyberhunter-test.key` ;
- jeton fine-grained de test : ce dépôt seulement, Contents: read-only ;
- compilation du lab avec la clé de test :
  `docker run … -e CYBERHUNTER_UPDATE_PUBKEY=<2ᵉ ligne du .pub de test> … rust:1-bookworm bash /src/lab/build.sh release agent backend cli mcp`,
  frontend compilé, puis `lab/deploy.ps1` (version `3.0.0-rc.1`) ;
- releases de test publiées depuis une branche jetable `vm/updates`, où l'on fait seulement le commit de
  version de chaque rc, avec
  `CYBERHUNTER_MINISIGN_KEY=~/.minisign/cyberhunter-test.key CYBERHUNTER_MINISIGN_PUB=~/.minisign/cyberhunter-test.pub bash scripts/release.sh`.

**Scénarios** :
1. **Sans configuration** : « Updates are not configured » ; `POST /api/update/apply` → 409
   `updates_not_configured` ; `manual-check` → 409 ; aucune connexion vers GitHub
   (`journalctl -u dockpanel-api | grep -c api.github.com` = 0, et `ss -tnp` pendant un « Check now »).
   L'ancienne annonce héritée a disparu (migration).
2. **Jeton enregistré** : « Token set », « Signing key ID » = ID de la clé de test. Un jeton faux →
   « The update token is missing or expired ».
3. **Canaux** : publier `v3.0.0-rc.2` (notes contenant `<b>bold</b>`). Sur « Stable », « Check now » ne
   propose rien. Sur « Beta », rc.2 est proposée avec le badge « Pre-release », et les notes s'affichent
   littéralement.
4. **Installation** : « Install v3.0.0-rc.2 » → 202 → le panel revient en `3.0.0-rc.2`, version de
   l'agent local aussi ; `/opt/dockpanel/scripts/update.sh` est la nouvelle version ; journal
   `update.apply_started` puis `update.apply_succeeded` ; **relever l'hôte de redirection** dans le log
   et l'ajuster dans `ALLOWED_DOWNLOAD_HOSTS` si besoin.
5. **Release piégée** : `v3.0.0-rc.3` construite avec `--dry-run`, puis `checksums.txt` modifié après
   signature, publiée à la main (`gh release create --prerelease`) → « Signature check failed, nothing
   was installed », version inchangée, pas de nouvel instantané, journal `update.apply_failed`. Variante :
   sans `.minisig` → même refus. Variante (liaison au tag) : le jeu complet et intact de rc.2 republié
   sous le tag `v3.0.0-rc.3` → même refus.
6. **Retour arrière automatique** : `v3.0.0-rc.4` dont `cyberhunter-api-linux-amd64` est un ELF qui
   s'arrête aussitôt (ex. `/bin/false` copié), avec `checksums.txt` régénéré et signé à la main avec la
   clé de test → l'installation se lance, `update.sh` restaure les `.bak`, l'état passe à `rolled_back`,
   journal `update.rolled_back`.
7. **Agent distant sans jeton** : prérequis, une URL de panel dont le certificat est reconnu par la
   seconde VM. L'agent (`reqwest` avec rustls et ses racines embarquées) et `install-agent.sh` (`curl`
   sans `-k`) refusent un certificat auto-signé, comme le fait déjà le `checkin`. Une seconde VM sur le
   même commutateur, installée avec la commande
   « Add server » (donc `install-agent.sh` depuis le panel, `current`), agent en `3.0.0-rc.2`. Publier
   `v3.0.0-rc.5` (saine), flotte avec `include_panel` vers rc.5 : l'agent se met à jour, puis le panel.
   Sur la seconde VM : pas de `/etc/dockpanel/update-token`, et le journal de l'agent ne montre que
   l'URL du panel.
8. **Agent hérité** (facultatif) : un agent `2.242.1` dans la flotte → échec de ce serveur avec le
   message de A-6.8, aucune requête envoyée.
9. **Jeton effacé** : « Clear token » → « Updates are not configured » ; apply, check et flotte → 409 ;
   l'agent distant reçoit `target_version: null` ; « Rollback » d'un instantané fonctionne encore.
10. **Ubuntu 22.04** : la seconde VM du scénario 7 est installée en Ubuntu 22.04. L'agent de release
    y démarre (`systemctl is-active dockpanel-agent`), et `ldd /usr/local/bin/dockpanel-agent` ne
    signale aucune version manquante. Le résumé de `release.sh` montre `GLIBC_` ≤ 2.35 pour chaque binaire.
11. **Nettoyage** : `gh release delete <tag> --cleanup-tag --yes` pour chaque rc de test, suppression de
    la branche `vm/updates`, retour à l'instantané.

## F. Fusion
1. Étape 0 commitée, puis worktrees A, B, C depuis ce commit.
2. Fusion de A, B et C dans n'importe quel ordre (aucun fichier commun).
3. Sur l'arbre fusionné : `lab/build.sh test agent backend cli` (avec et sans
   `-e CYBERHUNTER_UPDATE_PUBKEY`), `npm run build` dans `panel/frontend`, `tests/no-upstream-repo-pin.sh`,
   `tests/update-release-dir-pin.sh`, `tests/release-format-pin.sh`.
4. Plan VM (§V).
5. Release `v3.0.0` : commit de version `3.0.0`, `release.sh` avec la clé de production, installation à
   la main de cette première 3.0.0 sur les serveurs existants (§B-6).

## D. Décisions prises dans ce contrat, à confirmer par le propriétaire
1. **Binaires glibc compilés sur Ubuntu 22.04** (image épinglée, toolchain 1.100.0), plafond
   `GLIBC_2.35` contrôlé par `release.sh` : Ubuntu 22.04+ et Debian 12+ (confirmé par le propriétaire :
   22.04 obligatoire). L'interface reste dans Telemetry → Updates (confirmé).
2. **Version de développement `3.0.0-rc.1`**, releases de test `rc.2` à `rc.5` depuis une branche jetable.
3. **Les scripts ne vérifient pas la signature** : le binaire Rust vérifie, le script revérifie le
   SHA-256. Pas de copie de la clé dans `update.sh`, et `update.conf` n'est lu que par le backend.
4. **Plus de téléchargement GitHub depuis un script** : `update.sh` à la main en mode release est
   refusé ; `setup.sh` en mode release exige une release locale ; `install.sh` exige
   `CYBERHUNTER_REPO_URL` ; `install-agent.sh` passe par le panel (SHA-256 seulement).
5. **Tout est coupé sans configuration**, flotte et agents compris ; seul le retour arrière par
   instantané reste possible.
6. **Cible de flotte limitée** à la version du panel, ou à la version annoncée avec `include_panel`.
7. **Agents antérieurs à 3.0.0-rc.1** exclus des mises à jour de flotte : réinstallation à la main.
8. **L'interface reste dans Telemetry → Updates** (pas Settings), et le canal `candidate` est affiché
   « Beta (pre-releases) ».
9. **Commentaire de confiance** `cyberhunter-release <tag>` obligatoire.
10. **Mode `FullPanel` de l'agent supprimé** : un serveur qui porte un panel se met à jour par son panel.
11. **SBOM retirés** des releases ; mcp inclus.
12. **Dépôt par défaut compilé** `MrTheSkream/cyberhunter-panel`, modifiable dans l'interface.
13. **Installation asynchrone** : `apply` répond 202 après les contrôles rapides ; les erreurs de
    téléchargement ou de signature apparaissent dans l'état `failed` du statut, pas dans la réponse HTTP
    (coupure du proxy à 300 s).
14. **Test d'agent distant en VM** : il faut une URL de panel avec un certificat reconnu (l'agent refuse
    l'auto-signé).
15. `panel/frontend/tsconfig.tsbuildinfo` est ignoré par le contrôle « dépôt propre » de `release.sh` ;
    il vaudrait mieux le retirer du suivi git.
