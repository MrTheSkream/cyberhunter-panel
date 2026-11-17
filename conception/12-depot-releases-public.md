# 12 - Dépôt public de releases (conception)

État : **validé le 17/11/2026** (les trois points de la fin acceptés tels quels).

## But

Qu'un ami puisse installer et mettre à jour CyberHunter - Panel **sans jeton GitHub et sans accès au
dépôt privé**, sans rien perdre de la sécurité de la fonctionnalité 10 : une release qui n'est pas
signée par la clé compilée dans le panel est toujours refusée.

Le dépôt de développement `MrTheSkream/cyberhunter-panel` reste privé : historique, `conception/`,
`lab/`, tests, issues. Seules les releases deviennent publiques.

## Constat (code actuel)

- `update_source.rs` : les mises à jour exigent trois choses, la clé compilée, `update.conf` et un jeton
  non vide (`no_token`). Dépôt par défaut : `MrTheSkream/cyberhunter-panel`.
- `release_fetch.rs` : chaque appel à `api.github.com` porte `Authorization: Bearer <jeton>`.
- `scripts/release.sh` publie sur le dépôt privé, avec `gh release create --verify-tag` (le tag doit
  exister dans le dépôt cible).
- `scripts/install.sh` fait un `git clone` du dépôt privé (`CYBERHUNTER_REPO_URL` obligatoire) : sans
  accès au dépôt, **un ami ne peut même pas installer**. Les binaires d'une release doivent en plus être
  téléchargés à la main.
- Chaque release contient déjà `cyberhunter-source.tar.gz` (`git archive HEAD -- scripts panel`), ce qui
  fournit le code source de chaque version, comme l'exige l'AGPL v3. `conception/`, `lab/` et `tests/` n'y
  figurent pas. Recherche faite dans `scripts` et `panel` : aucun secret, seulement des IP de lab privées
  dans des tests unitaires.

## Décisions proposées

### D1. Un dépôt public dédié : `MrTheSkream/cyberhunter-releases`

- Contenu du dépôt : `README.md` (installation, ID de la clé de signature, lien vers le source de chaque
  release), `LICENSE` (AGPL v3), `install.sh`. Aucun code du panel dans l'historique git.
- Les releases (binaires, `cyberhunter-frontend.tar.gz`, `cyberhunter-source.tar.gz`, `checksums.txt`,
  `checksums.txt.minisig`) y sont publiées par `release.sh`.
- **Conséquence à accepter :** le code de chaque version publiée devient téléchargeable par tout le monde
  (archive source). C'est ce que demande l'AGPL dès qu'on distribue les binaires à quelqu'un. Ce qui
  reste privé : l'historique, les documents de conception et le lab.

### D2. Le jeton devient facultatif

- Prédicat : clé compilée + source valide. Le jeton n'est plus exigé, et la raison `no_token` disparaît.
- Sans jeton : requêtes anonymes à `api.github.com`. La limite est de 60 requêtes par heure et par IP ;
  une vérification en coûte environ 3, et le poller passe toutes les 6 h, donc la marge est large.
- Avec jeton : comportement inchangé. C'est ce qui permet de garder un dépôt privé si on le souhaite
  (lab, ou retour arrière sur ce choix).
- `update.conf` absent : source par défaut `MrTheSkream/cyberhunter-releases`, sans jeton. Une
  installation neuve fonctionne donc **sans aucune configuration**. Un `update.conf` invalide donne
  toujours `no_source`.
- Erreur claire : une réponse 404 sans jeton s'affiche « Repository not found or private. Add a token if
  the release repository is private. »
- Carte « Update source » : le champ jeton devient facultatif, avec le texte « Token (only for a private
  repository) ». Le dépôt affiché reste modifiable comme aujourd'hui.
- Signature, trusted comment `cyberhunter-release <tag>`, sommes, liste fermée d'hôtes de redirection :
  **aucun changement**.

### D3. Publication (`release.sh`)

- Dépôt cible par défaut : `MrTheSkream/cyberhunter-releases` (on peut toujours le changer avec
  `CYBERHUNTER_RELEASE_REPO`).
- Le tag `v3.0.0-rc.N` reste créé et poussé dans le dépôt privé, pour la traçabilité, avec les mêmes
  vérifications qu'aujourd'hui (arbre propre, tag sur `HEAD`).
- Sur le dépôt public, la release est créée avec `--target main` au lieu de `--verify-tag` : GitHub crée
  le tag sur le commit du README. Le lien avec le code passe par la signature (le tag figure dans le
  trusted comment) et par l'archive source jointe.
- `LICENSE` est ajouté à `cyberhunter-source.tar.gz`.

### D4. Installation sans dépôt privé (`install.sh`)

Nouveau mode par défaut : **release**.
1. Récupère la release voulue (`DOCKPANEL_VERSION`, sinon la dernière stable) par l'API anonyme ;
   télécharge `checksums.txt` et `checksums.txt.minisig`.
2. Vérifie la signature avec `minisign` (paquet Ubuntu, dépôt universe ; **disponibilité sur 22.04 à
   vérifier en VM**) contre la clé publique **écrite en dur dans `install.sh`**. Le trusted comment doit
   valoir `cyberhunter-release <tag>`. En cas d'échec, l'installation s'arrête.
3. Télécharge les fichiers et vérifie chacun contre `checksums.txt`, comme le fait déjà `setup.sh`.
4. Extrait `cyberhunter-source.tar.gz` dans `/opt/dockpanel`, puis lance `setup.sh` avec
   `INSTALL_FROM_RELEASE=1`.

Les modes actuels restent disponibles : `CYBERHUNTER_REPO_URL=...` (clone + compilation) et
`CYBERHUNTER_RELEASE_DIR=...` (release déjà téléchargée).

Commande pour un ami :
```
curl -fsSLO https://github.com/MrTheSkream/cyberhunter-releases/releases/latest/download/install.sh
sudo bash install.sh
```

**Limite honnête :** le tout premier `install.sh` vient de GitHub. Quelqu'un qui contrôlerait le compte
pourrait le remplacer. C'est inévitable pour un premier téléchargement. Pour s'en protéger, le README
publie l'ID de la clé et la commande de vérification : `install.sh` est une pièce de la release, listée dans
`checksums.txt` signé (`minisign -Vm checksums.txt -P <clé>` puis `sha256sum -c --ignore-missing`). Ensuite,
toutes les mises à jour sont vérifiées par le panel lui-même.

### D5. Ce qui ne change pas

- Agents distants : ils se mettent à jour depuis le panel central (`agent_updates.rs`), pas depuis GitHub.
- Instantanés : le jeton éventuel reste exclu (ed83afc).
- Clé de production : à générer comme prévu en section 2 de `11-mise-en-production.md`. Elle sera
  compilée dans le panel **et** écrite dans `install.sh`.

### D6. Suppression de la signature minisign (décision du 17/11/2026)

Constat de l'implémentation : le paquet `minisign` n'existe pas sur Ubuntu 22.04 (il existe sur 24.04).
Décision de l'utilisateur, prise **en connaissance du risque** : supprimer la signature **partout** et
revenir au modèle de DockPanel. Cette décision remplace la vérification par minisign décrite dans D2 à D5
et dans la fonctionnalité 10.

Ce qui disparaît :
- la clé minisign (plus de `CYBERHUNTER_UPDATE_PUBKEY` à la compilation, plus de clé dans `install.sh`) ;
- `checksums.txt.minisig` et l'étape de signature de `release.sh` (et donc l'invite PowerShell) ;
- le trusted comment `cyberhunter-release <tag>` ;
- la raison `no_signing_key` et l'affichage « Signing key ID » ;
- la même vérification dans la mise à jour des agents distants.

Ce qui reste :
- `checksums.txt` produit par `release.sh` ; chaque fichier est contrôlé (SHA-256 et taille) contre ce
  manifeste, dont le format est vérifié strictement ; tout écart ou fichier manquant interrompt
  l'opération (fail closed) ;
- HTTPS seulement, liste fermée d'hôtes, redirections suivies à la main ;
- validation du tag et de la version, limites de taille ;
- non-fuite du jeton (facultatif), refus d'un panel en http pour l'agent ;
- prédicat « configuré » = source valide (`update.conf` valide ou absent).

Risque accepté : les sommes viennent de la même release que les binaires. Quelqu'un qui prend le contrôle
du compte GitHub `MrTheSkream` (ou du dépôt de releases) peut publier une mise à jour piégée, que chaque
panel installera en root. Protection restante : la sécurité du compte GitHub (2FA, clés, jetons limités).

## Tests prévus

Unitaires (backend) :
- prédicat sans jeton = configuré ;
- `update.conf` absent = dépôt public par défaut ;
- aucune en-tête `Authorization` sans jeton ;
- 404 anonyme = message dédié ;
- les tests de non-fuite du jeton restent en place.

Shell :
- `release.sh --dry-run` vise le dépôt public, sans `--verify-tag` ;
- `install.sh` refuse une signature absente, fausse, ou pour un autre tag (trusted comment), et refuse
  une somme fausse.

VM (instantané avant chaque étape) :
1. Release `rc` de test publiée sur `cyberhunter-releases` avec la clé de test.
2. Installation à neuf **sans jeton** sur une VM Ubuntu 22.04 vierge par la commande ci-dessus. Cette
   étape avance aussi la section 3 de `11-mise-en-production.md`.
3. « Check now » puis installation de `rc+1` sans jeton.
4. Release falsifiée (signée avec une autre clé) : refusée par `install.sh` et par le panel.
5. VM de lab actuelle avec jeton et dépôt privé : fonctionne toujours (non-régression).

## Points à trancher avec toi

1. Accepter que le code de chaque version publiée soit public (archive source, obligation AGPL).
2. Nom du dépôt : `cyberhunter-releases` ?
3. Installation par défaut en mode release (D4) dans cette même fonctionnalité, ou plus tard ?
   Sans elle, un ami ne peut pas installer : je recommande de la faire maintenant.
