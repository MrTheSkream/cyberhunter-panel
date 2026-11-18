# Déployer par l'API avec une clé `dp_`

Ce guide s'adresse à un agent (Claude ou un script) qui pilote CyberHunter - Panel avec une clé API `dp_` d'un compte administrateur. Les blocs `bash` s'exécutent dans l'ordre, du début à la fin.

**Portée des tests.** Tous les blocs `bash` et les erreurs marquées « observée » ont été exécutés sur la version 3.0.0-rc.3, dans une VM Ubuntu 24.04. L'émission d'un vrai certificat Let's Encrypt n'a pas pu être testée, car les domaines du labo n'ont pas de DNS public : seuls son refus (412) et le téléversement d'un certificat l'ont été. Pour le déploiement Git, le dépôt de test est public et le second commit provenait d'un dépôt local à la VM, car le panel refuse les adresses privées et aucun commit ne pouvait être poussé sur ce dépôt. Les dépôts privés par clé SSH n'ont pas été testés.

## Règles pour l'agent

- Ne jamais afficher, journaliser ni committer la clé `dp_`. Elle donne les droits complets du compte.
- Ne jamais désactiver la vérification TLS en production (`-k`, `--insecure`).
- Avant une suppression, relire le site ou l'application visé et vérifier son domaine.
- Après chaque écriture, vérifier le résultat réel (HTTP, en-têtes), pas seulement le code de réponse de l'API.
- Attendre 3 secondes avant cette vérification. L'API répond avant que nginx ait fini de recharger sa configuration, et un contrôle immédiat peut encore voir l'ancienne.
- Ne pas relancer en boucle une émission de certificat refusée : les limites de l'autorité de certification s'aggravent à chaque essai.

## 1. Préparer la session

Prérequis : `curl` 7.81 ou plus récent et `jq`.

```bash
export PANEL_URL="${PANEL_URL:-https://panel.example.com}"   # sans /api final
export SERVER_IP="${SERVER_IP:-203.0.113.10}"                # IP publique du serveur
export DOMAIN="${DOMAIN:-app.example.com}"                   # site à créer
export UPSTREAM_PORT="${UPSTREAM_PORT:-5962}"                # port local de l'application
export APP_DOMAIN="${APP_DOMAIN:-outil.example.com}"         # domaine de l'app Docker
: "${DP_KEY:?Chargez la clé dans DP_KEY depuis un coffre, jamais en clair dans le script}"

# Corps de la réponse sur stdout, code HTTP sur stderr.
api() {
  local method=$1 path=$2; shift 2
  curl -sS --max-time 180 ${PANEL_CURL_OPTS:-} -X "$method" "$PANEL_URL/api$path" \
    -H "Authorization: Bearer $DP_KEY" \
    -H 'Content-Type: application/json' \
    -w '%{stderr}HTTP %{http_code}\n' "$@"
}
```

Vérifiez la clé et son rôle. Le champ `role` doit valoir `admin`.

```bash
api GET /auth/me | jq '{role}'
curl -sS ${PANEL_CURL_OPTS:-} "$PANEL_URL/api/health" | jq '{status, version}'
```

## 2. Créer un site proxy avec toutes ses options

### Créer le site

`proxy_port` est le port local de l'application, entre 1024 et 65535.

```bash
SITE_ID=$(api POST /sites -d "$(jq -n --arg d "$DOMAIN" --argjson p "$UPSTREAM_PORT" \
  '{domain: $d, runtime: "proxy", proxy_port: $p}')" | jq -r .id)
echo "SITE_ID=$SITE_ID"
```

Réponse attendue : `HTTP 201` et un identifiant de site.

### Régler la taille maximale et les directives nginx

**`PUT /limits` remplace tout.** Un champ absent est remis à zéro : `rate_limit` et `custom_nginx` sont effacés. Partez donc toujours de la valeur actuelle, comme ci-dessous.

```bash
api GET "/sites/$SITE_ID" \
  | jq '{rate_limit, max_upload_mb, php_memory_mb, php_max_workers, custom_nginx, bandwidth_quota_mb}
        + {max_upload_mb: 16, custom_nginx: "add_header X-Robots-Tag \"noindex, nofollow\" always;"}' \
  | api PUT "/sites/$SITE_ID/limits" -d @- \
  | jq '{max_upload_mb, custom_nginx}'
```

Retirez le `X-Robots-Tag` en production si le site doit être indexé.

### Activer le streaming et l'IP client stricte

```bash
api PUT "/sites/$SITE_ID/proxy-options" \
  -d '{"proxy_streaming": true, "proxy_strict_client_ip": true}'
```

| Option | Effet | Quand l'activer |
|---|---|---|
| `proxy_streaming` | Désactive `proxy_buffering` et `proxy_request_buffering` | Gros transferts, flux continus |
| `proxy_strict_client_ip` | `X-Forwarded-For` ne contient que l'IP vue par nginx, toute valeur envoyée par le client est ignorée | Uniquement si nginx reçoit directement les visiteurs |

**Derrière Cloudflare ou un autre proxy, laissez `proxy_strict_client_ip` à `false`.** Sinon, l'application verrait l'adresse du proxy pour tous les visiteurs.

### Définir la politique des permissions

Cet appel remplace `csp_policy` et `permissions_policy` ensemble. Renvoyez donc les deux.

```bash
api GET "/sites/$SITE_ID" \
  | jq '{csp_policy, permissions_policy: "camera=(), microphone=(), geolocation=()"}' \
  | api PUT "/sites/$SITE_ID/security-headers" -d @-
```

Les en-têtes HSTS, `X-Content-Type-Options`, `X-Frame-Options` et `Referrer-Policy` sont posés par défaut. Si l'application envoie sa propre valeur, c'est la sienne qui est conservée.

### Ajouter les alias et le domaine canonique

`canonical_host` vaut `apex`, `www` ou `null`. Avec `apex`, chaque alias redirige en 301 vers le domaine du site, en gardant le chemin et les paramètres.

```bash
api POST "/sites/$SITE_ID/aliases" -d "$(jq -n --arg a "www.$DOMAIN" '{alias: $a}')"
api POST "/sites/$SITE_ID/aliases" -d "$(jq -n --arg a "old-$DOMAIN" '{alias: $a}')"
api PUT "/sites/$SITE_ID/canonical-host" -d '{"canonical_host": "apex"}'
```

## 3. Activer le SSL

### Option A : Let's Encrypt

Le domaine et ses alias doivent pointer vers le serveur et le port 80 doit être joignable. Contrôlez d'abord le DNS.

```bash
api GET "/sites/$SITE_ID/preflight" | jq '{acme_contact_ok, dns: .dns.detail}'
api POST "/sites/$SITE_ID/ssl" | jq .
```

Sans DNS public, cet appel répond `412` et ne modifie rien.

### Option B : téléverser un certificat

Le certificat doit couvrir le domaine du site et, pour éviter une alerte navigateur, tous ses alias. La clé privée ne doit jamais apparaître dans les journaux.

```bash
jq -n --rawfile c "${CERT_FILE:-fullchain.pem}" --rawfile k "${KEY_FILE:-privkey.pem}" \
  '{certificate: $c, private_key: $k}' \
  | api POST "/sites/$SITE_ID/ssl/upload" -d @-
```

### Vérifier le certificat

```bash
sleep 3
api GET "/sites/$SITE_ID/ssl" | jq '{ssl_enabled, expiry, issuer}'
curl -sS -o /dev/null --resolve "$DOMAIN:443:$SERVER_IP" \
  -w 'TLS vérifié=%{ssl_verify_result} HTTP=%{http_code}\n' "https://$DOMAIN/"
```

`TLS vérifié=0` signifie que la chaîne et le nom sont valides.

## 4. Vérifier le site proxy

`--resolve` interroge le serveur directement, même avant la propagation du DNS.

```bash
web() { curl -sS --max-time 20 --resolve "$DOMAIN:443:$SERVER_IP" --resolve "www.$DOMAIN:443:$SERVER_IP" \
  --resolve "old-$DOMAIN:443:$SERVER_IP" --resolve "$DOMAIN:80:$SERVER_IP" "$@"; }

web -D - -o /dev/null "https://$DOMAIN/" \
  | grep -iE '^(HTTP|strict-transport|x-content-type|x-frame|referrer-policy|permissions-policy|x-robots)'

for url in "https://www.$DOMAIN/a?b=1" "https://old-$DOMAIN/a?b=1" "http://$DOMAIN/a?b=1"; do
  web -o /dev/null -w "$url -> %{http_code} %{redirect_url}\n" "$url"
done
```

Résultat attendu, avec `app.example.com` remplacé par votre domaine :

```text
HTTP/1.1 200 OK
Strict-Transport-Security: max-age=31536000; includeSubDomains
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
X-Robots-Tag: noindex, nofollow
https://www.app.example.com/a?b=1 -> 301 https://app.example.com/a?b=1
https://old-app.example.com/a?b=1 -> 301 https://app.example.com/a?b=1
http://app.example.com/a?b=1 -> 301 https://app.example.com/a?b=1
```

Contrôlez aussi la taille maximale : 15 Mo passent et 17 Mo sont refusés en `413`.

```bash
head -c 15000000 /dev/zero > /tmp/dp-15m; head -c 17000000 /dev/zero > /tmp/dp-17m
web -o /dev/null -w '15 Mo -> %{http_code}\n' -H 'Expect:' --data-binary @/tmp/dp-15m "https://$DOMAIN/"
web -o /dev/null -w '17 Mo -> %{http_code}\n' -H 'Expect:' --data-binary @/tmp/dp-17m "https://$DOMAIN/"
rm -f /tmp/dp-15m /tmp/dp-17m
```

## 5. Créer une redirection 301

`source` est un chemin exact : `/ancien` ne couvre pas `/ancien/page`. `target` est un chemin ou une URL `http(s)`. `redirect_type` vaut `301` (défaut) ou `302`. Une nouvelle règle sur la même source remplace la précédente.

```bash
api POST "/sites/$SITE_ID/redirects" \
  -d '{"source": "/ancien", "target": "/nouveau", "redirect_type": "301"}'
api GET "/sites/$SITE_ID/redirects" | jq .
sleep 3
web -o /dev/null -w '/ancien -> %{http_code} %{redirect_url}\n' "https://$DOMAIN/ancien"
```

Résultat attendu : `/ancien -> 301 https://app.example.com/nouveau`.

Pour retirer la règle :

```bash
api POST "/sites/$SITE_ID/redirects/remove" -d '{"source": "/ancien"}'
```

## 6. Déployer une application Docker

Choisissez un modèle avec `GET /apps/templates`, puis contrôlez les prérequis. `blocked` doit valoir `false`.

```bash
api GET /apps/templates | jq -r '.[] | select(.id == "adminer") | "\(.id) \(.image)"'
api GET "/apps/preflight?template_id=adminer&name=guide-adminer&port=18081" | jq '{blocked}'
```

Le déploiement est asynchrone : `HTTP 202` signifie qu'il a démarré, pas qu'il a réussi. `tls_mode` vaut `acme`, `provided` ou `none`. Le journal se lit en flux et se ferme à la fin du déploiement.

```bash
DEPLOY_ID=$(api POST /apps/deploy -d "$(jq -n --arg d "$APP_DOMAIN" '{
  template_id: "adminer", name: "guide-adminer", port: 18081,
  domain: $d, tls_mode: "none", memory_mb: 256}')" | jq -r .deploy_id)

curl -sSN --max-time 170 ${PANEL_CURL_OPTS:-} "$PANEL_URL/api/apps/deploy/$DEPLOY_ID/log" \
  -H "Authorization: Bearer $DP_KEY" | grep '^data:'
```

Le déploiement a réussi quand la dernière ligne contient `"step":"complete"` et `"status":"done"`. Une étape `dns` en `error` est normale si le DNS du domaine n'est pas géré par le panel.

Le panel préfixe le nom du conteneur par `dockpanel-app-`. Vérifiez l'état puis la réponse réelle :

```bash
CONTAINER_ID=$(api GET /apps | jq -r '.[] | select(.name == "dockpanel-app-guide-adminer") | .container_id')
api GET /apps | jq '.[] | select(.name == "dockpanel-app-guide-adminer") | {name, status, domain, port, image}'
sleep 3
curl -sS -o /dev/null --max-time 15 --resolve "$APP_DOMAIN:80:$SERVER_IP" \
  -w "$APP_DOMAIN -> %{http_code}\n" "http://$APP_DOMAIN/"
api GET "/apps/$CONTAINER_ID/logs" | jq -r '.logs' | tail -n 5
```

Résultat attendu : `status` à `running` et un code `200`.

Pour supprimer l'application, relisez d'abord son nom. **Supprimez aussi son moniteur** : le panel en crée un pour chaque application déployée sur un domaine et il survit à l'application. Un moniteur en échec ouvre un incident `major`, et un incident `major` ou `critical` ouvert bloque tous les déploiements Git.

```bash
api GET /apps | jq -r --arg id "$CONTAINER_ID" '.[] | select(.container_id == $id) | .name'
api DELETE "/apps/$CONTAINER_ID"
for id in $(api GET /monitors | jq -r '.[] | select(.name | startswith("guide-adminer")) | .id'); do
  api DELETE "/monitors/$id"
done
# Clôture uniquement les incidents ouverts par cette application.
for id in $(api GET /incidents | jq -r '.[] | select(.status != "resolved" and .status != "postmortem")
    | select(.title | startswith("guide-adminer")) | .id'); do
  api PUT "/incidents/$id" -d '{"status": "resolved"}' | jq '{title, status}'
done
```

## 7. Lister, modifier et supprimer un site

### Lister

`limit` et `offset` paginent la liste.

```bash
api GET '/sites?limit=100&offset=0' | jq -r '.[] | "\(.id) \(.domain) \(.runtime) \(.status) ssl=\(.ssl_enabled)"'
api GET "/sites/$SITE_ID" | jq '{domain, status, enabled, proxy_port, ssl_enabled, ssl_expiry,
  max_upload_mb, proxy_streaming, proxy_strict_client_ip, canonical_host, aliases}'
```

### Modifier

Pour changer une limite sans perdre les autres réglages :

```bash
api GET "/sites/$SITE_ID" \
  | jq '{rate_limit, max_upload_mb, php_memory_mb, php_max_workers, custom_nginx, bandwidth_quota_mb}
        + {max_upload_mb: 32}' \
  | api PUT "/sites/$SITE_ID/limits" -d @- | jq '{max_upload_mb, custom_nginx}'
```

Pour désactiver puis réactiver un site. Désactivé, il répond `503`. Le changement prend effet environ une seconde après la réponse de l'API.

```bash
api PUT "/sites/$SITE_ID/toggle" -d '{"enabled": false}'
sleep 3
web -o /dev/null -w 'désactivé HTTP -> %{http_code}\n' "http://$DOMAIN/"
web -o /dev/null -w 'désactivé HTTPS -> %{http_code}\n' "https://$DOMAIN/"
api PUT "/sites/$SITE_ID/toggle" -d '{"enabled": true}'
sleep 3
web -o /dev/null -w 'réactivé HTTPS -> %{http_code}\n' "https://$DOMAIN/"
```

Le renommage passe par `PUT /sites/{id}/domain` avec `{"new_domain": "..."}`. Le certificat doit ensuite couvrir le nouveau nom.

### Supprimer

**La suppression est définitive** pour le vhost, le dossier du site et ses bases. Le panel tente une sauvegarde avant de supprimer, sans garantie : un échec de cette sauvegarde n'arrête pas la suppression.

```bash
api GET "/sites/$SITE_ID" | jq -r .domain      # doit afficher le domaine attendu
api DELETE "/sites/$SITE_ID"
api GET "/sites/$SITE_ID"                      # doit répondre HTTP 404
```

## 8. Choisir comment déployer une application maison

| Votre situation | À utiliser | Pourquoi |
|---|---|---|
| Le code est dans un dépôt Git et doit être construit sur le serveur | `/api/git-deploys` | Construction, historique, rollback, domaine et SSL intégrés |
| Vous voulez revenir en arrière en un appel | `/api/git-deploys` | Seul mode avec un historique et un rollback |
| Une seule application web, avec ou sans `Dockerfile` | `/api/git-deploys` | Remplacement sans coupure quand aucun volume n'est déclaré |
| Plusieurs services liés, à partir d'images déjà publiées (web, Redis, worker) | `/api/apps/compose/deploy` | Réseau interne commun et volumes nommés |
| Une image déjà construite par votre CI | `/api/apps/compose/deploy` | Rien à construire sur le serveur |
| Un logiciel courant du catalogue | `/api/apps/deploy` (section 6) | Modèle prêt à l'emploi |

Limites à connaître avant de choisir :

- **Compose** n'a ni historique, ni rollback, ni construction (`build:` est refusé). La mise à jour coupe le service quelques secondes. Le domaine se branche avec un site proxy séparé.
- **Git** ne gère qu'un conteneur par déploiement. Ne placez pas de `docker-compose.yml` à la racine du contexte de construction : le déploiement passerait par le moteur compose et perdrait le domaine et le rollback.

## 9. Déployer avec Compose

### Exposition des ports : résultat du test

**Un compose ne peut pas publier un port sur `0.0.0.0`.** L'agent ignore l'adresse demandée et force `127.0.0.1` pour chaque port, ce qui empêche Docker de contourner ufw. Le test a déployé chaque écriture sur la version 3.0.0-rc.3, puis a sondé les ports depuis le serveur et depuis une autre machine. Le port 80 du serveur servait de témoin et répondait bien depuis cette autre machine.

| Écriture dans `ports:` | Publication réelle | Depuis le serveur | Depuis une autre machine |
|---|---|---|---|
| `0.0.0.0:18091:80` | `127.0.0.1:18091` | 200 | refusé |
| `18092:80` | `127.0.0.1:18092` | 200 | refusé |
| Forme longue avec `host_ip: 0.0.0.0` | `127.0.0.1:18093` | 200 | refusé |
| `192.168.250.10:18094:80` (IP du serveur) | `127.0.0.1:18094` | 200 | refusé |
| `18096:80/udp` | `127.0.0.1:18096/udp` | non sondé | non sondé |
| `network_mode: bridge` avec `18099:80` | `127.0.0.1:18099` | 200 | refusé |
| `[::]:18095:80` | **aucune** | fermé | refusé |
| `18097-18098:80` | **aucune** | fermé | refusé |

**Attention : ces réécritures sont silencieuses.** `validate` répond `valid: true` sans avertissement. Les formes IPv6 et les plages de ports ne publient rien, alors que le déploiement répond `201` et que le service est `running`. Écrivez donc toujours `127.0.0.1:PORT_HOTE:PORT_CONTENEUR` et vérifiez le port après le déploiement. Pour rendre le service public, passez par un site proxy.

Pour reproduire le test, lancez ce bloc depuis le serveur. `HostIp` doit valoir `127.0.0.1` :

```bash
printf 'services:\n  test-ports:\n    image: nginx:1.27-alpine\n    ports: ["0.0.0.0:18120:80"]\n' > /tmp/test-ports.yml
TEST_ID=$(jq -Rs '{yaml: .}' < /tmp/test-ports.yml | api POST /apps/compose/deploy -d @- | jq -r '.services[0].container_id')
sleep 3
sudo docker inspect -f '{{json .HostConfig.PortBindings}}' "$TEST_ID"
sudo ss -ltn | grep ':18120 '
curl -s -m 4 -o /dev/null -w 'adresse publique -> %{http_code}\n' "http://$SERVER_IP:18120/" || true
api DELETE "/apps/$TEST_ID"
```

Résultat obtenu :

```text
{"80/tcp":[{"HostIp":"127.0.0.1","HostPort":"18120"}]}
LISTEN 0 4096 127.0.0.1:18120 0.0.0.0:*
adresse publique -> 000
```

### Écrire le fichier

Tous les fichiers envoyés à cette route partagent le même espace : réseau `dockpanel-stack-adhoc`, conteneurs `dockpanel-compose-adhoc-<service>` et volumes `adhoc_<volume>`. **Préfixez donc chaque service et chaque volume par le nom de l'application**, sinon deux applications entrent en collision ou partagent leurs données.

```bash
export COMPOSE_DOMAIN="${COMPOSE_DOMAIN:-maison.example.com}"
cat > /tmp/monapp.yml <<'YAML'
services:
  monapp-web:
    image: nginx:1.26-alpine
    restart: unless-stopped
    environment:
      APP_VERSION: "1"
    ports:
      - "127.0.0.1:18110:80"
    volumes:
      - monapp-data:/usr/share/nginx/html
  monapp-cache:
    image: redis:7-alpine
    restart: unless-stopped
YAML
```

Les services se joignent par leur nom : ici `monapp-cache`. Les directives `user:`, `healthcheck:` et `entrypoint:` sont ignorées, et `validate` le signale.

### Valider

`valid` doit valoir `true`. Lisez aussi `warnings`.

```bash
jq -Rs '{yaml: .}' < /tmp/monapp.yml | api POST /apps/compose/validate -d @- | jq '{valid, errors, warnings}'
```

### Déployer

**Un `HTTP 201` ne prouve pas le succès.** L'état réel de chaque service est dans `.services[].status`.

```bash
jq -Rs '{yaml: .}' < /tmp/monapp.yml | api POST /apps/compose/deploy -d @- > /tmp/monapp-deploy.json
jq '{services: [.services[] | {name, status, error}]}' /tmp/monapp-deploy.json
jq -e 'all(.services[]; .status == "running")' /tmp/monapp-deploy.json
```

### Publier sur un domaine et vérifier

Le domaine passe par un site proxy vers le port local. Ajoutez ensuite le SSL comme en section 3.

```bash
COMPOSE_SITE_ID=$(api POST /sites -d "$(jq -n --arg d "$COMPOSE_DOMAIN" '{domain: $d, runtime: "proxy", proxy_port: 18110}')" | jq -r .id)
sleep 3
api GET /apps | jq '.[] | select(.name | startswith("dockpanel-compose-adhoc-monapp-")) | {name, status, image, port}'
curl -sS -o /dev/null -D - --max-time 15 --resolve "$COMPOSE_DOMAIN:80:$SERVER_IP" "http://$COMPOSE_DOMAIN/" | grep -iE '^(HTTP|server)'
```

### Lire les logs

```bash
WEB_ID=$(api GET /apps | jq -r '.[] | select(.name == "dockpanel-compose-adhoc-monapp-web") | .container_id')
api GET "/apps/$WEB_ID/logs" | jq -r .logs | tail -n 5
```

### Mettre à jour

Redéployer sans supprimer échoue : chaque service répond `status: failed` avec un conflit de nom, tandis que l'ancienne version continue de tourner. **N'utilisez pas non plus `PUT /apps/{id}/image` ni `PUT /apps/{id}/env` sur un service compose** : le conteneur recréé quitte le réseau interne et ne joint plus les autres services.

La méthode fiable est de supprimer les conteneurs puis de redéployer. Les volumes nommés sont conservés. Le service est coupé pendant l'opération.

```bash
sed -i 's/nginx:1.26-alpine/nginx:1.27-alpine/; s/APP_VERSION: "1"/APP_VERSION: "2"/' /tmp/monapp.yml
jq -Rs '{yaml: .}' < /tmp/monapp.yml | api POST /apps/compose/validate -d @- | jq -e .valid
for id in $(api GET /apps | jq -r '.[] | select(.name | startswith("dockpanel-compose-adhoc-monapp-")) | .container_id'); do
  api DELETE "/apps/$id"
done
jq -Rs '{yaml: .}' < /tmp/monapp.yml | api POST /apps/compose/deploy -d @- > /tmp/monapp-deploy.json
jq -e 'all(.services[]; .status == "running")' /tmp/monapp-deploy.json
sleep 3
api GET /apps | jq -r '.[] | select(.name == "dockpanel-compose-adhoc-monapp-web") | .image'
curl -sS -o /dev/null --max-time 15 --resolve "$COMPOSE_DOMAIN:80:$SERVER_IP" -w "$COMPOSE_DOMAIN -> %{http_code}\n" "http://$COMPOSE_DOMAIN/"
```

Résultat attendu : `nginx:1.27-alpine` et un code `200`.

### Supprimer

```bash
api DELETE "/sites/$COMPOSE_SITE_ID"
for id in $(api GET /apps | jq -r '.[] | select(.name | startswith("dockpanel-compose-adhoc-monapp-")) | .container_id'); do
  api DELETE "/apps/$id"
done
api GET /apps | jq '[.[] | select(.name | startswith("dockpanel-compose-adhoc-monapp-"))] | length'
```

Le dernier appel doit afficher `0`. **Le volume reste sur le serveur** : l'API ne le supprime pas. Pour effacer définitivement les données, un administrateur lance `sudo docker volume rm adhoc_monapp-data` sur le serveur.

## 10. Déployer depuis un dépôt Git

### Contrôler les incidents ouverts

Un incident `major` ou `critical` ouvert refuse tout déploiement Git avec un `409`. Cette liste doit être vide. Sinon, arrêtez-vous et prévenez un humain : un incident que vous n'avez pas causé peut signaler une vraie panne.

```bash
api GET /incidents | jq '[.[] | select(.status != "resolved" and .status != "postmortem")
  | select(.severity == "major" or .severity == "critical") | {id, severity, title}]'
```

### Créer le déploiement

Le panel attribue un port local entre 7000 et 7999, toujours lié à `127.0.0.1`. Le dépôt doit être joignable depuis Internet : les adresses privées et `file://` sont refusées. Pour un dépôt privé, utilisez une URL SSH et `POST /git-deploys/{id}/keygen`.

**Nixpacks passe avant votre `Dockerfile`.** S'il sait construire le projet, votre `Dockerfile` est ignoré. Le seul moyen testé de forcer le `Dockerfile` est de renseigner `pre_build_cmd` avec une commande autorisée, comme ci-dessous. Le journal affiche alors une étape `pre_build` en `error` : c'est normal, la commande n'est pas exécutée. Avec Nixpacks, les variables d'environnement sont aussi intégrées à l'image : n'y mettez pas de secret.

**Choisissez la bonne branche et la bonne URL dès la création.** Après le premier déploiement, les modifier avec `PUT` fait échouer les déploiements suivants, car le dépôt déjà cloné n'est pas mis à jour. Il faut alors supprimer et recréer le déploiement, ce qui efface l'historique.

```bash
export GIT_REPO="${GIT_REPO:-https://github.com/votre-compte/votre-app.git}"
export GIT_BRANCH="${GIT_BRANCH:-main}"
export GIT_CONTEXT="${GIT_CONTEXT:-.}"
export GIT_PORT="${GIT_PORT:-3000}"
export GIT_DOMAIN="${GIT_DOMAIN:-git.example.com}"

GIT_ID=$(api POST /git-deploys -d "$(jq -n --arg r "$GIT_REPO" --arg b "$GIT_BRANCH" --arg c "$GIT_CONTEXT" \
  --argjson p "$GIT_PORT" --arg d "$GIT_DOMAIN" '{
    name: "monapp-git", repo_url: $r, branch: $b, build_context: $c, dockerfile: "Dockerfile",
    container_port: $p, domain: $d, tls_mode: "none", memory_mb: 256,
    pre_build_cmd: "npm ci", env_vars: {APP_MODE: "production"}}')" | jq -r .id)
echo "GIT_ID=$GIT_ID"
```

Réponse attendue : `HTTP 201` et le statut `pending`. Mettez `tls_mode` à `acme` avec `ssl_email` pour obtenir un certificat, une fois le DNS en place.

### Déployer

`HTTP 202` signifie que le déploiement a démarré. Le journal se ferme à la fin. Vérifiez ensuite `status`.

```bash
git_deploy() {
  local deploy_id
  deploy_id=$(api POST "/git-deploys/$GIT_ID/deploy" | jq -r .deploy_id)
  curl -sSN --max-time 600 ${PANEL_CURL_OPTS:-} "$PANEL_URL/api/git-deploys/deploy/$deploy_id/log" \
    -H "Authorization: Bearer $DP_KEY" | grep '^data:' | tail -n 4
  sleep 3
  api GET "/git-deploys/$GIT_ID" | jq '{status, last_commit, image_tag, build_method}'
}
git_deploy
curl -sS -o /dev/null --max-time 15 --resolve "$GIT_DOMAIN:80:$SERVER_IP" -w "$GIT_DOMAIN -> %{http_code}\n" "http://$GIT_DOMAIN/"
api GET "/git-deploys/$GIT_ID/logs" | jq -r .logs | tail -n 3
```

Résultat attendu : `status` à `running`, `build_method` à `dockerfile` et un code `200`.

### Déployer une nouvelle version

Poussez d'abord votre commit sur la branche, puis relancez le déploiement. En cas d'échec, l'ancienne version continue de servir et `status` passe à `failed`.

```bash
# GIT_V2 : un nouveau commit vient d'être poussé sur la branche
git_deploy
```

### Consulter l'historique

```bash
api GET "/git-deploys/$GIT_ID/history" | jq '[.[] | {id, commit_hash, status, triggered_by, image_tag}]'
```

### Revenir à la version précédente

Le rollback relance l'image déjà construite, sans cloner ni reconstruire. Il prend l'identifiant d'une entrée `success` de l'historique. **Il ne restaure pas les variables d'environnement** : l'ancienne image démarre avec la configuration actuelle.

```bash
TARGET=$(api GET "/git-deploys/$GIT_ID/history" | jq -c '[.[] | select(.status == "success")][1]')
ROLLBACK_ID=$(api POST "/git-deploys/$GIT_ID/rollback/$(jq -r .id <<< "$TARGET")" | jq -r .deploy_id)
curl -sSN --max-time 170 ${PANEL_CURL_OPTS:-} "$PANEL_URL/api/git-deploys/deploy/$ROLLBACK_ID/log" \
  -H "Authorization: Bearer $DP_KEY" | grep '^data:' | tail -n 2
sleep 3
echo "commit attendu : $(jq -r .commit_hash <<< "$TARGET")"
api GET "/git-deploys/$GIT_ID" | jq '{status, last_commit, image_tag}'
curl -sS -o /dev/null --max-time 15 --resolve "$GIT_DOMAIN:80:$SERVER_IP" -w "$GIT_DOMAIN -> %{http_code}\n" "http://$GIT_DOMAIN/"
```

`last_commit` doit correspondre au commit attendu.

### Supprimer

La suppression retire le conteneur, le vhost et le dépôt cloné, mais **laisse les images Docker**. Supprimez-les ensuite pour libérer le disque.

```bash
api GET "/git-deploys/$GIT_ID" | jq -r .name
api DELETE "/git-deploys/$GIT_ID"
for image in $(api GET /apps/images | jq -r '.images[] | select(.repository == "dockpanel-git-monapp-git") | "\(.repository):\(.tag)"'); do
  api DELETE "/apps/images/$image"
done
api GET /apps/images | jq '[.images[] | select(.repository == "dockpanel-git-monapp-git")] | length'
```

## 11. Erreurs possibles

Le corps d'une erreur est de la forme `{"error": "message"}`. Lisez le message : il indique le plus souvent la correction.

| Code | Message ou cas | Que faire | Statut |
|---|---|---|---|
| 400 | `proxy_port is required for proxy runtime` | Ajouter `proxy_port` | observée |
| 400 | `proxy_port must be between 1024 and 65535...` | Choisir un port autorisé | observée |
| 400 | `Invalid domain` | Corriger le nom de domaine | observée |
| 400 | `Custom nginx config contains dangerous directive` | Retirer la directive refusée | observée |
| 400 | `Max upload must be between 1 and 10240 MB` | Corriger la valeur | observée |
| 400 | `'proxy_streaming' must be a boolean` | Envoyer `true` ou `false` | observée |
| 400 | `www.<domaine> is not served by this site: add it as an alias first` | Ajouter l'alias, puis recommencer | observée |
| 400 | `this certificate is for <autre>, not <domaine>` | Téléverser le bon certificat | observée |
| 400 | `Invalid redirect source...` ou `Invalid redirect target...` | Source en `/...`, cible en chemin ou `http(s)` | observée |
| 400 | `Type must be 301 or 302` | Corriger `redirect_type` | observée |
| 400 | `Invalid app name`, `memory_mb must be between 4 and 65536` | Corriger le champ | observée |
| 400 | `Invalid container ID` | Utiliser `container_id`, pas le nom | observée |
| 200 | Compose : `valid: false` avec `Invalid YAML` ou `No 'services' key found` | Corriger le fichier | observée |
| 201 | Compose : `status: failed` et `The container name ... is already in use` | Supprimer les conteneurs, puis redéployer | observée |
| 400 | `Compose: privileged mode is not allowed` | Retirer `privileged` | observée |
| 400 | `Compose: host namespace sharing is not allowed` | Retirer `network_mode`, `pid` ou `ipc: host` | observée |
| 400 | `Compose: dangerous capability not allowed` | Retirer la capacité de `cap_add` | observée |
| 400 | `Compose: Docker socket mount is not allowed` ou `sensitive host path mount is not allowed` | Utiliser un volume nommé | observée |
| 400 | `Compose: host device passthrough is not allowed` ou `disabling security profiles is not allowed` | Retirer `devices` ou `security_opt` | observée |
| 400 | `No deployable services found` | Donner une `image:` à chaque service, `build:` n'est pas pris en charge | observée |
| 400 | `Missing 'yaml' field` | Envoyer `{"yaml": "..."}` | observée |
| 400 | `Invalid deploy name`, `Repository URL is required` | Corriger le champ | observée |
| 400 | `Invalid repository URL: Host points to a private/internal address` | Utiliser un dépôt joignable depuis Internet | observée |
| 400 | `Repository URL must use https, http, ssh, or git@host:path` | Corriger le protocole | observée |
| 400 | `Invalid volume path` | Donner un chemin absolu dans le conteneur | observée |
| 404 | `Git deploy not found`, `History entry not found` | Relire la liste ou l'historique | observée |
| 409 | `A deploy with this name already exists` | Choisir un autre nom | observée |
| 409 | `Deploy already in progress` | Attendre la fin du déploiement en cours | observée |
| 409 | `Deploy blocked: active critical/major incident in progress` | Lire `GET /api/incidents`. Ne clôturer un incident que si vous en êtes la cause ou avec l'accord d'un humain | observée |
| Journal | `git reset failed: ... unknown revision` après un `PUT` de branche ou d'URL | Recréer le déploiement | observée |
| 401 | `Invalid or expired token` | Clé erronée ou révoquée : en demander une nouvelle | observée |
| 401 | `Authentication required` | Ajouter l'en-tête `Authorization` | observée |
| 403 | `Not a dockpanel-managed container` | Conteneur absent ou non géré par le panel : relire `GET /apps` | observée |
| 403 | `Admin only` | La clé n'appartient pas à un administrateur | d'après le code |
| 404 | `Site not found` | Relire la liste, le site a pu être supprimé | observée |
| 409 | `Domain already in use by a site` | Choisir un autre domaine ou reprendre le site existant | observée |
| 409 | `SSL is already enabled` | Rien à faire, ou téléverser un certificat de remplacement | observée |
| 409 | `No free port is left between 5000 and 5999` | Libérer un port (sites Node et Python) | d'après le code |
| 412 | `No DNS record was found for <domaine>` | Créer l'enregistrement DNS, puis réessayer | observée |
| 412 | Prérequis d'application non remplis | Lire `GET /apps/preflight` | d'après le code |
| 413 | Corps de requête trop gros sur le site | Augmenter `max_upload_mb` | observée |
| 422 | `A certificate for <domaine> could not be issued` | Vérifier DNS et port 80, ne pas relancer en boucle | d'après le code |
| 429 | `Site creation rate limit` ou `max 10 SSL certificates per hour` | Attendre, ne pas réessayer immédiatement | d'après le code |
| 502 | Agent injoignable ou erreur interne de l'agent | Vérifier le service agent sur le serveur | d'après le code |
| 503 | `System is in lockdown mode` | Le panel est verrouillé : prévenir un administrateur | d'après le code |

## 12. Liste de contrôle finale

- [ ] `GET /sites/{id}` affiche `status: active`, `enabled: true` et les options voulues.
- [ ] Le site répond `200` en HTTPS et le certificat est validé sans `-k`.
- [ ] HTTP et chaque alias redirigent en `301` vers le domaine canonique.
- [ ] Les en-têtes de sécurité sont présents.
- [ ] L'application reçoit la bonne IP client et les WebSockets fonctionnent, si elle en utilise.
- [ ] Toute application Docker est à l'état `running` et répond sur son domaine.
- [ ] Chaque service compose est `running` dans la réponse du déploiement, et son port est lié à `127.0.0.1`.
- [ ] Un déploiement Git affiche `status: running` et le commit attendu dans `last_commit`.
- [ ] Aucun moniteur ni incident de test ne reste ouvert.
