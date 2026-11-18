# Déployer par l'API avec une clé `dp_`

Ce guide s'adresse à un agent (Claude ou un script) qui pilote CyberHunter - Panel avec une clé API `dp_` d'un compte administrateur. Les blocs `bash` s'exécutent dans l'ordre, du début à la fin.

**Portée des tests.** Tous les blocs `bash` et les erreurs marquées « observée » ont été exécutés sur la version 3.0.0-rc.3, dans une VM Ubuntu 24.04. L'émission d'un vrai certificat Let's Encrypt n'a pas pu être testée, car les domaines du labo n'ont pas de DNS public : seuls son refus (412) et le téléversement d'un certificat l'ont été.

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

Pour supprimer l'application, relisez d'abord son nom :

```bash
api GET /apps | jq -r --arg id "$CONTAINER_ID" '.[] | select(.container_id == $id) | .name'
api DELETE "/apps/$CONTAINER_ID"
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

## 8. Erreurs possibles

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

## 9. Liste de contrôle finale

- [ ] `GET /sites/{id}` affiche `status: active`, `enabled: true` et les options voulues.
- [ ] Le site répond `200` en HTTPS et le certificat est validé sans `-k`.
- [ ] HTTP et chaque alias redirigent en `301` vers le domaine canonique.
- [ ] Les en-têtes de sécurité sont présents.
- [ ] L'application reçoit la bonne IP client et les WebSockets fonctionnent, si elle en utilise.
- [ ] Toute application Docker est à l'état `running` et répond sur son domaine.
