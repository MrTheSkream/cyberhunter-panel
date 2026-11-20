# 14 - Port de l'API PowerDNS : choix sûr et réponses vérifiées

Branche : `fix/pdns-api-port` (depuis `main`). Statut : conception à valider.

## Constat (recette réelle, Ubuntu 24.04)

- L'installeur (`panel/agent/src/routes/service_installer.rs`, `install_powerdns`)
  écrit `webserver-port=8081` en dur (gabarits SQLite et pgsql) et renvoie
  `api_url = "http://127.0.0.1:8081"` en dur.
- Si une app Docker publie déjà `127.0.0.1:8081`, le serveur web de pdns ne se
  lie pas, mais `systemctl is-active pdns` reste `active` (le DNS sur :53
  fonctionne) : l'installation est annoncée réussie.
- Le backend enregistre `pdns_api_url` (`routes/system.rs` vers la ligne 900) et
  envoie ensuite la clé API à ce conteneur, qui répond 200/201 à tout.
  `create_zone` crée une ligne `dns_zones` fantôme, les enregistrements
  « réussissent » sans exister.

Vérifié dans le source pdns 4.8 (`webserver.cc`, `ws-api.cc`) : le serveur web
ne pose **pas** d'en-tête `Server: PowerDNS` dans son propre code (reste à
confirmer en VM pour la couche YaHTTP). On ne s'appuie donc **pas** sur cet
en-tête. Ce qui est sûr : `GET /api/v1/servers/localhost` avec la clé renvoie un
JSON `{"type":"Server","daemon_type":"authoritative","version":...}`, et PATCH /
DELETE d'une zone renvoient exactement **204** sans corps.

## Partie A - Agent : choisir un port libre, prouver que c'est pdns

1. **Arrêter pdns avant la sonde** (`systemctl stop pdns`) : sur une
   réinstallation, pdns tient peut-être lui-même son ancien port, qui ne doit pas
   passer pour « occupé ». On le redémarre de toute façon à l'étape 7.
2. **Choisir le port** avec le motif déjà en place dans l'agent
   (`TcpListener::bind(("127.0.0.1", port))`, cf. `routes/system.rs:333`,
   `routes/database.rs:52`) :
   - 8081 d'abord (rétrocompatibilité, guide manuel dans Settings) ;
   - sinon la première adresse libre dans **18081 à 18099** : hors des ports du
     panel (8080, 8443, 8880), d'Apache (8091, 8092), et des plages d'apps et de
     bases ;
   - aucun libre : erreur claire, rien n'est écrit.
3. **Une seule variable `api_port`** alimente `webserver-port=` dans les deux
   gabarits **et** l'`api_url` renvoyée. Le backend enregistre déjà ce qu'il
   reçoit, donc `pdns_api_url` suit sans changement côté `system.rs`.
4. **Après le démarrage**, avant d'annoncer le succès (attente jusqu'à ~15 s,
   le serveur web peut suivre `active` avec un léger retard) :
   - `ss -tlnpH sport = :<port>` doit montrer un socket dont le processus est
     `pdns_server`. Sinon : échec, **sans envoyer la clé** à un inconnu ;
   - puis `GET http://127.0.0.1:<port>/api/v1/servers/localhost` avec
     `X-API-Key` : statut 200, JSON avec `daemon_type == "authoritative"`.
   - Échec de l'un ou l'autre : erreur `PowerDNS started but its HTTP API is not
     reachable on 127.0.0.1:<port> (...)`, avec la ligne utile du journal. Le
     backend n'enregistre alors ni URL ni clé (il n'enregistre que sur `Ok`).
5. Commentaire `services/apache.rs:22` mis à jour (8081 n'est plus garanti).

Fonctions pures testables : sélection du port (avec une fonction « est libre »
injectée), analyse de la sortie `ss` (le socket appartient-il à pdns), analyse
du JSON `servers/localhost`.

## Partie B - Backend : ne plus croire une réponse qui ne vient pas de pdns

Nouveau module partagé `panel/backend/src/services/pdns_api.rs` :

- `verify_server(client, url, key)` : `GET {url}/api/v1/servers/localhost`,
  exige 200 + JSON `daemon_type == "authoritative"`. Résultat mis en cache par
  `(url, empreinte de la clé)` pendant 60 s pour ne pas doubler chaque appel.
- `expect(resp, attendu)` : contrôle **strict** du statut par opération, au lieu
  de `is_success()` :
  - création de zone : 201 + JSON dont `name` == la zone demandée (409 reste
    accepté comme aujourd'hui) ;
  - PATCH rrsets, DELETE zone : 204 exactement (404 accepté au DELETE comme
    aujourd'hui) ;
  - GET zone / liste : 200 + JSON de la forme attendue (`rrsets` tableau,
    resp. tableau).
- Message opérateur unique : `The PowerDNS API URL did not answer as PowerDNS.
  Another service may hold its port. Reinstall PowerDNS or fix the API URL in
  Settings.` (502). Aucune ligne `dns_zones` n'est créée dans ce cas.

Sites d'appel à faire passer par le module (tous ceux qui lisent
`pdns_api_url`) :

| Fichier | Sites |
| --- | --- |
| `routes/dns.rs` | create_zone, delete_zone, liste/lecture d'enregistrements, création, modification, suppression (≈ 9 appels) |
| `routes/docker_apps.rs` | DNS automatique au déploiement (2) |
| `routes/mail.rs` | enregistrements mail (2) |
| `routes/sites.rs` | DNS automatique des sites (3) |

Le décodage de la clé reste celui de chaque site (pas de changement de
chiffrement dans ce lot).

## Question à trancher : la clé part-elle avant la vérification ?

La sonde `verify_server` envoie elle-même la clé. Côté agent, la vérification
`ss` garantit que l'URL enregistrée pointe vers pdns au moment de
l'installation. Reste le cas où pdns est arrêté plus tard et qu'une app prend
son port.

- **Option 1 (recommandée)** : vérification par réponses (sonde avec clé en
  cache 60 s + statuts stricts). Plus de faux succès ni de zones fantômes. La
  clé peut encore atteindre un intrus dans ce cas tardif : limite assumée, notée.
- **Option 2** : en plus, une sonde **sans clé** avant chaque envoi, si la VM
  montre que pdns a une réponse sans clé reconnaissable (401 avec un corps
  propre). Dépend d'une mesure en VM, et ajoute un aller-retour.

## Hors périmètre

- Empêcher une app de publier plus tard le port pris par pdns (allocateur de
  ports des apps) : suite possible.
- Tester l'URL saisie à la main dans Settings à l'enregistrement : suite
  possible (le module B s'appliquera de toute façon à l'usage).

## Tests

- Rust agent : sélection du port (8081 libre, 8081 pris, plage pleine), analyse
  `ss`, analyse du JSON serveur, gabarit contenant le bon `webserver-port`.
- Rust backend : `expect` sur 201/204/200 et sur les faux succès (200 HTML à un
  PATCH, 201 sans `name`), cache de `verify_server`.
- Pins existants verts (`lab/build.sh`, pins `debian:bookworm`).

## Recette VM (Ubuntu 24.04, snapshot propre, avec accord avant usage)

1. Lancer une app qui publie `127.0.0.1:8081` (nginx renvoyant 200 à tout).
2. Installer PowerDNS (SQLite) : succès, `pdns.conf` sur 18081,
   `pdns_api_url` = `http://127.0.0.1:18081`, zone et enregistrements réels
   (`dig @127.0.0.1`).
3. Forcer un faux pdns (pdns arrêté, app sur son port) : `create_zone` et PATCH
   refusés en 502, aucune ligne `dns_zones` ajoutée.
4. Sans app sur 8081 : comportement inchangé (8081).
5. Mesurer en passant les en-têtes réels de pdns (`curl -i`) pour 200/204/401.

## Résultats de recette (2026-11-20)

VM `cyberhunter-pdns` : clone du snapshot `propre-avant-recette` de
`cyberhunter-mailsni-b` (Ubuntu 24.04, panel 3.0.0-rc.4, app `traefik/whoami`
publiée sur `127.0.0.1:8081`), passée en 192.168.250.17 avec sa propre MAC.
Snapshot propre `propre-avant-recette-pdns`, restauré avant chaque série.
API appelée par tunnel SSH vers `127.0.0.1:3080` (nginx du clone lié à
l'ancienne IP).

| Cas | Résultat |
| --- | --- |
| Avant correctif (rc.4), 8081 pris | bug reproduit : installation « réussie », `pdns_api_url` sur 8081 tenu par docker-proxy, `create_zone` 201 avec ligne fantôme, enregistrement 201, `dig` vide |
| Correctif, 8081 pris | port 18081, tenu par `pdns_server` ; `pdns_api_url` = `http://127.0.0.1:18081` ; zone 201, enregistrement 201, `dig` = l'IP |
| Faux pdns sur 18081 (pdns arrêté, cache expiré) | `create_zone` et création d'enregistrement en 502 avec le message prévu, 0 ligne `dns_zones` |
| Faux pdns dans la fenêtre du cache (< 60 s) | idem 502, 0 ligne, l'enregistrement n'existe pas dans pdns |
| Réinstallation, 18082-18099 pris | pdns arrêté avant la sonde, récupère son 18081 |
| Réinstallation, 8081 et 18081-18099 pris | refus `No free port ...`, conf et `pdns_api_url` inchangées, pdns relancé |
| Cas normal, 8081 libre | port 8081 comme avant ; zone, enregistrement, `dig` OK ; suppression d'enregistrement et de zone OK (204 strict accepté) |

En-têtes réels de pdns 4.8.3 : **aucun** en-tête `Server`. 200 et 204 portent
`Access-Control-Allow-Origin` et les en-têtes de sécurité ; le 401 sans clé
porte `Www-Authenticate: X-API-Key realm="PowerDNS"` et le corps
`Unauthorized`.

Non testé en VM : backend pgsql, échec de la vérification HTTP après le
démarrage (course entre la sonde et le démarrage), DNS automatique des apps,
du mail et des sites (même module, couvert par les tests unitaires).
