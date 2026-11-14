# Fonctionnalité 1 — Multi-IP (sites + IP d'envoi mail)

Statut : **proposition, à valider** — 2026-11-14. Base : v2.242.1 (commit d'import `20342eb`).

## 1. Contexte

### Ce que fait ta prod HestiaCP
- 7 IPv4 publiques posées **directement sur `ens3`** en `/32` (IP additionnelles OVH Public Cloud), **aucun NAT**, toutes `shared`, 1 à 9 sites par IP.
- 1 IPv6 `/128` sur une seconde carte `ens4`.

### Ce que fait DockPanel aujourd'hui (vérifié dans le code et dans la VM)
- **Web** : `detect_bind_ip()` (`agent/src/services/nginx.rs:502`) devine l'IP de la route par défaut à chaque rendu de vhost (`:748`). Tous les vhosts écoutent `IP_principale:80/443` + `[::]:80/443`, sans `listen 80` générique : **les autres IP ne servent rien** (test VM : .11/.12 → connexion refusée).
- **DNS/SPF** : une seule IP par serveur, `helpers::public_ip_for_server()` (`backend/src/helpers.rs:1210`) — pour le serveur local elle interroge **ipify** (dans le labo : ton IP perso de box). Utilisée pour l'A auto des sites, l'A/SPF des domaines mail, les contrôles DNS.
- **Mail** : Postfix sans `smtp_bind_address` ni `sender_dependent_*` ; `master.cf` écrit une fois à l'install ; `myhostname` = nom du panel ; pas de `smtp_helo_name`. Les maps sont des fichiers `hash:` reconstruits par `POST /mail/sync`.
- Aucun inventaire des IP du serveur côté backend (`servers.ip_address` = une valeur).

### Écarts trouvés par rapport à `reprise.md`
- **Pas de SpamAssassin** : l'antispam est **Rspamd** (milter 11332). Impacte la fonctionnalité 5 (ClamAV), pas celle-ci.
- **Upstream abandonné** : la contrainte « modifications additives pour rebaser » n'a plus d'objet. On garde néanmoins des ajouts propres (nouvelles migrations, nouveaux modules) par hygiène, sans s'interdire de modifier le code existant.

## 2. Périmètre v1

**Dedans**
1. Inventaire des IPv4 par serveur (découverte sur l'interface + fiche par IP).
2. Choix de l'IP d'un site (création + changement ensuite), vhost nginx qui écoute sur cette IP.
3. Choix de l'IP d'envoi d'un domaine mail (transport Postfix dédié, HELO cohérent avec le PTR).
4. DNS automatiques (A du site, A/SPF du domaine mail) et contrôles DNS basés sur la bonne IP.

**Dehors (plus tard ou jamais)**
- IPv6 par site : l'IPv6 reste partagée (`[::]`) par tous les sites, comme chez toi aujourd'hui.
- IP « dédiée » réservée à un utilisateur/revendeur (pas de clients → inutile).
- Le panel n'ajoute pas d'IP au système (netplan) : on déclare dans le panel des IP **déjà présentes** sur l'interface (chez OVH, c'est la config réseau de l'instance qui les pose).
- Choix d'IP pour les apps Docker / stacks / déploiements git (ils restent sur l'IP principale) et pour le panel lui-même (reste sur l'IP principale, port 8443).
- CLI / IaC (`dockpanel sites create`, export/apply) : inchangés en v1.

## 3. Modèle de données

Nouvelle migration `20261114000000_server_ips.sql` :

```sql
CREATE TABLE server_ips (
  id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  server_id   UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  ip          VARCHAR(45) NOT NULL,          -- IPv4 posée sur l'interface (là où nginx/postfix se lient)
  public_ip   VARCHAR(45),                   -- NULL = identique à ip ; renseignée seulement en cas de NAT
  hostname    VARCHAR(253),                  -- nom HELO / PTR de cette IP (ex. mail2.mondomaine.fr)
  label       VARCHAR(100),
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (server_id, ip)
);
ALTER TABLE sites        ADD COLUMN IF NOT EXISTS ip_id      UUID REFERENCES server_ips(id);  -- NO ACTION
ALTER TABLE mail_domains ADD COLUMN IF NOT EXISTS send_ip_id UUID REFERENCES server_ips(id);  -- NO ACTION
```

- `ip_id` / `send_ip_id` **NULL = IP principale** (comportement upstream inchangé) : aucun site existant ne bouge à la migration.
- FK en `NO ACTION` (pas `RESTRICT`) : on ne peut pas supprimer une IP encore utilisée (l'API renvoie la liste des sites/domaines concernés), mais la suppression d'un **serveur** — qui supprime en cascade ses IP, ses sites et ses domaines mail — reste possible, car `NO ACTION` n'est vérifié qu'en fin d'instruction (un `RESTRICT` la bloquerait au milieu de la cascade).
- Règle de cohérence vérifiée par l'API : l'IP choisie appartient au **même serveur** que le site / domaine mail.

## 4. Agent (root, sur le serveur)

### 4.1 Inventaire
`GET /system/ips` → IPv4 globales par interface (`ip -o -4 addr show scope global`, même méthode que l'installeur PowerDNS `routes/service_installer.rs:405`) + IP principale détectée.

### 4.2 Vhost nginx
- `SiteConfig` (`agent/src/routes/nginx.rs:16`) gagne `bind_ip: Option<String>` (`serde(default)` → compatible).
- Validation dans `put_site` : IPv4 valide **et présente sur une interface** (sinon nginx refuserait de démarrer → on refuse avant d'écrire).
- `bind_ip` accepte une IPv4 **ou la valeur spéciale `"primary"`** (= IP principale détectée par l'agent ; le backend ne peut pas la connaître lui-même : côté backend, l'« IP du serveur local » vient d'ipify et vaut, dans le labo, l'IP de ta box).
- `render_site_config` choisit l'IP dans cet ordre :
  1. `config.bind_ip` = IPv4 → cette IP ; = `"primary"` → `detect_bind_ip()` directement ;
  2. champ **absent** → **l'IP déjà écrite dans le vhost existant** (parsing des `listen`, la fonction `listener_lines` sait déjà le faire), si elle est toujours sur l'interface ;
  3. sinon `detect_bind_ip()` (upstream).
- Règle : **le backend envoie toujours** soit une IP, soit `"primary"` (jamais un champ absent). Le champ n'est absent que pour les rendus internes à l'agent. Sans la valeur `"primary"`, remettre un site de `.11` sur l'IP principale le laisserait sur `.11` (repli du point 2).
- Pourquoi le point 2 : plusieurs chemins agent re-rendent un vhost **sans connaître l'IP** (upload de certificat, DNS-01, renouvellement, apps Docker, git deploy). Sans ce repli, un renouvellement SSL ferait revenir le site sur l'IP principale. Avec, tout chemin oublié conserve l'IP en place — correction en un seul endroit.
- `services/ssl.rs:992-1017` copie `SiteConfig` champ par champ : on y ajoute `bind_ip`.
- Les chemins qui patchent le texte (redirections, alias, protection par mot de passe, désactivation/réactivation) gardent les `listen` existants : rien à faire.

### 4.3 Postfix — IP d'envoi par domaine
`SyncDomain` (`agent/src/routes/mail.rs:35-47`) gagne `send_ip: Option<String>` et `helo: Option<String>`. À chaque `POST /mail/sync` (`sync_config`) :
1. **`/etc/postfix/sender_transport`** (hash) : `@domaine  dp-ip-192-0-2-107:` pour chaque domaine qui a une IP d'envoi ; `postmap`.
2. **`master.cf`** : un bloc géré entre marqueurs, **entièrement régénéré** :
   ```
   # BEGIN DockPanel IP transports (généré, ne pas éditer)
   dp-ip-192-0-2-107 unix - - n - - smtp
     -o smtp_bind_address=192.0.2.107
     -o smtp_helo_name=mail2.mondomaine.fr
     -o inet_protocols=ipv4
   # END DockPanel IP transports
   ```
   `inet_protocols=ipv4` : `smtp_bind_address` ne couvre que l'IPv4. Sans ça, un destinataire qui a un MX en IPv6 recevrait le mail depuis l'IPv6 d'`ens4` — ni l'IP choisie, ni le SPF `ip4:`. Les transports `dp-ip-*` sortent donc **uniquement en IPv4** (l'IP principale garde le comportement actuel).
3. `postconf sender_dependent_default_transport_maps=hash:/etc/postfix/sender_transport` (idempotent, comme les `postconf` déjà relancés à chaque sync).
4. Rate-limit : `<transport>_destination_rate_delay` et `<transport>_extra_recipient_limit` sont lus par le **gestionnaire de file (qmgr) dans `main.cf`**, pas par le service → un `-o` dans `master.cf` serait sans effet. Un même générateur écrit, dans un bloc géré de `main.cf`, les lignes `dp-ip-…_destination_rate_delay` / `…_extra_recipient_limit` recopiées des valeurs globales. Il est appelé **par la sync ET par la route rate-limit existante** (qui réécrit `main.cf`), sinon changer la limite désynchroniserait les transports `dp-ip-*`. Les `smtp_tls_*` sont lus par tous les clients smtp : rien à faire.
5. `postfix check` avant `reload` ; en cas d'échec on restaure les anciens `master.cf` / `main.cf`.
6. **Déclencheurs de la sync** : aujourd'hui `create_domain` n'appelle pas la sync (seule la mise à jour le fait). On l'ajoute à la création, au changement d'IP d'envoi, et à la modification du `hostname` d'une IP.

Limites assumées (documentées dans l'UI) :
- Le transport est choisi par **domaine de l'expéditeur** : un mail *redirigé* (forward) d'un expéditeur externe part par l'IP principale.
- Si un **relais SMTP** (`relayhost`) est configuré, le mail part via le relais : l'IP choisie n'est plus visible du destinataire → l'UI le signale.

## 5. Backend (API)

### 5.1 Nouvelles routes (admin uniquement, scopées serveur via `X-Server-Id`)
| Route | Rôle |
|---|---|
| `GET /api/server-ips` | liste + nb de sites / domaines mail par IP |
| `GET /api/server-ips/discover` | IP présentes sur l'interface (via agent) non encore déclarées |
| `POST /api/server-ips` | déclarer une IP (doit être sur l'interface) |
| `PUT /api/server-ips/{id}` | label, hostname, public_ip ; si hostname change → resync mail |
| `DELETE /api/server-ips/{id}` | refusé si utilisée |
| `PUT /api/sites/{id}/ip` | changer l'IP d'un site (`{ ip_id: uuid \| null }`) |

Journal d'activité (`log_activity`) : `server_ip.create/update/delete`, `site.ip.change`, `mail.domain.send_ip`.

### 5.2 Sites
- `CreateSiteRequest` gagne `ip_id` optionnel.
- `build_nginx_body()` (`routes/sites.rs:4148`, utilisé par ~12 chemins de reconstruction) envoie `bind_ip` résolu depuis `sites.ip_id` → **tous** les rebuilds backend le portent. Corps construits à la main à compléter : création (`:552`), clone (`:2898`), staging (`staging.rs:308`), import (`migration.rs:777`).
- `PUT /sites/{id}/ip` : met à jour la ligne → `build_nginx_body` → PUT agent → **si la zone DNS est gérée par le panel** et que l'A pointait sur l'ancienne IP, l'A est mis à jour.

### 5.3 IP publique « par objet »
Nouveau helper `public_ip_for_site(db, site)` / `public_ip_for_mail_domain(db, domain)` :
`server_ips.public_ip` → sinon `server_ips.ip` → sinon `public_ip_for_server()` (upstream).
Branché sur : A auto à la création de site (`sites.rs:767-800`), suppression d'A (`:2254`), préflight DNS (`prerequisites/dns.rs:66`), `mail_records()` (`prerequisites/mail.rs:87`) → **SPF `ip4:` = IP d'envoi du domaine**.

Point de vigilance : `mail_records()` crée aussi `A @` du domaine mail. Si le domaine a un site, cet A doit suivre **l'IP du site**, pas l'IP d'envoi. Règle : A `@` = IP du site du même domaine s'il existe, sinon IP d'envoi.

### 5.4 Mail
- `CreateDomainRequest` et `UpdateDomainRequest` gagnent `send_ip_id`.
- `mail_sync_payload` (`mail.rs:2539`) ajoute `send_ip` + `helo` (hostname de l'IP, sinon `myhostname`).

## 6. Interface (React)
- **Nouvelle page admin « Adresses IP »** (modèle : `pages/ContainerPolicies.tsx`, entrée dans `data/navItems.ts`, groupe admin) : tableau IP / label / hostname (PTR) / IP publique / nb sites / nb domaines mail ; bouton « Découvrir les IP de l'interface » ; édition ; suppression bloquée si utilisée.
- **Création de site** (`pages/Sites.tsx`) : sélecteur « IP » (défaut : « IP principale »).
- **Fiche site** (`pages/SiteDetail.tsx`) : carte « Adresse IP » avec changement + avertissement DNS si la zone n'est pas gérée par le panel.
- **Mail** (`pages/Mail.tsx`) : sélecteur à l'ajout d'un domaine + onglet « Réglages » du domaine (il n'existe aucune édition de domaine aujourd'hui) ; l'onglet DNS affiche le SPF avec la bonne IP ; rappel « le PTR de cette IP doit être `hostname` ».

## 7. Tests

### Unitaires (`cargo test`, dans les fichiers comme upstream)
- Rendu vhost : `bind_ip` explicite / repli sur le vhost existant / repli détection.
- Génération du bloc `master.cf` : idempotente, retrait propre quand plus aucun domaine n'a d'IP, noms de transport stables.
- Résolution `public_ip_for_site` / SPF.

### Réels dans la VM (restauration du checkpoint `dockpanel-upstream` avant)
1. Déclarer `.10/.11/.12` ; créer 3 sites, un par IP ; `curl -H Host:` sur chaque IP → seul le bon site répond sur chaque IP.
2. Changer l'IP d'un site `.10 → .11` puis **`.11 → IP principale`** → vhost réécrit à chaque fois, `nginx -t` OK, l'ancienne IP ne le sert plus.
3. Upload d'un certificat auto-signé sur un site en `.11` → le site **reste** sur `.11` (test du repli §4.2).
4. Mail : installer le serveur mail, 2 domaines (un sur `.11`, un sur `.12`) ; un récepteur SMTP de test sur l'hôte `192.168.250.1:25` journalise IP source + HELO ; envoyer depuis chaque domaine vers `test@[192.168.250.1]` (adresse IP littérale : pas besoin de MX) → IP et HELO attendus ; changer la limite d'envoi → les transports `dp-ip-*` suivent.
   **Prérequis à ton accord** : une règle du pare-feu Windows qui autorise le port 25 entrant **uniquement sur l'interface du labo** (`vEthernet (DockPanelLab)`), supprimée après le test.
5. Supprimer une IP utilisée → refus ; supprimer le serveur… non testé (serveur local) mais couvert par la FK `NO ACTION` ; panel, apps Docker inchangés.
6. **Non testé dans le labo** : la sortie IPv6 (le labo n'a pas d'IPv6). Le `inet_protocols=ipv4` est vérifié par lecture de `master.cf` et `postconf -P`, pas par un vrai envoi IPv6.

## 8. Décisions à valider
1. **IPv6** reste partagée (`[::]`) pour tous les sites — OK ?
2. **Pas de propriétaire** d'IP (pas d'IP dédiée par utilisateur) — OK ?
3. **Le panel ne pose pas les IP sur l'interface** (il les découvre) — OK ?
4. **Apps Docker / git / panel** restent sur l'IP principale en v1 — OK ?
5. **HELO par IP** : chaque IP a un `hostname` qui doit correspondre à son PTR chez OVH. Tes PTR actuels sont réglés comment (un nom par IP, ou tous identiques) ?
6. **Mail avec IP d'envoi choisie = IPv4 seulement** (pas de sortie IPv6 pour ces domaines) — OK ?
