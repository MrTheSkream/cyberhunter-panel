# Fonctionnalité 1 — Multi-IP (sites + IP d'envoi mail)

Statut : **proposition v2, à valider** — 2026-11-14. Base : v2.242.1 (commit d'import `20342eb`).
v2 : alignée sur le fonctionnement de HestiaCP (vérifié dans son code : `v-add-sys-ip`, `v-add-mail-domain`, template Exim).

## 1. Contexte

### Ta prod HestiaCP
- IP principale **`192.0.2.131`**, posée par OVH en DHCP (`/etc/netplan/50-cloud-init.yaml`).
- 6 IP additionnelles en `/32` sur `ens3`, **posées par HestiaCP** (`/etc/netplan/60-hestia.yaml`, « Added by Hestia »). Aucun NAT, toutes `shared`, 1 à 9 sites par IP.
- 1 IPv6 `/128` sur `ens4` (cloud-init).

### Comment HestiaCP fait (référence à reproduire)
| Sujet | HestiaCP |
|---|---|
| Ajouter une IP | `v-add-sys-ip` : `ip addr add` à chaud **+** fichier netplan `60-hestia.yaml` pour la persistance |
| IP d'un site | chaque domaine web a une IP ; nginx/apache écoutent `IP:80/443` |
| IP d'envoi mail | **pas de choix séparé** : le domaine mail reprend l'**IP du domaine web du même nom** (`/etc/exim4/domains/<dom>/ip`), suit quand on la change ; sans site → IP par défaut |
| HELO | **PTR de l'IP d'envoi**, résolu par Exim à chaque envoi (repli : hostname du serveur) |
| DNS | A du domaine = IP du domaine web |

### Ce que fait DockPanel aujourd'hui (vérifié dans le code et dans la VM)
- **Web** : `detect_bind_ip()` (`agent/src/services/nginx.rs:502`) devine l'IP de la route par défaut à chaque rendu de vhost (`:748`). Tous les vhosts écoutent `IP_principale:80/443` + `[::]:80/443`, sans `listen 80` générique : **les autres IP ne servent rien** (test VM : .11/.12 → connexion refusée).
- **DNS/SPF** : une seule IP par serveur, `helpers::public_ip_for_server()` (`backend/src/helpers.rs:1210`) — pour le serveur local elle interroge **ipify** (dans le labo : ton IP perso de box).
- **Mail** : Postfix sans `smtp_bind_address` ni `sender_dependent_*` ; `master.cf` écrit une fois à l'install ; pas de `smtp_helo_name`. Maps `hash:` reconstruites par `POST /mail/sync`.
- Aucun inventaire ni gestion des IP du serveur.

### Écarts trouvés par rapport à `reprise.md`
- **Pas de SpamAssassin** : l'antispam est **Rspamd** (milter 11332). Impacte la fonctionnalité 5 (ClamAV).
- **Upstream abandonné** : plus de contrainte « additif pour rebaser ». On garde des ajouts propres par hygiène, sans s'interdire de modifier l'existant.

## 2. Périmètre v1

**Dedans**
1. Gestion des IPv4 par serveur, comme `v-add-sys-ip` / `v-delete-sys-ip` : ajout à chaud + persistance netplan, retrait, découverte des IP déjà posées.
2. IP d'un site (création + changement), vhost nginx qui écoute sur cette IP.
3. Mail : **l'IP d'envoi suit l'IP du site du même domaine** (comme HestiaCP), avec un réglage optionnel pour forcer une autre IP. HELO = PTR de l'IP.
4. DNS automatiques (A du site, A/SPF du domaine mail) et contrôles DNS basés sur la bonne IP.

**Dehors**
- IPv6 par site : l'IPv6 reste partagée (`[::]`) par tous les sites.
- IP dédiée à un utilisateur/revendeur (pas de clients).
- Apps Docker / stacks / déploiements git et panel (port 8443) : restent sur l'IP principale.
- CLI / IaC : inchangés en v1.
- Import HestiaCP des IP : traité avec la migration (voir §9).

## 3. Modèle de données

Nouvelle migration `20261114000000_server_ips.sql` :

```sql
CREATE TABLE server_ips (
  id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  server_id    UUID NOT NULL REFERENCES servers(id) ON DELETE CASCADE,
  ip           VARCHAR(45) NOT NULL,      -- IPv4 sur l'interface (là où nginx/postfix se lient)
  prefix       SMALLINT NOT NULL DEFAULT 32,
  interface    VARCHAR(32),               -- ex. ens3
  public_ip    VARCHAR(45),               -- NULL = identique à ip ; seulement en cas de NAT
  ptr          VARCHAR(253),              -- PTR lu automatiquement → HELO
  ptr_checked_at TIMESTAMPTZ,
  managed      BOOLEAN NOT NULL DEFAULT false,  -- true = posée par le panel (60-dockpanel.yaml)
  label        VARCHAR(100),
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (server_id, ip)
);
ALTER TABLE sites        ADD COLUMN IF NOT EXISTS ip_id      UUID REFERENCES server_ips(id);  -- NO ACTION
ALTER TABLE mail_domains ADD COLUMN IF NOT EXISTS send_ip_id UUID REFERENCES server_ips(id);  -- NO ACTION
```

- `sites.ip_id` **NULL = IP principale** (comportement upstream) : aucun site existant ne bouge.
- `mail_domains.send_ip_id` **NULL = automatique, comme HestiaCP** : IP du site du même domaine s'il existe, sinon IP principale. Renseigné = IP forcée.
- FK en `NO ACTION` (pas `RESTRICT`) : impossible de supprimer une IP utilisée, mais la suppression d'un serveur (cascade sur ses IP, sites et domaines mail) reste possible, `NO ACTION` n'étant vérifié qu'en fin d'instruction.
- L'API vérifie que l'IP choisie appartient au **même serveur** que le site / domaine mail.

## 4. Agent (root, sur le serveur)

### 4.1 Gestion des IP (équivalent `v-add-sys-ip`)
- `GET /system/ips` : IPv4 globales par interface (`ip -o -4 addr show scope global`) + IP principale (route par défaut) + pour chacune : `managed` (présente dans notre fichier netplan) ou non.
- `POST /system/ips {ip, prefix?=32, interface?}` :
  1. validation stricte (IPv4 publique ou privée valide, prefix 8–32, interface existante, nom `[a-zA-Z0-9._-]+`) ; appels sans shell (arguments séparés) ;
  2. `ip addr add <ip>/<prefix> dev <iface>` (à chaud, aucune coupure) ;
  3. réécriture de **`/etc/netplan/60-dockpanel.yaml`** (mode 600) avec toutes les IP gérées, puis `netplan generate` pour valider. **Pas de `netplan apply`** (il peut couper le réseau d'un serveur distant ; HestiaCP non plus ne l'applique pas) ; si `generate` échoue, on restaure l'ancien fichier et on retire l'IP.
- `DELETE /system/ips/{ip}` : refusé pour l'IP principale et pour une IP **non gérée** (posée par OVH/cloud-init ou un autre outil) ; sinon `ip addr del` + réécriture du fichier.
- Les IP posées hors panel (DHCP OVH, `60-hestia.yaml`…) sont affichées et utilisables, mais le panel ne les retire jamais du système.

### 4.2 PTR
`GET /system/ips/{ip}/ptr` : résolution inverse (resolver système). Appelée à la déclaration d'une IP et par un bouton « Rafraîchir le PTR ». Pas de résolution à chaque envoi (Postfix ne sait pas le faire) : si tu changes un PTR chez OVH, on rafraîchit.

### 4.3 Vhost nginx
- `SiteConfig` (`agent/src/routes/nginx.rs:16`) gagne `bind_ip: Option<String>` (`serde(default)` → compatible).
- `bind_ip` accepte une IPv4 **ou la valeur spéciale `"primary"`** (IP principale détectée par l'agent — le backend ne peut pas la connaître : son « IP du serveur local » vient d'ipify).
- Validation dans `put_site` : IPv4 valide **et présente sur une interface** (sinon nginx refuserait de démarrer).
- `render_site_config` choisit l'IP dans cet ordre :
  1. `bind_ip` = IPv4 → cette IP ; = `"primary"` → `detect_bind_ip()` ;
  2. champ **absent** → **l'IP déjà écrite dans le vhost existant** (parsing des `listen`, via `listener_lines`), si elle est toujours sur l'interface ;
  3. sinon `detect_bind_ip()`.
- **Le backend envoie toujours** une IP ou `"primary"`. Le champ n'est absent que pour les rendus internes à l'agent (upload de certificat, DNS-01, renouvellement, apps Docker, git deploy) : grâce au point 2, ces chemins **conservent l'IP du site** au lieu de le ramener sur l'IP principale.
- `services/ssl.rs:992-1017` copie `SiteConfig` champ par champ : on y ajoute `bind_ip`.
- Les chemins qui patchent le texte (redirections, alias, protection par mot de passe, désactivation/réactivation) gardent les `listen` existants.

### 4.4 Postfix — IP d'envoi par domaine
`SyncDomain` (`agent/src/routes/mail.rs:35-47`) gagne `send_ip: Option<String>` et `helo: Option<String>` (déjà résolus par le backend). À chaque `POST /mail/sync` :
1. **`/etc/postfix/sender_transport`** (hash) : `@domaine  dp-ip-192-0-2-107:` pour chaque domaine dont l'IP d'envoi n'est pas l'IP principale ; `postmap`.
2. **`master.cf`** : bloc géré entre marqueurs, entièrement régénéré :
   ```
   # BEGIN DockPanel IP transports (généré, ne pas éditer)
   dp-ip-192-0-2-107 unix - - n - - smtp
     -o smtp_bind_address=192.0.2.107
     -o smtp_helo_name=<PTR de 192.0.2.107>
     -o inet_protocols=ipv4
   # END DockPanel IP transports
   ```
   `inet_protocols=ipv4` : `smtp_bind_address` ne couvre que l'IPv4 ; sans ça, vers un MX joignable en IPv6, le mail partirait de l'IPv6 d'`ens4` (ni l'IP choisie, ni le SPF `ip4:`).
3. `postconf sender_dependent_default_transport_maps=hash:/etc/postfix/sender_transport`.
4. Rate-limit : `<transport>_destination_rate_delay` / `_extra_recipient_limit` sont lus par **qmgr dans `main.cf`** (un `-o` serait sans effet) → un générateur écrit ces lignes pour chaque `dp-ip-*` dans un bloc géré de `main.cf`, appelé **par la sync et par la route rate-limit existante**.
5. HELO de l'IP principale : `smtp_helo_name` = PTR de l'IP principale s'il est connu (comme le repli d'Exim).
6. `postfix check` avant `reload` ; échec → restauration des anciens `master.cf` / `main.cf`.

Limites (affichées dans l'UI) :
- Le transport dépend du **domaine de l'expéditeur** : un mail redirigé d'un expéditeur externe part par l'IP principale (idem HestiaCP).
- Avec un **relais SMTP** configuré, le mail part via le relais : l'IP choisie n'est plus visible.

## 5. Backend (API)

### 5.1 Routes (admin, scopées serveur via `X-Server-Id`)
| Route | Rôle |
|---|---|
| `GET /api/server-ips` | liste + nb de sites / domaines mail par IP |
| `GET /api/server-ips/discover` | IP présentes sur l'interface non encore déclarées |
| `POST /api/server-ips` | `{ip, …, add_to_system: bool}` : déclarer une IP déjà posée, ou **la poser** (agent §4.1) ; lit le PTR |
| `PUT /api/server-ips/{id}` | label, public_ip |
| `POST /api/server-ips/{id}/refresh-ptr` | relit le PTR → resync mail si changé |
| `DELETE /api/server-ips/{id}` | refusé si utilisée ; `?remove_from_system=true` pour une IP gérée |
| `PUT /api/sites/{id}/ip` | changer l'IP d'un site (`{ ip_id: uuid \| null }`) |

Journal d'activité : `server_ip.add/remove/update`, `site.ip.change`, `mail.domain.send_ip`.

### 5.2 Sites
- `CreateSiteRequest` gagne `ip_id` optionnel.
- `build_nginx_body()` (`routes/sites.rs:4148`, ~12 chemins de reconstruction) envoie `bind_ip` (IP ou `"primary"`). Corps construits à la main à compléter : création (`:552`), clone (`:2898`), staging (`staging.rs:308`), import (`migration.rs:777`).
- `PUT /sites/{id}/ip` : ligne → `build_nginx_body` → PUT agent → si la zone DNS est gérée par le panel et que l'A pointait sur l'ancienne IP, l'A est mis à jour → **si un domaine mail du même nom est en mode automatique, resync mail + SPF** (comme `v-change-web-domain-ip` qui reconstruit le domaine mail).

### 5.3 Résolution des IP « par objet »
- `ip_for_site(site)` : `sites.ip_id` → sinon IP principale.
- `send_ip_for_mail_domain(dom)` : `send_ip_id` → sinon IP du site du même domaine sur le même serveur → sinon IP principale.
- IP publique (DNS) : `public_ip` → sinon `ip` → sinon `public_ip_for_server()` (upstream).
- Branché sur : A auto à la création de site (`sites.rs:767-800`), suppression d'A (`:2254`), préflight DNS (`prerequisites/dns.rs:66`), `mail_records()` (`prerequisites/mail.rs:87`) : **SPF `ip4:` = IP d'envoi**, **A `@` = IP du site** s'il existe, sinon IP d'envoi.

### 5.4 Mail
- `CreateDomainRequest` / `UpdateDomainRequest` gagnent `send_ip_id` (absent = automatique).
- `create_domain` déclenche désormais la sync (aujourd'hui seule la mise à jour le fait).
- `mail_sync_payload` (`mail.rs:2539`) ajoute `send_ip` + `helo` (PTR).

## 6. Interface (React)
- **Page admin « Adresses IP »** (modèle `pages/ContainerPolicies.tsx`, entrée admin dans `data/navItems.ts`) : tableau IP / interface / PTR / origine (« panel » ou « système ») / nb sites / nb domaines mail ; « Ajouter une IP » (poser sur l'interface) ; « Découvrir » (déclarer une IP déjà posée) ; « Rafraîchir le PTR » ; suppression bloquée si utilisée.
- **Création de site** (`pages/Sites.tsx`) : sélecteur « IP » (défaut : IP principale).
- **Fiche site** (`pages/SiteDetail.tsx`) : carte « Adresse IP » + avertissement DNS si la zone n'est pas gérée par le panel.
- **Mail** (`pages/Mail.tsx`) : onglet « Réglages » du domaine (aucune édition de domaine n'existe aujourd'hui) avec « IP d'envoi : Automatique (IP du site : x.x.x.x) / forcer… » ; l'onglet DNS montre le SPF et le PTR attendu, avec alerte si le PTR est vide.

## 7. Tests

### Unitaires (`cargo test`, dans les fichiers comme upstream)
- Rendu vhost : IP explicite / `"primary"` / repli vhost existant / repli détection.
- Génération `60-dockpanel.yaml` (ajout, retrait, fichier vide) et refus des IP non gérées / principale.
- Bloc `master.cf` + bloc rate-limit : idempotents, retrait propre, noms stables.
- Résolution `send_ip_for_mail_domain` (forcée / suit le site / principale) et SPF.

### Réels dans la VM (checkpoint `dockpanel-upstream` restauré avant)
1. Découvrir `.10/.11/.12` (posées par l'installeur Ubuntu = « système ») ; **ajouter `.13` par le panel** → présente à chaud, **toujours là après reboot** ; la retirer → absente après reboot ; tentative de retirer `.11` (système) → refus.
2. 3 sites sur `.10/.11/.12` ; `curl -H Host:` sur chaque IP → seul le bon site répond.
3. Changer l'IP d'un site `.10 → .11` puis `.11 → principale` → vhost réécrit, `nginx -t` OK, l'ancienne IP ne le sert plus.
4. Upload d'un certificat auto-signé sur un site en `.11` → il **reste** sur `.11`.
5. Mail : serveur mail installé, `a.lab` (site sur `.11`, IP d'envoi auto) et `b.lab` (sans site, forcé sur `.12`). Récepteur SMTP de test sur l'hôte `192.168.250.1:25` qui journalise IP source + HELO ; envoi vers `test@[192.168.250.1]` → `a.lab` sort de `.11`, `b.lab` de `.12` ; on passe le site `a.lab` sur `.10` → son mail suit ; changer la limite d'envoi → les `dp-ip-*` suivent.
   **Prérequis à ton accord** : règle du pare-feu Windows « port 25 entrant » limitée à l'interface `vEthernet (DockPanelLab)`, supprimée après le test.
6. Supprimer une IP utilisée → refus.
7. **Non testé dans le labo** : sortie IPv6 (pas d'IPv6) — `inet_protocols=ipv4` vérifié par lecture de `master.cf`. PTR : le labo n'a pas de PTR réel → test du repli (HELO = hostname) et d'un PTR simulé.

## 8. Décisions
Validées : IPv6 partagée ; pas de propriétaire d'IP ; Docker/git/panel sur l'IP principale ; mail à IP choisie en IPv4 seulement.
Ajustées pour coller à HestiaCP (à confirmer) :
1. Le panel **pose et retire** les IP (ip addr + `60-dockpanel.yaml`, sans `netplan apply`).
2. L'IP d'envoi **suit l'IP du site** par défaut, avec forçage possible.
3. HELO = **PTR lu automatiquement**, rafraîchissable.

## 9. Pour la migration (plus tard, rappel)
Sur ton serveur, 6 IP vivent dans `60-hestia.yaml` : si DockPanel est installé **à la place de HestiaCP sur la même machine**, ce fichier doit être repris dans `60-dockpanel.yaml` **avant** de désinstaller HestiaCP, sinon les IP disparaissent au reboot suivant. Sur un serveur neuf, on les ajoute simplement par le panel (et on les rattache côté OVH).
