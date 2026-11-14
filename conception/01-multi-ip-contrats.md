# Multi-IP — contrats d'interface (figés pour l'implémentation)

Référence de conception : `conception/01-multi-ip.md`. Ce fichier fixe les formats échangés entre
**agent** (`panel/agent`), **API** (`panel/backend`) et **frontend** (`panel/frontend`) pour qu'ils
soient développés en parallèle. Toute évolution d'un contrat se fait ici d'abord.

## A. Agent ← API (HTTP interne, token agent existant)

### A1. `GET /system/ips`
```json
{ "primary": "192.168.250.10",
  "ips": [ { "ip": "192.168.250.10", "prefix": 24, "interface": "eth0", "managed": false, "primary": true } ] }
```
- IPv4 globales uniquement (`ip -o -4 addr show scope global`). `primary` = IP de `detect_bind_ip()` (null si inconnue).
- `managed` = l'IP figure dans `/etc/netplan/60-dockpanel.yaml`.

### A2. `POST /system/ips` — `{ "ip": "192.168.250.13", "prefix": 32, "interface": "eth0" }`
- `prefix` optionnel (défaut 32), `interface` optionnelle (défaut : interface de la route par défaut).
- Effet : `ip addr add` (si pas déjà présente) + réécriture de `60-dockpanel.yaml` (600) + `netplan generate`.
  Échec de `generate` → fichier restauré, IP retirée si on l'avait ajoutée, erreur 500.
- Réponse 200 : l'entrée au format A1 **+ `"added": bool`** (true seulement si cet appel a fait `ip addr add` ;
  false si l'IP était déjà sur l'hôte et a juste été adoptée → le backend ne doit annuler par DELETE que si `added`).
  400 si IP / prefix / interface invalides. **409 si l'interface n'est définie dans aucun autre fichier netplan**
  (on refuse de créer une définition concurrente qui couperait le lien au reboot).

### A3. `DELETE /system/ips/{ip}`
- 409 `{"error": "..."}` si IP principale ou non gérée (absente de `60-dockpanel.yaml`).
- Sinon `ip addr del` + réécriture du fichier + `netplan generate`. 200 `{"ok": true}`.

### A4. `GET /system/ips/{ip}/ptr` → `{ "ip": "192.0.2.107", "ptr": "mail2.example.fr" }` (`ptr` null si aucun).

### A5. `PUT /nginx/sites/{domain}` — `SiteConfig.bind_ip: Option<String>`
- Valeurs : IPv4 présente sur une interface, ou `"primary"`. Autre → 400.
- Absent → IP lue dans le vhost existant (si encore sur l'interface), sinon IP principale.

### A6. `POST /mail/sync` — ajouts
- Chaque `SyncDomain` : `send_ip: Option<String>` (IPv4 ; null/absent = IP principale), `helo: Option<String>`.
- Racine : `primary_helo: Option<String>` (PTR de l'IP principale → `smtp_helo_name` global si fourni).
- Transports nommés `dp-ip-<ip avec - à la place des .>` ; carte `/etc/postfix/sender_transport`.
- Réponse : ajoute `"ip_transports": {"applied": bool, "skipped": ["ip", ...]}` (`skipped` = IP d'envoi ignorées car
  absentes de l'hôte). Si `postfix check` refuse : `master.cf`, `main.cf` **et la carte** sont restaurés, 500 `{error}`.

## B. Frontend ← API (JSON, auth existante, en-tête `X-Server-Id` existant)

### Type `ServerIp`
```ts
interface ServerIp {
  id: string; server_id: string; ip: string; prefix: number; interface: string | null;
  public_ip: string | null; ptr: string | null; ptr_checked_at: string | null;
  managed: boolean; label: string | null; created_at: string;
  site_count: number; mail_domain_count: number;
  on_system: boolean;   // encore présente sur l'interface (selon l'agent)
  is_primary: boolean;  // = IP principale détectée par l'agent
}
```

### Routes (admin)
| Méthode | Route | Corps | Réponse |
|---|---|---|---|
| GET | `/api/server-ips` | — | `ServerIp[]` |
| GET | `/api/server-ips/discover` | — | `{ip, prefix, interface, managed, primary}[]` (posées, non déclarées) |
| POST | `/api/server-ips` | `{ip, prefix?, interface?, label?, public_ip?, add_to_system: boolean}` | `ServerIp` |
| PUT | `/api/server-ips/{id}` | `{label?: string\|null, public_ip?: string\|null}` | `ServerIp` |
| POST | `/api/server-ips/{id}/refresh-ptr` | — | `ServerIp` |
| DELETE | `/api/server-ips/{id}?remove_from_system=true\|false` | — | `{ok: true}` ; 409 `{error, sites: string[], mail_domains: string[]}` si utilisée |

### Sites
- `Site` (liste et détail) gagne `ip_id: string | null` et `bind_ip: string | null` (IP effective : celle de `ip_id`, sinon null = principale).
- `POST /api/sites` accepte `ip_id?: string | null`.
- `PUT /api/sites/{id}/ip` — `{ip_id: string | null}` → `Site` mis à jour. 400 si l'IP n'est pas sur le serveur du site.

### Mail
- `MailDomain` gagne `send_ip_id: string | null` (null = automatique), `effective_send_ip: string | null`
  (IP réellement utilisée ; null = principale) et `send_ip_source: "forced" | "site" | "primary"`.
- `POST /api/mail/domains` accepte `send_ip_id?: string | null`.
- `PUT /api/mail/domains/{id}/send-ip` — `{send_ip_id: string | null}` → `MailDomain`.

## C. Migration SQL
`panel/backend/migrations/20261114000000_server_ips.sql` (voir §3 de la conception).
