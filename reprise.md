# CyberHunter - Panel personnalisé - document de reprise

Rédigé le 2026-11-14 sur le VPS OVH (où le code a été analysé). À donner tel quel à Claude
sur la nouvelle machine (celle avec Hyper-V) pour reprendre le travail.

## Objectif

Fork **personnel** (usage strictement privé, pas de clients) de
[ovexro/dockpanel](https://github.com/ovexro/dockpanel) - panel serveur Rust (API + agent root)
\+ React, AGPL v3 - pour remplacer HestiaCP. Ajouter les fonctionnalités HestiaCP utilisées
qui manquent dans CyberHunter - Panel. Version analysée : **v2.242.1**, commit `514d9ea`.

## Contraintes

- L'agent CyberHunter - Panel tourne **en root sur l'hôte** (useradd, vhosts nginx, systemd, UFW, sshd).
  Upstream ne teste que sur de vrais serveurs, pas en conteneur → tester dans une **VM Hyper-V
  Ubuntu 24.04** avec snapshot avant chaque essai.
- Upstream publie très souvent (138 migrations déjà) → garder les ajouts **additifs**
  (nouvelles migrations, nouvelles colonnes nullables, nouveaux modules/variables de template)
  pour que les rebases restent faisables. Travailler sur une branche, remote `upstream` = GitHub.

## Ce que CyberHunter - Panel a DÉJÀ (ne pas refaire)

- Mail : redirections (`forward_to`), catch-all, répondeur (`autoresponder_*`), quotas de boîte,
  SpamAssassin (spamd), rate limit, DKIM - `panel/backend/src/routes/mail.rs`.
- SFTP chrooté par site avec uid/gid propre - `panel/agent/src/services/sftp_accounts.rs`.
- PHP-FPM par site (8.1–8.5), mais seul `memory_limit` est réglable - `nginx.rs` ~l.880-900.
- Quotas bande passante par site, quotas revendeur (`max_sites`…), 2FA, sauvegardes distantes.
- Import HestiaCP : **stub beta** (`agent/src/services/migration.rs` `parse_hestiacp`), sites + BDD
  seulement, pas les mails.

## Fonctionnalités à ajouter (choisies par Bastien), ordre proposé

| # | Fonctionnalité | Taille | Notes / points d'entrée |
|---|---|---|---|
| 1 | **Multi-IP** (sites + IP d'envoi mail) | M-L | Bloquant n°1. Voir conception ci-dessous. |
| 2 | **Réglages PHP par domaine** | S | Étendre le pool FPM (`php_admin_value[...]`) : upload_max_filesize, post_max_size, max_execution_time, open_basedir, disable_functions. |
| 3 | **Se connecter en tant que** (impersonation admin) | S | Rien dans le code (`impersonat`/`login_as` absents). JWT d'impersonation court + journal d'activité + bandeau UI « retour admin ». |
| 4 | **Apache + .htaccess** | L | Absent (0 occurrence). Mode « nginx → Apache (mpm_event + PHP-FPM) » par site, comme HestiaCP. Nouveaux templates nginx proxy + vhost Apache, ports Apache en local. |
| 5 | **Antivirus mail ClamAV** | M | Absent. clamav-daemon + milter (clamav-milter ou via Rspamd/SpamAssassin déjà présent) + installeur/désinstalleur de service. |
| 6 | **FTP classique + quotas disque** | M | Absent (vsftpd/proftpd/pure-ftpd : 0). Réutiliser les uid de `sftp_accounts.rs`. Quotas disque FS (quota/setquota) absents. |
| 7 | **Stats web (AWStats)** | M | Absent. Ou GoAccess (plus simple). Logs nginx par site déjà présents. |
| 8 | **Cluster DNS** | L | DNS = PowerDNS/Cloudflare (`backend/src/routes/dns.rs`), rien sur slave/AXFR/NOTIFY. PowerDNS maître + esclaves (AXFR natif) ou réplication via l'API multi-serveur. |

## Conception du multi-IP (à valider avant de coder)

Aujourd'hui : `detect_bind_ip()` (`panel/agent/src/services/nginx.rs` ~l.502) trouve l'IP de la
route par défaut, injectée globalement en `bind_ip` dans le contexte Tera (~l.748) et utilisée par
les 3 templates `panel/agent/src/templates/nginx/{http,https,proxy}.conf`.

Proposition :
1. Table `ip_addresses` par serveur (ip, interface, ip NAT/publique optionnelle, partagée/dédiée,
   propriétaire user optionnel) + `sites.ip_address_id` nullable (null → `detect_bind_ip()`).
2. Passer l'IP du site dans le contexte Tera à la place de l'IP détectée globale.
3. Si NAT : nginx écoute sur l'IP **privée**, DNS/SPF utilisent l'IP **publique**.
4. DNS (`routes/dns.rs`) : les enregistrements A créés automatiquement prennent l'IP du site.
5. Mail : IP d'envoi par domaine dans Postfix - `sender_dependent_default_transport_maps` + un
   transport `smtp` par IP dans `master.cf` avec `-o smtp_bind_address=` et `smtp_helo_name`
   (+ SPF/PTR cohérents).
6. Vérifier le chemin ACME HTTP-01 (`ssl.rs`) : rien ne doit supposer l'IP détectée.
7. UI : page IP (lister les IP de l'interface, en ajouter), sélecteur d'IP à la création/édition d'un site.

## À récupérer sur le serveur HestiaCP actuel

Bastien ne sait pas si ses IP sont directement sur l'interface ou en NAT. Lancer :

```bash
v-list-sys-ips
```

```bash
ip -br addr
```

Noter aussi : nombre de sites/domaines, versions PHP utilisées, sites dépendant de `.htaccess`,
configuration du cluster DNS (serveurs esclaves).

## Environnement de test proposé (Hyper-V)

- VM Ubuntu 24.04, 2 vCPU, 4 Go RAM, 30 Go disque, **snapshot propre** juste après l'installation.
- 2-3 IP sur la carte réseau de la VM (commutateur interne/NAT Hyper-V) pour tester le multi-IP.
- Pour le cluster DNS : une 2ᵉ VM plus tard.
- Accès SSH root (clé) depuis la machine où tourne Claude.
- Compilation : Rust (edition 2024) + Node, cf. `CONTRIBUTING.md` (`cargo build --release` pour
  `panel/agent`, `panel/backend`, `panel/cli`, puis `npm install && npx vite build` dans
  `panel/frontend`). Pas de macros `sqlx::query!` → pas besoin de base pour compiler.

## Premières étapes sur la nouvelle machine

1. Cloner le dépôt complet (pas `--depth 1`) et créer le fork sur GitHub, branche `custom`.
2. Créer la VM, installer CyberHunter - Panel upstream avec le script officiel, vérifier qu'il marche tel quel.
3. Récupérer les infos IP de HestiaCP (ci-dessus), valider la conception multi-IP.
4. Implémenter la fonctionnalité 1, la tester sur la VM, puis enchaîner.
