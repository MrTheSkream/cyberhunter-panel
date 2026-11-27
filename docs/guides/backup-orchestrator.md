# Backup Orchestrator Guide

The Backup Orchestrator provides centralized backup management for all databases and app data (Docker volumes and bind mounts) on your server. It supports AES-256 encryption, automated policies, restore verification, and a health dashboard.

## Overview

Unlike per-site backups (see [Backups](backups.md)), the Backup Orchestrator works at the infrastructure level:

- **Database backups**: Any PostgreSQL, MySQL/MariaDB, or MongoDB container
- **App data backups**: The Docker volumes (named and anonymous) and the bind mounts under `/var/lib/dockpanel/apps`, `/var/lib/dockpanel/compose` and `/var/lib/dockpanel/git-data` of every app the panel manages: template apps, compose stacks and Git deployments
- **Mail and DNS backups** (administrators): every mailbox and the mail configuration, every PowerDNS zone and a snapshot of the PowerDNS database
- **Policies**: Automated schedules with retention rules
- **Encryption**: Optional AES-256 encryption at rest, for **database dumps and app data archives** (site archives are not encrypted yet)
- **Verification**: Automated restore tests to confirm backup integrity
- **Destinations**: Push backups to S3, SFTP, Backblaze B2, or Google Cloud Storage

## Quick Start: Protect Everything

The fastest way to get started is the one-click preset.

1. Go to **Backup Orchestrator** in the sidebar
2. Click **Protect Everything**
3. CyberHunter - Panel creates a policy that backs up all sites, databases, app data, mail and DNS daily at 2 AM, keeps 7 days of history, and verifies each backup after creation. Mail and DNS are only included for an administrator.

## Creating Backup Policies

For more control, create a custom policy.

1. Go to **Backup Orchestrator** > **Policies**
2. Click **Create Policy**
3. Configure:
   - **Name**: A label (e.g., `production-dbs-nightly`)
   - **What to back up**: Toggle sites, databases, and/or **App data (volumes and bind mounts)**
   - **Mail (all mailboxes and config)** and **DNS zones** (administrators only, see [Mail and DNS Backups](#mail-and-dns-backups))
   - **Stop apps during backup** (app data only, on by default): briefly stops the containers that use the data so databases are copied consistently. They are started again right after the copy, even when it fails. Untick it to archive the data while the app runs
   - **Données d'applications exclues** (app data only): tick a target to leave it out of this policy, see [Excluding app data](#excluding-app-data)
   - **Schedule**: Cron expression (default: `0 2 * * *` = daily at 2 AM)
   - **Destination**: Optional remote destination
   - **Retention**: Backups to keep, 1-365 (default: 7)
   - **Encrypt dumps and app data**: Enable AES-256 encryption for this policy's database dumps and app data archives. Site archives are always written and uploaded unencrypted
   - **Verify after backup**: Run automated verification after each backup
4. Click **Save**

Policies run on schedule. The last run time and status are shown in the policy list.

## Database Backups

### Create a Database Backup

1. Go to **Backup Orchestrator** > **Database Backups**
2. Select the database
3. Click **Create Backup**

The backup runs `pg_dump` or `mysqldump` inside the container and stores the compressed result.

**From the CLI:**

```bash
dockpanel backup db-create dockpanel-db-myapp myapp --db-type postgres --user root --password secret
```

### List Database Backups

```bash
dockpanel backup db-list myapp
```

### Restore a Database

1. Find the backup in the **Database Backups** list
2. Click **Restore**
3. Confirm

The restore replaces the database contents. Encrypted backups are decrypted automatically.

## App Data Backups (volumes and bind mounts)

A policy with **App data** ticked asks the agent for every backup target of its
server: each Docker volume, named or anonymous, and each bind mount whose real
path stays under `/var/lib/dockpanel/apps`, `/var/lib/dockpanel/compose` or
`/var/lib/dockpanel/git-data`, for every container the panel manages. A volume or
directory used by several containers of a stack is archived once. Other mounts
(`/var/run/docker.sock`, `/etc/localtime`, tmpfs, a symlink that leads outside
those directories) are left out on purpose and are not errors.

Each target becomes one archive named
`<app>-<v|b>-<name>-<YYYYMMDD-HHMMSS>.tar.gz` (`.tar.gz.enc` when encrypted) in
`/var/backups/dockpanel/volumes/<app>/`, where `<app>` is the template app, the
compose project or the Git deployment that owns the data, `v` marks a volume and
`b` a bind mount. Every target that fails is listed by name in the policy's
**Run history**; a server with no app data at all gives a successful run.

### Excluding app data

A policy can leave out targets that are not worth archiving, such as a cache or a
downloads directory the app regenerates. Each entry of the policy's
`excluded_targets` is `<app>/<name>`, the name the run history and
`GET /api/backup-orchestrator/policies/targets?policy_id=<id>` give the target
(its `key` field). For a bind mount `<name>` is the directory's last component
plus 8 hex characters derived from its full path, so it stays the same as long as
the directory does. Matching is exact, so excluding one mount never excludes
another mount of the same app.

An excluded target is skipped: it gets no archive, no upload and no retention.
The skip is not a failure, and the system log records it on each run. Archives
taken before the exclusion are kept as they are. Retention no longer touches
them, so delete them by hand to reclaim the space. An entry that matches no
current target (a stopped app, for example) stays on the policy and is reported
in the system log.

### Create an App Data Backup

Policies are the way to back up app data on a schedule. A one-off backup of one
target is available through the API: `POST /api/backup-orchestrator/volume-backup`
with `{"kind": "volume", "volume_name": "..."}` or
`{"kind": "bind", "source_path": "/var/lib/dockpanel/..."}`. The target must be
one the agent currently lists for a managed app. The app's containers are stopped
for the copy, and the archive is not encrypted.

**From the CLI:**

```bash
dockpanel backup vol-create my_app_data my-app-container
```

### List App Data Backups

```bash
dockpanel backup vol-list my-app-container
```

### Restore App Data

1. Find the backup in the **App Data Backups** list. The **Type** column says
   whether it is a volume or a bind mount, **Source** shows the volume name or
   the directory, and encrypted archives carry an **Encrypted** badge
2. Click **Restore**
3. Confirm

The app containers using this data are stopped during the restore and started
again afterwards, even when the restore fails. The archive is checked before
anything is replaced: an encrypted archive whose integrity tag does not match
(corrupted file, or a `JWT_SECRET` that is not the one it was made with) is
refused with a clear message and the live data is left untouched. A restore of
a large archive can outlast the request: the page then says the restore is
still running on the server, and the containers restart when it ends.

## Mail and DNS Backups

Mail and DNS are shared by every customer of a server, so these two parts of
a policy are reserved to administrators: the API refuses them (403, "Mail and
DNS backups are reserved to administrators") for anyone else, and the
executor skips them, with a reason in the run history, for a policy whose
owner is not an administrator.

**Mail** runs on the policy's server (the local server when the policy names
none) and writes to `/var/backups/dockpanel/mail/`:

- `mailcfg-<YYYYMMDD-HHMMSS>.tar.gz.enc`: the mail configuration, **always
  encrypted**. It holds a manifest exported from the panel database (domains,
  mailboxes with their password hashes, quotas, forwarding and keep-a-copy,
  aliases, DKIM selector and public key) and the files of
  `/etc/dockpanel/dkim`, `opendkim.conf`, and the Postfix and Dovecot
  configuration for reference. No secret is in clear in the manifest: the DKIM
  private key stays encrypted as the panel stores it, and passwords are only
  there as hashes.
- `mail-<domain>-<local part in base64url>-<YYYYMMDD-HHMMSS>.tar.gz` (plus
  `.enc` when the policy encrypts): one archive per mailbox. Mail arriving
  while it is archived is not an error.

**DNS** runs on the server PowerDNS was installed on (the local server for an
install that predates that record) and writes to `/var/backups/dockpanel/dns/`:

- `dns-zone-<zone>-<YYYYMMDD-HHMMSS>.json` (plus `.enc` when the policy
  encrypts): each zone exported through the PowerDNS API, records included;
- `dns-snapshot-<sqlite|pgsql>-<YYYYMMDD-HHMMSS>.gz.enc`: the whole PowerDNS
  database, **always encrypted**. Only the snapshot covers DNSSEC keys.

When the mail server or PowerDNS is not installed, that part is skipped: the
skip is written to the system log and the run is neither failed nor degraded
by it.

### Restore mail

On the **Mail** page, **Mailbox backups**:

- **Restore mailbox** puts one mailbox back on the server that holds the
  archive. By default the restore merges: messages newer than the backup are
  kept. Tick **Replace current mail** to replace the mailbox with the backup.
  When the mailbox no longer exists, it is recreated first from the newest
  mail config backup of that server, with its original password.
- **Restore all mail** (on a config backup) puts back the domains, mailboxes
  and aliases that are missing on that server, reinstalls the DKIM key of each
  domain it puts back, rebuilds the mail server configuration, then restores
  every mailbox from its newest backup, one by one, in the background. The
  outcome is written to the system log and to the panel notifications.

A restore never issues a certificate and never changes DNS records: the rows
are put back as they were, without going through domain creation.

### Restore DNS

On the **DNS** page, **DNS backups**:

- **Restore zone** applies the exported zone through the PowerDNS API. A zone
  that still exists is kept and its records are replaced by the backup's;
  records added since the backup are deleted, so the zone ends up exactly as
  it was saved. Its SOA serial still goes up (PowerDNS raises it on every
  change through the API), so secondary servers pick up the restored zone.
- **Restore full DNS database** replaces the PowerDNS database with the
  snapshot and restarts PowerDNS. This replaces every zone on the DNS server.

A restore that outlasts the request goes on on the server, and the page
follows it until it ends.

Retention follows the policy's retention count, per mailbox, per zone, and
for the mail config and the DNS snapshot, on this server and at the
destination (see [Backup Destinations](#backup-destinations)). Verification
and restore drills do not cover mail and DNS backups yet.

## Backup Verification

Verification confirms a backup is intact and restorable by checking file integrity, decompression, headers, and structure.

### Automatic Verification

Enable **Verify after backup** on a policy to verify every backup automatically. Results appear in the Verifications tab.

### Manual Verification

1. Find any backup in the list and click **Verify**
2. The check runs in the background

**From the CLI:**

```bash
dockpanel backup verify --type database myapp myapp_2026-03-22_020000.sql.gz
```

Sample output:

```
Verifying database backup: myapp_2026-03-22_020000.sql.gz...
  Verification PASSED (4/4 checks, 320ms)
    File exists and readable
    Decompresses without errors
    SQL header valid
    Table count matches (23 tables)
```

Verification types: `site`, `database`, `volume`.

## Backup Destinations

Store backups off-server. There are exactly two destination types - `s3` and `sftp` - and every S3-compatible provider uses the first:

| Provider | Type | Endpoint example |
|----------|------|-----------------|
| AWS S3 | `s3` | `https://s3.us-east-1.amazonaws.com` |
| Backblaze B2 | `s3` | `https://s3.us-west-001.backblazeb2.com` |
| Google Cloud Storage | `s3` | `https://storage.googleapis.com` |
| DigitalOcean Spaces | `s3` | `https://nyc3.digitaloceanspaces.com` |
| MinIO (self-hosted) | `s3` | `https://minio.example.com:9000` |
| Cloudflare R2 | `s3` | `https://<account>.r2.cloudflarestorage.com` |
| Any SFTP server | `sftp` | `sftp://backup.example.com:22` |

Add a destination under **Backup Manager** > **Destinations**, then select it on a policy.

> **SFTP with a private key: put the key where the agent can read it.** The agent that uploads, lists and downloads runs with `ProtectHome=yes`, so `/root` and `/home` do not exist for it: a `key_path` such as `/root/.ssh/backup_key` or `/home/me/.ssh/id_ed25519` cannot be read: ssh reports the identity file as not accessible and the connection fails, although the file is there. Use a path outside them, readable by root only, for example `/etc/dockpanel/sftp-keys/backup.key`:
>
> ```bash
> sudo install -d -m 700 /etc/dockpanel/sftp-keys
> sudo install -m 600 -o root -g root ~/.ssh/backup_key /etc/dockpanel/sftp-keys/backup.key
> ```

A policy with no destination writes its archives to this server's own disk and nowhere else. CyberHunter - Panel says so on the Backup Manager overview rather than leaving you to discover it - see [What CyberHunter - Panel checks for you](prerequisites.md).

> **Retention off-site covers site archives and database dumps, on S3 and SFTP.** After each upload the panel keeps the newest copies at the destination, up to the policy's retention count, and deletes older ones. Only files named exactly `<site or database>-<YYYYMMDD-HHMMSS><extension>` are ever deleted, so other files in the bucket or directory are left alone. Retention is skipped, and reported in the policy's run history, when two resources share a name (the same domain on two servers, or the same database name for two owners). App data archives follow the same rule, per volume or bind mount: only `<app>-<v|b>-<name>-<YYYYMMDD-HHMMSS>.tar.gz` and `.tar.gz.enc` of that exact target are ever deleted, and retention is skipped and reported when the same name is also used by another server or by a site. Mail and DNS files follow it too: per mailbox (`mail-<domain>-<local part>-`), per zone (`dns-zone-<zone>-`), and for `mailcfg-` and `dns-snapshot-<backend>-`; retention is skipped and reported when another server writes the same names (the mail config or DNS snapshot of a second server sent to the same destination, or the same mailbox or zone on two servers).

## Encryption

> **Encryption covers database dumps and app data archives, not site
> archives.** The agent has no encryption path for a site archive, so ticking
> **Encrypt dumps and app data** on a policy that also backs up sites leaves
> those archives in cleartext both on disk and at the destination. A site archive is the whole
> webroot - configuration files, and any database credentials in them - and
> since v2.34.0 it also carries a dump of every database attached to that site.
> So an encrypted policy covering sites ships an encrypted copy of that data and
> an unencrypted copy of the same data to the same destination.

When encryption is enabled, for the database dumps and app data archives it covers:

- **Algorithm**: AES-256-CBC with PBKDF2 (100,000 iterations), then an
  HMAC-SHA256 tag over the ciphertext (encrypt-then-MAC) so a corrupted or
  tampered backup is rejected before it is ever decrypted, rather than
  decrypting silently into wrong bytes. The MAC key is derived from the same
  backup passphrase via a domain-separated HMAC, independent of the key
  `openssl` derives for encryption itself. A backup encrypted before this
  scheme shipped has no tag and is still decrypted, unauthenticated, for
  backward compatibility.
- **Key management**: no key is stored anywhere. The passphrase is derived from
  the panel's `JWT_SECRET` (an HKDF derivation for current backups; backups made
  before key version 2 used an older derivation from the same secret) every time
  a dump or an app data archive is encrypted, verified or restored. On a standard install `JWT_SECRET`
  lives only in `/etc/dockpanel/api.env` (Docker Compose: `PANEL_JWT_SECRET` in
  `panel/.env`), so **losing that file, or changing `JWT_SECRET`, makes every
  encrypted backup made until then unreadable**, on this server and at the
  destination. Keep a copy of it somewhere safe, apart from the backups it
  unlocks. `SECRETS_ENCRYPTION_KEY` plays no part in this derivation. See
  [Configuration](../CONFIGURATION.md) for how these keys are handled.
- The mail config archive and the DNS snapshot are **always** encrypted with
  this passphrase, whatever the policy's Encrypt setting: they carry DKIM keys,
  password hashes and, for PowerDNS on PostgreSQL, its database password
- Encrypted backups have a `.enc` extension
- Decryption happens automatically during restore and verification

## Health Dashboard

**From the panel:** Go to **Backup Orchestrator** to see the health overview.

**From the CLI:**

```bash
dockpanel backup health
```

The dashboard shows:

- **Backup counts**: Site, database, and volume backups with total storage
- **Last 24h**: How many scheduled backups succeeded or failed
- **Active policies**: Enabled vs total policies
- **Verification rate**: Passed vs failed verifications
- **Stale resources**: Sites or databases with no backup in over 7 days

## Storage Tracking

The **Storage History** chart shows backup storage growth over the last 30 days. Use it to plan disk capacity.

## API Reference

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/backup-orchestrator/health` | Health dashboard (admin) |
| `GET` | `/api/backup-orchestrator/policies` | List policies |
| `POST` | `/api/backup-orchestrator/policies` | Create a policy |
| `PUT` | `/api/backup-orchestrator/policies/{id}` | Update a policy |
| `DELETE` | `/api/backup-orchestrator/policies/{id}` | Delete a policy |
| `POST` | `/api/backup-orchestrator/policies/protect-all` | Create "Protect Everything" policy |
| `GET` | `/api/backup-orchestrator/policies/targets` | App data targets of the policy's server, for `excluded_targets` (`?policy_id=`) |
| `POST` | `/api/backup-orchestrator/db-backup` | Create a database backup |
| `GET` | `/api/backup-orchestrator/db-backups` | List database backups |
| `DELETE` | `/api/backup-orchestrator/db-backups/{id}` | Delete a database backup |
| `POST` | `/api/backup-orchestrator/db-backups/{id}/restore` | Restore a database |
| `POST` | `/api/backup-orchestrator/volume-backup` | Back up one app data target (volume or bind mount) |
| `GET` | `/api/backup-orchestrator/volume-backups` | List app data backups |
| `POST` | `/api/backup-orchestrator/volume-backups/{id}/restore` | Restore app data (volume or bind mount) |
| `GET` | `/api/backup-orchestrator/mail-backups` | List mail backups (admin) |
| `GET` | `/api/backup-orchestrator/dns-backups` | List DNS backups (admin) |
| `GET` | `/api/backup-orchestrator/backup-jobs/{server_id}/{job_id}` | Follow a long mail or DNS restore (admin) |
| `POST` | `/api/mail/backups/{id}/restore` | Restore one mailbox, body `{"mode": "merge"}` or `{"mode": "replace"}` (admin) |
| `POST` | `/api/mail/backups/{id}/restore-all` | Restore the mail configuration, then every mailbox (admin) |
| `POST` | `/api/dns/backups/{id}/restore` | Restore one zone or the whole DNS database (admin) |
| `POST` | `/api/backup-orchestrator/verify` | Trigger verification |
| `GET` | `/api/backup-orchestrator/verifications` | List verifications |
| `GET` | `/api/backup-orchestrator/storage-history` | Storage growth (30 days) |

All endpoints require authentication. Health and storage endpoints require admin access.
