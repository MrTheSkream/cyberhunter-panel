# Disaster Recovery Guide

How to bring a CyberHunter - Panel server back on a new machine from its off-site panel
snapshots, then put its sites, databases, app data, mail and DNS back. Setting up the off-site
snapshots themselves is described in [Backups](backups.md#off-site-panel-snapshots-disaster-recovery).

## What you need before a disaster

Keep these three things somewhere that does not depend on the server:

1. **The recovery key**, the file shown once by **Set up recovery key** (or **Rotate recovery
   key**). An archive can only be opened with the key it was encrypted to.
2. **The Install ID**, shown on the **Disaster recovery** card. The off-site snapshots of a server
   live under `<destination base>/cyberhunter-dr/<Install ID>/`, and the restore asks for it.
   It is also part of every archive name.
3. **The destination credentials**: S3 bucket, endpoint, access key and secret key, or SFTP host,
   user and password or private key.

## What an off-site snapshot holds

- the panel database (accounts, 2FA, sites, databases, destinations, policies, backup history);
- the PowerDNS database when PowerDNS keeps its zones in the panel's PostgreSQL;
- `/etc/dockpanel` without the update token: `api.env` (`JWT_SECRET`, and
  `SECRETS_ENCRYPTION_KEY` if it is set: the keys every stored credential and every encrypted
  backup depends on), `agent.token`, the site certificates and the ACME account (`ssl/`), the
  panel's self-signed certificate when it was installed without a domain (`ssl/panel.crt`), DKIM
  keys, the mail configuration, deploy keys, and copies of the SFTP keys kept outside
  `/etc/dockpanel` (`backup-keys/`).

It does **not** hold the binaries and the frontend (the new machine runs the same version
instead), the nginx vhosts (rebuilt from the database), a panel certificate issued by certbot
(`/etc/letsencrypt`, issued again after the DNS switch, step 7), or the data of the sites,
databases, apps and mailboxes (restored from their own backups, step 6).

## Restore on a new machine

The new machine must have the **same architecture** (usually `x86_64`) and run the **same
version** as the snapshot. A different IP address is expected.

### 1. Install the same version

The version is `from_version` in the plaintext manifest next to each archive
(`cyberhunter-dr-<install id>-<stamp>.manifest.json`, readable with the provider's own tool), and
in the version column of the remote copies on the Disaster recovery card. If you install another
version first, `dr list` (step 3) still tells you which version each archive needs. Then install
exactly that release:

```bash
TAG=v<from_version>          # for example v2.47.3
curl -fsSLO https://github.com/MrTheSkream/cyberhunter-panel/releases/download/$TAG/install.sh
sudo DOCKPANEL_VERSION=$TAG bash install.sh
```

Do not create sites or anything else on this panel: the restore replaces its database.

### 2. Write the destination file

As root, a JSON file readable by root only. The restore refuses a file that other users can read.

S3 (any S3-compatible storage):

```json
{
  "type": "s3",
  "bucket": "my-backups",
  "region": "us-east-1",
  "endpoint": "https://s3.example.com",
  "access_key": "AKIA...",
  "secret_key": "...",
  "path_prefix": "panel",
  "install_id": "0b3f7a52-5f1e-4f53-9a43-7f2b8f0c1d2e"
}
```

SFTP:

```json
{
  "type": "sftp",
  "host": "backup.example.com",
  "port": 22,
  "username": "backup",
  "key_path": "/etc/dockpanel/dr-restore-key",
  "remote_path": "/backups",
  "install_id": "0b3f7a52-5f1e-4f53-9a43-7f2b8f0c1d2e"
}
```

`path_prefix` (S3) and `remote_path` (SFTP) are the same base as the destination in the panel,
without `cyberhunter-dr/...`: the restore adds it. Leave out `secret_key` (S3) or `password`
(SFTP) to be asked for it without echo. Secrets are never accepted on the command line.

The destination file and the recovery key are read by the `dockpanel-api dr` command itself
(run as root), so `/root` is fine for them. The SFTP private key named by `key_path` is not: the
download goes through the local agent, which runs with `ProtectHome=yes` and cannot see `/root`
or `/home` (a key there fails with "no such file"). Put it outside them, root only:

```bash
sudo install -m 600 /dev/null /root/dr-dest.json      # then edit it
sudo install -m 600 /dev/null /root/recovery-key.txt  # paste the recovery key into it
sudo install -m 600 -o root -g root /path/to/backup-key /etc/dockpanel/dr-restore-key   # SFTP with a key only
```

### 3. List the snapshots

```bash
sudo dockpanel-api dr list --destination-file /root/dr-dest.json
```

(`--install-id <uuid>` instead of `install_id` in the file also works.) Each archive is listed
with its version, architecture, size and date, and whether it can be restored on this machine.

### 4. Restore

```bash
sudo dockpanel-api dr restore \
  --archive cyberhunter-dr-<install id>-<YYYYMMDD-HHMMSS>.tar.gz.age \
  --identity-file /root/recovery-key.txt \
  --destination-file /root/dr-dest.json
```

The command says what it is about to do and asks you to type `RESTORE` (`--yes` skips the
question). Then, through the local agent:

1. it downloads the manifest and refuses an archive of another version or architecture, or one
   encrypted to another key, before anything else;
2. it downloads the encrypted archive and checks its sha256 against the manifest;
3. it decrypts it into a 0600 file of `/var/backups/dockpanel/restore-inbox` (removed at the end,
   whatever happens);
4. it starts `restore-snapshot.sh` in mode `dr`, which checks the version and the architecture
   again **before stopping anything**, stops the panel, saves the current database to
   `/var/lib/dockpanel/pre-rollback-<id>.sql.gz`, replaces the database in one transaction,
   restores the PowerDNS database if the snapshot has one, restores `/etc/dockpanel` (keeping this
   machine's `DATABASE_URL`, never shown), makes `agent.token` agree with `api.env`, reloads
   nginx after `nginx -t`, starts the panel and checks it answers;
5. at its first start, the panel rebuilds the nginx configuration of every site from the restored
   database. A site bound to an IP address that does not exist on this machine is moved to the
   primary IP address. SFTP destinations whose key was copied in the snapshot are pointed at the
   restored copy (`/etc/dockpanel/sftp-keys/`). Then it lists the off-site snapshots at the
   configured destinations and puts them back on the Disaster recovery card (the restored
   database was dumped during the run that made the archive, so it knew neither that archive nor
   the later ones), and records the last run as `restored` ("Panel restored from <archive>")
   instead of a failed run. It also checks that the panel's self-signed certificate, if there is
   one, names this machine's primary IP (step 5 below). The report is written to
   `/var/lib/dockpanel/vhost-rebuild.json`.

The command waits for the verdict (`/var/lib/dockpanel/last-restore.json`) and for that report,
and prints both: sites rebuilt, sites moved to the primary IP, failures (for example a PHP
version not installed yet on this machine), `nginx -t` and the reload. It exits 0 only when both
are clean. A refused restore changes nothing; `journalctl -u dockpanel-snapshot-restore-<id>`
shows the details.

Then remove the secret files: `sudo shred -u /root/recovery-key.txt /root/dr-dest.json`, and
`/etc/dockpanel/dr-restore-key` if you created it (a key left under `/etc/dockpanel` goes into
every later off-site snapshot). The restored SFTP destinations use their own copy in
`/etc/dockpanel/sftp-keys/`.

### 5. Sign in

Open the panel by the new IP address (the old domain does not point here yet): your accounts,
passwords and 2FA are those of the snapshot. On the **Disaster recovery** card, **Remote restore**
shows the last restore and the site rebuild report. Fix any failed site (install its PHP version
or Apache, then save it). **Test connection** on each backup destination proves the restored keys
work.

#### The panel's self-signed certificate

A panel installed without a domain serves a self-signed certificate,
`/etc/dockpanel/ssl/panel.crt`, made at install time for that machine's addresses. It is in the
archive, so it comes back naming the old IP address: the browser warning then adds a name
mismatch. No panel or installer step regenerates it (the installer never overwrites an existing
one), so the site rebuild report and `dr restore` say when it does not name the primary IP. To
make a new one for this machine (accept the new fingerprint in your browser afterwards):

```bash
IP=203.0.113.20   # this machine's primary IP address
sudo openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=$IP" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:$IP" \
  -keyout /etc/dockpanel/ssl/panel.key -out /etc/dockpanel/ssl/panel.crt
sudo chmod 600 /etc/dockpanel/ssl/panel.key && sudo chmod 644 /etc/dockpanel/ssl/panel.crt
sudo nginx -t && sudo systemctl reload nginx
```

A panel with a domain does not use this file: its certificate is issued again in step 7.

### 6. Restore the data, in this order

1. **Sites and databases**: on the **Disaster recovery** card, **Restore sites and databases from
   remote backups**. For each site and database whose latest backup was sent to a remote
   destination, it downloads that backup, checks its sha256, and restores it (sites first, with
   the databases their archives carry; a database dump older than its site's archive is skipped).
   An encrypted dump (`.enc`) whose sha256 differs from the recorded one is restored with a
   warning in its line: older agents recorded the hash of the unencrypted dump, and the
   integrity check (HMAC) of its decryption refuses a corrupted or modified file. For any other
   file, a different sha256 fails the item.
   Database containers that do not exist on this machine are recreated first, with the same name,
   engine, port and password. The report lists each item as restored, failed or skipped.
The next three restore from a file on THIS machine, and the bulk action above does not fetch
their archives. Copy each archive from the destination first, with the provider's own tool
(`aws s3 cp`, `rclone`, `sftp get`; the file names are those listed in the panel):

2. **App data** (Docker volumes and bind mounts): redeploy each app, put its archive in
   `/var/backups/dockpanel/volumes/<container name>/` (mode 0600, owner root), then restore it from
   the Backup Orchestrator.
3. **Mail**: put the configuration and mailbox archives in
   `/var/backups/dockpanel/restore-inbox/` (mode 0600), then on the Mail page, **Mail backups**,
   **Restore all mail** on the latest configuration backup (domains, mailboxes, configuration,
   then every mailbox).
4. **DNS**: the PowerDNS database came back with the snapshot when PowerDNS used the panel's
   PostgreSQL. Otherwise, or for a newer state, put the DNS archive in
   `/var/backups/dockpanel/restore-inbox/` and restore it from the DNS page, **DNS backups**.
   Then update the records that name the old IP address (the panel's A record, the sites, MX and
   SPF).

### 7. Switch the DNS, then the panel certificate

Point the panel's domain and the sites' domains at the new IP address. Once the panel's domain
resolves to the new machine, issue its certificate again:

```bash
sudo certbot --nginx -d panel.example.com
sudo certbot renew --dry-run
```

The site certificates came back with `/etc/dockpanel/ssl` and keep working until they expire; they
renew as usual once their domains point here, with the restored ACME account.

## Restore from the panel

When the panel itself still runs (same machine, same version), the **Disaster recovery** card
offers on each remote copy:

- **Download encrypted archive**: the `.tar.gz.age` as stored at the destination. It can only be
  opened with the recovery key (`age -d -i recovery-key.txt <archive> | tar -tz` lists it).
- **Restore from remote snapshot**: paste the recovery key ("It is used for this restore only and
  is never stored."), confirm. The same steps as `dr restore` run in the background; the panel
  stops and restarts, and the card keeps checking until the verdict and the site rebuild report
  are there.

After the restart, the card lists the off-site copies found at the destinations again, and the
last run reads `restored` with the archive name. The same resynchronisation also runs at the start
of every off-site snapshot run.

The recovery key goes from the request to the decryption in memory only: it is never written to
disk, put on a command line or in an environment variable, or logged. Only its fingerprint is
logged (`journalctl -u dockpanel-api`, "recovery key fingerprint"), with the archive name and
the operator.

## API

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/dr/remote-snapshots/{id}/download` | The encrypted archive of a remote copy (admin) |
| `POST` | `/api/dr/remote-snapshots/{id}/restore` | Body `{"identity": "<recovery key>"}`; 202, restore in the background (admin) |
| `GET` | `/api/dr/restore` | Progress, last restore verdict, site rebuild report, rehydration report (admin) |
| `POST` | `/api/dr/rehydrate` | 202, restore sites and databases from remote backups (admin) |
