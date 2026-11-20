<h1 align="center">CyberHunter - Panel</h1>

<p align="center">
  <strong>A free, self-hosted server management panel, written in Rust.</strong><br>
  Panel services run on <strong>~49MB of RAM</strong>. 840 HTTP routes. 147 app templates. 4837 regression assertions. ~57MB binaries. Zero subscriptions.
</p>

<p align="center">
  <a href="https://github.com/MrTheSkream/cyberhunter-panel/releases">Releases</a> &bull;
  <a href="CHANGELOG.md">Changelog</a> &bull;
  <a href="FEATURES.md">Features</a> &bull;
  <a href="LICENSE">License: AGPL v3</a>
</p>

---

## What it is

CyberHunter - Panel is a fork of [DockPanel](https://github.com/ovexro/dockpanel), a
Docker-native hosting panel written in Rust and React. It keeps everything DockPanel does
(sites, databases, Docker apps, mail, DNS, backups, monitoring, security) and adds what was
needed to move a shared-hosting server off HestiaCP: one IP per site, PHP settings per
domain, Apache with `.htaccess`, a full HestiaCP import, antivirus, FTP, web statistics, and
updates installed from the panel itself.

It is free software under the GNU Affero General Public License v3, like DockPanel. It is
not affiliated with the DockPanel project, and its releases are published here, not by
DockPanel.

## Added in this fork

- **Multi-IP** - Add extra IP addresses to the server from the panel (applied live
  and kept across reboots), and give each site its own IP. A mail domain sends from the IP of
  the site with the same name, with a matching HELO.
- **PHP settings per domain** - Upload size, execution time, memory, process manager and
  workers per site, plus isolation (`open_basedir`, `disable_functions`, private temp and
  session directories) and a per-site PHP error log. Each pool is tested before PHP-FPM
  reloads.
- **Log in as a user** - An admin can open the panel as one of their users, see exactly what
  that user sees, and return to their own session in one click. Every action taken that way
  is logged under the user's name with the admin recorded alongside.
- **Apache + .htaccess** - Optional per site: nginx stays in front (SSL, static files, WAF,
  logs) and passes the rest to Apache, which honours the site's `.htaccess`. Debian and
  Ubuntu only.
- **HestiaCP import** - Import a `v-backup-user` archive: sites, certificates, databases,
  mailboxes and FTP accounts, with the same passwords. The import can be run again and gives
  a report per item.
- **ClamAV antivirus** - Mail scanned through Rspamd's antivirus module, a nightly scan of
  site files (schedule adjustable) and a manual scan per site. Detections are reported and
  quarantined in one click; nothing is moved on its own. clamd keeps its signatures in RAM
  (about 1.5 GB), so it is opt-in.
- **FTP and disk quotas** - FTPS only (no plain-text FTP), using the site's existing SFTP
  account and password. Disk usage of each site is measured, with alerts when it nears its
  quota.
- **Web statistics** - GoAccess reports per site, refreshed every hour (or on demand) and
  kept for 12 months. They are shown inside the panel only, never on a public URL.
- **User terminal** - A browser shell as a non-root Linux user, attached to a persistent
  tmux session (for example one running Claude Code). Closing the tab or losing the
  connection does not end it; you find it again when you reconnect.
- **Updates from the interface** - Telemetry, Updates checks this repository's releases,
  installs a new version after a snapshot, and can roll back. Stable and beta (pre-release)
  channels. No GitHub account or token is needed (see [Updates](#updates)).

## Requirements

- A fresh **Ubuntu 22.04 or 24.04** server (other distributions inherited from DockPanel may
  work but are not what this fork is tested on).
- **root** access (the installer runs with `sudo`).
- x86_64. ARM64 only for releases that ship `-linux-arm64` binaries.

## Install

Releases are published on this repository's
[Releases page](https://github.com/MrTheSkream/cyberhunter-panel/releases). No GitHub
account and no token are needed.

**While only pre-releases exist** (`vX.Y.Z-rc.N`), take `install.sh` from the tag itself,
because `releases/latest` never points at a pre-release:

```bash
TAG=vX.Y.Z-rc.N        # the tag shown on the Releases page
curl -fsSLO https://github.com/MrTheSkream/cyberhunter-panel/releases/download/$TAG/install.sh
sudo DOCKPANEL_VERSION=$TAG bash install.sh
```

**Once a stable release exists**, the latest one:

```bash
curl -fsSLO https://github.com/MrTheSkream/cyberhunter-panel/releases/latest/download/install.sh
sudo bash install.sh
```

`install.sh`:

1. picks the latest stable release, or the one named by `DOCKPANEL_VERSION` (a pre-release is
   only installed when you name it);
2. downloads that release's `checksums.txt` over https and checks its format strictly;
3. downloads every file it installs and checks its SHA-256 against `checksums.txt`. Any
   mismatch or missing file stops the install;
4. unpacks the release source into `/opt/dockpanel` and runs its `setup.sh`. Nothing is
   compiled on the server.

Then open `https://YOUR_SERVER_IP:8443` and create your admin account. Without a domain the
panel serves a self-signed certificate, so your browser warns once; it is there so the admin
password you create is encrypted on the way to the server. Point a domain at the server and
pass `PANEL_DOMAIN=your.domain` to get a trusted Let's Encrypt certificate instead.

## Updates

Once installed, the panel updates itself from **Telemetry, Updates**: "Check now", then
install. It reads this repository's releases anonymously, checks every file against the
release's `checksums.txt` (same checks as `install.sh`), takes a snapshot first, and restores
the previous binaries if the panel does not come back.

A token is optional. It is only needed if you point the panel at a private release
repository of your own.

## Releases are not signed

There is no signature on these releases. `checksums.txt` comes from the same release as the
files it lists: it proves that a download is complete and intact, not who published it.

Someone who took control of the GitHub account that publishes this repository could publish a
modified release, with matching checksums, and every panel would install it as root. Trust in a
release therefore rests on the security of that GitHub account (two-factor authentication,
keys, scoped tokens).

## Check install.sh before running it

`install.sh` is listed in the `checksums.txt` of each release. To check that your copy matches
the release it came from:

```bash
TAG=vX.Y.Z-rc.N        # the release you are installing
BASE=https://github.com/MrTheSkream/cyberhunter-panel/releases/download/$TAG
curl -fsSLO "$BASE/install.sh"
curl -fsSLO "$BASE/checksums.txt"

sha256sum -c --ignore-missing checksums.txt
# must print: install.sh: OK

sudo DOCKPANEL_VERSION=$TAG bash install.sh
```

Use files from the same release (`releases/download/<tag>/`), not a mix of `latest` and a tag.
This catches a corrupted download; it does not protect against a release replaced on GitHub
(see above).

## What a release contains

| File | What it is |
| --- | --- |
| `cyberhunter-{agent,api,cli,mcp}-linux-amd64` | the binaries (x86_64) |
| `cyberhunter-{agent,api,cli,mcp}-linux-arm64` | the binaries (ARM64), when built |
| `cyberhunter-frontend.tar.gz` | the web interface |
| `cyberhunter-source.tar.gz` | the complete source code of this version (`scripts/`, `panel/`, `LICENSE`) |
| `install.sh` | the installer |
| `checksums.txt` | SHA-256 of every file above |

## Features

Everything below is inherited from DockPanel and kept in this fork. The complete manifest is
[FEATURES.md](FEATURES.md).

### Hosting
- **Sites** - Static, PHP (8.1-8.5), Node.js, Python, reverse proxy. Automatic Nginx config, SSL, PHP-FPM pools.
- **Databases** - MySQL/PostgreSQL in Docker. Built-in SQL browser, visual schema browser, scheduled dump/restore. Auto-cleanup on site delete.
- **Docker Apps** - 147 templates across 14 categories (AI, CMS, Database, Media, Monitoring, and more). Compose stacks. Resource limits. GPU passthrough.
- **Git Deploy** - Push-to-deploy. Atomic zero-downtime deploys (Capistrano-style). Nixpacks (30+ languages). Preview environments.
- **WordPress Toolkit** - Multi-site dashboard, vulnerability scanning, security hardening, bulk updates.
- **CMS Install** - WordPress, Laravel, Drupal, Joomla, Symfony, CodeIgniter - one click.
- **Backups** - Scheduled, S3/SFTP remote destinations, one-click restore.
- **Backup Orchestrator** - DB/volume backups, AES-256 encryption, restore verification, cross-resource policies, S3/SFTP/B2/GCS destinations, health dashboard.
- **CDN** - BunnyCDN and Cloudflare CDN management. Cache purge, bandwidth stats, pull zone discovery.
- **Image Optimization** - Server-side WebP/AVIF conversion per site.
- **Secrets Manager** - AES-256-GCM encrypted vaults, version history, auto-inject to .env, masked API, CLI pull endpoint.
- **Webhook Gateway** - Inbound endpoints with unique URLs, HMAC-SHA256/SHA1 verification, request inspector, route builder, retry/replay.

### Operations
- **Multi-Server** - Manage remote servers from one panel. Agent auto-registers.
- **DNS** - Cloudflare + PowerDNS. Zone templates, propagation checker, DNSSEC. Cloudflare cache purge, security settings, `cloudflared` install/uninstall.
- **Container Management** - Auto-sleep (stop idle containers), auto-update detection, per-user isolation policies.
- **Mail** - Postfix + Dovecot + OpenDKIM. Webmail (Roundcube), spam filter (Rspamd), SMTP relay.
- **Monitoring** - HTTP/TCP/ping uptime checks, SLA tracking, PagerDuty integration.
- **Prometheus + Grafana** - Token-gated `/api/metrics` scrape endpoint (off by default) plus a drop-in [fleet dashboard](dashboards/dockpanel-grafana.json) covering CPU/memory/disk, GPU utilization/VRAM/temp/power, sites, and alerts. See [docs/guides/prometheus.md](docs/guides/prometheus.md).
- **Incident Management** - Full lifecycle (investigating, identified, monitoring, resolved, postmortem), severity levels, timeline, affected components.
- **Public Status Page** - Standalone dark-themed page at `/status`, component groups, email subscribers, overall status auto-computed from checks.
- **Terminal** - Full SSH with tabs, themes, sharing, session recording.

### Security
- **Passkey/WebAuthn** - Passwordless login with biometrics or security keys. Plus 2FA/TOTP with recovery codes.
- **WAF** - ModSecurity3 + OWASP CRS v4 per site. Detection or prevention mode. Event viewer.
- **CSP & Bot Protection** - Per-site Content Security Policy headers and bot rate limiting.
- **Firewall** - UFW management with smart port opener.
- **Fail2Ban** - View/ban/unban IPs, panel-specific jail.
- **SSH Hardening** - Disable password/root login, change port - one click.
- **Vulnerability Scanning** - File integrity, security headers, full-server audits.
- **Per-Image CVE Scanning** - Scan every running Docker app's image with Anchore grype. Severity badge per app row on the Apps page. Scheduled background rescans (configurable interval). Soft deploy gate refuses images exceeding a critical/high/medium threshold - on template deploys, image changes, compose deploys and stacks alike. Grype installs self-contained into `/var/lib/dockpanel/scanners/` from the Settings UI. **Defaults to off** - opt in from Settings → Services → Image Vulnerability Scanning.
- **Per-Image SBOM Generation** - Generate an SPDX 2.3 JSON SBOM for any deployed Docker app's image on demand (syft). Click "Download SBOM" in any app's scan drawer. Self-contained install at `/var/lib/dockpanel/scanners/syft`. **Defaults to off** - opt in from Settings → Services → SBOM Generation.
- **Auto-Healing** - Restart crashed services, clean disk, renew expiring SSL, auto-sleep idle containers.

### Developer Experience
- **CLI** - `dockpanel status`, `sites`, `apps`, `diagnose`, `export`, `apply`
- **MCP Server** - Read-only fleet introspection (~40 tools: sites, apps, databases, logs, security, monitors, alerts, and more) for AI agents over the Model Context Protocol. Opt-in, off by default, zero mutating tools.
- **Infrastructure as Code** - Export/import server config as YAML. A Terraform/Pulumi-shaped provider API also exists for reading site/database inventory (see [FEATURES.md](FEATURES.md#withdrawn-claims) - its tokens don't yet authenticate).
- **Smart Diagnostics** - 6 check categories with one-click fixes. Auto-optimization recommendations.
- **File Manager** - Browse, edit, upload files from the browser.
- **Command Palette** - Ctrl+K to navigate anywhere.
- **Nginx FastCGI Cache** - Per-site toggle with smart bypass for logged-in users.
- **Redis Object Cache** - Per-site isolated Redis DB with WP auto-config.

### Themes & Layouts
- **6 Themes** - Terminal (hacker green), Midnight (navy blue), Ember (warm amber), Arctic (light teal), Clean (light blue SaaS), Clean Dark (GitHub-dark).
- **3 Layouts** - Sidebar (full sidebar nav), Compact (collapsible icon rail), Topbar (horizontal navbar).

### Business
- **Reseller Accounts** - Admin → Reseller → User hierarchy with quotas.
- **White-Label** - Custom logo, colors, panel name per reseller.
- **OAuth/SSO** - Google, GitHub, GitLab login.
- **Extension API** - Webhook events with HMAC signing.
- **WHMCS Integration** - Provisioning, suspension, termination hooks. Auto-create users from billing.
- **Migration Wizard** - Import from cPanel, HestiaCP. Plesk (beta).

## Architecture

```
Browser → React 19 SPA → Nginx
                           ├── /api/* → API (Rust/Axum)
                           │              ├── PostgreSQL 16
                           │              └── Agent (Unix socket / HTTPS)
                           │                     └── Docker, Nginx, SSL, files, terminal
                           └── /*     → Frontend (static files)
```

**4 Rust binaries**: Agent (~22MB), API (~25MB), CLI (~3.9MB), MCP server (~6.1MB, opt-in). Runtime RAM: ~35MB agent + ~14MB API ≈ 49MB for the panel itself; ~109MB with the bundled PostgreSQL. 17 supervised background services.

| Component | Tech | Role |
|-----------|------|------|
| Agent | Rust/Axum | Root-level host operations (Docker, Nginx, SSL, files) |
| API | Rust/Axum + SQLx | Auth, business logic, multi-server dispatch, background tasks |
| CLI | Rust/Clap | Command-line interface for automation |
| Frontend | React 19 + Vite + Tailwind 4 | Browser UI with 6 themes + 3 layouts |

## Security

Credentials are encrypted at rest with AES-256-GCM. All child processes run with sanitized environments. Per-image CVE scanning (grype) with optional deploy gating catches vulnerable images before they ship. Release integrity is covered in [Releases are not signed](#releases-are-not-signed). [SECURITY.md](SECURITY.md) covers vulnerability reporting.

## CLI

```bash
dockpanel status              # Server status (CPU, RAM, disk)
dockpanel sites               # List all sites
dockpanel apps                # List Docker apps
dockpanel diagnose            # Run smart diagnostics
dockpanel export -o config.yml  # Export server config as YAML
dockpanel apply config.yml    # Apply config (Infrastructure as Code)
```

## Uninstall

```bash
sudo bash /opt/dockpanel/scripts/uninstall.sh
```

## Development

```bash
git clone https://github.com/MrTheSkream/cyberhunter-panel.git && cd cyberhunter-panel

# Start database
docker run -d --name dockpanel-postgres \
  -e POSTGRES_USER=dockpanel -e POSTGRES_PASSWORD=dockpanel -e POSTGRES_DB=dockpanel \
  -p 5450:5432 postgres:16

# Build
cargo build --release --manifest-path panel/agent/Cargo.toml
cargo build --release --manifest-path panel/backend/Cargo.toml
cargo build --release --manifest-path panel/cli/Cargo.toml
cd panel/frontend && npm install && npx vite build
```

Releases are built and published by `scripts/release.sh`. See [CONTRIBUTING.md](CONTRIBUTING.md)
for the development setup inherited from DockPanel.

## Documentation

- [FEATURES.md](FEATURES.md) - Complete feature manifest
- [CHANGELOG.md](CHANGELOG.md) - Version history
- [docs/](docs/) - Getting started, guides, configuration (inherited from DockPanel)
- [SECURITY.md](SECURITY.md) - Security model and vulnerability reporting
- [CONTRIBUTING.md](CONTRIBUTING.md) - Development setup and PR process

## License and source code (AGPL v3)

CyberHunter - Panel is free software: you can redistribute it and/or modify it under the terms
of the GNU Affero General Public License v3 (see [LICENSE](LICENSE)). It is a modified version
of [DockPanel](https://github.com/ovexro/dockpanel), also AGPL v3.

The source code is this repository. The corresponding source of each release is also attached
to it as `cyberhunter-source.tar.gz`, listed in the same `checksums.txt` as the binaries:

```
https://github.com/MrTheSkream/cyberhunter-panel/releases/download/<tag>/cyberhunter-source.tar.gz
```

If you run a modified version of the panel for users over a network, the AGPL asks you to offer
them its source as well.
