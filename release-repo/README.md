# CyberHunter - Panel: releases

This repository only holds the **signed releases** of CyberHunter - Panel, a
self-hosted server management panel. There is no panel code in its git
history: the code of each version is attached to its release (see
[Source code](#source-code-agpl-v3) below).

## Install

On a fresh Linux server (x86_64 or ARM64), as root:

```bash
curl -fsSLO https://github.com/MrTheSkream/cyberhunter-releases/releases/latest/download/install.sh
sudo bash install.sh
```

A given release, pre-releases included (`releases/latest` never points at a
pre-release, so this is the only form while only `-rc` releases exist):

```bash
TAG=v3.0.0-rc.5
curl -fsSLO https://github.com/MrTheSkream/cyberhunter-releases/releases/download/$TAG/install.sh
sudo DOCKPANEL_VERSION=$TAG bash install.sh
```

No GitHub account and no token are needed. `install.sh`:

1. picks the latest stable release (or the one named by `DOCKPANEL_VERSION`,
   for example `sudo DOCKPANEL_VERSION=v3.0.0-rc.5 bash install.sh`; a
   pre-release is only installed when you name it);
2. installs `minisign` with the package manager if it is missing, and stops
   if it cannot (the signature is never skipped);
3. downloads `checksums.txt` and `checksums.txt.minisig`, and checks the
   signature against the release signing key written inside `install.sh`. The
   signature's trusted comment must be exactly `cyberhunter-release <tag>`;
4. downloads every file it installs and checks its SHA-256 against
   `checksums.txt`. Any mismatch or missing file stops the install;
5. unpacks the release source into `/opt/dockpanel` and runs its `setup.sh`.

Once installed, the panel updates itself (Telemetry, Updates). Every update is
checked against the same key, by the panel itself.

**Supported systems.** `minisign` comes from the distribution's packages:
Ubuntu 24.04 and Debian 12 have it (minisign 0.11). **Ubuntu 22.04 does not package
it**: install minisign 0.11 or later by hand first (for example from
<https://github.com/jedisct1/minisign/releases>, checking it as its author
documents), or `install.sh` stops.

## Verify install.sh before running it

The very first `install.sh` comes from GitHub, so check it yourself if you
want to be sure it is the one that was signed. `install.sh` is listed in the
signed `checksums.txt` of each release.

Release signing key (minisign):

```
Key ID:     <KEY_ID - filled in at the first public release>
Public key: <PUBLIC_KEY - filled in at the first public release>
```

```bash
TAG=v3.0.0                                   # the release you downloaded
BASE=https://github.com/MrTheSkream/cyberhunter-releases/releases/download/$TAG
curl -fsSLO "$BASE/install.sh"
curl -fsSLO "$BASE/checksums.txt"
curl -fsSLO "$BASE/checksums.txt.minisig"

minisign -Vm checksums.txt -P '<PUBLIC_KEY>'
# must print: Signature and comment signature verified
#             Trusted comment: cyberhunter-release v3.0.0   (your TAG)

sha256sum -c --ignore-missing checksums.txt
# must print: install.sh: OK

sudo DOCKPANEL_VERSION=$TAG bash install.sh
```

Check that the trusted comment names the tag you asked for: a signature made
for another release does not vouch for this one. Use files from the same
release (`releases/download/<tag>/`), not a mix of `latest` and a tag.

The key inside `install.sh` is on its `CYBERHUNTER_STAMPED_PUBKEY=` line; it
must be the public key above.

## What a release contains

| File | What it is |
| --- | --- |
| `cyberhunter-{agent,api,cli,mcp}-linux-amd64` | the binaries (x86_64) |
| `cyberhunter-{agent,api,cli,mcp}-linux-arm64` | the binaries (ARM64), when built |
| `cyberhunter-frontend.tar.gz` | the web interface |
| `cyberhunter-source.tar.gz` | the complete source code of this version |
| `install.sh` | the installer, with the signing key written in |
| `checksums.txt` | SHA-256 of every file above |
| `checksums.txt.minisig` | minisign signature of `checksums.txt` |

## Source code (AGPL v3)

CyberHunter - Panel is free software, under the GNU Affero General Public
License v3 (see [LICENSE](LICENSE)). It is a modified version of DockPanel,
also AGPL v3.

The corresponding source code of each release is attached to it as
`cyberhunter-source.tar.gz`:

```
https://github.com/MrTheSkream/cyberhunter-releases/releases/download/<tag>/cyberhunter-source.tar.gz
```

It is covered by the same signed `checksums.txt` as the binaries. If you run a
modified version of the panel for users over a network, the AGPL asks you to
offer them its source as well.
