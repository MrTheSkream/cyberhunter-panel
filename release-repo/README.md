# CyberHunter - Panel: releases

This repository only holds the **releases** of CyberHunter - Panel, a
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
2. downloads `checksums.txt` over https and checks its format strictly;
3. downloads every file it installs and checks its SHA-256 against
   `checksums.txt`. Any mismatch or missing file stops the install;
4. unpacks the release source into `/opt/dockpanel` and runs its `setup.sh`.

Once installed, the panel updates itself (Telemetry, Updates), with the same
checks against each release's `checksums.txt`.

## Releases are not signed

There is no signature on these releases. `checksums.txt` comes from the same
release as the files it lists: it proves that a download is complete and
intact, not who published it. Someone who took control of the GitHub account
that publishes this repository could publish a modified release, with matching
checksums, and every panel would install it as root. The integrity of a
release therefore rests on the security of that GitHub account (two-factor
authentication, keys, scoped tokens).

## Check install.sh before running it

`install.sh` is listed in the `checksums.txt` of each release. To check that
your copy matches the release it came from:

```bash
TAG=v3.0.0                                   # the release you downloaded
BASE=https://github.com/MrTheSkream/cyberhunter-releases/releases/download/$TAG
curl -fsSLO "$BASE/install.sh"
curl -fsSLO "$BASE/checksums.txt"

sha256sum -c --ignore-missing checksums.txt
# must print: install.sh: OK

sudo DOCKPANEL_VERSION=$TAG bash install.sh
```

Use files from the same release (`releases/download/<tag>/`), not a mix of
`latest` and a tag. This catches a corrupted download; it does not protect
against a release replaced on GitHub (see above).

## What a release contains

| File | What it is |
| --- | --- |
| `cyberhunter-{agent,api,cli,mcp}-linux-amd64` | the binaries (x86_64) |
| `cyberhunter-{agent,api,cli,mcp}-linux-arm64` | the binaries (ARM64), when built |
| `cyberhunter-frontend.tar.gz` | the web interface |
| `cyberhunter-source.tar.gz` | the complete source code of this version |
| `install.sh` | the installer |
| `checksums.txt` | SHA-256 of every file above |

## Source code (AGPL v3)

CyberHunter - Panel is free software, under the GNU Affero General Public
License v3 (see [LICENSE](LICENSE)). It is a modified version of DockPanel,
also AGPL v3.

The corresponding source code of each release is attached to it as
`cyberhunter-source.tar.gz`:

```
https://github.com/MrTheSkream/cyberhunter-releases/releases/download/<tag>/cyberhunter-source.tar.gz
```

It is listed in the same `checksums.txt` as the binaries. If you run a
modified version of the panel for users over a network, the AGPL asks you to
offer them its source as well.
