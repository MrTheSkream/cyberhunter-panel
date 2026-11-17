#!/usr/bin/env bash
#
# CyberHunter - Panel Quick Installer
# Usage: CYBERHUNTER_REPO_URL=<git clone URL> [DOCKPANEL_VERSION=vX.Y.Z] #          [CYBERHUNTER_RELEASE_DIR=<downloaded release>] sudo -E bash install.sh
#
# The repository is private: CYBERHUNTER_REPO_URL is required and has no
# default, and git authentication (deploy key, credential helper, token in
# the URL) is the operator's business.
#
# Modes:
#   Default:                    Clone repo, build from source (requires Rust, ~3GB RAM)
#   CYBERHUNTER_RELEASE_DIR=…:  Clone repo, install the binaries of a release
#                               downloaded by hand into that directory; setup.sh
#                               checks every file against its checksums.txt
#
# Nothing is downloaded from a release page by this script or by setup.sh.
# Once installed, the panel updates itself from Telemetry, Updates.
#
set -euo pipefail

VERSION="${DOCKPANEL_VERSION:-main}"
REPO_URL="${CYBERHUNTER_REPO_URL:?CYBERHUNTER_REPO_URL is required (the git URL of the CyberHunter - Panel repository)}"
INSTALL_DIR="/opt/dockpanel"

RED='\033[0;31m'
GREEN='\033[0;32m'
BOLD='\033[1m'
NC='\033[0m'

echo ""
echo -e "${GREEN}${BOLD}CyberHunter - Panel Installer${NC}"
echo -e "  Free, self-hosted server management panel"
echo ""

# Check root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: Run as root - sudo bash or pipe to sudo bash${NC}"
    exit 1
fi

# Detect package manager
if command -v apt-get &> /dev/null; then
    PKG_INSTALL="apt-get install -y"
    PKG_UPDATE="apt-get update -y"
elif command -v dnf &> /dev/null; then
    PKG_INSTALL="dnf install -y"
    PKG_UPDATE="dnf check-update || true"
elif command -v yum &> /dev/null; then
    PKG_INSTALL="yum install -y"
    PKG_UPDATE="yum check-update || true"
else
    echo -e "${RED}Error: No supported package manager found (apt/dnf/yum)${NC}"
    exit 1
fi

# Install git if needed
if ! command -v git &> /dev/null; then
    echo -e "${GREEN}[+]${NC} Installing git..."
    $PKG_UPDATE > /dev/null 2>&1
    $PKG_INSTALL git > /dev/null 2>&1
fi

# Clone or update repo
if [ -d "$INSTALL_DIR/.git" ]; then
    echo -e "${GREEN}[+]${NC} Updating existing installation..."
    if ! (cd "$INSTALL_DIR" && git pull --ff-only); then
        echo -e "${RED}[x] Git update failed (local changes?). Run: cd $INSTALL_DIR && git stash && git pull${NC}" >&2
        exit 1
    fi
else
    echo -e "${GREEN}[+]${NC} Downloading CyberHunter - Panel..."
    rm -rf "$INSTALL_DIR"
    git clone --quiet --depth 1 -b "$VERSION" "$REPO_URL" "$INSTALL_DIR"
fi

# Pre-built binaries only from a release the operator downloaded by hand
# (setup.sh verifies it); otherwise build the cloned tree.
if [ -n "${CYBERHUNTER_RELEASE_DIR:-}" ] && [ "${BUILD_FROM_SOURCE:-0}" != "1" ]; then
    export INSTALL_FROM_RELEASE=1
    export CYBERHUNTER_RELEASE_DIR
else
    export INSTALL_FROM_RELEASE=0
fi

# Run setup
echo -e "${GREEN}[+]${NC} Running setup..."
exec bash "$INSTALL_DIR/scripts/setup.sh"
