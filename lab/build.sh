#!/usr/bin/env bash
# Compilation des crates Rust de CyberHunter - Panel dans un conteneur, sans toucher à la copie de travail.
#
# Lancé depuis Windows (PowerShell ou Git Bash) :
#   docker run --rm -v F:/Project/cyberhunter-panel:/src:ro -v dp-cargo-registry:/usr/local/cargo/registry \
#     -v dp-target:/target -v F:/Project/cyberhunter-panel/lab/out:/out rust:1-bookworm bash /src/lab/build.sh [check|test|release] [crate...]
#
# - /src : le dépôt en lecture seule ; il est recopié dans /work et converti en LF
#   (la copie Windows peut être en CRLF, or les templates nginx sont embarqués tels quels).
# - /target : cache de compilation persistant (un sous-dossier par crate).
# - /out : binaires release (mode release uniquement).
set -euo pipefail
mode="${1:-check}"; shift || true
crates=("$@"); [ ${#crates[@]} -eq 0 ] && crates=(agent backend cli)

work="/work-$$"; rm -rf "$work" && mkdir -p "$work"
tar -C /src --exclude='./panel/*/target' --exclude='node_modules' --exclude='./.git' \
    --exclude='./lab/secrets' --exclude='./lab/out' -cf - . | tar -C "$work" -xf -
# CRLF -> LF sur les fichiers texte connus.
find "$work" -type f \( -name '*.rs' -o -name '*.toml' -o -name '*.sql' -o -name '*.conf' -o -name '*.sh' \
    -o -name '*.tera' -o -name '*.html' -o -name '*.json' -o -name '*.yml' -o -name '*.yaml' -o -name '*.txt' \
    -o -name '*.service' -o -name '*.md' -o -name '*.j2' -o -name '*.tpl' \
    -o -name '*.ts' -o -name '*.tsx' -o -name '*.js' -o -name '*.css' \) -print0 | xargs -0 sed -i 's/\r$//'

for c in "${crates[@]}"; do
  echo "=== $mode : panel/$c"
  cd "$work/panel/$c"
  export CARGO_TARGET_DIR="/target/$c"
  case "$mode" in
    check)   cargo check --all-targets --quiet ;;
    test)    cargo test --quiet ;;
    release)
      cargo build --release --quiet
      mkdir -p /out
      for b in "$CARGO_TARGET_DIR"/release/*; do
        [ -f "$b" ] && [ -x "$b" ] && cp "$b" /out/
      done ;;
    *) echo "mode inconnu: $mode"; exit 2 ;;
  esac
done
echo "=== OK ($mode)"
