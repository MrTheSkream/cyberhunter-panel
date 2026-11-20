#!/usr/bin/env bash
# Fabrique une sauvegarde `v-backup-user` HestiaCP synthetique et minimale,
# acceptee par l'import Hestia du panel (05-import-hestia, 14-certificats-mail-sni).
#
# Usage : lab/make-hestia-fixture.sh <sortie.tar> <ca_cert.pem> <ca_key.pem>
#
#   <sortie.tar>   archive produite (tar NON compresse : mode lazy de l'agent).
#                  Nommez-la `labuser.AAAA-MM-JJ_hh-mm-ss.tar` comme Hestia.
#   <ca_cert.pem>  CA de test qui signe le certificat mail.a.example.test.
#   <ca_key.pem>   cle de cette CA.
#
# Contenu : utilisateur `labuser` ;
#   - web  a.example.test (public_html/index.html, sans SSL web) ;
#   - mail a.example.test, boite contact@, DKIM (selecteur `mail`),
#     certificat mail/a.example.test/conf/ssl/a.example.test.{crt,key,ca,pem}
#     (SAN mail.a.example.test, webmail.a.example.test, 90 jours, signe par la CA) ;
#   - mail b.example.test, boite info@, SANS conf/ssl (cas `missing`).
#
# Le mot de passe des boites est genere, hache en {BLF-CRYPT}$2y$, et ecrit
# dans `<sortie.tar>.password` (0600). Il n'est jamais affiche.
#
# Dependances : bash, tar, gzip, openssl, et htpasswd (apache2-utils) OU
# python3 (module bcrypt, ou crypt avec libxcrypt) pour le hash bcrypt.
set -euo pipefail

die() { echo "make-hestia-fixture: $*" >&2; exit 1; }

[ $# -eq 3 ] || die "usage: $0 <sortie.tar> <ca_cert.pem> <ca_key.pem>"
OUT=$1
CA_CRT=$2
CA_KEY=$3
[ -r "$CA_CRT" ] || die "CA illisible : $CA_CRT"
[ -r "$CA_KEY" ] || die "cle de CA illisible : $CA_KEY"
for b in tar gzip openssl; do command -v "$b" >/dev/null || die "$b introuvable"; done
openssl x509 -in "$CA_CRT" -noout 2>/dev/null || die "$CA_CRT n'est pas un certificat PEM"

case "$(basename "$OUT")" in
  labuser.*.tar) ;;
  *) echo "make-hestia-fixture: conseil : nommez la sortie labuser.<date>.tar (nom d'archive Hestia)" >&2 ;;
esac

USER_NAME=labuser
WEB_D=a.example.test
MAIL_A=a.example.test
MAIL_B=b.example.test
NOW_DATE=$(date -u +%Y-%m-%d)
NOW_TIME=$(date -u +%H:%M:%S)

umask 077
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
R=$WORK/root      # racine de l'archive
T=$WORK/tmp       # fichiers de travail (jamais archives)
mkdir -p "$R" "$T"

# --------------------------------------------------------------------------
# Mot de passe + hash bcrypt $2y$ (jamais affiche, jamais en argument).
# --------------------------------------------------------------------------
PASSWORD=$(openssl rand -base64 18 | tr -d '/+=\n' | cut -c1-20)
[ ${#PASSWORD} -ge 16 ] || die "generation du mot de passe impossible"

bcrypt_hash() {
  local h=""
  if command -v htpasswd >/dev/null 2>&1; then
    h=$(printf '%s' "$PASSWORD" | htpasswd -niBC 10 x 2>/dev/null | head -n1 | cut -d: -f2- | tr -d '\r\n') || h=""
  fi
  if [ -z "$h" ] && command -v python3 >/dev/null 2>&1; then
    h=$(printf '%s' "$PASSWORD" | python3 -I -c '
import sys
pw = sys.stdin.buffer.read()
try:
    import bcrypt
    h = bcrypt.hashpw(pw, bcrypt.gensalt(rounds=10, prefix=b"2b")).decode()
except ImportError:
    import warnings
    warnings.simplefilter("ignore")
    import crypt
    h = crypt.crypt(pw.decode(), crypt.mksalt(crypt.METHOD_BLOWFISH, rounds=1024)) or ""
if h.startswith("$2b$") or h.startswith("$2a$"):
    h = "$2y$" + h[4:]
print(h)
' 2>/dev/null) || h=""
  fi
  case "$h" in
    '$2y$'*) printf '%s' "$h" ;;
    *) return 1 ;;
  esac
}
BCRYPT=$(bcrypt_hash) || die "aucun outil bcrypt (installez apache2-utils, ou python3-bcrypt)"
HASH="{BLF-CRYPT}$BCRYPT"

PWFILE="$OUT.password"
( umask 077; printf 'contact@%s %s\ninfo@%s %s\n' "$MAIL_A" "$PASSWORD" "$MAIL_B" "$PASSWORD" > "$PWFILE" )
chmod 600 "$PWFILE"
unset PASSWORD

# --------------------------------------------------------------------------
# hestia/ et pam/ (utilisateur)
# --------------------------------------------------------------------------
mkdir -p "$R/hestia" "$R/pam"
cat > "$R/hestia/user.conf" <<EOF
NAME='$USER_NAME' PACKAGE='default' CONTACT='admin@$WEB_D' CRON_REPORTS='no' MD5='' RKEY='' TWOFA='' QRCODE='' PHPCLI='' ROLE='user' SUSPENDED='no' SUSPENDED_USERS='0' SUSPENDED_WEB='0' SUSPENDED_DNS='0' SUSPENDED_MAIL='0' SUSPENDED_DB='0' SUSPENDED_CRON='0' IP_AVAIL='1' IP_OWNED='0' U_USERS='0' U_DISK='1' U_DISK_DIRS='0' U_DISK_WEB='1' U_DISK_MAIL='1' U_DISK_DB='0' U_BANDWIDTH='0' U_WEB_DOMAINS='1' U_WEB_SSL='0' U_WEB_ALIASES='0' U_DNS_DOMAINS='0' U_DNS_RECORDS='0' U_MAIL_DOMAINS='2' U_MAIL_DKIM='1' U_MAIL_ACCOUNTS='2' U_MAIL_SSL='1' U_DATABASES='0' U_CRON_JOBS='0' U_BACKUPS='0' LANGUAGE='' NOTIFICATIONS='no' TIME='$NOW_TIME' DATE='$NOW_DATE'
EOF
printf '%s:x:1001:1001::/home/%s:/bin/bash\n' "$USER_NAME" "$USER_NAME" > "$R/pam/passwd"
printf '%s:!:20000:0:99999:7:::\n' "$USER_NAME" > "$R/pam/shadow"
printf '%s:x:1001:\n' "$USER_NAME" > "$R/pam/group"

# --------------------------------------------------------------------------
# web/a.example.test : domain_data.tar.gz (./public_html/index.html), web.conf
# --------------------------------------------------------------------------
W=$R/web/$WEB_D
mkdir -p "$W/hestia" "$W/conf" "$T/dd/public_html" "$T/dd/private" "$T/dd/document_errors"
cat > "$T/dd/public_html/index.html" <<EOF
<!doctype html>
<html><head><meta charset="utf-8"><title>$WEB_D</title></head>
<body><p>Fixture Hestia $WEB_D</p></body></html>
EOF
chmod -R u+rwX,go+rX "$T/dd"
tar -C "$T/dd" --owner=0 --group=0 --numeric-owner -cf - . | gzip -9n > "$W/domain_data.tar.gz"
cat > "$W/hestia/web.conf" <<EOF
DOMAIN='$WEB_D' IP='192.0.2.10' IP6='' CUSTOM_DOCROOT='' CUSTOM_PHPROOT='' FASTCGI_CACHE='' FASTCGI_DURATION='' ALIAS='' TPL='default' SSL='no' SSL_FORCE='no' SSL_HOME='same' LETSENCRYPT='no' FTP_USER='' FTP_MD5='' FTP_PATH='' BACKEND='' PROXY='' PROXY_EXT='' STATS='' STATS_USER='' STATS_CRYPT='' REDIRECT='' REDIRECT_CODE='' U_DISK='1' U_BANDWIDTH='0' SUSPENDED='no' TIME='$NOW_TIME' DATE='$NOW_DATE'
EOF
cat > "$W/conf/nginx.conf" <<EOF
server {
    listen      192.0.2.10:80;
    server_name $WEB_D;
    root        /home/$USER_NAME/web/$WEB_D/public_html;
    index       index.html;
}
EOF

# --------------------------------------------------------------------------
# mail/<d> : un domaine
#   $1 domaine  $2 boite  $3 dkim yes|no
# --------------------------------------------------------------------------
make_mail_domain() {
  local d=$1 box=$2 dkim=$3
  local M=$R/mail/$d
  mkdir -p "$M/hestia" "$M/conf"

  cat > "$M/hestia/mail.conf" <<EOF
DOMAIN='$d' ANTIVIRUS='no' ANTISPAM='no' REJECT='no' DKIM='$dkim' WEBMAIL='' SSL='$([ "$d" = "$MAIL_A" ] && echo yes || echo no)' LETSENCRYPT='no' CATCHALL='' ACCOUNTS='1' RATE_LIMIT='' U_DISK='1' SUSPENDED='no' TIME='$NOW_TIME' DATE='$NOW_DATE' DKIM_SELECTOR='mail'
EOF
  cat > "$M/hestia/$d.conf" <<EOF
ACCOUNT='$box' ALIAS='' AUTOREPLY='no' FWD='' FWD_ONLY='' MD5='$HASH' QUOTA='unlimited' U_DISK='1' SUSPENDED='no' TIME='$NOW_TIME' DATE='$NOW_DATE'
EOF
  printf '%s:%s:%s:mail::/home/%s:0:userdb_quota_rule=*:storage=0M\n' "$box" "$HASH" "$USER_NAME" "$USER_NAME" > "$M/conf/passwd"
  printf '%s@%s:/home/%s/mail/%s/%s\n' "$box" "$d" "$USER_NAME" "$d" "$box" > "$M/conf/accounts"
  : > "$M/conf/aliases"
  : > "$M/conf/fwd_only"
  : > "$M/conf/antispam"
  : > "$M/conf/antivirus"
  printf '192.0.2.10\n' > "$M/conf/ip"
  printf 'unlimited\n' > "$M/conf/limits"

  if [ "$dkim" = yes ]; then
    openssl genrsa -out "$T/$d.dkim.pem" 2048 2>/dev/null
    openssl rsa -in "$T/$d.dkim.pem" -pubout -out "$T/$d.dkim.pub" 2>/dev/null
    cp "$T/$d.dkim.pem" "$M/conf/dkim.pem"
    cp "$T/$d.dkim.pem" "$M/hestia/$d.pem"
    cp "$T/$d.dkim.pub" "$M/hestia/$d.pub"
  fi

  # accounts.tar.gz : <boite>/{cur,new,tmp} + 1 message dans new/, noms SANS ./
  local MD=$T/maildir-$d
  mkdir -p "$MD/$box/cur" "$MD/$box/new" "$MD/$box/tmp"
  cat > "$MD/$box/new/1763600000.M1P1.lab" <<EOF
Return-Path: <sender@$WEB_D>
From: Fixture <sender@$WEB_D>
To: $box@$d
Subject: Message de recette $d
Date: Fri, 20 Nov 2026 00:00:00 +0000
Message-ID: <fixture-1@$d>
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Message synthetique de la fixture Hestia.
EOF
  chmod -R u+rwX,go-rwx "$MD"
  tar -C "$MD" --owner=0 --group=0 --numeric-owner -cf - "$box" | gzip -9n > "$M/accounts.tar.gz"
}

make_mail_domain "$MAIL_A" contact yes
make_mail_domain "$MAIL_B" info no

# --------------------------------------------------------------------------
# Certificat mail.<a> : mail/a/conf/ssl/a.{crt,key,ca,pem}, CERT_DAYS jours (defaut 90), signe CA.
# .crt = la feuille seule (l'agent refuse une chaine dans .crt), .ca = la CA,
# .pem = crt + ca (comme v-add-*-ssl de Hestia).
# --------------------------------------------------------------------------
S=$R/mail/$MAIL_A/conf/ssl
mkdir -p "$S"
openssl genrsa -out "$S/$MAIL_A.key" 2048 2>/dev/null
openssl req -new -key "$S/$MAIL_A.key" -subj "/CN=mail.$MAIL_A" -out "$T/mail.csr" 2>/dev/null
cat > "$T/mail.ext" <<EOF
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:mail.$MAIL_A, DNS:webmail.$MAIL_A
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF
openssl x509 -req -in "$T/mail.csr" -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial \
  -CAserial "$T/ca.srl" -days "${CERT_DAYS:-90}" -sha256 -extfile "$T/mail.ext" -out "$S/$MAIL_A.crt" 2>/dev/null \
  || die "signature du certificat mail par la CA impossible"
openssl x509 -in "$CA_CRT" -out "$S/$MAIL_A.ca"
cat "$S/$MAIL_A.crt" "$S/$MAIL_A.ca" > "$S/$MAIL_A.pem"
# La cle correspond bien au certificat.
[ "$(openssl x509 -in "$S/$MAIL_A.crt" -noout -pubkey | openssl sha256)" = \
  "$(openssl pkey -in "$S/$MAIL_A.key" -pubout | openssl sha256)" ] || die "cle et certificat mail divergent"

# --------------------------------------------------------------------------
# Archive : tar simple, membres prefixes par ./ (comme v-backup-user).
# --------------------------------------------------------------------------
chmod -R u+rwX,go+rX "$R"
chmod 600 "$S/$MAIL_A.key" "$R/mail/$MAIL_A/conf/dkim.pem" "$R/mail/$MAIL_A/hestia/$MAIL_A.pem" \
  "$R"/mail/*/conf/passwd "$R/pam/shadow"
OUT_TMP="$OUT.tmp.$$"
tar -C "$R" --owner=0 --group=0 --numeric-owner --sort=name -cf "$OUT_TMP" . 2>/dev/null \
  || tar -C "$R" --owner=0 --group=0 --numeric-owner -cf "$OUT_TMP" .
mv -f "$OUT_TMP" "$OUT"
echo "make-hestia-fixture: $OUT ecrit ; mots de passe dans $PWFILE"
