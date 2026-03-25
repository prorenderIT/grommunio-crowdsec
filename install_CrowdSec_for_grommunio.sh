#!/usr/bin/env bash

# ==========================================
# grommunio CrowdSec Installer
# Free for personal/testing use
# Commercial use requires a license:
# https://www.prorender.de
# © All rights reserved – prorender IT  
# Author: Dipl.-Ing. Daniel Krüger  
# Website: https://www.prorender.de
# ==========================================

set -euo pipefail

echo "==============================================="
echo "grommunio CrowdSec Installer"
echo "Free for testing. Commercial use requires license:"
echo "https://www.prorender.de"
echo "© All rights reserved – prorender IT "
echo "Author: Dipl.-Ing. Daniel Krüger"
echo "Website: https://www.prorender.de"
echo "==============================================="
echo ""

sleep 3

LOGFILE="/var/log/grommunio-crowdsec-install.log"
exec > >(tee -a "$LOGFILE") 2>&1

# -------------------------------
# Funktionen
# -------------------------------
log() { echo -e "[grommunio-crowdsec] [+] $1"; }

fail() {
  echo "[!] Fehler: $1"
  exit 1
}

backup_file() {
  if [[ -f "$1" ]]; then
    cp "$1" "$1.bak.$(date +%s)"
    log "Backup erstellt: $1"
  fi
}

# -------------------------------
# Root Check
# -------------------------------
if [[ $EUID -ne 0 ]]; then
  fail "Bitte als root ausführen"
fi

# -------------------------------
# Dependencies prüfen
# -------------------------------
for cmd in curl zypper systemctl; do
  if ! command -v $cmd >/dev/null; then
    fail "$cmd ist nicht installiert"
  fi
done

# -------------------------------
# OS prüfen
# -------------------------------
if ! grep -qi "opensuse" /etc/os-release; then
  fail "Dieses Script ist nur für openSUSE gedacht"
fi

VERSION=$(grep VERSION_ID /etc/os-release | cut -d '"' -f 2)

log "Starte Installation für openSUSE $VERSION"

# -------------------------------
# CrowdSec Installation (sicher)
# -------------------------------
if ! command -v crowdsec >/dev/null; then
  log "Installiere CrowdSec..."

  curl -fsSL https://install.crowdsec.net -o /tmp/crowdsec_install.sh \
    || fail "Download fehlgeschlagen"

  export os=opensuse
  export dist="$VERSION"
  bash /tmp/crowdsec_install.sh

  zypper --non-interactive refresh
  zypper --non-interactive install crowdsec crowdsec-firewall-bouncer-iptables
else
  log "CrowdSec bereits installiert"
fi

# -------------------------------
# Services aktivieren
# -------------------------------
log "Aktiviere Dienste..."
systemctl enable --now crowdsec
systemctl enable --now crowdsec-firewall-bouncer

# -------------------------------
# Collections installieren
# -------------------------------
log "Installiere Mail Collections..."
cscli collections install crowdsecurity/postfix || true
cscli collections install crowdsecurity/dovecot || true

# -------------------------------
# Verzeichnisse
# -------------------------------
BASE_DIR="/etc/crowdsec"
PARSER_DIR="$BASE_DIR/parsers/s01-parse"
SCENARIO_DIR="$BASE_DIR/scenarios"
COLLECTION_DIR="$BASE_DIR/collections"
ACQUIS_DIR="$BASE_DIR/acquis.d"

mkdir -p "$PARSER_DIR" "$SCENARIO_DIR" "$COLLECTION_DIR" "$ACQUIS_DIR"

# -------------------------------
# Parser
# -------------------------------
log "Installiere Parser..."
backup_file "$PARSER_DIR/grommunio-logs.yaml"

cat > "$PARSER_DIR/grommunio-logs.yaml" << 'EOF'
name: custom/grommunio-logs
description: "grommunio + postfix authentication failure parser for CrowdSec 1.7"

onsuccess: next_stage
filter: "evt.Line.Labels.type == 'grommunio'"

pattern_syntax:
  IPV4: (?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)
  IP: (?:%{IPV6}|%{IPV4})

nodes:
  # Postfix SASL auth failures 
  - grok:
      apply_on: message
      pattern: 'postfix/smtpd.*warning: [-._\w]+\[%{IP:source_ip}\]: SASL .* authentication failed'

  # web admin
  - grok:
      apply_on: message
      pattern: '\(grommunio Admin API\) Failed login attempt for user .* from ''%{IP:source_ip}'''

  # grommunio-sync
  - grok:
      apply_on: message
      pattern: 'cmd=''Sync''.*from=''%{IP:source_ip}''.*httpcode=''401'''

  # grommunio-dav
  - grok:
      apply_on: message
      pattern: 'dav.*user.*IP.%{IP:source_ip}'

  # grommunio-mapi
  - grok:
      apply_on: message
      pattern: 'authentication failure at MAPI.*client:\s*%{IP:source_ip}'
      
  # gromox imap/pop3
  - grok:
      apply_on: message
      pattern: 'rhost=\[(?:\S*:)?%{IP:source_ip}\].*(auth|login|logon|LOGIN).*reject(?:ed|ing)'

statics:
  - meta: service
    value: grommunio
  - meta: log_type
    value: grommunio_auth_failed
  - meta: source_ip
    expression: "evt.Parsed.source_ip"
EOF

# -------------------------------
# Scenario
# -------------------------------
log "Installiere Scenario..."
backup_file "$SCENARIO_DIR/grommunio-bruteforce.yaml"

cat > "$SCENARIO_DIR/grommunio-bruteforce.yaml" << 'EOF'
type: leaky
name: custom/grommunio-bruteforce
description: "Detect bruteforce on grommunio services"

filter: "evt.Meta.log_type == 'grommunio_auth_failed' && evt.Meta.source_ip != '' && evt.Meta.service == 'grommunio'"

groupby: evt.Meta.source_ip

capacity: 5
leakspeed: "1m"
blackhole: "5m"

labels:
  service: grommunio
  type: bruteforce
  remediation: true
EOF

# -------------------------------
# Collection
# -------------------------------
log "Installiere Collection..."
backup_file "$COLLECTION_DIR/grommunio.yaml"

cat > "$COLLECTION_DIR/grommunio.yaml" << 'EOF'
name: custom/grommunio
description: "Grommunio complete protection (SMTP, IMAP, POP3, DAV, Web)"

parsers:
  - custom/grommunio-logs

scenarios:
  - custom/grommunio-bruteforce
EOF

#############################################
# 4) ACQUISITIONS
#############################################
echo "[+] Installiere Acquisitions..."

# -------------------------------
# Acquisitions
# -------------------------------
log "Installiere Acquisitions..."

# Web (nginx)
backup_file "$ACQUIS_DIR/grommunio-web.yaml"
cat > "$ACQUIS_DIR/grommunio-web.yaml" << 'EOF'
source: file
filenames:
  - /var/log/nginx/nginx-web-error.log
labels:
  type: grommunio
EOF

# grommunio-admin-api login
backup_file "$ACQUIS_DIR/grommunio-admin-api.yaml"
cat > "$ACQUIS_DIR/grommunio-admin-api.yaml" << 'EOF'
source: journalctl
journalctl_filter:
  - "_SYSTEMD_UNIT=grommunio-admin-api.service"
labels:
  type: grommunio
EOF

# Sync
backup_file "$ACQUIS_DIR/grommunio-sync.yaml"
cat > "$ACQUIS_DIR/grommunio-sync.yaml" << 'EOF'
source: file
filenames:
  - /var/log/grommunio-sync/grommunio-sync.log
labels:
  type: grommunio
EOF

# IMAP
backup_file "$ACQUIS_DIR/grommunio-imap.yaml"
cat > "$ACQUIS_DIR/grommunio-imap.yaml" << 'EOF'
source: journalctl
journalctl_filter:
  - "_SYSTEMD_UNIT=gromox-imap.service"
labels:
  type: grommunio
EOF

# POP3
backup_file "$ACQUIS_DIR/grommunio-pop3.yaml"
cat > "$ACQUIS_DIR/grommunio-pop3.yaml" << 'EOF'
source: journalctl
journalctl_filter:
  - "_SYSTEMD_UNIT=gromox-pop3.service"
labels:
  type: grommunio
EOF

# DAV
backup_file "$ACQUIS_DIR/grommunio-dav.yaml"
cat > "$ACQUIS_DIR/grommunio-dav.yaml" << 'EOF'
source: file
filenames:
  - /var/log/grommunio-dav/dav.log
labels:
  type: grommunio
EOF

# Postfix
backup_file "$ACQUIS_DIR/grommunio-postfix.yaml"
cat > "$ACQUIS_DIR/grommunio-postfix.yaml" << 'EOF'
source: journalctl
journalctl_filter:
  - "_SYSTEMD_UNIT=postfix.service"
  - "_SYSTEMD_UNIT=postfix@-.service"
  - "_SYSTEMD_UNIT=gromox-delivery.service"
labels:
  type: grommunio
EOF

# -------------------------------
# Permissions
# -------------------------------
log "Setze Berechtigungen..."
chmod 644 "$PARSER_DIR/grommunio-logs.yaml"
chmod 644 "$SCENARIO_DIR/grommunio-bruteforce.yaml"
chmod 644 "$COLLECTION_DIR/grommunio.yaml"
chmod 644 "$ACQUIS_DIR"/grommunio*.yaml

# -------------------------------
# Test
# -------------------------------
log "Teste Konfiguration..."
if ! crowdsec -t; then
  fail "Konfiguration fehlerhaft"
fi

# -------------------------------
# Registriere Collection
# -------------------------------
log "Registriere Collection custom/grommunio..."
if ! cscli collections inspect custom/grommunio >/dev/null 2>&1; then
    cscli collections install custom/grommunio || fail "Collection konnte nicht installiert werden"
else
    log "Collection custom/grommunio bereits registriert"
fi

# -------------------------------
# Reload
# -------------------------------
log "Starte CrowdSec neu..."
systemctl reload crowdsec || systemctl restart crowdsec

# -------------------------------
# Fertig
# -------------------------------
log "Installation abgeschlossen"
log "Status prüfen: cscli metrics"
log "Logs: $LOGFILE"

echo
echo "==============================================="
echo "CrowdSec-Schutz für grommunio aktiv!"
echo "Bereitgestellt & unterstützt von prorender IT"
echo "Free for testing. Commercial use requires license:"
echo "https://www.prorender.de"
echo "==============================================="
echo
