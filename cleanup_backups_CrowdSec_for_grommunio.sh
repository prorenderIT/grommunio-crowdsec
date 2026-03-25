#!/usr/bin/env bash

# ==========================================
# grommunio CrowdSec cleanup backups
# Free for personal/testing use
# Commercial use requires a license:
# https://www.prorender.de
# © All rights reserved – prorender IT  
# Author: Dipl.-Ing. Daniel Krüger  
# Website: https://www.prorender.de
# ==========================================

set -euo pipefail

echo "==============================================="
echo "grommunio CrowdSec cleanup backups"
echo "Free for testing. Commercial use requires license:"
echo "https://www.prorender.de"
echo "© All rights reserved – prorender IT "
echo "Author: Dipl.-Ing. Daniel Krüger"
echo "Website: https://www.prorender.de"
echo "==============================================="
echo ""

sleep 3

# -------------------------------
# Funktion: Alte Backups löschen, optional Backups behalten
# -------------------------------
cleanup_backups_keep_last() {
    local KEEP="${1:-0}"   # Standard: 0 → keine Backups behalten
    echo "[grommunio-crowdsec] [+] Lösche alte Backups, behalte $KEEP Backup(s)…"

    # interne Funktion: löscht alte Backups eines Musters, neueste(n) behalten
    delete_old_backups() {
        local pattern="$1"
        local dir="$2"
        local keep="$3"

        # Dateien nach Änderungsdatum sortieren, neueste zuerst
        local files=( $(ls -1t "$dir"/$pattern 2>/dev/null) )
        local count=${#files[@]}

        if (( count > keep )); then
            echo "[grommunio-crowdsec] [+] $count Backup(s) gefunden, lösche $((count-keep)) alte(n)…"
            for ((i=keep; i<count; i++)); do
                rm -v "${files[i]}"
            done
        else
            echo "[grommunio-crowdsec] [+] $count Backup(s) gefunden, keine Dateien gelöscht"
        fi
    }

    # Parser Backups
    delete_old_backups "grommunio-logs.yaml.*" "/etc/crowdsec/parsers/s01-parse" "$KEEP"

    # Scenario Backups
    delete_old_backups "grommunio-bruteforce.yaml.*" "/etc/crowdsec/scenarios" "$KEEP"

    # Collection Backups
    delete_old_backups "grommunio.yaml.*" "/etc/crowdsec/collections" "$KEEP"

    # Acquisitions Backups
    delete_old_backups "grommunio-*.yaml.*" "/etc/crowdsec/acquis.d" "$KEEP"

    echo "[grommunio-crowdsec] [+] Backup-Bereinigung abgeschlossen, $KEEP Backup(s) behalten"
}

# -------------------------------
# Backup-Bereinigung mit Benutzerabfrage
# -------------------------------

# Standardwert: 1 Backup behalten
DEFAULT_KEEP=0

read -p "[grommunio-crowdsec] [+] Wie viele Backups sollen behalten werden (0 für keine)? [Standard: $DEFAULT_KEEP] " USER_KEEP

# Prüfen, ob Eingabe leer ist
if [[ -z "$USER_KEEP" ]]; then
    echo "[grommunio-crowdsec] [!] Abbruch: Keine Eingabe, Backup-Bereinigung nicht durchgeführt."
    exit 1
fi

# Wenn der Benutzer nichts eingibt, Standardwert verwenden
KEEP=${USER_KEEP:-$DEFAULT_KEEP}

# Auf Zahl prüfen
if ! [[ "$KEEP" =~ ^[0-9]+$ ]]; then
    echo "[grommunio-crowdsec] [+] Ungültiger Wert, Backup-Bereinigung nicht durchgeführt."
    exit 1
fi

# Backup-Bereinigung aufrufen
cleanup_backups_keep_last "$KEEP"
