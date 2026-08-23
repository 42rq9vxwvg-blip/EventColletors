#!/usr/bin/env python3
"""
DSM Syslog Relay -> n8n Webhook

Nimmt RFC 5424 (IETF) Syslog-Nachrichten per TCP entgegen (wie sie von der
Synology DiskStation ueber Protokoll-Center > Protokoll senden verschickt
werden), parst sie sicher und leitet sie als JSON per HTTP POST an einen
n8n-Webhook weiter.

TCP kennt keine Nachrichtengrenzen -> RFC 5424 ueber TCP nutzt "Octet
Counting" (RFC 6587): jede Nachricht beginnt mit "<LAENGE> " gefolgt von
genau LAENGE Bytes der eigentlichen Syslog-Nachricht. Das wird hier sauber
gepuffert/geparst, auch wenn Nachrichten ueber mehrere TCP-Pakete verteilt
ankommen oder mehrere Nachrichten in einem Paket stecken.

WICHTIG (2026-07-27 nachtraeglich ergaenzt): N8N_WEBHOOK_URL sollte auf den
internen Docker-Hostnamen von n8n zeigen (z.B. http://n8n:5678/webhook/...),
NICHT auf die oeffentliche DDNS-Adresse. Nachts kommt es wiederholt zu
kurzen DSL-Trennungen/Neueinwahlen (siehe FritzBox-Ereignisprotokoll), die
dann auch die DNS-Aufloesung der oeffentlichen n8n-URL fuer ein paar Minuten
lahmlegen - selbst wenn NAS und n8n-Container die ganze Zeit ueber lokal
laufen und ueber das interne Docker-Netz erreichbar waeren. Das ist eine
reine Konfigurationsfrage (Umgebungsvariable), keine Code-Aenderung.
"""

import json
import logging
import os
import re
import socketserver
import sys
import threading
import time
from datetime import datetime, timezone

import requests

# --- Konfiguration ueber Umgebungsvariablen ---
LISTEN_HOST = os.environ.get("LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "6514"))
N8N_WEBHOOK_URL = os.environ.get("N8N_WEBHOOK_URL")
N8N_WEBHOOK_TOKEN = os.environ.get("N8N_WEBHOOK_TOKEN")
FORWARD_TIMEOUT_SECONDS = float(os.environ.get("FORWARD_TIMEOUT_SECONDS", "5"))
BACKUP_LOG_PATH = os.environ.get("BACKUP_LOG_PATH", "/var/log/dsm-syslog-backup.log")

# Neu: kurze Retry-Logik fuer transiente Fehler (DNS-Haenger, Timeouts,
# einzelne 502er von n8n waehrend eines Neustarts). Deckt genau die Faelle
# ab, die zum Verlust der USB-Backup-Meldung und der "External IP"-Meldung
# gefuehrt haben. FORWARD_MAX_RETRIES=1 entspricht dem alten Verhalten
# (kein Retry), falls das mal explizit gewuenscht ist.
FORWARD_MAX_RETRIES = int(os.environ.get("FORWARD_MAX_RETRIES", "3"))
FORWARD_RETRY_BACKOFF_SECONDS = float(os.environ.get("FORWARD_RETRY_BACKOFF_SECONDS", "1.0"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("dsm-syslog-relay")

if not N8N_WEBHOOK_URL:
    log.error("N8N_WEBHOOK_URL ist nicht gesetzt. Bitte in .env eintragen.")
    sys.exit(1)

# RFC 5424: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID [SD] MSG
# Beispiel:
# <134>1 2026-07-11T14:00:00.123+02:00 DiskStation225 synoscgi 12345 - - User admin logged in
SYSLOG_5424_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>(?P<version>\d+)\s+"
    r"(?P<timestamp>\S+)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<app>\S+)\s+"
    r"(?P<pid>\S+)\s+"
    r"(?P<msgid>\S+)\s+"
    r"(?:\[.*?\]|-)\s?"
    r"(?P<message>.*)$",
    re.DOTALL,
)

FACILITY_NAMES = {
    0: "kern", 1: "user", 2: "mail", 3: "daemon", 4: "auth", 5: "syslog",
    6: "lpr", 7: "news", 8: "uucp", 9: "cron", 10: "authpriv", 11: "ftp",
    16: "local0", 17: "local1", 18: "local2", 19: "local3",
    20: "local4", 21: "local5", 22: "local6", 23: "local7",
}
SEVERITY_NAMES = {
    0: "emergency", 1: "alert", 2: "critical", 3: "error",
    4: "warning", 5: "notice", 6: "informational", 7: "debug",
}


def parse_pri(pri_value: int):
    """PRI = Facility * 8 + Severity (RFC 5424 6.2.1)"""
    facility_num = pri_value >> 3
    severity_num = pri_value & 0x07
    return (
        FACILITY_NAMES.get(facility_num, f"facility{facility_num}"),
        SEVERITY_NAMES.get(severity_num, f"severity{severity_num}"),
    )


def parse_syslog_message(raw: str) -> dict:
    """Parst eine einzelne RFC5424-Nachricht. Faellt bei Nichterkennung auf
    ein rohes Nachrichtenobjekt zurueck, statt die Nachricht zu verwerfen."""
    match = SYSLOG_5424_RE.match(raw.strip())
    if not match:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "host": "unknown",
            "facility": "unknown",
            "priority": "unknown",
            "program": "unknown",
            "pid": "",
            "msgid": "",
            "message": raw.strip(),
            "parsed": False,
        }

    parts = match.groupdict()
    pri_value = int(parts["pri"])
    facility, severity = parse_pri(pri_value)

    return {
        "timestamp": parts["timestamp"],
        "host": parts["host"],
        "facility": facility,
        "priority": severity,
        "program": parts["app"],
        "pid": parts["pid"] if parts["pid"] != "-" else "",
        "msgid": parts["msgid"] if parts["msgid"] != "-" else "",
        "message": parts["message"].strip(),
        "parsed": True,
    }


def write_backup(line: str):
    try:
        with open(BACKUP_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line.rstrip("\n") + "\n")
    except OSError as exc:
        log.warning("Konnte Backup-Log nicht schreiben: %s", exc)


def forward_to_n8n(event: dict) -> bool:
    """Sendet ein Event an n8n, mit kurzer Retry-Logik fuer transiente
    Fehler (DNS-Haenger, Verbindungsabbrueche, einzelne 5xx-Antworten).
    Das Event steht in jedem Fall bereits im lokalen Backup-Log (siehe
    write_backup, wird VOR dem Aufruf dieser Funktion geschrieben) - ein
    endgueltiger Fehlschlag hier bedeutet also keinen Totalverlust, nur
    dass es nicht automatisch in DSM-Syslog/Postgres ankommt."""
    headers = {"Content-Type": "application/json"}
    if N8N_WEBHOOK_TOKEN:
        headers["Token"] = N8N_WEBHOOK_TOKEN

    body = json.dumps(event, ensure_ascii=False).encode("utf-8")

    for attempt in range(1, FORWARD_MAX_RETRIES + 1):
        try:
            resp = requests.post(
                N8N_WEBHOOK_URL,
                data=body,
                headers=headers,
                timeout=FORWARD_TIMEOUT_SECONDS,
            )
            if resp.status_code < 300:
                return True
            log.warning(
                "n8n antwortete mit Status %s (Versuch %d/%d) fuer Event: %s",
                resp.status_code, attempt, FORWARD_MAX_RETRIES, event.get("message", "")[:100],
            )
        except requests.RequestException as exc:
            log.error(
                "Weiterleitung an n8n fehlgeschlagen (Versuch %d/%d): %s",
                attempt, FORWARD_MAX_RETRIES, exc,
            )

        if attempt < FORWARD_MAX_RETRIES:
            time.sleep(FORWARD_RETRY_BACKOFF_SECONDS * attempt)

    log.error(
        "Weiterleitung an n8n endgueltig gescheitert nach %d Versuchen - "
        "Event bleibt nur im Backup-Log (%s): %s",
        FORWARD_MAX_RETRIES, BACKUP_LOG_PATH, event.get("message", "")[:100],
    )
    return False


class SyslogTCPHandler(socketserver.StreamRequestHandler):
    """Verarbeitet RFC 6587 Octet-Counting-Framing ueber TCP:
    '<LAENGE> ' gefolgt von genau LAENGE Bytes der Syslog-Nachricht."""

    def handle(self):
        peer = self.client_address[0]
        log.info("Verbindung von %s", peer)
        buffer = b""

        while True:
            chunk = self.rstrip_read()
            if not chunk:
                break
            buffer += chunk

            while True:
                # Laenge am Anfang des Puffers suchen: Ziffern gefolgt von Leerzeichen
                space_idx = buffer.find(b" ")
                if space_idx == -1 or not buffer[:space_idx].isdigit():
                    break  # noch nicht genug Daten fuer den Header

                msg_len = int(buffer[:space_idx])
                start = space_idx + 1
                end = start + msg_len
                if len(buffer) < end:
                    break  # Nachricht noch nicht vollstaendig angekommen

                raw_message = buffer[start:end].decode("utf-8", errors="replace")
                buffer = buffer[end:]

                event = parse_syslog_message(raw_message)
                write_backup(raw_message)
                forward_to_n8n(event)

        log.info("Verbindung von %s beendet", peer)

    def rstrip_read(self, size=4096):
        try:
            return self.connection.recv(size)
        except OSError:
            return b""


class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    log.info(
        "DSM Syslog Relay startet auf %s:%s, Ziel: %s (max_retries=%d, backoff=%ss)",
        LISTEN_HOST, LISTEN_PORT, N8N_WEBHOOK_URL, FORWARD_MAX_RETRIES, FORWARD_RETRY_BACKOFF_SECONDS,
    )
    server = ThreadingTCPServer((LISTEN_HOST, LISTEN_PORT), SyslogTCPHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Beende Relay...")
        server.shutdown()


if __name__ == "__main__":
    main()
