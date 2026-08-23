#!/usr/bin/env python3
"""
n8n Log Watcher -> n8n Webhook

Liest die eigenen Container-Logs von n8n ueber die Docker Engine API
(unix:///var/run/docker.sock, read-only gemountet) und leitet sie im
selben JSON-Schema wie DSM-Syslog-Relay und FritzBox-Poller an denselben
n8n-Webhook weiter (host="n8n"). Damit landet n8n als weiterer Host in
derselben Pipeline (Dedup, NoiseRules, Patterns, Eskalation, Postgres-
Sync) - ohne dass an n8n selbst irgendetwas geaendert werden muss.

Docker liefert stdout und stderr getrennt ab; hier laufen deshalb zwei
unabhaengige Streaming-Threads, einer je Kanal. Jede Zeile wird zusaetzlich
in ein lokales Backup-Log geschrieben (analog zum DSM-Syslog-Relay) -
darueber lassen sich reale n8n-Logzeilen exportieren, um daraus passende
NoiseRules abzuleiten (n8n ist standardmaessig sehr geschwaetzig: Community-
Package-Housekeeping, HTTP-Node-Skip-Meldungen, Token-Rotation usw.).

Bei einem Verbindungsabbruch (z.B. n8n-Container-Neustart) reconnectet der
jeweilige Thread automatisch und nutzt dabei ein Wasserzeichen (Zeitpunkt
der zuletzt verarbeiteten Zeile je Stream), um Docker per 'since' nur die
Zeilen ab genau diesem Punkt erneut liefern zu lassen - vermeidet sowohl
Luecken als auch einen kompletten Log-Replay von vorne.
"""

import json
import logging
import os
import re
import sys
import threading
import time
from datetime import datetime, timezone

import docker
import requests

# --- Konfiguration ueber Umgebungsvariablen ---
DOCKER_SOCKET = os.environ.get("DOCKER_SOCKET", "unix://var/run/docker.sock")
# Idle-Timeout fuer den Log-Stream auf Docker-Client-Ebene. WICHTIG (2026-08-
# 01 nachtraeglich ergaenzt): In der Praxis hat sich gezeigt, dass dieser
# Timeout ueber den Unix-Socket NICHT zuverlaessig als Exception durchschlaegt
# (kein "Log-Stream unterbrochen" in den Logs, obwohl der Stream nachweislich
# still stand). Bleibt als Best-Effort-Absicherung drin, die eigentliche
# Absicherung ist der Watchdog weiter unten - siehe WATCHDOG_STALL_THRESHOLD_SECONDS.
STREAM_IDLE_TIMEOUT_SECONDS = int(os.environ.get("STREAM_IDLE_TIMEOUT_SECONDS", str(2 * 3600)))  # 2h

# Watchdog-Schwelle: WICHTIG, muss deutlich ueber dem normalen Abstand
# zwischen echten n8n-Logzeilen liegen, sonst startet der Container
# unnoetig staendig neu, OHNE dass die Verbindung je die Chance bekommt,
# eine Zeile durchzulassen (genau das ist am 2026-08-01 passiert: 30-Minuten-
# Schwelle bei einem natuerlichen Log-Abstand von 1-14 Stunden fuehrte zu
# einem Dauer-Neustart-Zyklus ohne jemals eine einzige Zeile zu empfangen).
# Beobachteter Abstand zwischen Routine-Zeilen: tagsueber bis ~3,5h, nachts
# bis ~14h. 6h ist ein Kompromiss: erkennt einen echten Stillstand noch am
# selben Tag, loest bei normaler naechtlicher Ruhe gelegentlich einen
# unnoetigen (aber voellig harmlosen, dank Wasserzeichen verlustfreien)
# Neustart aus - das ist bewusst in Kauf genommen, da falscher Alarm nichts
# kostet, ein zu spaet erkannter echter Stillstand aber schon.
WATCHDOG_STALL_THRESHOLD_SECONDS = int(os.environ.get("WATCHDOG_STALL_THRESHOLD_SECONDS", str(6 * 3600)))  # 6h
N8N_CONTAINER_NAME = os.environ.get("N8N_CONTAINER_NAME", "n8n")
N8N_WEBHOOK_URL = os.environ.get("N8N_WEBHOOK_URL")
N8N_WEBHOOK_TOKEN = os.environ.get("N8N_WEBHOOK_TOKEN")
BACKUP_LOG_PATH = os.environ.get("BACKUP_LOG_PATH", "/var/log/n8n-log-watcher-backup.log")
RECONNECT_DELAY_SECONDS = float(os.environ.get("RECONNECT_DELAY_SECONDS", "5"))
FORWARD_MAX_RETRIES = int(os.environ.get("FORWARD_MAX_RETRIES", "3"))
FORWARD_RETRY_BACKOFF_SECONDS = float(os.environ.get("FORWARD_RETRY_BACKOFF_SECONDS", "1.0"))
FORWARD_TIMEOUT_SECONDS = float(os.environ.get("FORWARD_TIMEOUT_SECONDS", "5"))

# --- Lokaler Vorfilter (WICHTIG, siehe unten) ---
# n8n selbst laeuft hier nicht nur fuer dieses Monitoring, sondern hostet
# eine ganze Reihe anderer Workflows (Bring!-Liste, Paperless-ngx, diverse
# Community-Node-Experimente usw.) - JEDER davon erzeugt laufend eigene
# Log-Zeilen, voellig unabhaengig von unserer Pipeline. Das Grundrauschen
# ist so hoch, dass selbst "nur filtern" nach einem vollen Workflow-
# Durchlauf pro Zeile (wie bei DSM/FritzBox ueber die NoiseRules-Tabelle)
# bereits zu teuer ist: Ein Testlauf hat gezeigt, dass allein n8ns eigene
# Chattigkeit ca. 3 Ausfuehrungen/Sekunde erzeugt hat und dabei den
# 15-Minuten-Sync-Zeitplan komplett verdraengt hat (n8n ueberwacht sich
# im Wortsinn selbst kaputt).
#
# Deshalb hier ein GUENSTIGER Vorfilter rein im Watcher-Prozess, VOR dem
# Versand: offensichtlich uninteressante Zeilen werden gar nicht erst als
# Webhook an n8n geschickt (kein DB-Zugriff, keine Workflow-Ausfuehrung).
# Sie landen aber weiterhin im lokalen Backup-Log (siehe write_backup) -
# fuer die Feinjustierung ueber die NotificationPatterns/NoiseRules-Tabelle
# bleibt also alles sichtbar, es kostet nur keine n8n-Ausfuehrung mehr.
#
# EINZIGE Quelle fuer die Muster: die Umgebungsvariable N8N_LOG_DENYLIST
# (ein Regex pro Zeile, \n-getrennt) - bewusst nicht zusaetzlich im Code
# hartcodiert, damit es nur eine Stelle zum Pflegen gibt. Der aktuelle
# Startsatz an Mustern steht als Default-Wert in docker-compose.yml.
# Aendern = Wert in docker-compose.yml/.env anpassen + Container neu
# starten (docker compose up -d) - kein Rebuild noetig.
N8N_LOG_DENYLIST_RAW = os.environ.get("N8N_LOG_DENYLIST", "")


def _load_denylist():
    patterns = [line.strip() for line in N8N_LOG_DENYLIST_RAW.splitlines() if line.strip()]
    compiled = []
    for p in patterns:
        try:
            compiled.append(re.compile(p))
        except re.error as exc:
            logging.getLogger("n8n-log-watcher").warning("Ungueltiges Denylist-Pattern '%s': %s", p, exc)
    return compiled


DENYLIST = _load_denylist()


def is_denylisted(message: str) -> bool:
    return any(p.search(message) for p in DENYLIST)


# Zweite, unabhaengige Absicherung gegen ein lautlos haengenbleibendes
# Docker-Socket (siehe STREAM_IDLE_TIMEOUT_SECONDS oben): jeder Stream-
# Thread traegt hier seinen letzten Lebenszeichen-Zeitpunkt ein (bei JEDER
# empfangenen Zeile, auch gefilterten - das ist der ehrlichste Beweis,
# dass die Verbindung noch Daten liefert). Ein separater Watchdog-Thread
# beendet den gesamten Prozess hart, falls beide Streams laenger als das
# Doppelte des Idle-Timeouts still sind - Docker startet den Container
# dann ueber "restart: unless-stopped" komplett neu. Das ist der
# garantiert wirksame Rueckfallplan, falls der Timeout auf Docker-Client-
# Ebene aus irgendeinem Grund doch nicht greifen sollte.
_last_activity = {"stdout": time.time(), "stderr": time.time()}
_last_activity_lock = threading.Lock()


def touch_activity(stream_name: str):
    with _last_activity_lock:
        _last_activity[stream_name] = time.time()


def watchdog_loop():
    check_interval = 60
    stall_threshold = WATCHDOG_STALL_THRESHOLD_SECONDS
    while True:
        time.sleep(check_interval)
        now = time.time()
        with _last_activity_lock:
            snapshot = dict(_last_activity)
        stalled = {name: now - ts for name, ts in snapshot.items() if now - ts > stall_threshold}
        if not stalled:
            continue
        # WICHTIG: stderr ist bei n8n im Normalbetrieb fast immer still (nur
        # kurz nach dem Start gibt es dort ueberhaupt etwas, z.B. Deprecation-
        # Warnungen) - ein alleine stiller stderr-Kanal ist erwartetes
        # Verhalten, KEIN Zeichen einer haengenden Verbindung. Nur wenn
        # WIRKLICH ALLE ueberwachten Streams gleichzeitig still sind (also
        # auch das normalerweise aktive stdout), ist das ein starkes Signal
        # fuer eine tatsaechlich tote Docker-Verbindung - erst dann lohnt
        # sich der harte Prozess-Neustart.
        if len(stalled) == len(snapshot):
            log.critical(
                "Watchdog: ALLE Streams (%s) seit ueber %ds ohne Lebenszeichen - "
                "beende den Prozess hart, damit die Docker restart-Policy neu startet.",
                stalled, stall_threshold,
            )
            os._exit(1)
        else:
            log.info(
                "Watchdog: Stream(s) %s seit ueber %ds ohne Lebenszeichen, aber mindestens "
                "ein anderer Stream ist noch aktiv (z.B. stdout) - kein Neustart, das ist bei "
                "stderr normal.",
                stalled, stall_threshold,
            )

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("n8n-log-watcher")

if not N8N_WEBHOOK_URL:
    log.error("N8N_WEBHOOK_URL ist nicht gesetzt.")
    sys.exit(1)

_backup_lock = threading.Lock()


def write_backup(line: str):
    try:
        with _backup_lock:
            with open(BACKUP_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(line.rstrip("\n") + "\n")
    except OSError as exc:
        log.warning("Konnte Backup-Log nicht schreiben: %s", exc)


def forward_to_n8n(event: dict) -> bool:
    """Sendet ein Event an n8n, mit kurzer Retry-Logik fuer transiente
    Fehler - identisches Verhalten zu dsm_syslog_relay.py und
    fritzbox_poller.py, damit alle drei Quellen gleich robust sind."""
    headers = {"Content-Type": "application/json"}
    if N8N_WEBHOOK_TOKEN:
        headers["Token"] = N8N_WEBHOOK_TOKEN

    body = json.dumps(event, ensure_ascii=False).encode("utf-8")

    for attempt in range(1, FORWARD_MAX_RETRIES + 1):
        try:
            resp = requests.post(N8N_WEBHOOK_URL, data=body, headers=headers, timeout=FORWARD_TIMEOUT_SECONDS)
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
        "Zeile bleibt nur im Backup-Log (%s): %s",
        FORWARD_MAX_RETRIES, BACKUP_LOG_PATH, event.get("message", "")[:100],
    )
    return False


def map_to_syslog_schema(stream_name: str, timestamp_iso: str, message: str) -> dict:
    """Bildet eine n8n-Logzeile auf dasselbe Schema ab, das DSM-Syslog-Relay
    und FritzBox-Poller verwenden. 'priority' ist hier nur eine grobe
    Starteinstufung (stderr = error, stdout = informational) - die
    eigentliche, feinere Einstufung uebernimmt wie bei den anderen Quellen
    die NotificationPatterns-Tabelle, nicht der Watcher selbst."""
    return {
        "timestamp": timestamp_iso,
        "host": N8N_CONTAINER_NAME,
        "facility": "docker",
        "priority": "error" if stream_name == "stderr" else "informational",
        "program": f"n8n-{stream_name}",
        "message": message,
    }


def stream_logs(client: "docker.DockerClient", stream_name: str):
    """Liest einen Log-Kanal (stdout oder stderr) endlos, mit automatischem
    Reconnect ab dem zuletzt gesehenen Zeitpunkt bei Verbindungsabbruch.

    WICHTIG: Der allererste Verbindungsaufbau nutzt bewusst KEIN tail=0,
    um 'keine Historie, nur neue Zeilen' auszudruecken - das fuehrte in der
    Praxis dazu, dass die komplette vorhandene Log-Historie (hier: 546
    Zeilen seit 8 Tagen) auf einmal geflutet wurde. Vermutungsweise wird der
    Wert 0 irgendwo intern als 'falsy'/nicht gesetzt behandelt und faellt
    auf den Docker-Default 'alle Zeilen' zurueck. Stattdessen wird das
    Wasserzeichen von Anfang an mit dem aktuellen Zeitpunkt vorinitialisiert
    und ausschliesslich ueber 'since' gearbeitet - das ist unabhaengig von
    einem etwaigen Zero-Handling-Bug in der Docker-Bibliothek."""
    since_ts = datetime.now(timezone.utc)  # niemals None: von Anfang an "ab jetzt"
    counters = {"seen": 0, "filtered": 0, "forwarded": 0}

    while True:
        try:
            container = client.containers.get(N8N_CONTAINER_NAME)
        except docker.errors.NotFound:
            log.error("Container '%s' nicht gefunden - warte %ss und versuche erneut.", N8N_CONTAINER_NAME, RECONNECT_DELAY_SECONDS)
            time.sleep(RECONNECT_DELAY_SECONDS)
            continue
        except Exception as exc:
            log.error("Docker-API nicht erreichbar: %s - warte %ss.", exc, RECONNECT_DELAY_SECONDS)
            time.sleep(RECONNECT_DELAY_SECONDS)
            continue

        log_kwargs = {
            "stdout": stream_name == "stdout",
            "stderr": stream_name == "stderr",
            "stream": True,
            "follow": True,
            "timestamps": True,
            "since": since_ts,
        }

        log.info("Starte Log-Stream fuer '%s' (%s), since=%s", N8N_CONTAINER_NAME, stream_name, since_ts)

        try:
            for raw_line in container.logs(**log_kwargs):
                line = raw_line.decode("utf-8", errors="replace").rstrip("\n")
                if not line:
                    continue

                # Docker stellt mit timestamps=True jeder Zeile einen
                # RFC3339-Zeitstempel voran, getrennt durch ein Leerzeichen.
                parts = line.split(" ", 1)
                if len(parts) == 2:
                    ts_str, message = parts
                else:
                    ts_str, message = datetime.now(timezone.utc).isoformat(), line

                try:
                    # Docker-Zeitstempel (timestamps=True) sind immer UTC im
                    # Format YYYY-MM-DDTHH:MM:SS.fffffffffZ (Nanosekunden).
                    # Python kennt nur Mikrosekunden - auf 6 Nachkommastellen
                    # kuerzen, Rest verwerfen.
                    if "." in ts_str and ts_str.endswith("Z"):
                        head, frac = ts_str[:-1].split(".", 1)
                        ts_parsed = datetime.strptime(f"{head}.{frac[:6].ljust(6, '0')}Z", "%Y-%m-%dT%H:%M:%S.%fZ")
                    else:
                        ts_parsed = datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%SZ")
                    ts_parsed = ts_parsed.replace(tzinfo=timezone.utc)
                    timestamp_iso = ts_parsed.isoformat()
                    since_ts = ts_parsed
                except ValueError:
                    timestamp_iso = datetime.now(timezone.utc).isoformat()

                write_backup(f"{stream_name} {ts_str} {message}")

                counters["seen"] += 1
                touch_activity(stream_name)
                if is_denylisted(message):
                    counters["filtered"] += 1
                else:
                    counters["forwarded"] += 1
                    event = map_to_syslog_schema(stream_name, timestamp_iso, message)
                    forward_to_n8n(event)

                if counters["seen"] % 500 == 0:
                    log.info(
                        "Zwischenstand (%s): %d gesehen, %d gefiltert (nicht an n8n gesendet), %d weitergeleitet.",
                        stream_name, counters["seen"], counters["filtered"], counters["forwarded"],
                    )

        except Exception as exc:
            log.error("Log-Stream '%s' unterbrochen: %s - reconnect in %ss.", stream_name, exc, RECONNECT_DELAY_SECONDS)

        time.sleep(RECONNECT_DELAY_SECONDS)


def main():
    log.info(
        "n8n Log Watcher startet. Container: %s, Docker-Socket: %s, Ziel: %s, Denylist-Regeln: %d",
        N8N_CONTAINER_NAME, DOCKER_SOCKET, N8N_WEBHOOK_URL, len(DENYLIST),
    )
    if not DENYLIST:
        log.warning(
            "N8N_LOG_DENYLIST ist leer - es wird NICHTS vorgefiltert, jede n8n-Logzeile "
            "geht einzeln als Webhook an n8n raus. Das hat zuvor den 15-Minuten-Sync-"
            "Zeitplan komplett verdraengt - bitte N8N_LOG_DENYLIST in docker-compose.yml/"
            ".env setzen."
        )
    client = docker.DockerClient(base_url=DOCKER_SOCKET, timeout=STREAM_IDLE_TIMEOUT_SECONDS)

    threads = [
        threading.Thread(target=stream_logs, args=(client, "stdout"), daemon=True, name="stdout-stream"),
        threading.Thread(target=stream_logs, args=(client, "stderr"), daemon=True, name="stderr-stream"),
        threading.Thread(target=watchdog_loop, daemon=True, name="watchdog"),
    ]
    for t in threads:
        t.start()

    # Hauptthread haelt den Prozess am Leben, solange die Streaming-Threads
    # laufen (die sind daemon=True und reconnecten selbststaendig).
    while any(t.is_alive() for t in threads):
        time.sleep(5)

    log.error("Beide Log-Streams sind unerwartet beendet - Container wird neu gestartet (restart policy).")
    sys.exit(1)


if __name__ == "__main__":
    main()
