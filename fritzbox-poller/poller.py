#!/usr/bin/env python3
"""
FRITZ!Box Event-Log Poller -> n8n Webhook (v2, TR-064-basiert)

Fragt periodisch (Standard: alle 10 Minuten) das Ereignis-Log der FRITZ!Box
ueber den offiziellen TR-064-Mechanismus X_AVM-DE_GetDeviceLogPath ab
(FritzOS >= 8) und leitet alle Eintraege der letzten POLL_INTERVAL_SECONDS
(+ ein kleiner Sicherheitspuffer) im selben JSON-Schema wie der DSM-Syslog-
Relay an denselben n8n-Webhook weiter (host="FritzBox").

Im Gegensatz zur Vorgaengerversion wird kein Fortschritts-Marker in einer
externen Tabelle gepflegt. Stattdessen wird bei jedem Poll das komplette
verfuegbare Log (bei dieser FRITZ!Box ca. 11 Tage) abgerufen und rein nach
dem Ereigniszeitpunkt gefiltert ("alles seit jetzt - Intervall"). Das macht
den Poller robust gegenueber Ereignis-Stuermen (das Log-Fenster ist bei
dieser FRITZ!Box mit ~11 Tagen bequem groesser als jedes sinnvolle
Poll-Intervall) und eliminiert die Fehlerklasse "Marker nicht mehr im
aktuellen Log gefunden", die in der Vorgaengerversion zu Duplikaten fuehrte.

Ein OVERLAP_SECONDS-Puffer sorgt dafuer, dass bei leicht schwankenden
Poll-Zeitpunkten keine Eintraege durch die Ritzen fallen; dupliziert
gesendete Eintraege werden von n8n-seitig (DSM-Syslog Tabelle) ueber die
Kombination aus timestamp+message als harmlos behandelt, da sie inhaltlich
identisch sind - werden aber durch den kleinen Puffer ohnehin nur in
Ausnahmefaellen ueberhaupt auftreten.

WICHTIG (2026-07-27 nachtraeglich ergaenzt): Die reine "jetzt minus
Intervall"-Fensterlogik hatte eine Luecke: schlaegt die Zustellung fuer
laenger als POLL_INTERVAL_SECONDS + OVERLAP_SECONDS am Stueck fehl (z.B.
bei einer laengeren naechtlichen DSL-Neueinwahl-Serie), rutschen die
betroffenen Ereignisse beim naechsten Poll aus dem Zeitfenster heraus und
gehen dauerhaft verloren - obwohl sie im FritzBox-eigenen ~11-Tage-Log noch
vorhanden waeren. Deshalb jetzt zusaetzlich ein In-Prozess-Wasserzeichen
(LAST_FORWARDED_TS): Es wird nur ueber erfolgreich zugestellte Ereignisse
hinweg vorgerueckt und bleibt an der ersten fehlgeschlagenen Zustellung
"haengen", sodass der naechste Poll-Durchlauf genau dort weitermacht statt
das feste Zeitfenster zu benutzen. Ein MAX_LOOKBACK_SECONDS-Deckel
verhindert, dass nach einem sehr langen Ausfall (Neustart des Containers,
tagelange Downtime) ploetzlich Tage an Backlog auf einmal gesendet werden.
Das Wasserzeichen lebt nur im Prozessspeicher und setzt sich bei einem
Container-Neustart zurueck - das FritzBox-eigene Log dient dabei weiterhin
als eigentliches Sicherheitsnetz.
"""

import json
import logging
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from fritzconnection import FritzConnection
from fritzconnection.core.utils import get_xml_root

FRITZ_TIMEZONE = ZoneInfo("Europe/Berlin")

# --- Konfiguration ueber Umgebungsvariablen ---
FRITZ_ADDRESS = os.environ.get("FRITZ_ADDRESS", "192.168.178.1")
FRITZ_USER = os.environ.get("FRITZ_USER")
FRITZ_PASSWORD = os.environ.get("FRITZ_PASSWORD")
POLL_INTERVAL_SECONDS = int(os.environ.get("POLL_INTERVAL_SECONDS", "600"))  # 10 Min
OVERLAP_SECONDS = int(os.environ.get("OVERLAP_SECONDS", "120"))  # 2 Min Sicherheitspuffer

# Neu: Deckel fuers Wasserzeichen (siehe Modul-Docstring) und Retry-Logik,
# analog zum DSM-Syslog-Relay.
MAX_LOOKBACK_SECONDS = int(os.environ.get("MAX_LOOKBACK_SECONDS", str(24 * 3600)))  # 24h
FORWARD_MAX_RETRIES = int(os.environ.get("FORWARD_MAX_RETRIES", "3"))
FORWARD_RETRY_BACKOFF_SECONDS = float(os.environ.get("FORWARD_RETRY_BACKOFF_SECONDS", "1.0"))

N8N_WEBHOOK_URL = os.environ.get("N8N_WEBHOOK_URL")
N8N_WEBHOOK_TOKEN = os.environ.get("N8N_WEBHOOK_TOKEN")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("fritzbox-poller")

for required in ["FRITZ_USER", "FRITZ_PASSWORD", "N8N_WEBHOOK_URL"]:
    if not os.environ.get(required):
        log.error("Umgebungsvariable %s ist nicht gesetzt.", required)
        sys.exit(1)

# In-Prozess-Wasserzeichen: Zeitpunkt des zuletzt ERFOLGREICH zugestellten
# Ereignisses. None = "noch kein erfolgreicher Poll seit Start", dann gilt
# die alte feste Fenster-Logik als Startwert.
LAST_FORWARDED_TS = None


def fetch_all_events(fc):
    """Ruft das komplette verfuegbare Ereignis-Log ueber TR-064
    X_AVM-DE_GetDeviceLogPath ab und gibt eine Liste von dicts zurueck."""
    result = fc.call_action("DeviceInfo:1", "X_AVM-DE_GetDeviceLogPath")
    log_path = result.get("NewDeviceLogPath")
    if not log_path:
        log.error("Keine NewDeviceLogPath in der TR-064-Antwort erhalten.")
        return []

    url = f"{fc.address}:{fc.port}{log_path}"
    xml_root = get_xml_root(url, session=fc.session)

    events = []
    for ev in xml_root:
        entry = {item.tag: (item.text.strip() if item.text else "") for item in ev}
        events.append(entry)
    return events


def parse_event_datetime(entry):
    """Kombiniert date ('TT.MM.JJ') und time ('HH:MM:SS') zu einem
    timezone-aware datetime-Objekt in Europe/Berlin (die FRITZ!Box liefert
    lokale Zeit). ZoneInfo behandelt Sommer-/Winterzeit automatisch korrekt
    (UTC+2 im Sommer, UTC+1 im Winter), statt einen festen Offset anzunehmen."""
    try:
        naive = datetime.strptime(f"{entry['date']} {entry['time']}", "%d.%m.%y %H:%M:%S")
        return naive.replace(tzinfo=FRITZ_TIMEZONE)
    except (KeyError, ValueError):
        return None


def map_to_syslog_schema(entry):
    """Bildet einen FRITZ!Box-Log-Eintrag auf dasselbe Schema ab, das der
    DSM-Syslog-Relay verwendet (timestamp, host, facility, priority, program, message).
    Der Timestamp wird nach ISO 8601 konvertiert, da die n8n Data Table
    Spalte 'timestamp' vom Typ dateTime ist und das deutsche TT.MM.JJ-Format
    nicht zuverlaessig automatisch erkennt (fuehrte zuvor zu Fehlern bzw.
    fehlinterpretierten Datumswerten)."""
    dt = parse_event_datetime(entry)
    timestamp_iso = dt.isoformat() if dt else datetime.now(timezone.utc).isoformat()
    return {
        "timestamp": timestamp_iso,
        "host": "FritzBox",
        "facility": entry.get("group", "fritzbox"),
        "priority": "informational",
        "program": f"EventLog-{entry.get('id', '')}".rstrip("-"),
        "message": entry.get("msg", ""),
    }


def forward_to_n8n(event) -> bool:
    """Sendet ein Event an n8n, mit kurzer Retry-Logik fuer transiente
    Fehler (DNS-Haenger, Verbindungsabbrueche, einzelne 5xx-Antworten) -
    genau die Fehlerklasse, die waehrend der naechtlichen DSL-Neueinwahlen
    auftritt."""
    import requests

    headers = {"Content-Type": "application/json"}
    if N8N_WEBHOOK_TOKEN:
        headers["Token"] = N8N_WEBHOOK_TOKEN

    body = json.dumps(event, ensure_ascii=False).encode("utf-8")

    for attempt in range(1, FORWARD_MAX_RETRIES + 1):
        try:
            resp = requests.post(N8N_WEBHOOK_URL, data=body, headers=headers, timeout=10)
            if resp.status_code < 300:
                return True
            log.warning(
                "n8n antwortete mit Status %s (Versuch %d/%d) fuer Event: %s",
                resp.status_code, attempt, FORWARD_MAX_RETRIES, event["message"][:100],
            )
        except Exception as exc:
            log.error(
                "Weiterleitung an n8n fehlgeschlagen (Versuch %d/%d): %s",
                attempt, FORWARD_MAX_RETRIES, exc,
            )

        if attempt < FORWARD_MAX_RETRIES:
            time.sleep(FORWARD_RETRY_BACKOFF_SECONDS * attempt)

    log.error(
        "Weiterleitung an n8n endgueltig gescheitert nach %d Versuchen fuer Event: %s",
        FORWARD_MAX_RETRIES, event["message"][:100],
    )
    return False


def poll_once():
    global LAST_FORWARDED_TS

    log.info("Login bei FRITZ!Box ...")
    try:
        fc = FritzConnection(address=FRITZ_ADDRESS, user=FRITZ_USER, password=FRITZ_PASSWORD)
    except Exception as exc:
        log.error("Verbindung zur FRITZ!Box fehlgeschlagen: %s", exc)
        return

    all_events = fetch_all_events(fc)
    if not all_events:
        log.info("Keine Log-Eintraege erhalten.")
        return

    log.info("%d Eintraege insgesamt im Log verfuegbar.", len(all_events))

    now = datetime.now(FRITZ_TIMEZONE)
    default_cutoff = now - timedelta(seconds=POLL_INTERVAL_SECONDS + OVERLAP_SECONDS)
    max_lookback_cutoff = now - timedelta(seconds=MAX_LOOKBACK_SECONDS)

    if LAST_FORWARDED_TS is not None:
        # Wasserzeichen aus einem vorherigen Durchlauf vorhanden - damit
        # weitermachen (mit Deckel, falls es sehr lange her ist), statt dem
        # festen Zeitfenster. Das ist der eigentliche Fix fuer laengere
        # Ausfaelle: Ereignisse aus einem verpassten Zeitraum bleiben so im
        # Blick, bis sie erfolgreich zugestellt wurden.
        cutoff = max(LAST_FORWARDED_TS, max_lookback_cutoff)
    else:
        cutoff = default_cutoff

    new_events = []
    for entry in all_events:
        ts = parse_event_datetime(entry)
        if ts is not None and ts >= cutoff:
            new_events.append((ts, entry))

    if not new_events:
        log.info("Keine Eintraege im aktuellen Zeitfenster (seit %s).", cutoff)
        return

    # Chronologisch aufsteigend senden
    new_events.sort(key=lambda pair: pair[0])

    log.info("%d Eintrag/Eintraege im Zeitfenster seit %s gefunden.", len(new_events), cutoff)

    sent_count = 0
    watermark_advancing = True
    for ts, entry in new_events:
        event = map_to_syslog_schema(entry)
        if forward_to_n8n(event):
            sent_count += 1
            if watermark_advancing:
                LAST_FORWARDED_TS = ts
        else:
            # Ab der ersten fehlgeschlagenen Zustellung das Wasserzeichen
            # NICHT mehr vorruecken, damit der naechste Poll-Durchlauf hier
            # wieder ansetzt - auch wenn spaeter in dieser Runde weitere,
            # neuere Ereignisse noch erfolgreich durchkommen.
            watermark_advancing = False

    log.info("%d von %d Eintraegen erfolgreich weitergeleitet.", sent_count, len(new_events))
    if not watermark_advancing:
        log.warning(
            "Mindestens eine Zustellung ist fehlgeschlagen - Wasserzeichen bleibt bei %s, "
            "naechster Poll versucht es erneut ab diesem Zeitpunkt.",
            LAST_FORWARDED_TS,
        )


def main():
    log.info(
        "FRITZ!Box Poller (v2, TR-064) startet. Intervall: %ss, Puffer: %ss, "
        "max_lookback: %ss, max_retries: %d, Ziel: %s",
        POLL_INTERVAL_SECONDS, OVERLAP_SECONDS, MAX_LOOKBACK_SECONDS, FORWARD_MAX_RETRIES, N8N_WEBHOOK_URL,
    )
    while True:
        try:
            poll_once()
        except Exception as exc:
            log.error("Unerwarteter Fehler im Poll-Durchlauf: %s", exc, exc_info=True)
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()