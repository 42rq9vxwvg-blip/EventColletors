-- 006: Phase 2 -- incident_types, incident_type_config
-- (Incident-Modell_Konzept-C_Gesamtkonzept.pdf, Kapitel 6 und 8.2)
--
-- Muss vor 007 und 008 laufen: fingerprints.incident_type (007) und
-- incidents.incident_type (008) zeigen per Fremdschluessel hierher. Ersetzt
-- die drei divergierenden Incident-Typ-Regexe (CHECK in 001, main.py,
-- n8n-Workflow) durch eine Nachschlagetabelle -- Voraussetzung dafuer, dass
-- I-14 ueberhaupt vergebbar wird.
--
-- Severity-Vokabular durchgaengig info|warning|error|critical (Projektregel 5),
-- nicht informational -- CHECK statt Wiederholung an mehreren Stellen.

CREATE TABLE IF NOT EXISTS monitoring.incident_types (
    code  TEXT PRIMARY KEY,
    label TEXT NOT NULL
);

INSERT INTO monitoring.incident_types (code, label) VALUES
    ('I-00',      'Auffangtyp'),
    ('I-00-CRIT', 'Kritisches Rohereignis ohne Klassifikation'),
    ('I-01',      'Backup-Lauf'),
    ('I-02',      'Integritaetspruefung'),
    ('I-03',      'Repeater-Backhaul unterbrochen'),
    ('I-04',      'DFS-Radar auf 5 GHz'),
    ('I-05',      'Backhaul-Bandbreite herabgesetzt'),
    ('I-06',      'WLAN-Anmeldefehler'),
    ('I-07',      'Syslog-Ingest gestoert'),
    ('I-08',      'n8n-Datenbankfehler'),
    ('I-09',      'n8n-Neustart'),
    ('I-10',      'Fehlgeschlagene Anmeldung DiskStation'),
    ('I-11',      'DSM-Paketaktualisierung'),
    ('I-12',      'Internet- / DDNS-Stoerung'),
    ('I-13',      'Ueberwachung ausgefallen (Watchdog)'),
    ('I-14',      'DSM-Berechtigungsaenderung'),
    ('I-15',      'Ratenanomalie je Host')
ON CONFLICT (code) DO NOTHING;

-- rule_name statt incident_type als Primaerschluessel: mehrere Regeln je Typ
-- sind noetig, weil Ziele (I-01, I-02), Baender (I-05) und ip_class (I-10)
-- unterschiedliche Schwellwerte brauchen.
CREATE TABLE IF NOT EXISTS monitoring.incident_type_config (
    rule_name                  TEXT PRIMARY KEY,
    incident_type               TEXT NOT NULL REFERENCES monitoring.incident_types(code),

    -- Regelauswahl. Vokabular deckungsgleich mit fingerprints.group_key_fields
    -- (Migration 007) und event_fingerprints.extracted (Kapitel 5.3):
    -- host|program|fingerprint|mac|target|channel|ip|user|service|rate_mbit
    match_field                 TEXT,
    match_value                 TEXT,

    mechanism                   TEXT NOT NULL,
    base_severity                TEXT NOT NULL,

    -- burst
    open_threshold_count        INTEGER,
    open_window_minutes         INTEGER,

    -- pair (I-03 Rekeying)
    open_delay_seconds          INTEGER,

    -- Eskalation ueber Zaehlung
    escalate_count               INTEGER,
    escalate_window_minutes      INTEGER,
    escalate_basis               TEXT,
    escalate_to_severity         TEXT,

    -- Eskalation ueber Dauer. Minuten seit opened_at -> Ziel-Severity,
    -- z.B. {"360": "warning", "720": "error"}. Ersetzt fixe Einzelspalten,
    -- weil I-03, I-07 und I-13 unterschiedlich viele Stufen brauchen.
    severity_by_duration         JSONB,

    -- pair / absence
    max_open_minutes             INTEGER,
    autoclose_silence_minutes    INTEGER,
    expected_every_minutes        INTEGER,
    expected_at_local             TIME,
    timezone                      TEXT NOT NULL DEFAULT 'Europe/Berlin',
    pair_reopen_grace_minutes     INTEGER,

    require_ack                   BOOLEAN NOT NULL DEFAULT FALSE,
    notify_on_close                BOOLEAN NOT NULL DEFAULT FALSE,

    -- Migrationssteuerung (Kapitel 11.1): alles startet auf 'old', Phase 4
    -- schaltet Typ fuer Typ auf 'new'. I-00 und I-00-CRIT bleiben bis zuletzt
    -- auf 'old' -- sie fangen per Konstruktion alles auf.
    reported_via                  TEXT NOT NULL DEFAULT 'old',

    live_activity                 BOOLEAN NOT NULL DEFAULT FALSE,
    active                         BOOLEAN NOT NULL DEFAULT TRUE,
    note                           TEXT,

    CONSTRAINT incident_type_config_mechanism_valid CHECK (
        mechanism IN ('pair', 'burst', 'absence', 'rate')
    ),
    CONSTRAINT incident_type_config_severity_valid CHECK (
        base_severity IN ('info', 'warning', 'error', 'critical')
    ),
    CONSTRAINT incident_type_config_escalate_severity_valid CHECK (
        escalate_to_severity IS NULL
        OR escalate_to_severity IN ('info', 'warning', 'error', 'critical')
    ),
    CONSTRAINT incident_type_config_escalate_basis_valid CHECK (
        escalate_basis IS NULL OR escalate_basis IN ('occurrences', 'incidents')
    ),
    CONSTRAINT incident_type_config_reported_via_valid CHECK (
        reported_via IN ('old', 'new')
    )
);

CREATE INDEX IF NOT EXISTS incident_type_config_type_idx
    ON monitoring.incident_type_config (incident_type);
CREATE INDEX IF NOT EXISTS incident_type_config_active_idx
    ON monitoring.incident_type_config (incident_type)
    WHERE active;

-- Seed: Kapitel 6.2. Werte in Kursivschrift dort (I-14, I-15) sind
-- Vorschlaege, im Replay zu bestaetigen -- so auch hier markiert.
-- Notify_on_close = true nur bei Mechanismen mit klarem Aufloesungsereignis
-- (pair, absence); burst-Typen schliessen still per Stille.
INSERT INTO monitoring.incident_type_config
    (rule_name, incident_type, match_field, match_value, mechanism, base_severity,
     open_threshold_count, open_window_minutes, open_delay_seconds,
     escalate_count, escalate_window_minutes, escalate_basis, escalate_to_severity,
     severity_by_duration, max_open_minutes, autoclose_silence_minutes,
     expected_every_minutes, expected_at_local, pair_reopen_grace_minutes,
     require_ack, notify_on_close, note)
VALUES
    -- I-01 Backup-Lauf: 3 Ziele, unterschiedliche Laufzeitgrenzen und Startzeiten.
    -- Nachmessung 2026-09-04: lokale Zeiten C2 03:00, USB 04:00, paperless 01:55.
    ('i01-c2', 'I-01', 'target', 'Synology C2', 'pair', 'warning',
     NULL, NULL, NULL, 2, 4320, 'incidents', 'critical',
     '{"30": "warning", "240": "error"}', 25, NULL, NULL, '03:00', NULL,
     TRUE, TRUE, NULL),
    ('i01-usb', 'I-01', 'target', 'USBFestplatte', 'pair', 'warning',
     NULL, NULL, NULL, 2, 4320, 'incidents', 'critical',
     '{"30": "warning", "240": "error"}', 90, NULL, NULL, '04:00', NULL,
     TRUE, TRUE, NULL),
    ('i01-paperless', 'I-01', 'target', 'paperless-ngx', 'pair', 'warning',
     NULL, NULL, NULL, 2, 4320, 'incidents', 'critical',
     '{"30": "warning", "240": "error"}', 20, NULL, NULL, '01:55', NULL,
     TRUE, TRUE, NULL),

    -- I-02 Integritaetspruefung: USB vs. uebrige Ziele.
    -- TODO i02-default: match_value kennt nur Gleichheit, keine Negation.
    -- Regel greift aktuell nur, wenn correlate() sie explizit als Fallback
    -- behandelt (Prioritaet nach spezifischeren Regeln) -- nicht nur ueber
    -- match_field/match_value allein loesbar. Vor Inbetriebnahme klaeren.
    ('i02-usb', 'I-02', 'target', 'USBFestplatte', 'pair', 'error',
     NULL, NULL, NULL, NULL, NULL, NULL, NULL,
     NULL, 180, NULL, NULL, NULL, NULL,
     TRUE, TRUE, NULL),
    ('i02-default', 'I-02', 'target', NULL, 'pair', 'error',
     NULL, NULL, NULL, NULL, NULL, NULL, NULL,
     NULL, 30, NULL, NULL, NULL, NULL,
     TRUE, TRUE,
     'TODO: Fallback-Semantik fuer "alle Ziele ausser USB" -- match_value '
     'kennt keine Negation. Regelauswahl-Prioritaet in correlate() klaeren.'),

    -- I-03 Repeater-Backhaul unterbrochen. base_severity ist die Stufe fuer
    -- Luecken <= 300s; severity_by_duration deckt die weiteren Stufen ab.
    ('i03', 'I-03', NULL, NULL, 'pair', 'info',
     NULL, NULL, 5, 4, 1440, 'incidents', 'error',
     '{"5": "warning", "30": "error"}', NULL, NULL, NULL, NULL, NULL,
     FALSE, TRUE, NULL),

    -- I-04 DFS-Radar auf 5 GHz.
    ('i04', 'I-04', NULL, NULL, 'pair', 'info',
     NULL, NULL, NULL, 3, 10080, 'incidents', 'warning',
     NULL, NULL, 60, NULL, NULL, NULL,
     FALSE, TRUE, NULL),

    -- I-05 Backhaul-Bandbreite herabgesetzt: Wertevergleich, kein Zaehl-
    -- oder Zeitfenster. Schema bildet das nicht ab (siehe Gesamtkonzept
    -- Kapitel 5.3: extracted.rate_mbit).
    -- TODO: correlate() muss match_value hier als Zahlenschwelle interpretieren
    -- (< statt =); im Schema aktuell nicht von Gleichheitsvergleich unterscheidbar.
    ('i05-5ghz', 'I-05', 'channel', '5GHz', 'burst', 'warning',
     NULL, NULL, NULL, NULL, NULL, NULL, NULL,
     NULL, NULL, NULL, NULL, NULL, NULL,
     FALSE, FALSE,
     'TODO: Wertevergleich rate_mbit < 800 (Mbit/s), kein Zaehlschwellwert. '
     'Schwelle bislang nur hier im Text hinterlegt, nicht strukturiert.'),
    ('i05-24ghz', 'I-05', 'channel', '2.4GHz', 'burst', 'warning',
     NULL, NULL, NULL, NULL, NULL, NULL, NULL,
     NULL, NULL, NULL, NULL, NULL, NULL,
     FALSE, FALSE,
     'TODO: Wertevergleich rate_mbit < 100 (Mbit/s), kein Zaehlschwellwert. '
     'Schwelle bislang nur hier im Text hinterlegt, nicht strukturiert.'),

    -- I-06 WLAN-Anmeldefehler: Client vs. Repeater (eigener Fingerprint ueber
    -- rule_hint, siehe fingerprints.rule_hint in Migration 007).
    ('i06-client', 'I-06', NULL, NULL, 'burst', 'warning',
     5, 15, NULL, 15, 60, 'occurrences', 'warning',
     NULL, NULL, 60, NULL, NULL, NULL,
     FALSE, FALSE, NULL),
    ('i06-repeater', 'I-06', NULL, NULL, 'burst', 'warning',
     2, 30, NULL, NULL, NULL, NULL, NULL,
     NULL, NULL, NULL, NULL, NULL, NULL,
     FALSE, FALSE,
     'Eskalation und Auto-Close fuer die Repeater-Variante im Konzept nicht '
     'beziffert, nur die Oeffnungsschwelle (2 in 30 min).'),

    -- I-07 Syslog-Ingest gestoert.
    ('i07', 'I-07', NULL, NULL, 'burst', 'warning',
     10, 5, NULL, 100, NULL, 'occurrences', 'error',
     NULL, NULL, 15, NULL, NULL, NULL,
     FALSE, FALSE,
     'Zweite Eskalationsbedingung "Dauer > 20 min" nicht abgebildet -- '
     'siehe Offene_Punkte.md. escalate_window_minutes bewusst NULL, im '
     'Konzept kein Fenster fuer die 100-Vorkommen-Schwelle genannt.'),

    -- I-08 n8n-Datenbankfehler. Stacktrace-Faltung via attach_mode
    -- (fingerprints, Migration 007), nicht hier.
    ('i08', 'I-08', NULL, NULL, 'burst', 'warning',
     1, NULL, NULL, 3, 1440, 'incidents', 'error',
     NULL, NULL, 30, NULL, NULL, NULL,
     FALSE, FALSE, NULL),

    -- I-09 n8n-Neustart.
    ('i09', 'I-09', NULL, NULL, 'pair', 'warning',
     NULL, NULL, NULL, 3, 360, 'incidents', 'error',
     NULL, 10, NULL, NULL, NULL, NULL,
     FALSE, TRUE, NULL),

    -- I-10 Fehlgeschlagene Anmeldung DiskStation: Regelwahl ueber ip_class.
    ('i10-internal', 'I-10', 'ip_class', 'internal', 'burst', 'info',
     5, 10, NULL, 10, 30, 'occurrences', 'warning',
     NULL, NULL, 120, NULL, NULL, NULL,
     FALSE, FALSE,
     'base_severity=info als Annahme -- Konzept nennt nur die '
     'Eskalationsstufe (warning), keine explizite Oeffnungs-Severity.'),
    ('i10-foreign', 'I-10', 'ip_class', 'foreign', 'burst', 'warning',
     1, NULL, NULL, 3, 60, 'occurrences', 'critical',
     NULL, NULL, NULL, NULL, NULL, NULL,
     TRUE, FALSE, NULL),
    ('i10-timemachine-smb', 'I-10', 'ip_class', 'timemachine-smb', 'burst', 'info',
     NULL, NULL, NULL, NULL, NULL, NULL, NULL,
     NULL, NULL, NULL, NULL, NULL, NULL,
     FALSE, FALSE,
     'Konfigurationsfehler, info-Zweig ohne Meldung laut Konzept. active=true '
     'gesetzt, aber ohne Autoclose/Eskalation -- pruefen, ob das dem '
     'gewuenschten "keine Meldung" tatsaechlich entspricht oder active=false '
     'treffender waere.'),

    -- I-11 DSM-Paketaktualisierung. closure=pair_balanced lebt an
    -- fingerprints (Migration 007), nicht hier.
    ('i11', 'I-11', NULL, NULL, 'pair', 'error',
     NULL, 15, NULL, NULL, NULL, NULL, NULL,
     NULL, 30, NULL, NULL, NULL, NULL,
     FALSE, TRUE, NULL),

    -- I-12 Internet-/DDNS-Stoerung. Mischform: pair (Verbindungsverlust)
    -- plus expected_every_minutes (ausbleibende DDNS-Registrierung).
    ('i12', 'I-12', NULL, NULL, 'pair', 'info',
     NULL, NULL, NULL, 2, 30, 'incidents', 'warning',
     NULL, NULL, 360, 2160, NULL, NULL,
     FALSE, TRUE, NULL),

    -- I-13 Watchdog: absence je Host, plus Gesamtstille uebergreifend.
    -- TODO: Text laesst offen, ob severity_by_duration je Regel eigene
    -- Stufen hat oder nur fuer eine gilt. Hier vorlaeufig einheitlich auf
    -- allen drei Regeln gesetzt -- im Replay zu pruefen.
    ('i13-diskstation', 'I-13', 'host', 'DiskStation225', 'absence', 'warning',
     NULL, NULL, NULL, NULL, NULL, NULL, NULL,
     '{"360": "warning", "720": "error"}', NULL, NULL, 360, NULL, NULL,
     FALSE, TRUE,
     'TODO: Verhaeltnis von expected_every_minutes (Oeffnungsschwelle) zu '
     'severity_by_duration (6h/12h) unklar -- siehe Offene_Punkte.md.'),
    ('i13-fritzbox', 'I-13', 'host', 'FritzBox', 'absence', 'warning',
     NULL, NULL, NULL, NULL, NULL, NULL, NULL,
     '{"360": "warning", "720": "error"}', NULL, NULL, 720, NULL, NULL,
     FALSE, TRUE,
     'TODO: siehe i13-diskstation.'),
    ('i13-gesamtstille', 'I-13', NULL, NULL, 'absence', 'warning',
     NULL, NULL, NULL, NULL, NULL, NULL, NULL,
     '{"360": "warning", "720": "error"}', NULL, NULL, 120, NULL, NULL,
     FALSE, TRUE,
     'TODO: siehe i13-diskstation. match_field/match_value bewusst NULL -- '
     'Regel bezieht sich auf den gesamten Ereignisstrom, nicht einen Host.'),

    -- I-14 DSM-Berechtigungsaenderung: Vorschlag, im Replay zu bestaetigen.
    ('i14', 'I-14', NULL, NULL, 'burst', 'info',
     1, 15, NULL, NULL, NULL, NULL, NULL,
     NULL, NULL, 30, NULL, NULL, NULL,
     TRUE, FALSE, 'Vorschlag aus Kapitel 6.2, im Replay zu bestaetigen.'),

    -- I-15 Ratenanomalie je Host: Vorschlag, im Replay zu bestaetigen.
    -- TODO: Schema hat kein Feld fuer Multiplikator (5x) oder
    -- Beobachtungsfenster (14 Tage Median) -- siehe Offene_Punkte.md.
    ('i15', 'I-15', 'host', NULL, 'rate', 'warning',
     NULL, NULL, NULL, NULL, NULL, NULL, NULL,
     NULL, NULL, NULL, NULL, NULL, NULL,
     FALSE, FALSE,
     'TODO: Multiplikator (5x Median) und Beobachtungsfenster (14 Tage) '
     'nicht im Schema abbildbar. Vorschlag aus Kapitel 6.2, im Replay zu '
     'bestaetigen. Nach einigen Wochen Beobachtung nachzuschaerfen.'),

    -- I-00 Auffangtyp: reported_via bleibt auf 'old' (Default), auch nach
    -- Phase 4 -- faengt per Konstruktion alles auf.
    ('i00', 'I-00', NULL, NULL, 'burst', 'info',
     NULL, NULL, NULL, NULL, NULL, NULL, NULL,
     NULL, NULL, NULL, NULL, NULL, NULL,
     FALSE, FALSE,
     'Auto-Close-Fenster in der Typologie nie beziffert -- siehe '
     'Offene_Punkte.md. NULL statt Ratewert.'),

    -- I-00-CRIT: Sicherheitsnetz (Kapitel 5.8). reported_via bleibt auf 'old'.
    ('i00-crit', 'I-00-CRIT', NULL, NULL, 'burst', 'critical',
     NULL, NULL, NULL, NULL, NULL, NULL, NULL,
     NULL, NULL, 60, NULL, NULL, NULL,
     FALSE, FALSE, NULL)
ON CONFLICT (rule_name) DO NOTHING;

GRANT SELECT ON monitoring.incident_types TO monitoring_mcp;
GRANT SELECT ON monitoring.incident_type_config TO monitoring_mcp;
-- Schreibender Zugriff (fuer incident-engine) noch nicht vergeben --
-- welcher DB-User correlate() nutzt, ist Teil der offenen Entscheidung
-- "ein Prozess oder zwei?" (Offene_Punkte.md) und wird spaetestens mit
-- Migration 008 festgelegt.

-- Nachtrag: fehlender FK event_fingerprints.event_id -> events.id.
-- Existierte seit Migration 002 nicht -- nur die fingerprint-Spalte hatte
-- dort einen FK (DEFERRABLE, wegen der Schreibreihenfolge in pipeline.py),
-- event_id blieb ein blosser BIGINT PRIMARY KEY ohne Fremdschluesselbezug.
-- Nicht DEFERRABLE: pipeline.py liest Events aus einer bereits committeten
-- Tabelle (Ingest laeuft als eigener, vorgelagerter Prozess), event_fingerprints
-- wird erst danach geschrieben -- kein Reihenfolgeproblem wie beim
-- fingerprint-FK.
-- ADD CONSTRAINT kennt kein IF NOT EXISTS in Postgres, daher ueber
-- pg_constraint abgesichert, damit ein erneuter Lauf dieser Datei (wie bei
-- allen anderen CREATE TABLE IF NOT EXISTS / ON CONFLICT DO NOTHING hier)
-- keinen Fehler wirft.
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'event_fingerprints_event_fk'
    ) THEN
        ALTER TABLE monitoring.event_fingerprints
            ADD CONSTRAINT event_fingerprints_event_fk
            FOREIGN KEY (event_id) REFERENCES monitoring.events (id);
    END IF;
END $$;
