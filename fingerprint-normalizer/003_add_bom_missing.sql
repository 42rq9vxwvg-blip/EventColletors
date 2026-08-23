-- Persistiert, was bisher nur als [warn]-Log-Zeile in pipeline.py existierte
-- (Abschnitt 11.3: "Kein Vertrauensvorschuss fuer die Regel" -- ein
-- fehlendes BOM bei einer DiskStation225-Zeile ist ein Signal, das
-- ausgewertet werden koennen muss, nicht nur geloggt).
--
-- bom_missing: true, wenn diese Zeile von DiskStation225 kam und KEIN BOM
--   enthielt (normalizer.clean() ist dann durchgereicht statt zu schneiden).
--   Fuer FritzBox/n8n immer false -- dort ist Fehlen des BOM der Normalfall,
--   kein Signal.
-- bom_missing_unverified: true nur, wenn zusaetzlich das Programm noch
--   nicht zu den drei belegten Quellen (Hyper_Backup, Connection, System)
--   gehoert -- also eine bislang unbekannte DSM-Nachrichtenform.
--
-- DEFAULT false, damit ALTER TABLE ohne Tabellen-Rewrite fuer die
-- Bestandsdaten durchlaeuft (Postgres fuellt neue Spalten mit konstantem
-- Default per Katalogeintrag, nicht per Zeilen-Update, seit PG 11).
-- Bestandsdaten sind damit als bom_missing=false markiert, obwohl der
-- tatsaechliche Wert zum Verarbeitungszeitpunkt nicht mehr rekonstruierbar
-- ist ohne Rueckgriff auf message NOT LIKE '%' || chr(65279) || '%' gegen
-- die rohen events -- siehe Nachtrag unten fuer den Backfill dieser Spalte.

ALTER TABLE monitoring.event_fingerprints
    ADD COLUMN IF NOT EXISTS bom_missing BOOLEAN NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS bom_missing_unverified BOOLEAN NOT NULL DEFAULT false;

CREATE INDEX IF NOT EXISTS event_fingerprints_bom_missing_idx
    ON monitoring.event_fingerprints (bom_missing)
    WHERE bom_missing;

-- Nachtrag: die neuen Spalten ruecknachfuellen fuer die 22755 bereits
-- verarbeiteten Ereignisse aus dem 90-Tage-Backfill (2026-08-21), damit die
-- Saettigungskurven-API nicht bei Zeile 0 anfaengt. Rekonstruiert exakt die
-- Bedingung aus pipeline.py: bom_missing, wenn Host DiskStation225 ist und
-- die rohe Nachricht kein BOM (U+FEFF, chr(65279)) enthaelt.
UPDATE monitoring.event_fingerprints ef
SET bom_missing = true
FROM monitoring.events e
WHERE e.id = ef.event_id
  AND e.host = 'DiskStation225'
  AND e.message NOT LIKE '%' || chr(65279) || '%';

-- bom_missing_unverified fuer den Nachtrag bewusst nicht rueckwirkend
-- gesetzt: das haengt von _VERIFIED_DSM_PROGRAMS in normalizer.py ab, einer
-- Python-Konstante, die sich aendern kann -- eine SQL-Nachbildung wuerde
-- stillschweigend veralten. Die beiden betroffenen Zeilen aus dem
-- 90-Tage-Backfill (WinFileService, siehe Chat vom 2026-08-21) muessten
-- notfalls von Hand markiert werden:
--   UPDATE monitoring.event_fingerprints SET bom_missing_unverified = true
--     WHERE event_id IN (7342, 5783);
-- Optional, nicht sicherheitsrelevant -- betrifft nur die Feinunterscheidung
-- "unbekannte Quelle" vs. "bekannte Quelle, Einzelfall".
