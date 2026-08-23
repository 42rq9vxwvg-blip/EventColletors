"""
Fingerprint normalizer for the Incident-Modell (Konzept C).

Two INDEPENDENT stages, each with its own version number (see PDF
Abschnitt 11.3/11.4 and the fingerprints table: cleaner_ver, normalizer_ver).
They must stay independent because they have different lifecycles: the
cleaner is source-specific and grows whenever a new DSM program shows up
with an unfamiliar wrapper; the normalizer is generic token replacement and
is comparatively stable. Bumping either one requires a full recompute of the
fingerprints register from the event table (never an in-place patch),
otherwise fingerprints derived under different rule versions sit side by
side and the saturation curve (the normalizer's own self-test) becomes
unreadable.

  Stage 1 -- clean(): DSM (Synology) events carry a CEF-style raw fragment
  before the actual message, which duplicates every variable value and
  can carry things that must never be persisted (session tokens, user
  agents in arg_5/arg_6). Discovered empirically via the Event-Monitoring
  connector (2026-08-21): the real message always starts right after the
  LAST BOM character (U+FEFF) in the string. FritzBox (EventLog-*) and n8n
  lines never contain a BOM and pass through unchanged. This stage MUST run
  before anything is stored (not just before hashing) -- beispiel_roh in
  the register holds the cleaned text, never the raw text.

  Stage 2 -- normalize(): applies the token replacement rules from
  Abschnitt 11.4, in the documented order (order matters -- quantities and
  paths must be replaced before generic version numbers/integers, or they
  get partially eaten).

ASCII-only per project rule 5 (Python container script).
"""

import re

BOM = "\ufeff"

# Bump on any change to clean(). Triggers a full register recompute.
CLEANER_VERSION = 1

# Bump on any change to normalize(). Triggers a full register recompute.
NORMALIZER_VERSION = 1

# Programs the BOM-prefix rule has actually been verified against
# (Abschnitt 11.3: "Kein Vertrauensvorschuss fuer die Regel"). Used only
# for the missing-BOM counter below, not to gate cleaning itself.
_VERIFIED_DSM_PROGRAMS = {"Hyper_Backup", "Connection", "System"}


def clean(host: str, program: str, message: str) -> tuple[str, bool]:
    """Stage 1: strip the CEF raw-fragment prefix DSM lines carry.

    Returns (cleaned_text, bom_found). If a BOM is present, keep only the
    text after the last BOM. Otherwise the message is returned unchanged
    (expected for FritzBox / n8n; unexpected -- and worth counting -- for
    an unverified DiskStation225 program, see missing-BOM counter in the
    backfill).
    """
    if BOM in message:
        return message.rsplit(BOM, 1)[1].strip(), True
    return message.strip(), False


def is_unverified_dsm_source(host: str, program: str) -> bool:
    """True if this is a DiskStation225 line whose program the BOM rule
    has not been checked against yet (Abschnitt 11.3). A missing BOM on
    such a line is expected until verified, not necessarily a new problem;
    a missing BOM on Hyper_Backup/Connection/System IS a signal worth
    surfacing."""
    return host == "DiskStation225" and program not in _VERIFIED_DSM_PROGRAMS


# --- token patterns, ORDER MATTERS ---

_MAC_RE = re.compile(r"\b[0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5}\b")

# Real IPv6 addresses in practice show up with either "::" compression or
# at least 4 groups (3 colons). A plain HH:MM:SS time also matches a loose
# "hex-with-colons" pattern (43 and 14 are valid hex digits!), so the loose
# form must NOT run before date/time extraction, and is restricted to at
# least 3 colons to avoid eating times outright.
_IPV6_RE = re.compile(
    r"\b(?:[0-9A-Fa-f]{1,4}:){3,7}[0-9A-Fa-f]{1,4}\b"
    r"|\b(?:[0-9A-Fa-f]{1,4}:)+:(?:[0-9A-Fa-f]{1,4}:?)*\b"
)

_IPV4_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")

# ISO timestamp, e.g. 2026-08-21T02:42:49+00:00 or with space separator
_ISO_TS_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
)

# German date + time, e.g. "18.08.26 17:43:14" or bare "18.08.26" / "18.08.2026"
_DE_DATETIME_RE = re.compile(
    r"\b\d{2}\.\d{2}\.\d{2,4}(?:\s+\d{2}:\d{2}:\d{2})?\b"
)

# bare time HH:MM:SS or HH:MM (must run before IPv6, see note above)
_TIME_RE = re.compile(r"\b\d{2}:\d{2}(?::\d{2})?\b")

# file paths: two or more "/segment" or a Windows-style path
_PATH_RE = re.compile(r"(?:/[\w.\-@+]+){2,}")

# hex strings >= 16 chars (content hashes, commit ids, etc.)
_HASH_RE = re.compile(r"\b[0-9A-Fa-f]{16,}\b")

# quantities with a unit: number (possibly with thousand/decimal separators)
# directly followed by a known unit token. Must run BEFORE version numbers,
# otherwise "5.322 GHz" gets half-eaten as version "5.322" first.
_UNITS = r"(?:GB|MB|KB|TB|Mbit/s|Kbit/s|Gbit/s|kbit/s|%|GHz|MHz|Min\.|min|h|s)"
_QTY_RE = re.compile(r"\b\d[\d.,]*\s*" + _UNITS + r"\b")

# version numbers, e.g. 1.2.3, v22, 22.1
_VERSION_RE = re.compile(r"\bv?\d+(?:\.\d+){1,3}\b")

# alphanumeric tokens >= 8 chars that mix letters and digits, requiring at
# least 2 digits so German compound words like "5-GHz-Band" (only 1 digit)
# are not mistaken for an id/hash/webhook-token.
_ID_RE = re.compile(
    r"\b(?=[A-Za-z0-9_-]*[A-Za-z])(?=[A-Za-z0-9_-]*\d[A-Za-z0-9_-]*\d)[A-Za-z0-9_-]{8,}\b"
)

# remaining plain integers
_INT_RE = re.compile(r"\b\d+\b")


def normalize(raw_message: str) -> str:
    """Return the normalized fingerprint form of a single message.

    Assumes clean_dsm_prefix() has already been applied if needed.
    """
    text = raw_message

    text = _MAC_RE.sub("<MAC>", text)
    text = _ISO_TS_RE.sub("<TS>", text)
    text = _DE_DATETIME_RE.sub("<DATE>", text)
    text = _TIME_RE.sub("<TS>", text)
    text = _IPV6_RE.sub("<IP6>", text)
    text = _IPV4_RE.sub("<IP>", text)
    text = _PATH_RE.sub("<PATH>", text)
    text = _HASH_RE.sub("<HASH>", text)
    text = _QTY_RE.sub("<QTY>", text)
    text = _VERSION_RE.sub("<VER>", text)
    text = _ID_RE.sub("<ID>", text)
    text = _INT_RE.sub("<N>", text)

    # collapse whitespace introduced by the DSM prefix cleanup / tabs
    text = re.sub(r"\s+", " ", text).strip()
    return text


class FingerprintResult:
    __slots__ = (
        "fingerprint", "beispiel_roh", "bom_found",
        "bom_missing", "bom_missing_unverified",
    )

    def __init__(self, fingerprint, beispiel_roh, bom_found,
                 bom_missing, bom_missing_unverified):
        self.fingerprint = fingerprint
        self.beispiel_roh = beispiel_roh  # cleaned, never raw -- see module docstring
        self.bom_found = bom_found
        # bom_missing is derived here, where host is in scope, rather than
        # recomputed by each caller: pipeline.py previously spelled out
        # "host == 'DiskStation225' and not r.bom_found" in two separate
        # places (the INSERT tuple and the warning counter), which is exactly
        # the kind of duplicated condition that drifts apart on the next
        # change. bom_missing_unverified is a strict subset of bom_missing.
        self.bom_missing = bom_missing
        self.bom_missing_unverified = bom_missing_unverified


def fingerprint(host: str, program: str, raw_message: str) -> FingerprintResult:
    """Full pipeline: clean -> normalize -> compose group key material.

    raw_message is consumed here and nowhere else -- callers must persist
    only .beispiel_roh (cleaned), never the raw_message argument itself.
    """
    cleaned, bom_found = clean(host, program, raw_message)
    form = normalize(cleaned)
    fp = f"{host}|{program}|{form}"
    bom_missing = (not bom_found) and host == "DiskStation225"
    unverified_missing = bom_missing and is_unverified_dsm_source(host, program)
    return FingerprintResult(fp, cleaned, bom_found, bom_missing, unverified_missing)


if __name__ == "__main__":
    import json
    import sys

    samples = json.load(sys.stdin)
    seen = {}
    bom_missing_count = 0
    for s in samples:
        r = fingerprint(s["host"], s["program"], s["message"])
        seen.setdefault(r.fingerprint, []).append(r.beispiel_roh[:80])
        if r.bom_missing:
            bom_missing_count += 1
            marker = "UNVERIFIED SOURCE" if r.bom_missing_unverified else "expected"
            print(f"[BOM fehlt, {marker}] {s['program']}: {s['message'][:80]!r}", file=sys.stderr)

    print(f"cleaner_ver={CLEANER_VERSION} normalizer_ver={NORMALIZER_VERSION}")
    print(f"raw messages: {len(samples)}")
    print(f"fingerprints: {len(seen)}")
    print(f"collapse factor: {len(samples) / len(seen):.2f}x")
    print(f"DiskStation225 lines without BOM: {bom_missing_count}")
    print()
    for fp, examples in sorted(seen.items(), key=lambda kv: -len(kv[1])):
        print(f"[{len(examples)}x] {fp}")
