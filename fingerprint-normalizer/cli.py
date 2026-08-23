"""
Dispatcher. First argv is the mode: backfill | follow | migrate.
Everything after is passed through to that mode's own argparse.

ASCII-only per project rule 5.
"""

import sys

MODES = {}


def _lazy_import(name):
    import importlib

    return importlib.import_module(name)


def main():
    if len(sys.argv) < 2:
        print("Usage: cli.py <backfill|follow|migrate> [args...]", file=sys.stderr)
        return 2

    mode, rest = sys.argv[1], sys.argv[2:]
    if mode not in ("backfill", "follow", "migrate"):
        print(f"Unbekannter Modus: {mode!r}. Erlaubt: backfill, follow, migrate.", file=sys.stderr)
        return 2

    module = _lazy_import(mode)
    return module.main(rest)


if __name__ == "__main__":
    sys.exit(main())
