#!/usr/bin/env python3
"""Thin shim so you can still run `python3 brukal_cli.py ...` from the repo root.
The real logic lives in brukal/cli.py (installed as the `brukal` command)."""
from brukal.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
