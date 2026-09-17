#!/usr/bin/env python3
"""Compatibility wrapper. The liveness check now lives in grab.py, as `grab status`.

    python3 status.py                     # equivalent to: grab status
    python3 status.py urls-ip.txt --insecure

Kept so that existing muscle memory and documented commands keep working. New use should
prefer `grab status`, which is the same code.
"""

import sys
from pathlib import Path

# The checkout wins over any installed copy, so this file always runs the code beside it.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from grab import status_main  # noqa: E402

if __name__ == "__main__":
    sys.exit(status_main(prog="status.py"))
