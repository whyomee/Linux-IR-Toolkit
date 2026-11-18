#!/usr/bin/env python3
"""Linux-IR-Toolkit command-line entry point.

This script is intentionally small so it can be copied to a response host and
run with the system Python interpreter.  It performs no privileged action and
makes no network connection.
"""

from __future__ import annotations

import sys

from irkit.cli import main

if __name__ == "__main__":
    sys.exit(main())
