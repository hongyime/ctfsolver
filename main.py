#!/usr/bin/env python3
"""CTF Toolkit - Main entry point."""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

import signal
from ctf_core.utils.resilience import _SHUTDOWN


def _handle_sigint(signum, frame):
    if _SHUTDOWN.is_set():
        print("\n[FORCE EXIT] Forcing exit now.")
        raise SystemExit(1)
    _SHUTDOWN.set()
    print("\n[STOPPING] Finishing current operation... Ctrl+C again to force exit.")


signal.signal(signal.SIGINT, _handle_sigint)

from ctf_core.cli import main

if __name__ == "__main__":
    main()
