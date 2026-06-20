#!/usr/bin/env python3
"""
DataShield -- Admin Console shortcut
--------------------------------------
This file exists for convenience only.

The single unified login lives in main.py.
When an admin signs in, the AdminConsole window opens automatically.
Employees who sign in get the employee agent window instead.

Usage:
    python admin_console.py
    python main.py
    python -m server.run_admin_console
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import main as _main
_main.main()
