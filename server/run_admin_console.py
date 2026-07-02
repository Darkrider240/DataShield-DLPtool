"""
server/run_admin_console.py
────────────────────────────
Module entry point so the admin console can be launched as:

    python -m server.run_admin_console

This simply delegates to the root-level admin_console.py launcher.
"""
import sys
from pathlib import Path

# Ensure the project root (parent of server/) is on sys.path
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Import and run the login screen
from admin_console import AdminLogin

if __name__ == "__main__":
    login = AdminLogin()
    login.mainloop()
