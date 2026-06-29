"""
comms/cloud_watcher.py
======================
DataShield Cloud DLP Monitor.

Watches local sync folders for Google Drive, OneDrive, and Dropbox.
When a file is created or modified inside any sync folder, the existing
DLP scanner runs on it immediately. If the file is HIGH or MEDIUM risk
the event is reported exactly like any other DataShield finding, and the
file is quarantined by being moved to a _DATASHIELD_BLOCKED/ subfolder.

No API keys or OAuth required — works with the native sync clients
(Google Drive for Desktop, OneDrive, Dropbox) that employees already have.

Architecture:
    watchdog.Observer  (background thread, OS-level file events)
        |
        v
    CloudFolderHandler.on_created / on_modified
        |
        v  (calls existing scanner + classifier)
    scan_file()  ->  classify_file()
        |
        v
    _on_finding_callback(channel="CLOUD", action, detail, decision)
        |
        v
    main.py  _bg_event_with_feed  ->  FastAPI  +  GUI threat feed
"""

import os
import sys
import time
import shutil
import threading

import scanner
import classifier
import alerts
import comms.comms_engine as comms_engine

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False


# ── File types to skip (binary, media, executables) ───────────────────────────
SKIP_EXTENSIONS = {
    ".exe", ".dll", ".so", ".dylib", ".bin", ".iso",
    ".mp4", ".mp3", ".avi", ".mkv", ".mov",
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp",
    ".zip", ".tar", ".gz", ".7z", ".rar",
    ".psd", ".ai", ".fig",
}

# Max file size to scan (10 MB) — skip huge files silently
MAX_SCAN_BYTES = 10 * 1024 * 1024

# Quarantine folder name created inside each provider's root
QUARANTINE_DIR = "_DATASHIELD_BLOCKED"


def _detect_cloud_folders() -> dict:
    """
    Returns a dict of { provider_name: folder_path } for every cloud sync
    folder that exists on this machine right now.
    """
    home = os.path.expanduser("~")
    candidates = {
        "Google Drive": [
            os.path.join(home, "Google Drive"),
            os.path.join(home, "My Drive"),
            "G:\\My Drive",
            "G:\\",
        ],
        "OneDrive": [
            os.path.join(home, "OneDrive"),
            os.path.join(home, "OneDrive - Personal"),
        ],
        "Dropbox": [
            os.path.join(home, "Dropbox"),
        ],
        "iCloud Drive": [
            os.path.join(home, "iCloudDrive"),
        ],
    }
    found = {}
    for provider, paths in candidates.items():
        for p in paths:
            if os.path.isdir(p):
                found[provider] = p
                break
    return found


class _CloudFileHandler(FileSystemEventHandler):
    """
    watchdog event handler for a single cloud provider folder.
    Fires on file creation and modification; runs DLP scan.
    """

    def __init__(self, provider: str, root_path: str,
                 state: dict, on_finding_callback):
        super().__init__()
        self.provider         = provider
        self.root_path        = root_path
        self.state            = state
        self.on_finding       = on_finding_callback
        self._recently_seen   = {}   # path -> last-scan epoch, to debounce rapid events
        self._lock            = threading.Lock()

    # watchdog calls this for new files
    def on_created(self, event):
        if not event.is_directory:
            self._handle(event.src_path)

    # watchdog calls this when a file's content changes
    def on_modified(self, event):
        if not event.is_directory:
            self._handle(event.src_path)

    def _handle(self, path: str):
        # Skip quarantine folder itself
        if QUARANTINE_DIR in path:
            return

        ext = os.path.splitext(path)[1].lower()
        if ext in SKIP_EXTENSIONS:
            return

        # Debounce: same file re-fires events multiple times during upload
        with self._lock:
            now = time.time()
            if now - self._recently_seen.get(path, 0) < 5.0:
                return
            self._recently_seen[path] = now

        # File may still be being written — wait briefly
        time.sleep(0.8)

        try:
            if not os.path.isfile(path):
                return
            if os.path.getsize(path) > MAX_SCAN_BYTES:
                return

            config = {
                "root_path":      os.path.dirname(path),
                "policy_manager": self.state.get("policy_manager"),
            }
            matches        = scanner.scan_file(path, config)
            classification = classifier.classify_file(matches, file_path=path)

            risk = classification.get("risk_level", "CLEAN")
            if risk not in ("HIGH", "MEDIUM"):
                return   # clean file — do nothing

            decision = comms_engine.decide(
                classification,
                channel="CLOUD",
                audit_logger=self.state.get("audit_logger"),
                explain=True,
            )

            # Log to audit ledger
            audit = self.state.get("audit_logger")
            if audit:
                audit.log("CLOUD_DLP_BLOCK", {
                    "provider":      self.provider,
                    "file":          path,
                    "risk_level":    risk,
                    "top_pattern":   getattr(decision, "top_pattern", ""),
                })

            # Quarantine: move file so it cannot sync to the cloud
            if decision.action == "BLOCK":
                self._quarantine(path)

            # Desktop notification
            fname = os.path.basename(path)
            alerts.send_desktop_notification(
                f"DataShield | {self.provider} DLP",
                f"{decision.action}: {fname} — {getattr(decision, 'top_pattern', risk)} detected.",
            )

            # Fire the GUI / reporting callback (same signature as USB / clipboard)
            if self.on_finding:
                root = self.state.get("root_window")
                detail_str = f"[{self.provider}] {fname}"
                if root:
                    root.after(0, lambda: self.on_finding(
                        "CLOUD", decision.action, detail_str, decision=decision))
                else:
                    self.on_finding("CLOUD", decision.action, detail_str, decision=decision)

        except Exception as exc:
            print(f"[CloudWatcher] Error scanning {path}: {exc}", file=sys.stderr)

    def _quarantine(self, path: str):
        """Move the file into the provider's quarantine subfolder."""
        try:
            q_dir = os.path.join(self.root_path, QUARANTINE_DIR)
            os.makedirs(q_dir, exist_ok=True)
            dest = os.path.join(q_dir, os.path.basename(path))
            # Avoid overwriting if a file with the same name already exists
            if os.path.exists(dest):
                base, ext = os.path.splitext(os.path.basename(path))
                dest = os.path.join(q_dir, f"{base}_{int(time.time())}{ext}")
            shutil.move(path, dest)
            print(f"[CloudWatcher] Quarantined: {path} -> {dest}")
        except Exception as exc:
            print(f"[CloudWatcher] Could not quarantine {path}: {exc}", file=sys.stderr)


class CloudWatcher:
    """
    Public interface: start() / stop() exactly like ClipboardMonitor and USBWatcher.

    Spins up one watchdog Observer per detected cloud provider folder.
    If no sync folders exist on this machine the watcher silently does nothing.
    """

    def __init__(self, state: dict, on_finding_callback=None):
        self.state            = state
        self.on_finding_callback = on_finding_callback
        self._observers       = []   # list of (Observer, provider_name)
        self._folders         = {}   # provider -> path
        self.running          = False

    def start(self):
        if not WATCHDOG_AVAILABLE:
            print("[CloudWatcher] watchdog library not installed — cloud monitoring disabled.")
            return

        self._folders = _detect_cloud_folders()
        if not self._folders:
            print("[CloudWatcher] No cloud sync folders detected on this machine.")
            return

        for provider, path in self._folders.items():
            handler  = _CloudFileHandler(
                provider, path, self.state, self.on_finding_callback)
            observer = Observer()
            observer.schedule(handler, path=path, recursive=True)
            observer.daemon = True
            observer.start()
            self._observers.append((observer, provider))
            print(f"[*] Cloud DLP active — watching {provider}: {path}")

        self.running = True

    def stop(self):
        for observer, _ in self._observers:
            try:
                observer.stop()
                observer.join(timeout=2.0)
            except Exception:
                pass
        self._observers.clear()
        self.running = False
        print("[CloudWatcher] Stopped.")

    @property
    def active_providers(self) -> list:
        """Returns list of provider names being watched."""
        return list(self._folders.keys())

    @property
    def watched_folders(self) -> dict:
        return dict(self._folders)
