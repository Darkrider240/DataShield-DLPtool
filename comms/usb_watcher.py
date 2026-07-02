import os
import sys
import time
import subprocess
import threading
import ctypes
from pathlib import Path
from dataclasses import dataclass
from datetime import datetime
import tkinter as tk
from tkinter import messagebox

# watchdog imports — live file-system event monitoring
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# DataShield components
import scanner
import classifier
import alerts
import comms.comms_engine as comms_engine

# behaviour helpers — use root-level if available, else no-op stubs
try:
    import behaviour as _behaviour
    def _proximity_mult(m): return _behaviour.proximity_multiplier(m)
    def _file_type_mismatch(p): return _behaviour.detect_file_type_mismatch(p)
except ImportError:
    def _proximity_mult(m): return m       # no-op: pass matches through unchanged
    def _file_type_mismatch(p): return False  # no-op: assume no mismatch


@dataclass
class USBScanReport:
    mount_path: str
    scan_timestamp: str
    total_files: int
    high_risk_files: list
    medium_risk_files: list
    all_findings: list


class LiveTransferHandler(FileSystemEventHandler):
    """
    Watchdog handler that fires when files are created, modified, moved, or
    deleted on a connected USB drive.

    CREATE / MODIFY  -> file copied TO the drive  (inbound)
    MOVED / DELETED  -> file removed FROM the drive (outbound / exfiltration risk)
    """

    # Extensions that are truly system noise — skip entirely.
    # NOTE: .txt, .csv, .doc, .pdf, .py, .sql etc. are intentionally NOT here
    #       because they are common exfiltration vectors.
    _SKIP_EXTENSIONS = {
        ".tmp", ".lnk", ".db",
        ".sys", ".dll", ".exe", ".msi", ".bak",
        ".ico", ".png", ".jpg", ".jpeg", ".gif",
        ".mp3", ".mp4", ".avi", ".mov",
    }

    def __init__(self, mount_path, state, on_event_callback=None, reporting_client=None):
        super().__init__()
        self.mount_path        = mount_path
        self.state             = state
        self.on_event_callback = on_event_callback
        self.reporting_client  = reporting_client
        self._scan_lock        = threading.Lock()
        self._recently_scanned = {}   # path -> epoch, debounce cache
        # Session findings accumulated while the drive is connected
        self.session_high        = []
        self.session_medium      = []
        self.session_quarantined = []   # files actually deleted from USB
        self.session_total       = 0
        self.session_scanned_files = 0

    def _wait_for_file_ready(self, filepath, timeout=5.0):
        """Wait until the file size stabilises and it is accessible/unlocked.

        When a file is being copied *to* the USB drive, Windows fires
        on_created while the write handle is still open (file may be 0 bytes).
        This helper polls until two consecutive reads yield the same size and
        the file can be opened without a PermissionError, signalling the copy
        is complete.  Returns False if the file disappears or the timeout
        expires.
        """
        start_time = time.time()
        last_size = -1
        while time.time() - start_time < timeout:
            try:
                if not os.path.exists(filepath):
                    return False
                # Try to open for reading — raises PermissionError if write-locked
                with open(filepath, "rb"):
                    pass
                current_size = os.path.getsize(filepath)
                if current_size == last_size:
                    return True          # size has stabilised — copy done
                last_size = current_size
            except (OSError, PermissionError):
                pass
            time.sleep(0.3)
        return False                     # timed out waiting

    def _debounce(self, path):
        """Return True if this path was scanned < 2 seconds ago (skip it)."""
        now  = time.time()
        last = self._recently_scanned.get(path, 0)
        if now - last < 2.0:
            return True
        self._recently_scanned[path] = now
        self._recently_scanned = {k: v for k, v in self._recently_scanned.items()
                                   if now - v < 30}
        return False

    def _scan_and_alert(self, filepath, direction):
        """Scan a single file; alert if sensitive content found, log if clean.

        Inbound  = file being copied TO the USB drive.
        Outbound = file being moved / read FROM the USB drive.
        In both cases we want to surface the activity in the UI in real time.
        """
        print(f"[USBWatcher] ▶ _scan_and_alert called: {filepath} ({direction})", flush=True)
        if self._debounce(filepath):
            print(f"[USBWatcher] ⏭ Debounced (scanned recently): {filepath}", flush=True)
            return
        if not os.path.exists(filepath):
            print(f"[USBWatcher] ❌ File gone before scan: {filepath}", flush=True)
            return

        # ── wait for the copy to finish before scanning ─────────────────────
        print(f"[USBWatcher] ⏳ Waiting for file to be ready: {filepath}", flush=True)
        if not self._wait_for_file_ready(filepath):
            print(f"[USBWatcher] ⏰ Timed out waiting for file: {filepath}", flush=True)
            return

        try:
            if os.path.getsize(filepath) < 10:
                print(f"[USBWatcher] 📌 File too small (<10 bytes), skipping: {filepath}", flush=True)
                return
            ext = Path(filepath).suffix.lower()
            if ext in self._SKIP_EXTENSIONS or ext == "":
                print(f"[USBWatcher] ⏭ Skipped extension ({ext}): {filepath}", flush=True)
                return
            print(f"[USBWatcher] ✔ Extension OK ({ext}), proceeding to scan", flush=True)
        except OSError:
            return

        root_win = self.state.get("root_window")
        fname    = os.path.basename(filepath)

        # ── show "scanning…" status on the main window ──────────────────────
        if root_win and hasattr(root_win, "set_status_text"):
            root_win.set_status_text(f"USB: Scanning {fname}…", "#94a3b8")

        try:
            self.session_scanned_files += 1

            # Use the USB mount path as the sandbox root so the traversal
            # check in scanner.py never rejects files in sub-directories.
            config = {
                "root_path":      self.mount_path,
                "policy_manager": self.state.get("policy_manager"),
            }
            print(f"[USBWatcher] 🔍 Scanning {fname} (root={self.mount_path})", flush=True)
            with self._scan_lock:
                matches        = scanner.scan_file(filepath, config)
                matches        = _proximity_mult(matches)
                mismatch       = _file_type_mismatch(filepath)
                classification = classifier.classify_file(
                    matches, file_path=filepath, file_type_mismatch=mismatch
                )

            risk = classification.get("risk_level", "CLEAN")
            print(f"[USBWatcher] 📊 Result for {fname}: risk={risk}, matches={len(matches)}", flush=True)

            # ── UNREADABLE (encrypted / password-protected) ───────────────────
            # If the scanner returned a sentinel UNREADABLE match, we cannot verify
            # the file's content.  For INBOUND transfers this is a security concern
            # — the file might contain sensitive data deliberately obfuscated.
            unreadable_matches = [m for m in matches if m.category == "UNREADABLE"]
            if unreadable_matches and direction == "INBOUND":
                reason = unreadable_matches[0].matched_value
                print(f"[USBWatcher] 🔒 Unreadable file on USB (inbound): {fname} — {reason}", flush=True)
                self.state["audit_logger"].log("USB_INBOUND_UNREADABLE", {
                    "file_path": filepath,
                    "reason":    reason,
                })
                self._warn_unreadable_inbound(filepath, fname, reason, root_win)
                if self.on_event_callback and root_win:
                    detail = f"🔒 Unreadable file on USB: {fname} ({reason}) — cannot verify content"
                    root_win.after(0, lambda d=detail:
                                   self.on_event_callback("USB", "WARN", d))
                return

            # ── CLEAN ────────────────────────────────────────────────────────
            if risk not in ("HIGH", "MEDIUM"):
                if root_win and hasattr(root_win, "set_status_text"):
                    root_win.set_status_text(
                        f"USB: Monitored {fname} (Clean)", "#22c55e"
                    )
                    root_win.after(4000, lambda: root_win.set_status_text(""))

                # Log clean transfer to threat feed so user can see activity
                arrow  = "📥" if direction == "INBOUND" else "📤"
                detail = f"{arrow} Monitored transfer: {fname} (Clean)"
                if self.on_event_callback and root_win:
                    root_win.after(0, lambda d=detail:
                                   self.on_event_callback("USB", "LOG", d))
                return

            # ── SENSITIVE (HIGH / MEDIUM) ─────────────────────────────────
            top_pattern = (classification["top_matches"][0].pattern_name
                           if classification.get("top_matches") else "Unknown")
            emoji  = "🔴" if risk == "HIGH" else "🟡"


            # Accumulate for the session summary shown on drive removal
            self.session_total += 1
            if risk == "HIGH":
                self.session_high.append(f"{direction}: {fname} [{top_pattern}]")
            else:
                self.session_medium.append(f"{direction}: {fname} [{top_pattern}]")

            # ── INTERCEPTION: attempt to quarantine INBOUND sensitive files ───
            quarantined = False
            if direction == "INBOUND":
                quarantined = self._quarantine_inbound(
                    filepath, fname, risk, top_pattern, root_win
                )

            action = "BLOCK" if quarantined else "WARN"
            detail = (
                f"{emoji} {'BLOCKED' if quarantined else direction.upper()} USB — {risk}: "
                f"{top_pattern} in {fname}"
                + (" [QUARANTINED — removed from drive]" if quarantined else "")
            )

            # Status bar update
            if root_win and hasattr(root_win, "set_status_text"):
                if quarantined:
                    root_win.set_status_text(
                        f"USB: 🚫 Transfer BLOCKED — {fname} removed from drive", "#ef4444"
                    )
                else:
                    root_win.set_status_text(
                        f"USB: ⚠ Sensitive transfer detected — {fname}", "#f59e0b"
                    )
                root_win.after(5000, lambda: root_win.set_status_text(""))

            if not quarantined:   # only notify if we didn't already show a dialog
                alerts.send_desktop_notification(
                    f"DataShield — USB WARN",
                    f"{direction} sensitive file on USB:\n{fname}\n({top_pattern})"
                )

            self.state["audit_logger"].log(
                f"USB_{direction.upper()}_{'QUARANTINED' if quarantined else 'SENSITIVE'}", {
                    "file_path":    filepath,
                    "direction":    direction,
                    "risk_level":   risk,
                    "top_pattern":  top_pattern,
                    "risk_score":   classification.get("risk_score", 0),
                    "quarantined":  quarantined,
                }
            )

            if self.reporting_client:
                comms_engine.decide(
                    classification, channel="USB",
                    audit_logger=self.state["audit_logger"], explain=False
                )
                self.reporting_client.enqueue_event(
                    classification, channel="USB",
                    action=action, justification=detail
                )

            if self.on_event_callback and root_win:
                root_win.after(0, lambda d=detail, a=action:
                               self.on_event_callback("USB", a, d))

        except Exception as e:
            print(f"[USBWatcher] Live scan error for {filepath}: {e}", file=sys.stderr)

    # ── quarantine (interception) ─────────────────────────────────────────────

    def _quarantine_inbound(self, filepath, fname, risk, top_pattern, root_win):
        """Attempt to delete a sensitive file that was just copied to the USB drive.

        HIGH risk  → auto-delete immediately; show a non-blocking desktop alert.
        MEDIUM risk → ask the admin via a Tkinter dialog (blocks the watchdog
                      thread via threading.Event until the user responds).

        Returns True if the file was successfully deleted, False otherwise.
        """
        deleted = False

        if risk == "HIGH":
            # ── Auto-quarantine HIGH risk ─────────────────────────────────────
            retries = 3
            for attempt in range(retries):
                try:
                    os.remove(filepath)
                    deleted = True
                    break
                except PermissionError:
                    if attempt < retries - 1:
                        time.sleep(0.5)
                    else:
                        print(f"[USBWatcher] PermissionError quarantining {fname} (handle locked)", file=sys.stderr)
                except Exception as e:
                    print(f"[USBWatcher] Quarantine error for {fname}: {e}", file=sys.stderr)
                    break

            if deleted:
                self.session_quarantined.append(f"{fname} [{top_pattern}]")
                alerts.send_desktop_notification(
                    "DataShield — Transfer BLOCKED",
                    f"HIGH-risk file removed from USB drive:\n{fname}\n"
                    f"Pattern: {top_pattern}"
                )
                self.state["audit_logger"].log("USB_INBOUND_QUARANTINE_AUTO", {
                    "file": fname, "pattern": top_pattern, "risk": "HIGH",
                })

        elif risk == "MEDIUM" and root_win:
            # ── Ask the admin for MEDIUM risk ─────────────────────────────────
            result_event  = threading.Event()
            result_holder = [False]   # mutable so inner lambda can write to it

            def _ask():
                try:
                    answer = messagebox.askyesno(
                        "DataShield — Sensitive Transfer Detected",
                        f"A MEDIUM-risk file was copied to the USB drive:\n\n"
                        f"  File:    {fname}\n"
                        f"  Pattern: {top_pattern}\n\n"
                        f"Remove this file from the drive?",
                        icon="warning",
                        parent=root_win,
                    )
                    result_holder[0] = bool(answer)
                except Exception:
                    result_holder[0] = False
                finally:
                    result_event.set()

            root_win.after(0, _ask)
            result_event.wait(timeout=30)   # wait up to 30 s for admin response

            if result_holder[0]:
                try:
                    os.remove(filepath)
                    deleted = True
                    self.session_quarantined.append(f"{fname} [{top_pattern}]")
                    self.state["audit_logger"].log("USB_INBOUND_QUARANTINE_CONFIRMED", {
                        "file": fname, "pattern": top_pattern, "risk": "MEDIUM",
                    })
                except Exception as e:
                    print(f"[USBWatcher] Quarantine error for {fname}: {e}", file=sys.stderr)

        return deleted

    def _warn_unreadable_inbound(self, filepath, fname, reason, root_win):
        """Show an admin dialog when an unreadable/encrypted file lands on the USB drive.

        Content cannot be verified — this could be deliberate obfuscation.
        The admin is given the option to remove the file immediately.
        """
        if not root_win:
            # No GUI — just fire a desktop notification
            alerts.send_desktop_notification(
                "DataShield — Unreadable File on USB",
                f"Cannot scan: {fname}\nReason: {reason}\nReview manually."
            )
            return

        result_event  = threading.Event()
        result_holder = [False]

        def _ask():
            try:
                answer = messagebox.askyesno(
                    "DataShield — Unreadable File on USB",
                    f"⚠️  A file was copied to the USB drive that DataShield\n"
                    f"   CANNOT scan because it is {reason}.\n\n"
                    f"   File:    {fname}\n\n"
                    f"   Since the content cannot be verified, this file\n"
                    f"   could contain sensitive data.\n\n"
                    f"Remove this file from the drive?",
                    icon="warning",
                    parent=root_win,
                )
                result_holder[0] = bool(answer)
            except Exception:
                result_holder[0] = False
            finally:
                result_event.set()

        root_win.after(0, _ask)
        result_event.wait(timeout=30)

        if result_holder[0]:
            try:
                os.remove(filepath)
                self.session_quarantined.append(f"{fname} [Unreadable — {reason}]")
                self.state["audit_logger"].log("USB_INBOUND_UNREADABLE_REMOVED", {
                    "file": fname, "reason": reason,
                })
                alerts.send_desktop_notification(
                    "DataShield — Unreadable File Removed",
                    f"Removed from USB: {fname}\n({reason})"
                )
            except Exception as e:
                print(f"[USBWatcher] Could not remove unreadable file {fname}: {e}", file=sys.stderr)

    # ── watchdog event handlers ───────────────────────────────────────────────

    def on_created(self, event):
        if not event.is_directory:
            print(f"[USBWatcher] 📥 on_created: {event.src_path}", flush=True)
            self._scan_and_alert(event.src_path, "INBOUND")

    def on_modified(self, event):
        if not event.is_directory:
            print(f"[USBWatcher] 📝 on_modified: {event.src_path}", flush=True)
            self._scan_and_alert(event.src_path, "INBOUND")

    def on_moved(self, event):
        if not event.is_directory:
            # src moved away from drive = outbound exfiltration
            self._scan_and_alert(event.src_path, "OUTBOUND")
            # dest may be a new copy on the drive
            self._scan_and_alert(event.dest_path, "INBOUND")

    def on_deleted(self, event):
        if event.is_directory:
            return
        self.state["audit_logger"].log("USB_FILE_DELETED", {
            "file_path": event.src_path,
            "note": "File removed from USB while drive connected.",
        })
        if self.on_event_callback:
            root = self.state.get("root_window")
            if root:
                name   = os.path.basename(event.src_path)
                detail = f"📤 File removed from USB: {name}"
                root.after(0, lambda: self.on_event_callback("USB", "LOG", detail))


class _MountEventHandler(FileSystemEventHandler):
    """Bridges watchdog dir-created events to USBWatcher (Linux / macOS)."""
    def __init__(self, watcher):
        super().__init__()
        self.watcher = watcher

    def on_created(self, event):
        if event.is_directory:
            self.watcher.on_usb_mounted(event.src_path)


class USBWatcher:
    """
    USB mount event watcher.

    On Windows  : polls removable drive letters every 1 second.
    On Linux/macOS : uses watchdog inotify to detect new mounts.

    For each newly connected drive:
      1. Full recursive mount scan of all existing files.
      2. Starts a LiveTransferHandler watchdog observer for real-time
         inbound / outbound transfer scanning.
      3. On drive removal: stops observer, logs disconnection audit.

    The "Safely Eject Drive" dialog button runs a fresh pre-eject re-scan
    before physically ejecting the drive.
    """

    def __init__(self, state, on_report_callback=None, on_event_callback=None):
        self.state              = state
        self.on_report_callback = on_report_callback
        self.on_event_callback  = on_event_callback
        self.running            = False
        self.thread             = None
        self.observer           = None                  # Linux/macOS mount observer
        self._live_observers    = {}                    # mount_path -> (Observer, LiveTransferHandler)

    # ── lifecycle ─────────────────────────────────────────────────────────────

    def start(self):
        if self.running:
            return
        self.running = True
        if sys.platform == "win32":
            self.thread = threading.Thread(target=self._win_poll_loop, daemon=True)
            self.thread.start()
        else:
            self.observer = Observer()
            handler = _MountEventHandler(self)
            for root in ["/media", "/mnt", "/Volumes"]:
                if os.path.exists(root):
                    try:
                        self.observer.schedule(handler, root, recursive=True)
                    except Exception as e:
                        print(f"[USBWatcher] Cannot watch {root}: {e}", file=sys.stderr)
            self.observer.start()

    def stop(self):
        self.running = False
        for entry in list(self._live_observers.values()):
            try:
                obs, _ = entry
                obs.stop()
                obs.join(timeout=1.0)
            except Exception:
                pass
        self._live_observers.clear()
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
        if self.thread:
            self.thread.join(timeout=1.0)
            self.thread = None

    # ── Windows polling ───────────────────────────────────────────────────────

    def _get_win_removable_drives(self):
        drives = set()
        for code in range(68, 91):                     # D: to Z:
            path = f"{chr(code)}:\\"
            if os.path.exists(path):
                try:
                    if ctypes.windll.kernel32.GetDriveTypeW(path) == 2:   # DRIVE_REMOVABLE
                        drives.add(path)
                except Exception:
                    pass
        return drives

    def _win_poll_loop(self):
        existing = self._get_win_removable_drives()
        while self.running:
            time.sleep(1.0)
            current = self._get_win_removable_drives()
            for drive in current - existing:
                print(f"[USBWatcher] Drive inserted: {drive}")
                threading.Thread(target=self.on_usb_mounted,
                                 args=(drive,), daemon=True).start()
            for drive in existing - current:
                print(f"[USBWatcher] Drive removed: {drive}")
                self._on_usb_removed(drive)
            existing = current

    def _on_usb_removed(self, mount_path):
        entry = self._live_observers.pop(mount_path, None)
        handler = None
        if entry:
            obs, handler = entry
            try:
                obs.stop()
                obs.join(timeout=2.0)
            except Exception:
                pass
        self.state["audit_logger"].log("USB_DISCONNECTED", {"mount_path": mount_path})
        alerts.send_desktop_notification(
            "USB Drive Removed",
            f"DataShield: USB {mount_path} disconnected."
        )
        if self.on_event_callback:
            root_win = self.state.get("root_window")
            if root_win:
                root_win.after(0, lambda: self.on_event_callback(
                    "USB", "LOG", f"USB drive disconnected: {mount_path}"))

        # Show session summary dialog on removal
        root_win = self.state.get("root_window")
        if root_win and handler is not None:
            root_win.after(300, lambda h=handler, mp=mount_path:
                           self._show_removal_report(mp, h))

    # ── mount handler ─────────────────────────────────────────────────────────

    def on_usb_mounted(self, mount_path):
        """Start live observer immediately, then run full mount scan, then show report.

        The live watchdog observer is armed FIRST so that any file copied to the
        drive DURING the initial scan is caught in real time — no blind spot.
        """
        alerts.send_desktop_notification(
            "USB Drive Connected",
            f"DataShield scanning USB: {mount_path}"
        )
        if self.on_event_callback:
            self.on_event_callback("USB", "LOG", f"USB mounted: {mount_path} — live monitor armed, scanning…")

        # ── Arm live transfer monitor immediately (before the mount scan) ─────
        # This ensures files copied DURING the scan are intercepted in real time.
        self._start_live_observer(mount_path)

        # Full mount scan
        total_files, high_risk_files, medium_risk_files, all_findings = 0, [], [], []
        config = {"root_path": mount_path, "policy_manager": self.state.get("policy_manager")}
        root_win = self.state.get("root_window")

        for root, dirs, files in os.walk(mount_path):
            for f in files:
                filepath     = os.path.join(root, f)
                total_files += 1

                # ── live progress on the main window status bar ──────────
                if root_win and hasattr(root_win, "set_status_text"):
                    root_win.set_status_text(
                        f"USB Mount Scan: {total_files} file(s) scanned…", "#94a3b8"
                    )

                try:
                    matches        = scanner.scan_file(filepath, config)
                    matches        = _proximity_mult(matches)
                    mismatch       = _file_type_mismatch(filepath)
                    classification = classifier.classify_file(
                        matches, file_path=filepath, file_type_mismatch=mismatch
                    )
                    risk = classification.get("risk_level", "CLEAN")
                    if risk != "CLEAN":
                        all_findings.append(classification)
                        if risk == "HIGH":
                            high_risk_files.append(filepath)
                            self.state["audit_logger"].log("USB_HIGH_RISK_DETECTED", {
                                "file_path":   filepath,
                                "risk_score":  classification.get("risk_score", 0),
                                "top_pattern": (classification["top_matches"][0].pattern_name
                                                if classification.get("top_matches") else "None"),
                            })
                            comms_engine.decide(classification, channel="USB",
                                                audit_logger=self.state["audit_logger"], explain=False)
                        elif risk == "MEDIUM":
                            medium_risk_files.append(filepath)
                except Exception as e:
                    print(f"[USBWatcher] Scan error {filepath}: {e}", file=sys.stderr)

        # ── show final status then auto-clear after 4 s ──────────────────────
        if root_win and hasattr(root_win, "set_status_text"):
            h = len(high_risk_files)
            m = len(medium_risk_files)
            if h or m:
                root_win.set_status_text(
                    f"USB Mount Scan Done — {total_files} files | {h} High, {m} Medium", "#f59e0b"
                )
            else:
                root_win.set_status_text(
                    f"USB Mount Scan Done — {total_files} files, all clean ✓", "#22c55e"
                )
            root_win.after(5000, lambda: root_win.set_status_text(""))

        # (Live observer already running — no second call needed)

        # Build and show report
        report = USBScanReport(
            mount_path=mount_path,
            scan_timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_files=total_files,
            high_risk_files=high_risk_files,
            medium_risk_files=medium_risk_files,
            all_findings=all_findings,
        )
        summary = f"{len(high_risk_files)} High / {len(medium_risk_files)} Medium risk files"
        if self.on_event_callback:
            action = "WARN" if (high_risk_files or medium_risk_files) else "LOG"
            self.on_event_callback("USB", action, f"Mount scan done {mount_path} ({total_files} files scanned) — {summary}")

        root_win = self.state.get("root_window")
        if root_win:
            if self.on_report_callback:
                root_win.after(0, self.on_report_callback, report)
            root_win.after(0, lambda r=report: self.show_summary_dialog(r))

    def _start_live_observer(self, mount_path):
        if mount_path in self._live_observers:
            return
        try:
            handler = LiveTransferHandler(
                mount_path=mount_path,
                state=self.state,
                on_event_callback=self.on_event_callback,
                reporting_client=self.state.get("reporting_client"),
            )
            obs        = Observer()
            obs.daemon = True
            obs.schedule(handler, mount_path, recursive=True)
            obs.start()
            self._live_observers[mount_path] = (obs, handler)  # store both
            print(f"[USBWatcher] Live transfer monitor active on {mount_path}")
        except Exception as e:
            print(f"[USBWatcher] Could not start live observer on {mount_path}: {e}", file=sys.stderr)

    def _show_removal_report(self, mount_path, handler):
        """Dialog shown when drive is removed — summarises live transfer session."""
        root_win = self.state.get("root_window")
        if not root_win:
            return

        high_items   = handler.session_high
        medium_items = handler.session_medium
        total_events = handler.session_total
        total_scanned = handler.session_scanned_files
        quarantined_items = getattr(handler, "session_quarantined", [])

        dialog = tk.Toplevel(root_win)
        dialog.title("DataShield DLP — USB Removal Report")
        dialog.geometry("520x460")
        dialog.resizable(False, False)
        dialog.configure(background="#0f172a")
        dialog.transient(root_win)
        dialog.grab_set()

        tk.Label(dialog,
                 text=f"🔌 USB Removed: {mount_path}",
                 bg="#0f172a", fg="#f59e0b",
                 font=("Segoe UI", 12, "bold")
                 ).pack(pady=14, padx=15, anchor="w")

        tk.Label(dialog,
                 text="Session summary — files monitored while drive was connected:",
                 bg="#0f172a", fg="#94a3b8", font=("Segoe UI", 9)
                 ).pack(padx=15, anchor="w")

        sf = tk.Frame(dialog, bg="#1e293b", bd=1, relief="solid")
        sf.pack(fill="x", padx=15, pady=8)
        tk.Label(sf, text=f"Total file transfers monitored:    {total_scanned}",
                 bg="#1e293b", fg="#f8fafc", font=("Segoe UI", 10)
                 ).pack(anchor="w", padx=10, pady=5)
        tk.Label(sf, text=f"Total sensitive transfers:        {total_events}",
                 bg="#1e293b", fg="#cbd5e1", font=("Segoe UI", 10)
                 ).pack(anchor="w", padx=10, pady=2)
        tk.Label(sf, text=f"🔴  High Risk Transfers:    {len(high_items)}",
                 bg="#1e293b", fg="#ef4444", font=("Segoe UI", 10, "bold")
                 ).pack(anchor="w", padx=10, pady=2)
        tk.Label(sf, text=f"🟡  Medium Risk Transfers: {len(medium_items)}",
                 bg="#1e293b", fg="#f59e0b", font=("Segoe UI", 10, "bold")
                 ).pack(anchor="w", padx=10, pady=2)
        tk.Label(sf, text=f"🚫  Quarantined (Blocked):  {len(quarantined_items)}",
                 bg="#1e293b", fg="#f43f5e", font=("Segoe UI", 10, "bold")
                 ).pack(anchor="w", padx=10, pady=5)

        all_items = [(i, "HIGH") for i in high_items] + [(i, "MEDIUM") for i in medium_items]
        if all_items:
            lf = tk.Frame(dialog, bg="#1e293b")
            lf.pack(fill="x", padx=15, pady=4)
            tk.Label(lf, text="Flagged transfers:",
                     bg="#1e293b", fg="#94a3b8", font=("Segoe UI", 8, "bold")
                     ).pack(anchor="w", padx=8, pady=3)
            for item, level in all_items[:6]:
                col = "#ef4444" if level == "HIGH" else "#f59e0b"
                tk.Label(lf, text=f"  • {item}",
                         bg="#1e293b", fg=col, font=("Segoe UI", 8)
                         ).pack(anchor="w", padx=8)
            if len(all_items) > 6:
                tk.Label(lf, text=f"  … and {len(all_items) - 6} more",
                         bg="#1e293b", fg="#64748b", font=("Segoe UI", 8)
                         ).pack(anchor="w", padx=8, pady=3)
        else:
            tk.Label(dialog,
                     text="✅  No sensitive file transfers detected during this session.",
                     bg="#0f172a", fg="#22c55e", font=("Segoe UI", 9, "bold")
                     ).pack(pady=10, padx=15, anchor="w")

        tk.Button(
            dialog, text="Close",
            bg="#1e293b", fg="#94a3b8",
            font=("Segoe UI", 9), padx=14, pady=6,
            relief="flat", cursor="hand2",
            command=dialog.destroy,
        ).pack(side="bottom", pady=14)

    # ── Summary Dialog ────────────────────────────────────────────────────────

    def show_summary_dialog(self, report):
        root = self.state.get("root_window")
        if not root:
            return

        dialog = tk.Toplevel(root)
        dialog.title("DataShield DLP — USB Device Assessment")
        dialog.geometry("520x460")
        dialog.resizable(False, False)
        dialog.configure(background="#0f172a")
        dialog.transient(root)
        dialog.grab_set()

        tk.Label(dialog, text=f"🔌 USB Mount Scan: {report.mount_path}",
                 bg="#0f172a", fg="#3b82f6",
                 font=("Segoe UI", 12, "bold")).pack(pady=14, padx=15, anchor="w")

        sf = tk.Frame(dialog, bg="#1e293b", bd=1, relief="solid")
        sf.pack(fill="x", padx=15, pady=4)
        tk.Label(sf, text=f"Total Files Scanned:   {report.total_files}",
                 bg="#1e293b", fg="#f8fafc", font=("Segoe UI", 10)).pack(anchor="w", padx=10, pady=5)
        tk.Label(sf, text=f"🔴  High Risk Files:   {len(report.high_risk_files)}",
                 bg="#1e293b", fg="#ef4444", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=10, pady=2)
        tk.Label(sf, text=f"🟡  Medium Risk Files: {len(report.medium_risk_files)}",
                 bg="#1e293b", fg="#f59e0b", font=("Segoe UI", 10, "bold")).pack(anchor="w", padx=10, pady=5)

        tk.Label(dialog,
                 text="🟢  Live Transfer Monitor ACTIVE — every file copied in/out is scanned in real time.",
                 bg="#0f172a", fg="#22c55e",
                 font=("Segoe UI", 8, "bold"), wraplength=480, justify="left",
                 ).pack(pady=6, padx=15, anchor="w")

        if report.high_risk_files:
            rec, col = ("❌  HIGH RISK files found. Eject the drive immediately.", "#ef4444")
        elif report.medium_risk_files:
            rec, col = ("⚠️  Medium risk files detected. Review before proceeding.", "#f59e0b")
        else:
            rec, col = ("✅  SECURED — no sensitive violations found.", "#10b981")

        tk.Label(dialog, text=rec, bg="#0f172a", fg=col,
                 font=("Segoe UI", 9, "bold"), wraplength=480, justify="left",
                 ).pack(pady=8, padx=15, anchor="w")

        if report.high_risk_files:
            lf = tk.Frame(dialog, bg="#1e293b")
            lf.pack(fill="x", padx=15, pady=4)
            tk.Label(lf, text="Flagged files:", bg="#1e293b", fg="#94a3b8",
                     font=("Segoe UI", 8, "bold")).pack(anchor="w", padx=8, pady=3)
            for fp in report.high_risk_files[:5]:
                tk.Label(lf, text=f"  • {os.path.basename(fp)}",
                         bg="#1e293b", fg="#ef4444", font=("Segoe UI", 8)).pack(anchor="w", padx=8)
            if len(report.high_risk_files) > 5:
                tk.Label(lf, text=f"  … and {len(report.high_risk_files) - 5} more",
                         bg="#1e293b", fg="#64748b", font=("Segoe UI", 8)).pack(anchor="w", padx=8, pady=3)

        btn_frame = tk.Frame(dialog, bg="#0f172a")
        btn_frame.pack(fill="x", side="bottom", pady=14, padx=15)

        def run_eject():
            btn_eject.config(state="disabled", text="Scanning before eject…")
            dialog.update()

            pre_high = []
            cfg = {"root_path": report.mount_path, "policy_manager": self.state.get("policy_manager")}
            for r, ds, fs in os.walk(report.mount_path):
                for f in fs:
                    fp = os.path.join(r, f)
                    try:
                        m  = scanner.scan_file(fp, cfg)
                        cl = classifier.classify_file(m, file_path=fp)
                        if cl.get("risk_level") == "HIGH":
                            pre_high.append(os.path.basename(fp))
                    except Exception:
                        pass

            _entry = self._live_observers.pop(report.mount_path, None)
            if _entry:
                _eobs, _ = _entry
                try:
                    _eobs.stop()
                    _eobs.join(timeout=2.0)
                except Exception:
                    pass

            if pre_high:
                names = "\n".join(pre_high[:5])
                go = messagebox.askyesno(
                    "Pre-Eject Scan — Risk Detected",
                    f"⚠️  {len(pre_high)} HIGH risk file(s) remain on this drive:\n\n{names}\n\n"
                    "Ejecting may leave sensitive data on the device.\nEject anyway?",
                    parent=dialog,
                )
                if not go:
                    btn_eject.config(state="normal", text="🔒 Safely Eject Drive")
                    self._start_live_observer(report.mount_path)  # re-arm observer
                    return

            try:
                if sys.platform == "win32":
                    dl  = report.mount_path.rstrip("\\").rstrip(":")
                    cmd = (f"powershell -Command \"(New-Object -comObject Shell.Application)"
                           f".Namespace(17).ParseName('{dl}:').InvokeVerb('Eject')\"")
                    subprocess.run(cmd, shell=True, check=True)
                elif sys.platform == "darwin":
                    subprocess.run(f"diskutil eject \"{report.mount_path}\"", shell=True, check=True)
                else:
                    subprocess.run(f"eject \"{report.mount_path}\"", shell=True, check=True)

                messagebox.showinfo("Drive Ejected",
                                    f"USB {report.mount_path} safely ejected.", parent=dialog)
                dialog.destroy()
            except Exception as e:
                messagebox.showerror("Eject Error", f"Cannot eject drive:\n{e}", parent=dialog)
                btn_eject.config(state="normal", text="🔒 Safely Eject Drive")

        btn_eject = tk.Button(
            btn_frame, text="🔒 Safely Eject Drive",
            bg="#6366f1", fg="white", font=("Segoe UI", 9, "bold"),
            padx=12, pady=6, relief="flat", cursor="hand2",
            command=run_eject,
        )
        btn_eject.pack(side="left", padx=5)

        tk.Button(
            btn_frame, text="Close Report",
            bg="#1e293b", fg="#94a3b8", font=("Segoe UI", 9),
            padx=12, pady=6, relief="flat", cursor="hand2",
            command=dialog.destroy,
        ).pack(side="right", padx=5)
