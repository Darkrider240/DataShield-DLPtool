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
from tkinter import ttk, messagebox

# watchdog imports
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# DataShield components
import scanner
import classifier
import alerts
import comms.comms_engine as comms_engine

@dataclass
class USBScanReport:
    mount_path: str
    scan_timestamp: str
    total_files: int
    high_risk_files: list[str]
    medium_risk_files: list[str]
    all_findings: list[dict]


class USBMountHandler(FileSystemEventHandler):
    def __init__(self, watcher):
        super().__init__()
        self.watcher = watcher

    def on_created(self, event):
        if event.is_directory:
            # New mount directory added (e.g. under /media/username/)
            self.watcher.on_usb_mounted(event.src_path)


class USBWatcher:
    """
    USB mount event watcher. Listens for folder additions under Unix mount paths
    and polls removable drive letters on Windows using kernel32.
    """
    def __init__(self, state, on_report_callback=None, on_event_callback=None):
        self.state = state  # Shared app state
        self.on_report_callback = on_report_callback  # Callback to pass report to GUI Tab
        self.on_event_callback = on_event_callback  # Callback to write lines in live feed
        self.running = False
        self.thread = None
        self.observer = None

    def start(self):
        """Starts background observers or polling threads based on OS platform."""
        if self.running:
            return
        self.running = True

        if sys.platform == "win32":
            self.thread = threading.Thread(target=self._win_poll_loop, daemon=True)
            self.thread.start()
        else:
            self.observer = Observer()
            handler = USBMountHandler(self)
            
            # Common mount points on macOS and Linux
            mount_roots = ["/media", "/mnt", "/Volumes"]
            for root in mount_roots:
                if os.path.exists(root):
                    try:
                        self.observer.schedule(handler, root, recursive=True)
                    except Exception as e:
                        print(f"Warning: USBWatcher failed to watch {root}: {e}", file=sys.stderr)
            self.observer.start()

    def stop(self):
        """Terminates observers and polling threads."""
        self.running = False
        if self.observer:
            self.observer.stop()
            self.observer.join()
            self.observer = None
        if self.thread:
            self.thread.join(timeout=1.0)
            self.thread = None

    def _get_win_removable_drives(self) -> set:
        """Helper to scan active Windows removable drive letters."""
        drives = set()
        # Check letters D:\ to Z:\
        for letter_code in range(68, 91):
            drive_path = f"{chr(letter_code)}:\\"
            if os.path.exists(drive_path):
                try:
                    # DRIVE_REMOVABLE = 2
                    drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive_path)
                    if drive_type == 2:
                        drives.add(drive_path)
                except Exception:
                    # Fallback if ctypes call fails
                    pass
        return drives

    def _win_poll_loop(self):
        """Windows polling loop checking for new drive arrivals."""
        existing_drives = self._get_win_removable_drives()
        while self.running:
            time.sleep(1.0)
            current_drives = self._get_win_removable_drives()
            new_drives = current_drives - existing_drives
            for drive in new_drives:
                # Trigger scan asynchronously
                threading.Thread(target=self.on_usb_mounted, args=(drive,), daemon=True).start()
            existing_drives = current_drives

    def on_usb_mounted(self, mount_path: str):
        """Scans the newly mounted drive recursively and displays statistics summary dialogs."""
        # 1. Dispatch starting desktop notification
        alerts.send_desktop_notification(
            "USB Drive Connected",
            f"DataShield is running a background scan on USB drive: {mount_path}"
        )
        if self.on_event_callback:
            self.on_event_callback("USB", "ALLOW", f"USB drive mounted: {mount_path}")

        # 2. Walk directories recursively
        total_files = 0
        high_risk_files = []
        medium_risk_files = []
        all_findings = []

        config = {
            "root_path": mount_path,
            "policy_manager": self.state.get("policy_manager")
        }

        # Scan the drive root folder
        for root, dirs, files in os.walk(mount_path):
            for f in files:
                filepath = os.path.join(root, f)
                total_files += 1
                try:
                    # Perform scan
                    matches = scanner.scan_file(filepath, config)
                    matches = behaviour.proximity_multiplier(matches)
                    mismatch = behaviour.detect_file_type_mismatch(filepath)
                    
                    classification = classifier.classify_file(matches, file_path=filepath, file_type_mismatch=mismatch)
                    
                    if classification["risk_level"] != "CLEAN":
                        all_findings.append(classification)
                        
                        if classification["risk_level"] == "HIGH":
                            high_risk_files.append(filepath)
                            # Log audit
                            self.state["audit_logger"].log("USB_HIGH_RISK_DETECTED", {
                                "file_path": filepath,
                                "risk_score": classification["risk_score"],
                                "top_pattern": classification["top_matches"][0].pattern_name if classification["top_matches"] else "None"
                            })
                            # Trigger comms decision to record detail
                            comms_engine.decide(
                                classification, channel="USB", 
                                audit_logger=self.state["audit_logger"], explain=False
                            )
                        elif classification["risk_level"] == "MEDIUM":
                            medium_risk_files.append(filepath)
                except Exception as e:
                    print(f"Warning: Failed to scan USB file {filepath}: {e}", file=sys.stderr)

        # 3. Compile report
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        report = USBScanReport(
            mount_path=mount_path,
            scan_timestamp=timestamp,
            total_files=total_files,
            high_risk_files=high_risk_files,
            medium_risk_files=medium_risk_files,
            all_findings=all_findings
        )

        # 4. Trigger UI notification event callback
        if self.on_event_callback:
            action = "BLOCKED" if high_risk_files else "ALLOW"
            pattern_summary = f"{len(high_risk_files)} High / {len(medium_risk_files)} Medium risk files found"
            self.on_event_callback("USB", action, f"Scan finished on {mount_path} — {pattern_summary}")

        if self.on_report_callback:
            # Update GUI Stats / Lists
            root = self.state.get("root_window")
            if root:
                root.after(0, self.on_report_callback, report)

        # 5. Display Dialog Summary
        root = self.state.get("root_window")
        if root:
            root.after(0, lambda: self.show_summary_dialog(report))

    def show_summary_dialog(self, report: USBScanReport):
        """Renders the top-level scan findings and offers program ejecting triggers."""
        root = self.state.get("root_window")
        if not root:
            return

        dialog = tk.Toplevel(root)
        dialog.title("DataShield DLP — USB Device Assessment")
        dialog.geometry("500x380")
        dialog.resizable(False, False)
        dialog.configure(background="#0f172a")
        dialog.transient(root)
        dialog.grab_set()

        style_lbl = {"bg": "#0f172a", "fg": "#f8fafc", "font": ("Segoe UI", 10)}
        
        # Heading
        title_lbl = tk.Label(
            dialog, 
            text=f"🔌 USB Device Scan Complete: {report.mount_path}",
            bg="#0f172a", fg="#3b82f6", font=("Segoe UI", 12, "bold")
        )
        title_lbl.pack(pady=15, padx=15, anchor="w")

        # Stats
        stats_frame = tk.Frame(dialog, bg="#1e293b", bd=1, relief="solid")
        stats_frame.pack(fill="x", padx=15, pady=5)
        
        tk.Label(stats_frame, text=f"Total Files Scanned: {report.total_files}", bg="#1e293b", fg="#f8fafc", font=("Segoe UI", 10)).pack(anchor="w", padx=10, pady=5)
        
        high_lbl = tk.Label(stats_frame, text=f"High Risk Violations: {len(report.high_risk_files)}", bg="#1e293b", fg="#ef4444", font=("Segoe UI", 10, "bold"))
        high_lbl.pack(anchor="w", padx=10, pady=2)
        
        med_lbl = tk.Label(stats_frame, text=f"Medium Risk Violations: {len(report.medium_risk_files)}", bg="#1e293b", fg="#f59e0b", font=("Segoe UI", 10, "bold"))
        med_lbl.pack(anchor="w", padx=10, pady=5)

        # Recommendation note
        rec_text = "Status: SECURED. No sensitive violations found on device."
        rec_color = "#10b981"
        if report.high_risk_files:
            rec_text = "❌ WARNING: High-risk violations identified. It is recommended to eject the drive immediately to prevent data exposure."
            rec_color = "#ef4444"
        elif report.medium_risk_files:
            rec_text = "⚠️ WARNING: Medium-risk files detected. Review files before proceeding."
            rec_color = "#f59e0b"

        rec_lbl = tk.Label(
            dialog, text=rec_text, bg="#0f172a", fg=rec_color, 
            font=("Segoe UI", 9, "bold"), justify="left", wraplength=460
        )
        rec_lbl.pack(pady=15, padx=15, anchor="w")

        # Actions
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill="x", side="bottom", pady=20, padx=15)

        def run_eject():
            try:
                if sys.platform == "win32":
                    drive_letter = report.mount_path.rstrip('\\').rstrip(':')
                    # Run powershell shell command verb to eject drive letter
                    cmd = f"powershell -Command \"(New-Object -comObject Shell.Application).Namespace(17).ParseName('{drive_letter}:').InvokeVerb('Eject')\""
                    subprocess.run(cmd, shell=True, check=True)
                elif sys.platform == "darwin":
                    cmd = f"diskutil eject \"{report.mount_path}\""
                    subprocess.run(cmd, shell=True, check=True)
                else:
                    cmd = f"eject \"{report.mount_path}\""
                    subprocess.run(cmd, shell=True, check=True)
                messagebox.showinfo("Drive Ejected", f"The USB device at {report.mount_path} has been safely ejected.", parent=dialog)
                dialog.destroy()
            except Exception as e:
                messagebox.showerror("Eject Error", f"Unable to safely eject drive:\n{e}", parent=dialog)

        btn_eject = ttk.Button(btn_frame, text="Safely Eject Drive", command=run_eject)
        btn_eject.pack(side="left", padx=5)

        btn_close = ttk.Button(btn_frame, text="Close Report", command=dialog.destroy)
        btn_close.pack(side="right", padx=5)
