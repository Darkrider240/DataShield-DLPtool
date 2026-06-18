import argparse
import os
import sys
import time
from pathlib import Path

# Add project root to path to ensure modules load in all environments
sys.path.insert(0, str(Path(__file__).resolve().parent))

# Import core scanning and parsing components
import scanner
import behaviour
import classifier
import ai_explain
import quarantine
import alerts
import reporter
import watcher
import audit
from audit import AuditLogger
from policy import PolicyManager

def run_cli_scan(target_dir: str, output_dir: str, enable_quarantine: bool):
    """
    Executes a headless, recursive DLP assessment scan on target_dir
    and generates reports in output_dir.
    """
    target_path = Path(target_dir).resolve()
    output_path = Path(output_dir).resolve()
    
    if not target_path.exists():
        print(f"Error: Target path '{target_dir}' does not exist.", file=sys.stderr)
        sys.exit(1)
        
    os.makedirs(output_path, exist_ok=True)
    audit_path = output_path / "datashield_audit.log"
    report_path = output_path / "report.html"
    csv_path = output_path / "report.csv"
    
    # 1. Initialize tamper-evident audit logger
    audit_logger = AuditLogger(str(audit_path))
    
    # 2. Load rule policies
    policy_manager = PolicyManager()
    
    # 3. Discover target files (excluding quarantine folder and audit logs)
    files_to_scan = []
    for root, dirs, files in os.walk(str(target_path)):
        if "quarantine" in Path(root).parts:
            continue
        for f in files:
            filepath = os.path.join(root, f)
            path_obj = Path(filepath)
            if path_obj.name.endswith(".quarantine_info") or path_obj.name == "datashield_audit.log":
                continue
            files_to_scan.append(filepath)
            
    print(f"[*] Target Directory: {target_path}")
    print(f"[*] Discovering files... Found {len(files_to_scan)} files to assess.")
    print(f"[*] Initializing audit ledger ledger at: {audit_path}")
    
    audit_logger.log("SCAN_STARTED", {"target_directory": str(target_path), "total_files": len(files_to_scan)})
    
    start_time = time.time()
    file_results = []
    high_threat_detected = False
    
    config = {
        "root_path": str(target_path),
        "policy_manager": policy_manager
    }
    
    # 4. Scan files
    for idx, file in enumerate(files_to_scan):
        rel_path = os.path.relpath(file, target_path)
        print(f"[{idx+1}/{len(files_to_scan)}] Scanning: {rel_path} ... ", end="", flush=True)
        
        try:
            # Basic pattern matching
            matches = scanner.scan_file(file, config)
            
            # Proximity calculations
            matches = behaviour.proximity_multiplier(matches)
            
            # Shannon entropy analysis
            entropy_matches = behaviour.detect_high_entropy_strings(file)
            matches.extend(entropy_matches)
            
            # Verify magic byte mismatches
            mismatch = behaviour.detect_file_type_mismatch(file)
            
            # Score and classify
            file_report = classifier.classify_file(matches, file_path=file, file_type_mismatch=mismatch)
            
            # Run Gemini AI explanations if key is set
            api_key = os.environ.get("GEMINI_API_KEY")
            if file_report["risk_level"] != "CLEAN" and api_key:
                if file_report["top_matches"]:
                    print("(Querying Gemini AI) ... ", end="", flush=True)
                    explanation = ai_explain.explain_finding(file_report["top_matches"][0], file, api_key=api_key)
                    file_report["ai_explanation"] = explanation
            
            # Auto-quarantine
            if file_report["risk_level"] == "HIGH" and enable_quarantine:
                q_dir = os.path.join(str(target_path), "quarantine")
                triggered_patterns = [m.pattern_name for m in file_report["top_matches"]]
                
                new_path = quarantine.quarantine_file(file, q_dir, audit_logger, triggered_patterns)
                file_report["file_path"] = new_path
                print(f"[QUARANTINED] ", end="")
                
                alerts.send_desktop_notification(
                    "DLP Quarantine Event",
                    f"Quarantined high-risk file: {os.path.basename(file)}"
                )
            elif file_report["risk_level"] == "HIGH" or file_report["risk_level"] == "MEDIUM":
                high_threat_detected = True
                alerts.send_desktop_notification(
                    "DLP Threat Alert",
                    f"Sensitive data found in: {os.path.basename(file)}"
                )
                
            file_results.append(file_report)
            
            # Log individual file scan to ledger
            audit_logger.log("FILE_SCANNED", {
                "file_path": file,
                "risk_level": file_report["risk_level"],
                "risk_score": file_report["risk_score"],
                "matches_count": file_report["match_count"]
            })
            
            print(f"Severity: {file_report['risk_level']} (Score: {file_report['risk_score']})")
            
        except Exception as e:
            print(f"FAILED: {e}")
            
    scan_duration = time.time() - start_time
    print(f"[*] Analysis complete. Scan duration: {scan_duration:.2f} seconds.")
    
    # 5. Export Reports
    last_hash = audit_logger._get_last_hash()
    
    print(f"[*] Generating visual HTML dashboard at: {report_path}")
    reporter.generate_html_report(file_results, scan_duration, last_hash, str(report_path))
    
    print(f"[*] Exporting CSV metadata table at: {csv_path}")
    reporter.export_csv_report(file_results, str(csv_path))
    
    # Log report creation
    audit_logger.log("REPORT_GENERATED", {
        "html_report_path": str(report_path),
        "csv_report_path": str(csv_path),
        "integrity_hash": last_hash
    })
    
    # 6. Audit Chain validation
    print("[*] Validating ledger blockchain security... ", end="", flush=True)
    is_valid = audit.verify_chain(str(audit_path))
    if is_valid:
        print("SECURED (Chain intact)")
    else:
        print("WARNING (Tampering or ledger mismatch detected!)")
        
    return file_results, audit_logger


def main():
    parser = argparse.ArgumentParser(description="DataShield v2 — Python DLP Scanner & Classifier")
    parser.add_argument("--cli", action="store_true", help="Launch headlessly in CLI command mode")
    parser.add_argument("--path", default="./demo_vault", help="Target path of the directory to scan")
    parser.add_argument("--output", default="./output", help="Directory where reports and logs are exported")
    parser.add_argument("--watch", action="store_true", help="Monitor directory for modifications in real-time")
    parser.add_argument("--auto-quarantine", action="store_true", help="Quarantine file automatically if risk score is HIGH")
    parser.add_argument("--smtp-proxy", action="store_true", help="Run local SMTP proxy on port 1025 in CLI mode")
    parser.add_argument("--smtp-host", default="localhost", help="Outbound SMTP relay server host")
    parser.add_argument("--smtp-port", type=int, default=1026, help="Outbound SMTP relay server port")
    parser.add_argument("--clipboard", action="store_true", help="Run clipboard DLP watcher in CLI mode")
    parser.add_argument("--usb", action="store_true", help="Run USB mount event watcher in CLI mode")
    
    args = parser.parse_args()
    
    if args.cli:
        # HEADLESS CLI SCAN
        print("=====================================================================")
        print("            DataShield v2 — Data Loss Prevention Engine            ")
        print("=====================================================================")
        
        print("            DataShield v2 — Data Loss Prevention Engine            ")
        print("=====================================================================")
        
        file_results, audit_logger = run_cli_scan(args.path, args.output, args.auto_quarantine)
        
        comms_active = args.smtp_proxy or args.clipboard or args.usb
        proxy_obj = None
        clip_obj = None
        usb_obj = None
        
        def cli_comms_callback(channel, action, detail, decision=None, **kwargs):
            print(f"[{time.strftime('%H:%M:%S')}] [{channel}] {action} — {detail}")

        # Start SMTP Proxy
        if args.smtp_proxy:
            from comms.smtp_proxy import DataShieldSMTPProxy
            from policy import PolicyManager
            state = {
                "audit_logger": audit_logger,
                "policy_manager": PolicyManager(),
                "smtp_config": {
                    "host": args.smtp_host,
                    "port": args.smtp_port
                },
                "enable_ai": True,
                "enable_justification_bypass": True,
                "root_window": None
            }
            proxy_obj = DataShieldSMTPProxy(state, host="127.0.0.1", port=1025, on_event_callback=cli_comms_callback)
            proxy_obj.start()
            print("[*] Local SMTP intercept proxy listening on localhost:1025.")

        # Start Clipboard Monitor
        if args.clipboard:
            from comms.clipboard_monitor import ClipboardMonitor
            from policy import PolicyManager
            state = {
                "audit_logger": audit_logger,
                "policy_manager": PolicyManager(),
                "root_window": None
            }
            clip_obj = ClipboardMonitor(state, on_finding_callback=cli_comms_callback)
            clip_obj.start()
            print("[*] Clipboard monitor active (polling every 300ms).")

        # Start USB Watcher
        if args.usb:
            from comms.usb_watcher import USBWatcher
            from policy import PolicyManager
            state = {
                "audit_logger": audit_logger,
                "policy_manager": PolicyManager(),
                "root_window": None
            }
            usb_obj = USBWatcher(state, on_report_callback=None, on_event_callback=cli_comms_callback)
            usb_obj.start()
            print("[*] USB mount watcher active.")

        # Incremental folder watcher
        dir_watcher = None
        if args.watch:
            target_path = Path(args.path).resolve()
            policy_manager = PolicyManager()
            config = {
                "root_path": str(target_path),
                "policy_manager": policy_manager
            }
            
            print(f"\n[*] Active Monitor Initiated. Watching '{target_path}'...")
            
            def incremental_cli_callback(filepath):
                print(f"\n[Watchdog Alert] Modified file registered: {os.path.basename(filepath)}")
                try:
                    matches = scanner.scan_file(filepath, config)
                    matches = behaviour.proximity_multiplier(matches)
                    entropy_matches = behaviour.detect_high_entropy_strings(filepath)
                    matches.extend(entropy_matches)
                    mismatch = behaviour.detect_file_type_mismatch(filepath)
                    
                    file_report = classifier.classify_file(matches, file_path=filepath, file_type_mismatch=mismatch)
                    
                    # AI
                    api_key = os.environ.get("GEMINI_API_KEY")
                    if file_report["risk_level"] != "CLEAN" and api_key:
                        if file_report["top_matches"]:
                            file_report["ai_explanation"] = ai_explain.explain_finding(file_report["top_matches"][0], filepath, api_key=api_key)
                    
                    # Quarantine
                    if file_report["risk_level"] == "HIGH" and args.auto_quarantine:
                        q_dir = os.path.join(str(target_path), "quarantine")
                        triggered_patterns = [m.pattern_name for m in file_report["top_matches"]]
                        new_path = quarantine.quarantine_file(filepath, q_dir, audit_logger, triggered_patterns)
                        file_report["file_path"] = new_path
                        print(f"  [QUARANTINED -> {os.path.basename(new_path)}]")
                        
                    audit_logger.log("FILE_SCANNED", {
                        "file_path": filepath,
                        "risk_level": file_report["risk_level"],
                        "risk_score": file_report["risk_score"],
                        "matches_count": file_report["match_count"]
                    })
                    print(f"  Result: {file_report['risk_level']} (Score: {file_report['risk_score']})")
                except Exception as e:
                    print(f"  Error conducting scan: {e}")
            
            dir_watcher = watcher.DLPWatcher(str(target_path), incremental_cli_callback)
            dir_watcher.start()
            
        if comms_active or args.watch:
            print("[*] Monitoring services active. Press Ctrl+C to terminate.")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[*] Terminating background monitors...")
                if dir_watcher:
                    dir_watcher.stop()
                if proxy_obj:
                    proxy_obj.stop()
                if clip_obj:
                    clip_obj.stop()
                if usb_obj:
                    usb_obj.stop()
                print("[*] Exit.")
    else:
        # TKINTER DESKTOP GUI
        try:
            from gui.main_window import MainWindow
            print("[*] Initializing Tkinter GUI...")
            app = MainWindow()
            app.mainloop()
        except ImportError as e:
            print(f"Error: Failed to launch Tkinter GUI: {e}", file=sys.stderr)
            print("Please run headlessly using command arguments: python main.py --cli", file=sys.stderr)
            sys.exit(1)

if __name__ == "__main__":
    main()
