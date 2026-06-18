import os
import shutil
import json
import sys
from datetime import datetime
from pathlib import Path

def quarantine_file(file_path: str, quarantine_dir: str, audit_logger, triggered_patterns: list[str] = None) -> str:
    """
    Safely relocates a high-risk file into the designated quarantine directory.
    Generates a sidecar metadata JSON file containing the original path, timestamp, and triggered rules.
    Logs the execution to the audit log.
    """
    try:
        src_path = Path(file_path).resolve()
        dest_dir = Path(quarantine_dir).resolve()
        
        # Ensure destination quarantine directory exists
        os.makedirs(dest_dir, exist_ok=True)
        
        dest_file_path = dest_dir / src_path.name
        
        # Avoid file collision by appending a timestamp if a file with the same name exists
        if dest_file_path.exists():
            timestamp_suffix = datetime.now().strftime("%Y%m%d_%H%M%S")
            dest_file_path = dest_dir / f"{src_path.stem}_{timestamp_suffix}{src_path.suffix}"
            
        # Move the source file
        shutil.move(str(src_path), str(dest_file_path))
        
        # Write the sidecar .quarantine_info file
        sidecar_path = dest_file_path.with_suffix(dest_file_path.suffix + ".quarantine_info")
        info = {
            "original_path": str(src_path),
            "quarantine_timestamp": datetime.utcnow().isoformat() + "Z",
            "triggered_patterns": triggered_patterns or []
        }
        
        with open(sidecar_path, "w", encoding="utf-8") as f:
            json.dump(info, f, indent=4)
            
        # Write to audit ledger
        if audit_logger:
            audit_logger.log("FILE_QUARANTINED", {
                "original_path": str(src_path),
                "quarantine_path": str(dest_file_path),
                "triggered_patterns": triggered_patterns or []
            })
            
        return str(dest_file_path)
        
    except Exception as e:
        # Abort quarantine and log error if anything goes wrong
        print(f"Error: Quarantine failed for {file_path}: {e}", file=sys.stderr)
        if audit_logger:
            audit_logger.log("QUARANTINE_FAILED", {
                "file_path": file_path,
                "error": str(e)
            })
        raise e
