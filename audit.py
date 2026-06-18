import os
import json
import hashlib
from datetime import datetime

class AuditLogger:
    """
    Implements a tamper-evident, append-only JSON audit ledger.
    Each block is chained to the SHA-256 hash of the previous block.
    """
    def __init__(self, log_path: str):
        self.log_path = os.path.abspath(log_path)
        
    def _get_last_hash(self) -> str:
        """Retrieves the hash of the last entry in the ledger."""
        if not os.path.exists(self.log_path) or os.path.getsize(self.log_path) == 0:
            return "GENESIS"
        try:
            with open(self.log_path, "r", encoding="utf-8") as f:
                lines = f.read().splitlines()
                if not lines:
                    return "GENESIS"
                # Parse the last line as JSON to read its hash
                last_line = lines[-1].strip()
                if not last_line:
                    return "GENESIS"
                entry = json.loads(last_line)
                return entry.get("entry_hash", "GENESIS")
        except Exception:
            return "GENESIS"

    def log(self, action: str, detail: dict) -> str:
        """Appends a new action block to the ledger and returns its entry hash."""
        timestamp = datetime.utcnow().isoformat() + "Z"
        prev_hash = self._get_last_hash()
        
        # Build entry without hash
        entry = {
            "timestamp": timestamp,
            "action": action,
            "detail": detail,
            "previous_hash": prev_hash
        }
        
        # Serialize with sorted keys for consistent hashing
        serialized = json.dumps(entry, sort_keys=True)
        # Chain hash computation: sha256(prev_hash + serialized_entry)
        hash_payload = (prev_hash + serialized).encode("utf-8")
        entry_hash = hashlib.sha256(hash_payload).hexdigest()
        
        entry["entry_hash"] = entry_hash
        
        # Make sure parent dirs exist
        os.makedirs(os.path.dirname(self.log_path), exist_ok=True)
        
        # Write to file
        with open(self.log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
            
        return entry_hash

def verify_chain(log_path: str) -> bool:
    """
    Validates the entire audit log blockchain.
    Re-computes all block hashes sequentially and checks for consistency.
    """
    if not os.path.exists(log_path) or os.path.getsize(log_path) == 0:
        return True  # Empty log is technically untampered
        
    try:
        expected_prev_hash = "GENESIS"
        with open(log_path, "r", encoding="utf-8") as f:
            for idx, line in enumerate(f):
                clean_line = line.strip()
                if not clean_line:
                    continue
                    
                entry = json.loads(clean_line)
                
                # Check previous_hash match
                if entry.get("previous_hash") != expected_prev_hash:
                    print(f"Chain broken at line {idx+1}: expected prev hash {expected_prev_hash}, got {entry.get('previous_hash')}")
                    return False
                    
                # Store original hash
                recorded_hash = entry.get("entry_hash")
                
                # Reconstruct entry structure without its hash
                recreated_entry = {
                    "timestamp": entry.get("timestamp"),
                    "action": entry.get("action"),
                    "detail": entry.get("detail"),
                    "previous_hash": entry.get("previous_hash")
                }
                
                # Serialize and hash to verify
                serialized = json.dumps(recreated_entry, sort_keys=True)
                hash_payload = (expected_prev_hash + serialized).encode("utf-8")
                computed_hash = hashlib.sha256(hash_payload).hexdigest()
                
                if recorded_hash != computed_hash:
                    print(f"Hash mismatch at line {idx+1}: recorded {recorded_hash}, computed {computed_hash}")
                    return False
                    
                expected_prev_hash = recorded_hash
                
        return True
    except Exception as e:
        print(f"Error during audit chain verification: {e}")
        return False
