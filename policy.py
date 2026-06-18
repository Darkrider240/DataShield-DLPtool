import yaml
import re
import os
from pathlib import Path

class PolicyManager:
    def __init__(self, rules_path=None, allowlist_path=None):
        self.rules = []
        self.allowlist_patterns = []
        
        # Resolve path directories
        base_dir = Path(__file__).parent
        if not rules_path:
            rules_path = base_dir / "rules" / "default_rules.yaml"
        if not allowlist_path:
            allowlist_path = base_dir / "rules" / "allowlist.yaml"
            
        self.load_rules(rules_path)
        self.load_allowlist(allowlist_path)

    def load_rules(self, path):
        """Loads scanning rules from a YAML configuration file."""
        if not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if data and "rules" in data:
                    # Overwrite or append rules
                    self.rules = data["rules"]
        except Exception as e:
            print(f"Warning: Failed to load rules from {path}: {e}")

    def load_allowlist(self, path):
        """Loads allowlist values or patterns from a YAML configuration file."""
        self.allowlist_patterns = []
        if not os.path.exists(path):
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
                if data and "allowlist" in data:
                    raw_allowlist = data["allowlist"]
                    if isinstance(raw_allowlist, list):
                        for item in raw_allowlist:
                            if not item:
                                continue
                            try:
                                # Compile as regex
                                self.allowlist_patterns.append(re.compile(f"^{item}$"))
                            except re.error:
                                # Fallback to literal exact match
                                self.allowlist_patterns.append(re.compile(f"^{re.escape(str(item))}$"))
        except Exception as e:
            print(f"Warning: Failed to load allowlist from {path}: {e}")

    def is_suppressed(self, value: str) -> bool:
        """Checks if a value (unredacted or redacted) matches any allowlist entry."""
        for pattern in self.allowlist_patterns:
            if pattern.search(value):
                return True
        return False

def regulation_summary(results: list[dict]) -> dict:
    """Returns a dict mapping regulation name to the count of files it was triggered in."""
    summary = {}
    for file_result in results:
        # Avoid double counting if the same regulation hit occurs multiple times in one file
        unique_hits = set(file_result.get("regulation_hits", []))
        for tag in unique_hits:
            summary[tag] = summary.get(tag, 0) + 1
    return summary
