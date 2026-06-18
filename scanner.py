import re
import os
import sys
import pdfplumber
import docx
from dataclasses import dataclass
from pathlib import Path

@dataclass
class Match:
    file_path: str
    line_number: int
    matched_value: str          # Redacted to first 4 + asterisks for display
    pattern_name: str
    category: str               # PII | FINANCIAL | SECRETS | HEALTH
    base_weight: float
    regulation_tags: list[str]  # e.g. ["GDPR Art.9", "HIPAA §164.312"]
    context_lines: list[str]    # ±2 lines around the match
    proximity_triggered: bool = False


# Default Regex Rule Definitions (compiled constants)
PII_PATTERNS = {
    "AADHAAR": (re.compile(r'(?<!\d)(?<!\d\s)(?<!\d-)\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b(?![-\s]?\d)'), 3.0, ["DPDP Act 2023", "GDPR Art.6"]),
    "PAN": (re.compile(r'\b[A-Z]{5}[0-9]{4}[A-Z]\b'), 3.0, ["Income Tax Act India", "GDPR Art.6"]),
    "SSN": (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), 3.0, ["HIPAA §164.514", "GDPR Art.6"]),
    "PASSPORT": (re.compile(r'\b[A-PR-WY][1-9]\d{7}\b'), 3.5, ["GDPR Art.9", "DPDP Act 2023"]),
    "VOTER_ID": (re.compile(r'\b[A-Z]{3}[0-9]{7}\b'), 2.5, ["DPDP Act 2023"]),
    "EMAIL": (re.compile(r'\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b'), 1.0, ["GDPR Art.6"]),
    "PHONE_IN": (re.compile(r'\b(?:\+91|0)?[6-9]\d{9}\b'), 1.5, ["DPDP Act 2023"]),
    "PHONE_US": (re.compile(r'\b(?:\+1\s?)?\(?\d{3}\)?[\s.\-]\d{3}[\s.\-]\d{4}\b'), 1.5, ["HIPAA §164.514"])
}

FINANCIAL_PATTERNS = {
    "CREDIT_CARD": (re.compile(r'\b(?:4(?:[0-9][-\s]?){12}(?:(?:[0-9][-\s]?){3})?|5[1-5](?:[0-9][-\s]?){14}|3[47](?:[0-9][-\s]?){13}|3(?:0[0-5]|[68][0-9])(?:[0-9][-\s]?){11}|6(?:011|5[0-9]{2})(?:[0-9][-\s]?){12})\b'), 4.0, ["PCI-DSS Req.3.4"]),
    "UPI": (re.compile(r'\b[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}\b'), 2.0, ["RBI Guidelines India"]),
    "IFSC": (re.compile(r'\b[A-Z]{4}0[A-Z0-9]{6}\b'), 2.0, ["RBI Guidelines India"]),
    "IBAN": (re.compile(r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b'), 3.0, ["PCI-DSS Req.3.4", "GDPR Art.6"])
}

SECRETS_PATTERNS = {
    "API_KEY_GENERIC": (re.compile(r'(?i)(?:api[_\-]?key|api[_\-]?secret|access[_\-]?key)\s*[=:]\s*["\']?([A-Za-z0-9_\-]{16,64})'), 5.0, ["OWASP A02:2021"]),
    "AWS_KEY": (re.compile(r'\bAKIA[0-9A-Z]{16}\b'), 5.0, ["OWASP A02:2021", "CIS AWS Benchmark"]),
    "BEARER_TOKEN": (re.compile(r'(?i)bearer\s+([A-Za-z0-9\-_\.]{20,})'), 4.5, ["OWASP A02:2021"]),
    "PRIVATE_KEY": (re.compile(r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'), 5.0, ["OWASP A02:2021"]),
    "PASSWORD_FIELD": (re.compile(r'(?i)(?:password|passwd|pwd)\s*[=:]\s*["\']?(\S{6,})'), 4.0, ["OWASP A02:2021"])
}

HEALTH_PATTERNS = {
    "ICD10_CODE": (re.compile(r'\b[A-TV-Z][0-9][0-9A-Z]\.?[0-9A-Z]{0,4}\b'), 4.0, ["HIPAA §164.312", "GDPR Art.9"]),
    "PHI_KEYWORDS": (re.compile(r'(?i)\b(?:diagnosis|prescription|medical\s+record|blood\s+type|HIV|diabetes|patient\s+id|insurance\s+number)\b'), 3.5, ["HIPAA §164.312", "GDPR Art.9"]),
    "BIOMETRIC_KEYWORDS": (re.compile(r'(?i)\b(?:fingerprint|retina\s+scan|facial\s+recognition|iris\s+scan|biometric)\b'), 4.0, ["GDPR Art.9(1)(a)"])
}

def luhn_checksum_is_valid(card_number: str) -> bool:
    """Validates credit card checksum using Luhn algorithm."""
    digits = [int(char) for char in card_number if char.isdigit()]
    if not digits:
        return False
    digits.reverse()
    total = 0
    for idx, d in enumerate(digits):
        if idx % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0

def redact_value(val: str) -> str:
    """Redacts values by displaying the first 4 characters and masking the rest."""
    # Strip quotes or spaces
    cleaned = val.strip().strip('"').strip("'")
    if len(cleaned) <= 4:
        return "*" * len(cleaned)
    return cleaned[:4] + "*" * (len(cleaned) - 4)

def scan_file(file_path: str, config: dict) -> list[Match]:
    """
    Scans a local file for sensitive data patterns based on configuration.
    
    Guarantees:
      - Path resolution validation to prevent directory traversal
      - Safe error handling for Unicode, permission, and missing files
      - Proper regex match execution and allowlist filtering (via policy manager)
    """
    matches = []
    
    # 1. Sandboxing Check
    try:
        resolved_path = Path(file_path).resolve()
        root_path = Path(config.get("root_path", ".")).resolve()
        if not resolved_path.is_relative_to(root_path):
            print(f"Warning: Attempted traversal blocked for path {file_path}", file=sys.stderr)
            return []
    except Exception as e:
        print(f"Warning: Failed to resolve path {file_path}: {e}", file=sys.stderr)
        return []

    # Silently skip symbolic links pointing outside the sandbox or directory folders
    if resolved_path.is_symlink() and not resolved_path.resolve().is_relative_to(root_path):
        return []
    if resolved_path.is_dir():
        return []

    # 2. Determine File Type & Extract Lines
    suffix = resolved_path.suffix.lower()
    text_extensions = {
        ".txt", ".csv", ".json", ".log", ".py", ".js", ".env", ".config", ".ini",
        ".yaml", ".yml", ".xml"
    }

    lines = []
    try:
        if suffix in text_extensions or resolved_path.name.startswith(".env"):
            with open(resolved_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.read().splitlines()
        elif suffix == ".pdf":
            with pdfplumber.open(resolved_path) as pdf:
                for page in pdf.pages:
                    text = page.extract_text()
                    if text:
                        lines.extend(text.splitlines())
        elif suffix == ".docx":
            doc = docx.Document(resolved_path)
            lines = [p.text for p in doc.paragraphs]
        else:
            # Skip unsupported/binary formats silently
            return []
    except UnicodeDecodeError as e:
        print(f"Warning: UnicodeDecodeError reading {file_path}: {e}", file=sys.stderr)
        return []
    except PermissionError as e:
        print(f"Warning: PermissionError accessing {file_path}: {e}", file=sys.stderr)
        return []
    except FileNotFoundError as e:
        print(f"Warning: FileNotFoundError: {file_path}: {e}", file=sys.stderr)
        return []
    except Exception as e:
        print(f"Warning: Failed to read file {file_path}: {e}", file=sys.stderr)
        return []

    # 3. Retrieve Policies/Rules
    policy_manager = config.get("policy_manager", None)
    
    # Compile rule lists
    rules_to_run = []
    if policy_manager and policy_manager.rules:
        # Load rules from custom manager
        for r in policy_manager.rules:
            try:
                name = r["name"]
                pat_str = r["pattern"]
                category = r["category"]
                weight = float(r["base_weight"])
                tags = r["regulation_tags"]
                
                # Check category to define specific handlers (like Credit Card Luhn verification)
                rules_to_run.append((name, re.compile(pat_str), category, weight, tags))
            except Exception as e:
                print(f"Warning: Invalid rule schema {r}: {e}", file=sys.stderr)
    else:
        # Fall back to default hardcoded rule mappings
        for name, (compiled_re, weight, tags) in PII_PATTERNS.items():
            rules_to_run.append((name, compiled_re, "PII", weight, tags))
        for name, (compiled_re, weight, tags) in FINANCIAL_PATTERNS.items():
            rules_to_run.append((name, compiled_re, "FINANCIAL", weight, tags))
        for name, (compiled_re, weight, tags) in SECRETS_PATTERNS.items():
            rules_to_run.append((name, compiled_re, "SECRETS", weight, tags))
        for name, (compiled_re, weight, tags) in HEALTH_PATTERNS.items():
            rules_to_run.append((name, compiled_re, "HEALTH", weight, tags))

    # 4. Perform Regex Matching
    for line_idx, line_content in enumerate(lines):
        line_num = line_idx + 1
        
        for name, pattern_re, category, weight, tags in rules_to_run:
            try:
                for match_obj in pattern_re.finditer(line_content):
                    # For secrets patterns that contain capture groups, extract the secret itself
                    matched_str = match_obj.group(1) if pattern_re.groups > 0 and match_obj.group(1) else match_obj.group(0)
                    
                    if not matched_str:
                        continue
                        
                    # Custom rule verification
                    if name == "CREDIT_CARD":
                        # Validate checksum
                        if not luhn_checksum_is_valid(matched_str):
                            continue
                    
                    # Check if the matched value is in the policy manager's allowlist
                    if policy_manager and (policy_manager.is_suppressed(matched_str) or policy_manager.is_suppressed(redact_value(matched_str))):
                        continue

                    # Extract context (±2 lines)
                    start_context = max(0, line_idx - 2)
                    end_context = min(len(lines), line_idx + 3)
                    context_lines = lines[start_context:end_context]

                    matches.append(Match(
                        file_path=str(resolved_path),
                        line_number=line_num,
                        matched_value=redact_value(matched_str),
                        pattern_name=name,
                        category=category,
                        base_weight=weight,
                        regulation_tags=tags,
                        context_lines=context_lines
                    ))
            except re.error as e:
                print(f"Warning: Regex execution error for {name} on file {file_path}: {e}", file=sys.stderr)
            except Exception as e:
                print(f"Warning: Unexpected match execution error on file {file_path}: {e}", file=sys.stderr)

    return matches
