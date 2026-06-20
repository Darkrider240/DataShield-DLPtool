import re
import math
import sys
from pathlib import Path
from collections import Counter, defaultdict
from scanner import Match, redact_value

def proximity_multiplier(matches: list[Match], window: int = 5) -> list[Match]:
    """
    Groups matches by file_path and checks if PII + PII or PII + FINANCIAL matches
    fall within ±window lines of each other. If detected, doubles the weight and
    sets proximity_triggered = True.
    """
    matches_by_file = defaultdict(list)
    for m in matches:
        matches_by_file[m.file_path].append(m)

    for file_path, file_matches in matches_by_file.items():
        # Sort matches by line number to scan sequentially
        file_matches.sort(key=lambda x: x.line_number)
        n = len(file_matches)
        triggered_indices = set()
        
        for i in range(n):
            for j in range(i + 1, n):
                m1 = file_matches[i]
                m2 = file_matches[j]
                
                # Check proximity window
                if abs(m1.line_number - m2.line_number) <= window:
                    c1, c2 = m1.category, m2.category
                    is_pii_pii = (c1 == "PII" and c2 == "PII")
                    is_pii_fin = (c1 == "PII" and c2 == "FINANCIAL") or (c1 == "FINANCIAL" and c2 == "PII")
                    
                    if is_pii_pii or is_pii_fin:
                        triggered_indices.add(i)
                        triggered_indices.add(j)
                        
        # Apply the doubling multiplier to all triggered matches
        for idx in triggered_indices:
            m = file_matches[idx]
            if not m.proximity_triggered:
                m.base_weight *= 2.0
                m.proximity_triggered = True

    return matches

def entropy_score(text: str) -> float:
    """Calculates Shannon entropy for a given string."""
    if not text:
        return 0.0
    counts = Counter(text)
    total = len(text)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return entropy

def detect_high_entropy_strings(file_path: str, threshold: float = 4.5) -> list[Match]:
    """
    Scans a text-based file line by line, extracts alphanumeric/base64 tokens >= 20 chars,
    and returns matches if their Shannon entropy exceeds the specified threshold.
    """
    matches = []
    resolved_path = Path(file_path).resolve()
    
    # Read file lines safely
    try:
        if resolved_path.suffix.lower() in {
            ".pdf", ".docx"
        } or resolved_path.is_dir():
            # Skip non-plain-text files or directories for raw entropy parsing
            return []
            
        with open(resolved_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    except Exception as e:
        print(f"Warning: Failed to read file {file_path} for entropy analysis: {e}", file=sys.stderr)
        return []

    for line_idx, line_content in enumerate(lines):
        line_num = line_idx + 1
        
        # Tokenize by whitespace and common non-alphanumeric characters (preserving base64 chars)
        tokens = re.split(r'[\s\'",;:\(\)\[\]\{\}\<\>|\\&!]', line_content)
        
        for token in tokens:
            # Clean token and filter by length
            token_clean = token.strip()
            if len(token_clean) >= 20:
                score = entropy_score(token_clean)
                if score >= threshold:
                    # Capture context
                    start_context = max(0, line_idx - 2)
                    end_context = min(len(lines), line_idx + 3)
                    context_lines = lines[start_context:end_context]

                    matches.append(Match(
                        file_path=str(resolved_path),
                        line_number=line_num,
                        matched_value=redact_value(token_clean),
                        pattern_name="HIGH_ENTROPY_STRING",
                        category="SECRETS",
                        base_weight=3.5,
                        regulation_tags=["OWASP A02:2021"],
                        context_lines=context_lines
                    ))
                    
    return matches

def detect_file_type_mismatch(file_path: str) -> bool:
    """
    Reads the first 8 bytes of the file and compares magic bytes against 
    known file type signatures to detect extension manipulation.
    """
    resolved_path = Path(file_path).resolve()
    if resolved_path.is_dir():
        return False
        
    try:
        with open(resolved_path, "rb") as f:
            header = f.read(8)
    except Exception:
        return False  # If unreadable, skip type validation

    # Define common binary file signatures
    signatures = {
        b'%PDF': "pdf",
        b'PK\x03\x04': "zip",  # Zip container, also covers docx/xlsx/pptx
        b'\x89PNG': "png",
        b'\xff\xd8\xff': "jpeg",
        b'\x7fELF': "elf"
    }

    detected_type = None
    for sig, label in signatures.items():
        if header.startswith(sig):
            detected_type = label
            break

    if detected_type is not None:
        ext = resolved_path.suffix.lower().lstrip(".")
        
        # Verify mismatches
        if detected_type == "pdf" and ext != "pdf":
            return True
        elif detected_type == "zip" and ext not in {"zip", "docx", "xlsx", "pptx"}:
            return True
        elif detected_type == "png" and ext != "png":
            return True
        elif detected_type == "jpeg" and ext not in {"jpg", "jpeg"}:
            return True
        elif detected_type == "elf" and ext in {
            "txt", "csv", "json", "log", "py", "js", "env", "config", "ini", "yaml", "yml", "xml"
        }:
            # Executable disguised as configuration/text
            return True

    return False
