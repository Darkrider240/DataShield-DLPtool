from scanner import Match

def classify_file(matches: list[Match], file_path: str = "", file_type_mismatch: bool = False) -> dict:
    """
    Classifies a file's threat profile based on regex match weights and metadata.
    
    Returns a dictionary structure:
      {
        "file_path": str,
        "risk_level": "HIGH" | "MEDIUM" | "LOW" | "CLEAN",
        "risk_label": "Restricted" | "Confidential" | "Internal" | "Public",
        "risk_score": float,
        "match_count": int,
        "top_matches": list[Match],
        "regulation_hits": list[str],
        "file_type_mismatch": bool
      }
    """
    # If no file path is provided but matches exist, infer from the first match
    if not file_path and matches:
        file_path = matches[0].file_path

    # Calculate total score from base weights (assumes proximity multipliers already applied)
    risk_score = sum(m.base_weight for m in matches)
    match_count = len(matches)
    
    # Sort matches by base_weight descending
    top_matches = sorted(matches, key=lambda x: x.base_weight, reverse=True)[:5]
    
    # Deduplicate regulation tags
    regulation_hits = []
    seen_regs = set()
    for m in matches:
        for tag in m.regulation_tags:
            if tag not in seen_regs:
                seen_regs.add(tag)
                regulation_hits.append(tag)

    # Classify based on score boundaries
    if risk_score >= 10.0:
        risk_level = "HIGH"
        risk_label = "Restricted"
    elif risk_score >= 4.0:
        risk_level = "MEDIUM"
        risk_label = "Confidential"
    elif risk_score >= 1.0:
        risk_level = "LOW"
        risk_label = "Internal"
    else:
        risk_level = "CLEAN"
        risk_label = "Public"

    return {
        "file_path": file_path,
        "risk_level": risk_level,
        "risk_label": risk_label,
        "risk_score": round(risk_score, 2),
        "match_count": match_count,
        "top_matches": top_matches,
        "regulation_hits": regulation_hits,
        "file_type_mismatch": file_type_mismatch
      }
