import time
from dataclasses import dataclass
from datetime import datetime

# Core DLP modules
import ai_explain

RISK_POLICY = {
    "HIGH":   "BLOCK",
    "MEDIUM": "WARN",
    "LOW":    "ALLOW",
    "CLEAN":  "ALLOW",
}

@dataclass
class CommsDecision:
    action: str           # "BLOCK" | "WARN" | "ALLOW"
    channel: str          # "EMAIL" | "CLIPBOARD" | "USB"
    risk_level: str
    risk_score: float
    top_pattern: str
    regulation_tags: list[str]
    ai_explanation: str
    timestamp: str
    justification: str = ""


def decide(classification: dict, channel: str, audit_logger, explain: bool = True, api_key: str = None) -> CommsDecision:
    """
    Takes a classifier.classify_file() result dict and computes the policy action.
    Optionally queries Gemini AI for compliance explanations.
    """
    risk_level = classification.get("risk_level", "CLEAN")
    risk_score = classification.get("risk_score", 0.0)
    top_matches = classification.get("top_matches", [])
    regulation_hits = classification.get("regulation_hits", [])
    
    # Map risk level to policy action
    action = RISK_POLICY.get(risk_level, "ALLOW")
    
    top_pattern = "None"
    ai_explanation = "No sensitive patterns identified."
    
    if top_matches:
        top_match = top_matches[0]
        top_pattern = top_match.pattern_name
        
        if explain:
            # Query Gemini API using key stored in environment or settings
            ai_explanation = ai_explain.explain_finding(top_match, classification.get("file_path", "Outbound"), api_key=api_key)
    
    timestamp = datetime.utcnow().isoformat() + "Z"
    
    decision = CommsDecision(
        action=action,
        channel=channel,
        risk_level=risk_level,
        risk_score=risk_score,
        top_pattern=top_pattern,
        regulation_tags=regulation_hits,
        ai_explanation=ai_explanation,
        timestamp=timestamp
    )
    
    # Log generic action initially (callers will write specific block/warn details)
    if audit_logger:
        audit_logger.log("COMMS_DECISION", {
            "channel": channel,
            "action": action,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "top_pattern": top_pattern,
            "regulations": regulation_hits
        })
        
    return decision


def format_warning_message(decision: CommsDecision) -> str:
    """Generates a structured, user-friendly plaintext warning box."""
    # Action taken formatting
    action_taken_str = "Message blocked" if decision.action == "BLOCK" else "User warning issued"
    if decision.action == "ALLOW":
        action_taken_str = "Allowed"
        
    regs_str = " · ".join(decision.regulation_tags) if decision.regulation_tags else "None"
    
    # Split explanation into paragraphs to extract specific parts
    paragraphs = [p.strip() for p in decision.ai_explanation.split("\n\n") if p.strip()]
    why_risk = paragraphs[0] if len(paragraphs) > 0 else decision.ai_explanation
    remediation = paragraphs[2] if len(paragraphs) > 2 else (paragraphs[1] if len(paragraphs) > 1 else "Limit exposure and encrypt files.")

    msg = (
        f"⚠ DataShield Alert — {decision.channel} DLP\n"
        f"─────────────────────────────────\n"
        f"Risk level   : {decision.risk_level}\n"
        f"Pattern found: {decision.top_pattern}\n"
        f"Regulation   : {regs_str}\n"
        f"Action taken : {action_taken_str}\n\n"
        f"Why this is a risk:\n"
        f"{why_risk}\n\n"
        f"What you should do:\n"
        f"{remediation}"
    )
    return msg
