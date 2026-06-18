import os
import pandas as pd
from datetime import datetime
from jinja2 import Environment, FileSystemLoader
from pathlib import Path

def generate_html_report(file_results: list[dict], scan_duration: float, audit_hash: str, output_path: str, comms_events: list = None):
    """
    Renders a standalone, responsive HTML report containing metrics summary,
    a CSS-only bar graph, expandable findings, AI analysis, and remediation actions.
    """
    total_files = len(file_results)
    high_count = sum(1 for r in file_results if r["risk_level"] == "HIGH")
    medium_count = sum(1 for r in file_results if r["risk_level"] == "MEDIUM")
    low_count = sum(1 for r in file_results if r["risk_level"] == "LOW")
    clean_count = sum(1 for r in file_results if r["risk_level"] == "CLEAN")
    
    # Calculate the frequency of regulatory violations across all scanned files
    regulation_counts = {}
    for r in file_results:
        unique_regs = set(r.get("regulation_hits", []))
        for reg in unique_regs:
            regulation_counts[reg] = regulation_counts.get(reg, 0) + 1
            
    # If comms events are present, merge their regulations into counts too
    if comms_events:
        for event in comms_events:
            for reg in event.get("regulation_tags", []):
                regulation_counts[reg] = regulation_counts.get(reg, 0) + 1

    # Resolve project and templates directories
    base_dir = Path(__file__).parent
    templates_dir = base_dir / "templates"
    
    # Setup Jinja2 and load template
    env = Environment(loader=FileSystemLoader(str(templates_dir)))
    template = env.get_template("report.html")
    
    scan_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    html_content = template.render(
        file_results=file_results,
        scan_timestamp=scan_timestamp,
        scan_duration_seconds=scan_duration,
        total_files=total_files,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        clean_count=clean_count,
        regulation_counts=regulation_counts,
        audit_hash=audit_hash,
        comms_events=comms_events
    )
    
    # Ensure destination directory exists and write HTML report
    out_abspath = os.path.abspath(output_path)
    os.makedirs(os.path.dirname(out_abspath), exist_ok=True)
    
    with open(out_abspath, "w", encoding="utf-8") as f:
        f.write(html_content)

def export_csv_report(file_results: list[dict], output_path: str):
    """
    Exports the file-level DLP assessment metadata as a CSV file using pandas.
    """
    rows = []
    scan_timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    for r in file_results:
        # Extract unique pattern names from top matches
        pattern_names = list(set(m.pattern_name for m in r.get("top_matches", [])))
        patterns_str = ",".join(pattern_names)
        regs_str = ",".join(r.get("regulation_hits", []))
        
        row = {
            "file_path": r.get("file_path"),
            "risk_level": r.get("risk_level"),
            "risk_score": r.get("risk_score"),
            "match_count": r.get("match_count"),
            "pattern_names": patterns_str,
            "regulation_hits": regs_str,
            "ai_explanation": r.get("ai_explanation", ""),
            "scan_timestamp": scan_timestamp
        }
        rows.append(row)
        
    df = pd.DataFrame(rows)
    
    out_abspath = os.path.abspath(output_path)
    os.makedirs(os.path.dirname(out_abspath), exist_ok=True)
    
    df.to_csv(out_abspath, index=False)
