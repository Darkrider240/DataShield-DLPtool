import os
import sys
from scanner import Match

# In-memory cache to prevent duplicate network calls for identical finding patterns
_explanation_cache = {}

def explain_finding(match: Match, file_path: str, api_key: str = None) -> str:
    """
    Queries Gemini API to generate plain-English risk explanations and remediation.
    Caches responses by (pattern_name, category).
    Falls back to a static three-paragraph template if API key is missing or calls fail.
    Uses google.genai (new SDK) instead of deprecated google.generativeai.
    """
    pattern_name = match.pattern_name
    category     = match.category
    cache_key    = (pattern_name, category)

    # 1. Check in-memory cache first
    if cache_key in _explanation_cache:
        return _explanation_cache[cache_key]

    effective_api_key = api_key or os.environ.get("GEMINI_API_KEY")

    regs_str = ", ".join(match.regulation_tags) if match.regulation_tags else "General Data Protection Standards"
    filename = os.path.basename(file_path)

    # 2. Static fallback (used when key absent or on network errors)
    fallback_explanation = (
        f"Storing raw information of category '{category}' poses a substantial data privacy risk. "
        f"If exposed, this data could lead to identity theft, financial fraud, or credential abuse.\n\n"
        f"This finding triggers compliance rules tied to {regs_str}. These regulatory frameworks "
        f"require systems to strictly limit access, implement encryption-at-rest, and redact sensitive information.\n\n"
        f"Remediation steps:\n"
        f"1. Immediately restrict access permissions on the file '{filename}'.\n"
        f"2. Redact the matched values or relocate the record to a secure, encrypted vaults database."
    )

    if not effective_api_key:
        return "AI Explanation skipped: Gemini API key not configured."

    # 3. Perform Gemini API call using the new google.genai SDK
    from google import genai                          # new SDK
    from google.genai import types as genai_types
    from google.genai.errors import APIError

    client = genai.Client(api_key=effective_api_key)
    prompt = (
        f"You are a data privacy compliance expert. Explain DLP findings to non-technical "
        f"users in clear, plain English. Be specific, concise, and always cite the exact regulation article.\n\n"
        f"A file named '{filename}' triggered a {match.pattern_name} pattern on line "
        f"{match.line_number}. The matched data category is {match.category}. The applicable regulations "
        f"are: {regs_str}.\n\n"
        f"Answer these three questions in exactly three short paragraphs:\n"
        f"1. Why is this a data privacy risk?\n"
        f"2. Which specific regulation article is violated and what does it require?\n"
        f"3. What are the top two remediation steps the user should take right now?"
    )

    models_to_try = ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-flash", "gemini-1.5-flash-8b"]
    for model_name in models_to_try:
        try:
            response = client.models.generate_content(
                model=model_name,
                contents=prompt,
                config=genai_types.GenerateContentConfig(
                    max_output_tokens=300,
                    temperature=0.2,
                ),
            )
            explanation = response.text.strip() if response.text else fallback_explanation
            _explanation_cache[cache_key] = explanation
            return explanation
        except APIError as e:
            print(f"Warning: Gemini API request failed with {model_name}: {e.message} (code={getattr(e, 'code', 'unknown')})", file=sys.stderr)
            continue
        except Exception as e:
            print(f"Warning: Gemini API request failed with {model_name}: {e}", file=sys.stderr)
            continue

    _explanation_cache[cache_key] = fallback_explanation
    return fallback_explanation
