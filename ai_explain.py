import os
import sys
import google.generativeai as genai
from scanner import Match

# In-memory cache to prevent duplicate network calls for identical finding patterns
_explanation_cache = {}

def explain_finding(match: Match, file_path: str, api_key: str = None) -> str:
    """
    Queries Gemini API to generate plain-English risk explanations and remediation.
    Caches responses by (pattern_name, category).
    Falls back to a static three-paragraph template if API key is missing or calls fail.
    """
    pattern_name = match.pattern_name
    category = match.category
    cache_key = (pattern_name, category)
    
    # 1. Check in-memory cache first
    if cache_key in _explanation_cache:
        return _explanation_cache[cache_key]

    # Get API key from argument or environment variables
    effective_api_key = api_key or os.environ.get("GEMINI_API_KEY")

    # Regulations string
    regs_str = ", ".join(match.regulation_tags) if match.regulation_tags else "General Data Protection Standards"
    filename = os.path.basename(file_path)

    # 2. Static Fallback Generator (used if key is absent or on network errors)
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

    # 3. Perform Gemini API Call
    try:
        genai.configure(api_key=effective_api_key)
        
        system_instruction = (
            "You are a data privacy compliance expert. You explain DLP findings to non-technical "
            "users in clear, plain English. Be specific, concise, and always cite the exact regulation article."
        )
        
        prompt = (
            f"A file named '{filename}' triggered a {match.pattern_name} pattern on line "
            f"{match.line_number}. The matched data category is {match.category}. The applicable regulations "
            f"are: {regs_str}.\n\n"
            f"Answer these three questions in exactly three short paragraphs:\n"
            f"1. Why is this a data privacy risk?\n"
            f"2. Which specific regulation article is violated and what does it require?\n"
            f"3. What are the top two remediation steps the user should take right now?"
        )
        
        # We specify gemini-1.5-flash as it is highly efficient and standard
        model = genai.GenerativeModel(
            model_name="gemini-1.5-flash",
            system_instruction=system_instruction,
            generation_config={"max_output_tokens": 300, "temperature": 0.2}
        )
        
        response = model.generate_content(prompt, request_options={"timeout": 5})
        explanation = response.text.strip() if response.text else fallback_explanation
        
        # Save to cache
        _explanation_cache[cache_key] = explanation
        return explanation
        
    except Exception as e:
        print(f"Warning: Gemini API request failed: {e}. Falling back to static template.", file=sys.stderr)
        # Store fallback in cache for this session to prevent repeated failed calls
        _explanation_cache[cache_key] = fallback_explanation
        return fallback_explanation
