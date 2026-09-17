# ============================================================
#  ai_analyzer.py — AI-Assisted Analysis of Scan Results
#  Author : Muhammad Abdullah
#  Domain : AI/ML — Week 4 Task
#
#  NOTE: This module generates structured AI prompts.
#  You can paste the prompt into ChatGPT/Claude/Gemini
#  OR use the OpenAI API if you have a key.
#  All AI outputs are clearly labelled as AI-assisted.
# ============================================================

import json
import os
from datetime import datetime
from config import AI_PROMPT_TEMPLATE


# ─── Simulated AI responses (for demo when no API key) ───────
SIMULATED_AI_RESPONSES = {
    "vulnerable": {
        "VULNERABILITY_DETECTED": "YES",
        "SEVERITY": "High",
        "EVIDENCE": [
            "All 20 requests returned HTTP 200 with no rate limiting triggered",
            "No Retry-After header observed in any response",
            "No HTTP 429 (Too Many Requests) returned across all requests",
            "Endpoint accepted rapid sequential requests without any throttling"
        ],
        "IMPACT": (
            "A Lifestyle application without rate limiting on login or form endpoints "
            "is critically exposed to brute-force attacks. Attackers can automate "
            "credential stuffing or password guessing attacks at high speed, potentially "
            "compromising thousands of user accounts within minutes."
        ),
        "REMEDIATION": [
            "Implement server-side rate limiting: max 5 failed login attempts per IP per 15 minutes",
            "Return HTTP 429 with Retry-After header when limit is exceeded",
            "Add CAPTCHA (hCaptcha / reCAPTCHA) after 3 consecutive failures",
            "Use account lockout with exponential backoff (e.g., 30s, 2m, 10m, 1h)",
            "Log and alert on rapid repeated requests from the same IP",
            "Use a WAF (Web Application Firewall) rule to block brute-force patterns",
            "Consider using Redis or a token-bucket algorithm for rate limiting"
        ],
        "FALSE_POSITIVE_RISK": (
            "A false positive could occur if the target uses IP-level rate limiting at "
            "the load balancer or CDN layer (e.g., Cloudflare), which would not be "
            "visible in application-level HTTP response codes. Manual verification "
            "by checking infrastructure config is recommended."
        )
    },
    "protected": {
        "VULNERABILITY_DETECTED": "NO",
        "SEVERITY": "None",
        "EVIDENCE": [
            "HTTP 429 (Too Many Requests) triggered after rapid requests",
            "Retry-After header present in response",
            "Server blocked further requests after rate limit threshold"
        ],
        "IMPACT": "Endpoint is protected. Brute-force attacks will be throttled.",
        "REMEDIATION": ["No action required. Current rate limiting is functioning correctly."],
        "FALSE_POSITIVE_RISK": (
            "Rate limiting may be IP-based; test from multiple IPs to ensure "
            "protection is not bypassed by IP rotation."
        )
    }
}


def build_ai_prompt(result: dict) -> str:
    """Build a structured AI prompt from scan facts."""
    facts_summary = f"""
Target: {result['target_name']}
URL: {result['url']}
Method: {result['method']}
Context: {result['context']} (Lifestyle App)
Endpoint Type: {result['endpoint_type']}

--- DETECTED FACTS (Automated Script Output) ---
Total Requests Sent    : {result['total_requests']}
Unique Status Codes    : {result['unique_codes']}
Rate Limit Triggered   : {'YES — at request #' + str(result['rate_limit_at_req']) if result['rate_limited'] else 'NO'}
Retry-After Header     : {'PRESENT' if result['retry_after_seen'] else 'NOT SEEN'}
Average Response Time  : {result['avg_response_ms']} ms
Vulnerable (no limit)  : {'YES' if result['vulnerable'] else 'NO'}

Request-by-Request Status Codes (first 10):
{json.dumps([r['status_code'] for r in result['responses'][:10]], indent=2)}
"""
    return AI_PROMPT_TEMPLATE.format(results=facts_summary)


def get_ai_analysis(result: dict, use_api: bool = False, api_key: str = None) -> dict:
    """
    Get AI analysis for a single scan result.
    use_api=False → use simulated response (for demo)
    use_api=True  → call OpenAI API (requires api_key)
    """
    prompt = build_ai_prompt(result)

    if use_api and api_key:
        try:
            import openai
            client = openai.OpenAI(api_key=api_key)
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[
                    {"role": "system", "content": "You are a cybersecurity analyst specializing in web application vulnerabilities."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.3
            )
            raw_text = response.choices[0].message.content
            return parse_ai_response(raw_text)
        except Exception as e:
            print(f"  [!] API call failed: {e}. Using simulated response.")

    # Simulated response based on vulnerability status
    sim_key = "vulnerable" if result["vulnerable"] else "protected"
    return SIMULATED_AI_RESPONSES[sim_key]


def parse_ai_response(raw_text: str) -> dict:
    """Parse structured AI response text into a dict."""
    lines   = raw_text.strip().split("\n")
    result  = {}
    current_key = None
    buffer  = []

    for line in lines:
        if line.startswith("VULNERABILITY_DETECTED:"):
            result["VULNERABILITY_DETECTED"] = line.split(":", 1)[1].strip()
        elif line.startswith("SEVERITY:"):
            result["SEVERITY"] = line.split(":", 1)[1].strip()
        elif line.startswith("EVIDENCE:"):
            current_key = "EVIDENCE"
            buffer = []
        elif line.startswith("IMPACT:"):
            if current_key == "EVIDENCE":
                result["EVIDENCE"] = buffer
            current_key = "IMPACT"
            buffer = []
        elif line.startswith("REMEDIATION:"):
            if current_key:
                result[current_key] = "\n".join(buffer) if current_key != "EVIDENCE" else buffer
            current_key = "REMEDIATION"
            buffer = []
        elif line.startswith("FALSE_POSITIVE_RISK:"):
            if current_key:
                result[current_key] = buffer if current_key in ["EVIDENCE", "REMEDIATION"] else "\n".join(buffer)
            current_key = "FALSE_POSITIVE_RISK"
            buffer = []
        elif current_key and line.strip():
            clean = line.strip().lstrip("•-* ").strip()
            if clean:
                buffer.append(clean)

    if current_key and buffer:
        result[current_key] = "\n".join(buffer) if current_key == "FALSE_POSITIVE_RISK" else buffer

    return result


def analyze_all(scan_results: list, use_api: bool = False, api_key: str = None) -> list:
    """Run AI analysis on all scan results."""
    print("[+] Running AI-Assisted Analysis...")
    print("    ⚠ All interpretations below are AI-generated. Verify manually.\n")

    analyzed = []
    for i, result in enumerate(scan_results, 1):
        print(f"  [{i}/{len(scan_results)}] Analyzing: {result['target_name']}")
        prompt     = build_ai_prompt(result)
        ai_output  = get_ai_analysis(result, use_api, api_key)

        analyzed.append({
            "scan_facts"        : result,
            "ai_prompt_used"    : prompt,
            "ai_analysis"       : ai_output,
            "ai_label"          : "⚠ AI-ASSISTED INTERPRETATION — Verify manually",
            "analyzed_at"       : datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })

        vuln = ai_output.get("VULNERABILITY_DETECTED", "UNKNOWN")
        sev  = ai_output.get("SEVERITY", "UNKNOWN")
        print(f"      Detected: {vuln} | Severity: {sev}")

    print(f"\n[+] Analysis complete for {len(analyzed)} targets.")
    return analyzed


if __name__ == "__main__":
    results_path = "../reports/raw_results.json"
    if not os.path.exists(results_path):
        print("[!] raw_results.json not found. Run scanner.py first.")
        exit(1)

    with open(results_path) as f:
        scan_results = json.load(f)

    # Set use_api=True and provide api_key if you have OpenAI access
    analyzed = analyze_all(scan_results, use_api=False, api_key=None)

    with open("../reports/analyzed_results.json", "w") as f:
        json.dump(analyzed, f, indent=2)

    print("[+] Analyzed results saved to reports/analyzed_results.json")
    print("[+] Run report_generator.py to generate HTML report")
