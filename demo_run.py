# ============================================================
#  demo_run.py — Generate Full Report Using Simulated Data
#  (No internet needed — perfect for demo/portfolio)
#  Author : Muhammad Abdullah | AI/ML Group 3 | Week 4
# ============================================================
import sys, os, json
sys.path.insert(0, "tool")

from datetime import datetime

# ── Simulated scan results (as if scanner.py ran) ────────────
SIMULATED_SCAN_RESULTS = [
    {
        "target_name"       : "Juice Shop — Login Endpoint",
        "url"               : "https://juice-shop.herokuapp.com/rest/user/login",
        "method"            : "POST",
        "context"           : "Lifestyle App — User Authentication",
        "endpoint_type"     : "login",
        "total_requests"    : 20,
        "status_codes"      : [200]*20,
        "unique_codes"      : [200],
        "rate_limited"      : False,
        "rate_limit_at_req" : None,
        "retry_after_seen"  : False,
        "avg_response_ms"   : 312.4,
        "responses"         : [{"request_num": i+1, "status_code": 200, "response_ms": 290+i*5, "retry_after": None} for i in range(20)],
        "vulnerable"        : True,
        "tested_at"         : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    {
        "target_name"       : "Juice Shop — Password Reset",
        "url"               : "https://juice-shop.herokuapp.com/rest/user/reset-password",
        "method"            : "POST",
        "context"           : "Lifestyle App — Password Recovery",
        "endpoint_type"     : "reset",
        "total_requests"    : 20,
        "status_codes"      : [200]*20,
        "unique_codes"      : [200],
        "rate_limited"      : False,
        "rate_limit_at_req" : None,
        "retry_after_seen"  : False,
        "avg_response_ms"   : 285.7,
        "responses"         : [{"request_num": i+1, "status_code": 200, "response_ms": 270+i*3, "retry_after": None} for i in range(20)],
        "vulnerable"        : True,
        "tested_at"         : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    {
        "target_name"       : "Juice Shop — Product Search",
        "url"               : "https://juice-shop.herokuapp.com/rest/products/search?q=test",
        "method"            : "GET",
        "context"           : "Lifestyle App — Product Catalog",
        "endpoint_type"     : "search",
        "total_requests"    : 20,
        "status_codes"      : [200]*13 + [429]*7,
        "unique_codes"      : [200, 429],
        "rate_limited"      : True,
        "rate_limit_at_req" : 14,
        "retry_after_seen"  : True,
        "avg_response_ms"   : 198.2,
        "responses"         : [{"request_num": i+1, "status_code": 200 if i < 13 else 429, "response_ms": 190+i*2, "retry_after": "30" if i >= 13 else None} for i in range(20)],
        "vulnerable"        : False,
        "tested_at"         : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    {
        "target_name"       : "Juice Shop — User Profile API",
        "url"               : "https://juice-shop.herokuapp.com/api/Users/1",
        "method"            : "GET",
        "context"           : "Lifestyle App — User Data",
        "endpoint_type"     : "api",
        "total_requests"    : 20,
        "status_codes"      : [401]*20,
        "unique_codes"      : [401],
        "rate_limited"      : False,
        "rate_limit_at_req" : None,
        "retry_after_seen"  : False,
        "avg_response_ms"   : 145.3,
        "responses"         : [{"request_num": i+1, "status_code": 401, "response_ms": 140+i, "retry_after": None} for i in range(20)],
        "vulnerable"        : True,
        "tested_at"         : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
    {
        "target_name"       : "Juice Shop — Feedback Submit",
        "url"               : "https://juice-shop.herokuapp.com/api/Feedbacks",
        "method"            : "POST",
        "context"           : "Lifestyle App — Customer Feedback",
        "endpoint_type"     : "form",
        "total_requests"    : 20,
        "status_codes"      : [200]*20,
        "unique_codes"      : [200],
        "rate_limited"      : False,
        "rate_limit_at_req" : None,
        "retry_after_seen"  : False,
        "avg_response_ms"   : 267.9,
        "responses"         : [{"request_num": i+1, "status_code": 200, "response_ms": 260+i*2, "retry_after": None} for i in range(20)],
        "vulnerable"        : True,
        "tested_at"         : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    },
]

# ── AI Analysis Results ───────────────────────────────────────
AI_RESPONSES = {
    True: {   # vulnerable = True
        "VULNERABILITY_DETECTED": "YES",
        "SEVERITY": "High",
        "EVIDENCE": [
            "All 20 requests completed with no HTTP 429 (Too Many Requests) response",
            "No Retry-After header observed in any of the 20 responses",
            "Server accepted rapid sequential requests without any throttling or delay",
            "No account lockout mechanism detected after repeated failed attempts"
        ],
        "IMPACT": (
            "A Lifestyle application without rate limiting on authentication or form endpoints "
            "is directly exposed to automated brute-force and credential stuffing attacks. "
            "Attackers can test thousands of password combinations per minute, potentially "
            "compromising user accounts and exposing sensitive personal and payment data."
        ),
        "REMEDIATION": [
            "Implement server-side rate limiting: max 5 failed attempts per IP per 15 minutes",
            "Return HTTP 429 with a Retry-After header when the threshold is exceeded",
            "Add CAPTCHA (hCaptcha / reCAPTCHA v3) after 3 consecutive failures",
            "Implement account lockout with exponential backoff (30s → 2m → 10m → 1h)",
            "Log and alert on high request volumes from a single IP address",
            "Deploy a WAF (Web Application Firewall) rule to block automated request patterns",
            "Consider Redis token-bucket algorithm for distributed rate limiting"
        ],
        "FALSE_POSITIVE_RISK": (
            "A false positive could occur if rate limiting is enforced at the CDN or load balancer "
            "layer (e.g., Cloudflare, AWS WAF) rather than the application layer. "
            "Infrastructure-level blocking would not produce HTTP 429 responses visible to this tool. "
            "Manual verification of infrastructure configs is recommended."
        )
    },
    False: {   # vulnerable = False (protected)
        "VULNERABILITY_DETECTED": "NO",
        "SEVERITY": "None",
        "EVIDENCE": [
            "HTTP 429 (Too Many Requests) triggered at request #14 of 20",
            "Retry-After header present with 30-second cooldown value",
            "Server successfully blocked further requests after rate limit threshold",
            "Rate limiting appears to be functioning correctly"
        ],
        "IMPACT": (
            "This endpoint is protected against brute-force attacks. "
            "The rate limiting mechanism is functioning as expected and will throttle automated attackers."
        ),
        "REMEDIATION": [
            "No immediate action required — rate limiting is functioning correctly",
            "Consider testing from multiple IPs to ensure protection is not bypassable via IP rotation",
            "Periodically review rate limit thresholds to align with evolving attack patterns"
        ],
        "FALSE_POSITIVE_RISK": (
            "The endpoint may still be vulnerable to distributed brute-force attacks using IP rotation. "
            "Test with multiple source IPs to confirm protection is comprehensive."
        )
    }
}

def run_demo():
    print("=" * 65)
    print("  DEMO MODE — Generating Report with Simulated Data")
    print("  Author: Muhammad Abdullah | SAFEX AI/ML Week 4")
    print("=" * 65 + "\n")

    os.makedirs("reports", exist_ok=True)

    # Build analyzed results
    analyzed = []
    for result in SIMULATED_SCAN_RESULTS:
        ai_resp = AI_RESPONSES[result["vulnerable"]]
        analyzed.append({
            "scan_facts"     : result,
            "ai_prompt_used" : f"[Prompt for {result['target_name']}]",
            "ai_analysis"    : ai_resp,
            "ai_label"       : "⚠ AI-ASSISTED INTERPRETATION — Verify manually",
            "analyzed_at"    : datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })

    # Save JSONs
    with open("reports/raw_results.json", "w") as f:
        json.dump(SIMULATED_SCAN_RESULTS, f, indent=2)
    with open("reports/analyzed_results.json", "w") as f:
        json.dump(analyzed, f, indent=2)

    # Generate Report
    from tool.report_generator import generate_html_report
    report_path = generate_html_report(analyzed, "reports/audit_report.html")

    print(f"\n{'='*65}")
    print(f"  [OK] REPORT READY!")
    print(f"  Open: {os.path.abspath('reports/audit_report.html')}")
    print(f"{'='*65}\n")

if __name__ == "__main__":
    run_demo()
