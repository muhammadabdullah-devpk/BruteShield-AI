# ============================================================
#  config.py — Configuration for Rate Limiting Detection Tool
#  Author : Muhammad Abdullah
#  Domain : AI/ML — Week 4 Task
# ============================================================

# ─── Lab Target URLs (Authorized Only) ──────────────────────
# Using OWASP Juice Shop demo instance (public, read-only testing allowed)
# Replace with your own local OWASP Juice Shop / DVWA / WebGoat
TARGETS = [
    {
        "name": "Juice Shop — Login Endpoint",
        "url": "https://juice-shop.herokuapp.com/rest/user/login",
        "method": "POST",
        "payload": {"email": "test@test.com", "password": "wrongpass"},
        "type": "login",
        "context": "Lifestyle App — User Authentication"
    },
    {
        "name": "Juice Shop — Password Reset",
        "url": "https://juice-shop.herokuapp.com/rest/user/reset-password",
        "method": "POST",
        "payload": {"email": "test@test.com", "answer": "abc"},
        "type": "reset",
        "context": "Lifestyle App — Password Recovery"
    },
    {
        "name": "Juice Shop — Product Search",
        "url": "https://juice-shop.herokuapp.com/rest/products/search?q=test",
        "method": "GET",
        "payload": {},
        "type": "search",
        "context": "Lifestyle App — Product Catalog"
    },
    {
        "name": "Juice Shop — User Profile",
        "url": "https://juice-shop.herokuapp.com/api/Users/1",
        "method": "GET",
        "payload": {},
        "type": "api",
        "context": "Lifestyle App — User Data"
    },
    {
        "name": "Juice Shop — Feedback Submit",
        "url": "https://juice-shop.herokuapp.com/api/Feedbacks",
        "method": "POST",
        "payload": {"comment": "test", "rating": 5},
        "type": "form",
        "context": "Lifestyle App — Customer Feedback"
    },
]

# ─── Brute-Force Test Settings ───────────────────────────────
BRUTE_FORCE_REQUESTS   = 20    # Number of rapid requests to send
BRUTE_FORCE_DELAY_MS   = 50    # Milliseconds between requests
RATE_LIMIT_THRESHOLD   = 429   # HTTP status = Too Many Requests
BLOCK_STATUS_CODES     = [429, 403, 503]  # Codes that indicate blocking

# ─── Request Settings ────────────────────────────────────────
REQUEST_TIMEOUT        = 8     # Seconds
HEADERS = {
    "Content-Type": "application/json",
    "User-Agent": "RateLimitDetector/1.0 (Security Research — Lab Only)"
}

# ─── AI Prompt Template ──────────────────────────────────────
AI_PROMPT_TEMPLATE = """
You are a security analyst. Analyze the following rate limiting test results and produce a structured security finding.

## Test Results:
{results}

## Instructions:
1. Determine if Missing Rate Limiting / Brute-Force Exposure is present (YES/NO)
2. Assign severity: Critical / High / Medium / Low
3. List the evidence from results above
4. Explain the real-world impact for a Lifestyle application
5. Provide specific, actionable remediation steps
6. Note any false-positive risks

## Output Format (strictly follow this):
VULNERABILITY_DETECTED: YES or NO
SEVERITY: Critical/High/Medium/Low
EVIDENCE: [bullet points]
IMPACT: [2-3 sentences]
REMEDIATION: [numbered steps]
FALSE_POSITIVE_RISK: [1-2 sentences]

IMPORTANT: Clearly label everything as AI-assisted interpretation.
"""
