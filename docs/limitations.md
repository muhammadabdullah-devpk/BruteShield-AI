# Tool Limitations — AI-Assisted Rate Limiting Detector
**Author:** Muhammad Abdullah | AI/ML Group 3 | SAFEX Week 4

---

## What This Tool Cannot Reliably Detect

### 1. CDN / Load Balancer Level Rate Limiting
If rate limiting is implemented at the **Cloudflare, AWS WAF, or Nginx** level (before reaching the application), the tool may report a **false negative** (showing vulnerable when actually protected). The application returns HTTP 200 but the infrastructure blocks real attack traffic.

**Recommendation:** Check infrastructure config manually or test from multiple IP addresses simultaneously.

---

### 2. IP Rotation Bypass
This tool sends requests from **one IP address**. A real attacker using **IP rotation** (rotating proxies) can bypass IP-based rate limiting. The tool does NOT simulate this attack vector.

---

### 3. Session/Token-Based Rate Limiting
Some applications implement rate limiting based on **session tokens or user accounts**, not IP addresses. This tool only tests IP-based limiting. Token-based controls require authenticated testing.

---

### 4. Behavioral / ML-Based Bot Detection
Modern applications use **behavioral analysis** (mouse movements, typing patterns, request timing) to detect bots. This tool sends simple HTTP requests and will not trigger such detections — a real attacker might also be blocked by these systems.

---

### 5. Encrypted or Non-Standard Endpoints
Endpoints that require **custom authentication headers, encrypted payloads, or multi-step flows** (e.g., CSRF tokens + login) are not fully covered. The tool uses simple JSON payloads.

---

### 6. AI Interpretation Accuracy
All AI-generated findings (severity, impact, remediation) are **estimates based on pattern matching** and general security knowledge. They may:
- Over-estimate severity for non-critical endpoints
- Under-estimate severity if context is ambiguous
- Miss application-specific business logic risks

**Always have a qualified security professional review AI-generated findings before acting on them.**

---

## What a Human Should Double-Check

1. Test from multiple IP addresses to rule out CDN-level blocking
2. Verify infrastructure-level rate limiting configs (Nginx, AWS WAF, Cloudflare)
3. Check if token rotation is needed to bypass session-based limits
4. Manually review AI severity ratings against actual business impact
5. Re-test after any remediation to confirm fixes work end-to-end
