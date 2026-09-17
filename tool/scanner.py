# ============================================================
#  scanner.py — Rate Limiting / Brute-Force Detection Engine
#  Author : Muhammad Abdullah
#  Domain : AI/ML — Week 4 Task
#  NOTE   : Run ONLY against authorized / lab targets
# ============================================================

import requests
import time
import json
from datetime import datetime
from config import (
    TARGETS, BRUTE_FORCE_REQUESTS, BRUTE_FORCE_DELAY_MS,
    RATE_LIMIT_THRESHOLD, BLOCK_STATUS_CODES, REQUEST_TIMEOUT, HEADERS
)


def print_banner():
    print("=" * 65)
    print("  AI-Assisted Rate Limiting / Brute-Force Exposure Detector")
    print("  Author : Muhammad Abdullah | AI/ML Group 3 | Week 4")
    print("  WARNING: Use ONLY on authorized lab targets")
    print("=" * 65)
    print()


def send_rapid_requests(target: dict) -> dict:
    """
    Send BRUTE_FORCE_REQUESTS rapid requests to the target URL
    and record all response codes, headers, and timings.
    Returns: dict with all test facts (no AI judgment here)
    """
    url      = target["url"]
    method   = target["method"].upper()
    payload  = target["payload"]
    name     = target["name"]

    print(f"  [*] Testing: {name}")
    print(f"      URL    : {url}")
    print(f"      Method : {method} | Requests: {BRUTE_FORCE_REQUESTS}")

    responses        = []
    status_codes     = []
    rate_limited     = False
    rate_limit_at    = None
    response_times   = []
    retry_after_seen = False

    for i in range(BRUTE_FORCE_REQUESTS):
        start_time = time.time()
        try:
            if method == "POST":
                resp = requests.post(
                    url,
                    json=payload,
                    headers=HEADERS,
                    timeout=REQUEST_TIMEOUT
                )
            else:
                resp = requests.get(
                    url,
                    headers=HEADERS,
                    timeout=REQUEST_TIMEOUT
                )

            elapsed      = round((time.time() - start_time) * 1000, 1)
            status       = resp.status_code
            status_codes.append(status)
            response_times.append(elapsed)

            # Check for Retry-After header (strong rate limit signal)
            if "Retry-After" in resp.headers:
                retry_after_seen = True

            # Check if rate limited / blocked
            if status in BLOCK_STATUS_CODES:
                if not rate_limited:
                    rate_limited  = True
                    rate_limit_at = i + 1
                    print(f"      [!] Rate limit triggered at request #{i+1} — HTTP {status}")

            responses.append({
                "request_num"  : i + 1,
                "status_code"  : status,
                "response_ms"  : elapsed,
                "retry_after"  : resp.headers.get("Retry-After", None)
            })

        except requests.exceptions.Timeout:
            status_codes.append("TIMEOUT")
            responses.append({"request_num": i + 1, "status_code": "TIMEOUT", "response_ms": None})
        except requests.exceptions.ConnectionError:
            status_codes.append("CONNECTION_ERROR")
            responses.append({"request_num": i + 1, "status_code": "CONNECTION_ERROR", "response_ms": None})
        except Exception as e:
            status_codes.append(f"ERROR: {str(e)[:40]}")
            responses.append({"request_num": i + 1, "status_code": f"ERROR", "response_ms": None})

        time.sleep(BRUTE_FORCE_DELAY_MS / 1000)

    # ── Analyze the collected facts ──
    valid_codes  = [c for c in status_codes if isinstance(c, int)]
    unique_codes = list(set(valid_codes))
    avg_time     = round(sum(r for r in response_times if r) / max(len(response_times), 1), 1)

    # Vulnerability present if NO rate limiting triggered
    vulnerable = not rate_limited

    result = {
        "target_name"       : name,
        "url"               : url,
        "method"            : method,
        "context"           : target.get("context", ""),
        "endpoint_type"     : target.get("type", "unknown"),
        "total_requests"    : BRUTE_FORCE_REQUESTS,
        "status_codes"      : status_codes,
        "unique_codes"      : unique_codes,
        "rate_limited"      : rate_limited,
        "rate_limit_at_req" : rate_limit_at,
        "retry_after_seen"  : retry_after_seen,
        "avg_response_ms"   : avg_time,
        "responses"         : responses,
        "vulnerable"        : vulnerable,
        "tested_at"         : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }

    status_icon = "✓ PROTECTED" if not vulnerable else "✗ VULNERABLE"
    print(f"      Result : {status_icon}")
    print(f"      Codes  : {unique_codes} | Avg: {avg_time}ms")
    print()
    return result


def run_all_scans() -> list:
    """Scan all configured targets and return list of results."""
    print_banner()
    print(f"[+] Starting scan — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[+] Targets: {len(TARGETS)} | Requests per target: {BRUTE_FORCE_REQUESTS}\n")

    all_results = []
    for target in TARGETS:
        result = send_rapid_requests(target)
        all_results.append(result)

    vulnerable_count = sum(1 for r in all_results if r["vulnerable"])
    print(f"[+] Scan Complete!")
    print(f"    Vulnerable : {vulnerable_count}/{len(TARGETS)} endpoints")
    print(f"    Protected  : {len(TARGETS) - vulnerable_count}/{len(TARGETS)} endpoints\n")

    return all_results


if __name__ == "__main__":
    results = run_all_scans()
    # Save raw results for AI analysis
    with open("../reports/raw_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print("[+] Raw results saved to reports/raw_results.json")
    print("[+] Run ai_analyzer.py next to get AI-assisted interpretation")
