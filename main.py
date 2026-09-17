# ============================================================
#  main.py — Run Everything in One Command
#  Author : Muhammad Abdullah | AI/ML Group 3 | Week 4
# ============================================================
import os, sys

# Add tool directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "tool"))

from tool.scanner          import run_all_scans
from tool.ai_analyzer      import analyze_all
from tool.report_generator import generate_html_report
import json

def main():
    print("\n" + "="*65)
    print("  Rate Limiting / Brute-Force Exposure — Full Pipeline")
    print("  Author: Muhammad Abdullah | SAFEX AI/ML Week 4")
    print("="*65 + "\n")

    os.makedirs("reports", exist_ok=True)

    # Step 1: Scan
    print("STEP 1: Running Detection Scans...")
    print("-"*40)
    scan_results = run_all_scans()
    with open("reports/raw_results.json", "w") as f:
        json.dump(scan_results, f, indent=2)
    print("[✓] Scan complete\n")

    # Step 2: AI Analysis
    print("STEP 2: AI-Assisted Analysis...")
    print("-"*40)
    analyzed = analyze_all(scan_results, use_api=False)
    with open("reports/analyzed_results.json", "w") as f:
        json.dump(analyzed, f, indent=2)
    print("[✓] Analysis complete\n")

    # Step 3: Generate Report
    print("STEP 3: Generating HTML Report...")
    print("-"*40)
    report_path = generate_html_report(analyzed, "reports/audit_report.html")
    print(f"[✓] Report ready!\n")

    print("="*65)
    print(f"  ✅ ALL DONE!")
    print(f"  📄 Report : reports/audit_report.html")
    print(f"  📦 Data   : reports/raw_results.json")
    print(f"  🤖 AI     : reports/analyzed_results.json")
    print("="*65 + "\n")

if __name__ == "__main__":
    main()
