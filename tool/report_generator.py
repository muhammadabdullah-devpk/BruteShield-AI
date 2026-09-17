# ============================================================
#  report_generator.py — Premium HTML Report Generator
#  Author : Muhammad Abdullah | AI/ML Group 3 | Week 4
# ============================================================

import json, os
from datetime import datetime


def generate_html_report(analyzed_results: list, output_path: str):
    total      = len(analyzed_results)
    vuln_count = sum(1 for r in analyzed_results
                     if r["ai_analysis"].get("VULNERABILITY_DETECTED") == "YES")
    safe_count = total - vuln_count
    now        = datetime.now().strftime("%Y-%m-%d %H:%M")

    # ── Build each finding card ───────────────────────────────
    cards = ""
    for i, item in enumerate(analyzed_results):
        f   = item["scan_facts"]
        ai  = item["ai_analysis"]

        vuln     = ai.get("VULNERABILITY_DETECTED", "UNKNOWN")
        sev      = ai.get("SEVERITY", "UNKNOWN")
        evidence = ai.get("EVIDENCE", [])
        impact   = ai.get("IMPACT", "N/A")
        remed    = ai.get("REMEDIATION", [])
        fpr      = ai.get("FALSE_POSITIVE_RISK", "N/A")
        cvss     = f.get("cvss_score", 0.0)
        fp_test  = f.get("false_positive_test", False)

        is_vuln  = vuln == "YES"
        card_clr = "#ff4757" if is_vuln else "#00ff88"
        sev_clr  = "#ff4757" if sev in ("High","Critical") else ("#ffa502" if sev=="Medium" else "#00ff88")

        # code chips
        chips = ""
        for r in f.get("responses", []):
            sc  = r.get("status_code", "?")
            cls = "c200" if sc == 200 else ("c429" if sc == 429 else "cerr")
            chips += f'<span class="cc {cls}">{sc}</span>'

        # evidence list
        ev_html = "".join(f"<li>{e}</li>" for e in (evidence if isinstance(evidence, list) else [evidence]))

        # remediation list
        rm_list = remed if isinstance(remed, list) else str(remed).split("\n")
        rm_html = "".join(f"<li>{r}</li>" for r in rm_list if r.strip())

        fp_label = '<span class="tag-fp">FALSE-POSITIVE CONTROL TEST</span>' if fp_test else '<span class="tag-tp">TRUE-POSITIVE TEST</span>'
        vuln_badge = f'<span class="badge-vuln">VULNERABLE</span>' if is_vuln else '<span class="badge-safe">PROTECTED</span>'
        sev_badge  = f'<span class="badge-sev" style="color:{sev_clr};border-color:{sev_clr}40;background:{sev_clr}15">{sev}</span>'

        cards += f"""
<div class="card" style="border-left:3px solid {card_clr}">

  <!-- Card Header -->
  <div class="card-hdr">
    <div class="card-hdr-left">
      <div class="card-num">#{i+1:02d}</div>
      <div>
        <h3 class="card-title">{f['target_name']}</h3>
        <code class="url-pill">{f['method']} {f['url']}</code>
        <p class="ctx-tag">&#128205; {f.get('context','')}</p>
      </div>
    </div>
    <div class="card-hdr-right">
      {vuln_badge}
      {sev_badge}
      <div style="display:flex;gap:6px;margin-top:4px">
        {fp_label}
        <span class="tag-cvss">CVSS {cvss}</span>
      </div>
    </div>
  </div>

  <!-- Card Body -->
  <div class="card-body">

    <!-- Facts -->
    <div class="section">
      <div class="section-title">
        <span class="icon">&#128202;</span> Detected Facts
        <span class="auto-label">AUTOMATED SCRIPT OUTPUT</span>
      </div>
      <div class="facts-grid">
        <div class="fact"><span>Total Requests</span><strong>{f['total_requests']}</strong></div>
        <div class="fact"><span>Unique Status Codes</span><strong style="font-family:monospace">{f['unique_codes']}</strong></div>
        <div class="fact"><span>Rate Limited?</span><strong style="color:{'#00ff88' if f['rate_limited'] else '#ff4757'}">{'YES @ req #'+str(f['rate_limit_at_req']) if f['rate_limited'] else 'NO'}</strong></div>
        <div class="fact"><span>Retry-After Header</span><strong style="color:{'#00ff88' if f['retry_after_seen'] else '#ff4757'}">{'Present' if f['retry_after_seen'] else 'Not Seen'}</strong></div>
        <div class="fact"><span>Avg Response Time</span><strong>{f['avg_response_ms']} ms</strong></div>
        <div class="fact"><span>Tested At</span><strong>{f['tested_at']}</strong></div>
      </div>
      <p class="codes-lbl">Response Code Sequence:</p>
      <div class="codes-row">{chips}</div>
    </div>

    <!-- AI Section -->
    <div class="section ai-section">
      <div class="section-title">
        <span class="icon">&#129302;</span> AI-Assisted Analysis
        <span class="ai-label">&#9888; AI-GENERATED — VERIFY MANUALLY</span>
      </div>

      <div class="ai-grid">
        <div class="ai-block">
          <h4 class="ai-block-title">&#128204; Evidence</h4>
          <ul>{ev_html}</ul>
        </div>
        <div class="ai-block">
          <h4 class="ai-block-title">&#128165; Real-World Impact</h4>
          <p>{impact}</p>
        </div>
        <div class="ai-block">
          <h4 class="ai-block-title">&#128295; Recommended Remediation</h4>
          <ol>{rm_html}</ol>
        </div>
        <div class="ai-block fp-block">
          <h4 class="ai-block-title" style="color:#ffa502">&#9888; False Positive Risk</h4>
          <p>{fpr}</p>
        </div>
      </div>
    </div>

  </div>
</div>
"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1.0">
  <title>BruteShield — Audit Report | Muhammad Abdullah</title>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    :root{{
      --bg:#04080f; --s1:#080e1a; --s2:#0c1420; --s3:#101a28;
      --border:#122338; --border2:#1c3858;
      --green:#00ff88; --green2:#00cc6a; --green3:#009950;
      --cyan:#00d4ff; --purple:#a855f7; --red:#ff4757; --yellow:#ffa502;
      --text:#d4eeff; --muted:#5883a4; --white:#f4faff;
      --card:#091220; --card2:#0e1b2f;
    }}
    *{{margin:0;padding:0;box-sizing:border-box}}
    ::-webkit-scrollbar{{width:5px}}
    ::-webkit-scrollbar-track{{background:var(--s1)}}
    ::-webkit-scrollbar-thumb{{background:var(--border2);border-radius:3px}}
    body{{font-family:'Inter',sans-serif;background:var(--bg);color:var(--text);min-height:100vh}}

    /* ── HERO ── */
    .hero{{
      background:radial-gradient(ellipse at 85% 20%,#00d4ff15 0%,transparent 50%),
                 radial-gradient(ellipse at 15% 90%,#a855f712 0%,transparent 50%),
                 linear-gradient(135deg,#04080f 0%,#091322 50%,#050c18 100%);
      border-bottom:2px solid var(--border2);padding:48px 48px 40px;
      position:relative;overflow:hidden;
    }}
    .hero::after{{
      content:'';position:absolute;top:0;left:0;right:0;height:3px;
      background:linear-gradient(90deg,var(--purple),var(--cyan),var(--green),var(--purple));
    }}
    .hero-inner{{max-width:960px;margin:0 auto;position:relative}}
    .hero-top-badge{{
      display:inline-flex;align-items:center;gap:8px;
      font-size:11px;font-weight:700;letter-spacing:2px;text-transform:uppercase;
      color:var(--cyan);background:#00d4ff12;border:1px solid #00d4ff30;
      padding:5px 14px;border-radius:20px;margin-bottom:18px;
    }}
    .hero-top-badge::before{{content:'●';font-size:8px;color:var(--green);animation:pulse 2s infinite}}
    @keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:0.3}}}}
    .hero h1{{
      font-size:36px;font-weight:800;line-height:1.2;
      background:linear-gradient(135deg,var(--white) 0%,#a5f3fc 50%,var(--green) 100%);
      -webkit-background-clip:text;-webkit-text-fill-color:transparent;
      margin-bottom:8px;
    }}
    .hero-sub{{font-size:14px;color:var(--muted);margin-bottom:28px}}

    /* Author & Meta bar in hero */
    .author-card{{
      display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:20px;
      background:rgba(12,20,32,0.7);backdrop-filter:blur(10px);
      border:1px solid var(--border2);border-radius:14px;padding:16px 20px;margin-bottom:24px;
    }}
    .author-left{{display:flex;align-items:center;gap:14px}}
    .author-avatar{{
      width:52px;height:52px;border-radius:50%;
      border:2px solid var(--cyan);box-shadow:0 0 16px rgba(0,212,255,0.3);
      object-fit:cover;
    }}
    .author-name{{font-size:16px;font-weight:800;color:var(--white);letter-spacing:0.3px}}
    .author-role{{font-size:12px;color:var(--cyan);margin-top:2px}}
    .github-link{{
      display:inline-flex;align-items:center;gap:7px;
      background:#ffffff0d;border:1px solid var(--border2);
      padding:6px 14px;border-radius:8px;font-size:12px;
      color:var(--white);text-decoration:none;font-family:'JetBrains Mono',monospace;
      transition:all .2s;
    }}
    .github-link:hover{{border-color:var(--cyan);color:var(--cyan);background:#00d4ff10}}
    .github-link svg{{width:15px;height:15px;fill:currentColor}}

    .meta-row{{display:flex;flex-wrap:wrap;gap:24px}}
    .meta-item span{{display:block;font-size:10px;text-transform:uppercase;letter-spacing:1.5px;color:var(--muted);margin-bottom:3px}}
    .meta-item strong{{font-size:13px;color:var(--white)}}

    /* ── STATS BAR ── */
    .stats-bar{{
      background:var(--s1);border-bottom:1px solid var(--border);
      padding:0 48px;
    }}
    .stats-inner{{max-width:960px;margin:0 auto;display:flex;gap:0}}
    .stat-item{{padding:20px 36px 20px 0;border-right:1px solid var(--border);margin-right:36px}}
    .stat-item:last-child{{border-right:none;margin-right:0}}
    .stat-num{{font-size:32px;font-weight:800;line-height:1}}
    .stat-num.red{{color:var(--red)}}
    .stat-num.green{{color:var(--green)}}
    .stat-num.yellow{{color:var(--yellow)}}
    .stat-num.cyan{{color:var(--cyan)}}
    .stat-lbl{{font-size:11px;color:var(--muted);margin-top:4px;letter-spacing:0.5px}}

    /* ── AUTH BOX ── */
    .content{{max-width:960px;margin:0 auto;padding:36px 48px}}
    .auth-box{{
      background:linear-gradient(135deg,rgba(0,212,255,0.06),rgba(0,255,136,0.06));
      border:1px solid rgba(0,212,255,0.25);border-radius:12px;
      padding:16px 22px;margin-bottom:28px;
      font-size:13px;color:var(--text);line-height:1.7;
    }}
    .auth-box strong{{color:var(--green)}}

    /* ── CARD ── */
    .card{{
      background:var(--card);border:1px solid var(--border);
      border-radius:14px;margin-bottom:24px;overflow:hidden;
      transition:transform .2s;
    }}
    .card:hover{{transform:translateY(-2px)}}
    .card-hdr{{
      padding:22px 26px;background:var(--card2);
      border-bottom:1px solid var(--border);
      display:flex;align-items:flex-start;justify-content:space-between;gap:16px;
    }}
    .card-hdr-left{{display:flex;align-items:flex-start;gap:14px}}
    .card-num{{
      font-family:'JetBrains Mono',monospace;font-size:12px;font-weight:700;
      color:var(--green);background:#00ff8815;border:1px solid #00ff8830;
      padding:4px 10px;border-radius:6px;white-space:nowrap;margin-top:2px;
    }}
    .card-title{{font-size:17px;font-weight:700;color:var(--white);margin-bottom:6px}}
    .url-pill{{
      font-family:'JetBrains Mono',monospace;font-size:11px;
      color:var(--cyan);background:#00e5ff12;border:1px solid #00e5ff25;
      padding:3px 10px;border-radius:4px;display:inline-block;margin-bottom:6px;
    }}
    .ctx-tag{{font-size:12px;color:var(--muted)}}
    .card-hdr-right{{display:flex;flex-direction:column;align-items:flex-end;gap:6px;min-width:160px}}

    /* badges */
    .badge-vuln{{
      display:inline-block;padding:5px 14px;border-radius:20px;
      font-size:12px;font-weight:700;
      color:var(--red);background:#ff475720;border:1px solid #ff475740;
    }}
    .badge-safe{{
      display:inline-block;padding:5px 14px;border-radius:20px;
      font-size:12px;font-weight:700;
      color:var(--green);background:#00ff8820;border:1px solid #00ff8840;
    }}
    .badge-sev{{
      display:inline-block;padding:3px 12px;border-radius:20px;
      font-size:11px;font-weight:700;border:1px solid;
    }}
    .tag-tp{{font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;color:var(--cyan);background:#00e5ff15;border:1px solid #00e5ff30}}
    .tag-fp{{font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;color:var(--yellow);background:#ffa50215;border:1px solid #ffa50230}}
    .tag-cvss{{font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;color:var(--muted);background:#ffffff10}}

    /* ── CARD BODY ── */
    .card-body{{padding:0 26px 26px}}
    .section{{margin-top:22px}}
    .section-title{{
      display:flex;align-items:center;gap:8px;
      font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:1.5px;
      color:var(--muted);margin-bottom:16px;
    }}
    .icon{{font-size:14px}}
    .auto-label{{
      font-size:9px;letter-spacing:1px;font-weight:700;
      padding:2px 8px;border-radius:4px;background:#ffffff08;color:#ffffff40;
    }}
    .ai-label{{
      font-size:9px;letter-spacing:1px;font-weight:700;
      padding:2px 8px;border-radius:4px;background:#ffa50215;color:var(--yellow);
    }}

    /* FACTS GRID */
    .facts-grid{{
      display:grid;grid-template-columns:repeat(3,1fr);
      gap:10px;margin-bottom:14px;
    }}
    .fact{{
      background:#00000030;border:1px solid var(--border);
      border-radius:8px;padding:10px 14px;
    }}
    .fact span{{font-size:10px;color:var(--muted);display:block;margin-bottom:3px;text-transform:uppercase;letter-spacing:0.5px}}
    .fact strong{{font-family:'JetBrains Mono',monospace;font-size:13px}}
    .codes-lbl{{font-size:11px;color:var(--muted);margin-bottom:7px}}
    .codes-row{{display:flex;flex-wrap:wrap;gap:3px}}
    .cc{{font-family:'JetBrains Mono',monospace;font-size:11px;padding:2px 7px;border-radius:4px;font-weight:500}}
    .c200{{background:#00ff8818;color:var(--green)}}
    .c429{{background:#ffa50218;color:var(--yellow)}}
    .cerr{{background:#ff475718;color:var(--red)}}

    /* AI SECTION */
    .ai-section{{border-top:1px solid var(--border);padding-top:20px}}
    .ai-grid{{display:grid;grid-template-columns:1fr 1fr;gap:14px}}
    .ai-block{{background:#00000030;border:1px solid var(--border);border-radius:10px;padding:16px}}
    .ai-block-title{{font-size:12px;font-weight:700;color:var(--white);margin-bottom:10px}}
    .ai-block ul,.ai-block ol{{padding-left:18px;font-size:13px;line-height:1.85;color:var(--text)}}
    .ai-block p{{font-size:13px;line-height:1.75;color:var(--text)}}
    .fp-block{{border-color:#ffa50240;background:#ffa50210}}

    /* ── FOOTER ── */
    footer{{
      background:var(--s1);border-top:1px solid var(--border);
      text-align:center;padding:32px 48px;
    }}
    footer p{{font-size:12px;color:var(--muted);line-height:1.8}}
    footer .f-brand{{
      font-size:18px;font-weight:800;
      background:linear-gradient(90deg,var(--green),var(--cyan));
      -webkit-background-clip:text;-webkit-text-fill-color:transparent;
      margin-bottom:8px;
    }}
    .divider{{
      max-width:900px;margin:0 auto 28px;
      height:1px;background:linear-gradient(90deg,transparent,var(--border2),transparent);
    }}
  </style>
</head>
<body>

<!-- HERO -->
<div class="hero">
  <div class="hero-inner">
    <div class="hero-top-badge">Week 4 — AI/ML Group 3 &bull; SAFEX Internship</div>
    <h1>Rate Limiting &amp; Brute-Force<br>Exposure Audit Report</h1>
    <p class="hero-sub">AI-Assisted Security Tool — Lifestyle Application Context</p>

    <!-- Author Profile Card -->
    <div class="author-card">
      <div class="author-left">
        <img src="https://avatars.githubusercontent.com/u/268538267?v=4" alt="Muhammad Abdullah" class="author-avatar">
        <div>
          <div class="author-name">Muhammad Abdullah</div>
          <div class="author-role">AI/ML &amp; Cybersecurity Developer &bull; BSCS 6th Sem</div>
        </div>
      </div>
      <a href="https://github.com/muhammadabdullah-devpk" target="_blank" class="github-link">
        <svg viewBox="0 0 24 24"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/></svg>
        muhammadabdullah-devpk
      </a>
    </div>

    <div class="meta-row">
      <div class="meta-item"><span>Institution</span><strong>Lahore Garrison University</strong></div>
      <div class="meta-item"><span>Specialization</span><strong>AI/ML &bull; Group 3</strong></div>
      <div class="meta-item"><span>Report Generated</span><strong>{now}</strong></div>
      <div class="meta-item"><span>Lab Target</span><strong>OWASP Juice Shop (Authorized)</strong></div>
    </div>
  </div>
</div>

<!-- STATS BAR -->
<div class="stats-bar">
  <div class="stats-inner">
    <div class="stat-item">
      <div class="stat-num cyan">{total}</div>
      <div class="stat-lbl">Endpoints Tested</div>
    </div>
    <div class="stat-item">
      <div class="stat-num red">{vuln_count}</div>
      <div class="stat-lbl">Vulnerable</div>
    </div>
    <div class="stat-item">
      <div class="stat-num green">{safe_count}</div>
      <div class="stat-lbl">Protected</div>
    </div>
    <div class="stat-item">
      <div class="stat-num yellow">High</div>
      <div class="stat-lbl">Max Severity Found</div>
    </div>
  </div>
</div>

<!-- CONTENT -->
<div class="content">

  <!-- AUTH NOTE -->
  <div class="auth-box">
    <strong>&#9989; Authorization Notice:</strong> All tests were conducted exclusively against
    <strong>OWASP Juice Shop</strong> — an intentionally vulnerable lab application (authorized).
    No live production systems were accessed. AI-generated interpretations are clearly labelled
    and must be verified by a qualified security analyst before acting on them.
  </div>

  <!-- FINDING CARDS -->
  {cards}

  <div class="divider"></div>
</div>

<!-- FOOTER -->
<footer>
  <div class="f-brand">BruteShield</div>
  <p>Generated by AI-Assisted Rate Limiting Detection Tool &nbsp;|&nbsp;
     <strong style="color:var(--white)">Muhammad Abdullah</strong> &nbsp;|&nbsp;
     <a href="https://github.com/muhammadabdullah-devpk" target="_blank" style="color:var(--cyan);text-decoration:none">github.com/muhammadabdullah-devpk</a> &nbsp;|&nbsp;
     Lahore Garrison University &bull; SAFEX Internship (AI/ML Group 3)
  </p>
  <p style="margin-top:8px;font-size:11px">
    &#9888; This report contains AI-assisted interpretations. All findings must be
    verified by a qualified security professional before taking action.
  </p>
</footer>

</body>
</html>"""

    os.makedirs(os.path.dirname(output_path) if os.path.dirname(output_path) else ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[+] HTML Report saved to: {output_path}")
    return output_path
