#!/usr/bin/env python3
"""
HTML Report Generator
Reads reports/vulns.json and produces reports/index.html
"""

import json
from datetime import datetime
from pathlib import Path

OUTPUT_DIR = Path("reports")
JSON_FILE  = OUTPUT_DIR / "vulns.json"
HTML_FILE  = OUTPUT_DIR / "index.html"

SEVERITY_COLOR = {
    "CRITICAL": "#ff3b3b",
    "HIGH":     "#ff8c00",
    "MEDIUM":   "#f5c518",
    "LOW":      "#4caf7d",
    "UNKNOWN":  "#888888",
}

CATEGORY_ICON = {
    "linux":      "🐧",
    "kubernetes": "☸️",
    "openshift":  "🔴",
    "other":      "🔒",
}


def badge(severity):
    color = SEVERITY_COLOR.get(severity, "#888")
    return f'<span class="badge" style="background:{color}">{severity}</span>'


def category_pills(cats):
    pills = ""
    for c in cats:
        icon = CATEGORY_ICON.get(c, "🔒")
        pills += f'<span class="pill pill-{c}">{icon} {c.capitalize()}</span>'
    return pills


def score_bar(score):
    if score is None:
        return '<span class="score-na">N/A</span>'
    pct = min(score / 10 * 100, 100)
    color = SEVERITY_COLOR.get(
        "CRITICAL" if score >= 9 else "HIGH" if score >= 7 else "MEDIUM" if score >= 4 else "LOW",
        "#888"
    )
    return f'''
      <div class="score-wrap">
        <div class="score-bar" style="width:{pct:.0f}%;background:{color}"></div>
        <span class="score-num">{score:.1f}</span>
      </div>'''


def render_card(v):
    sev = v.get("severity", "UNKNOWN")
    sev_color = SEVERITY_COLOR.get(sev, "#888")
    refs_html = ""
    for r in v.get("refs", []):
        label = r.split("/")[-1] or r
        refs_html += f'<a href="{r}" target="_blank" class="ref-link">{label}</a> '

    return f'''
    <div class="card" data-severity="{sev}" data-cats="{" ".join(v.get("categories", []))}">
      <div class="card-stripe" style="background:{sev_color}"></div>
      <div class="card-body">
        <div class="card-header">
          <div class="card-left">
            {badge(sev)}
            {category_pills(v.get("categories", ["other"]))}
          </div>
          <div class="card-meta">
            <span class="source-tag">{v.get("source","")}</span>
            <span class="date-tag">📅 {v.get("published","")}</span>
          </div>
        </div>
        <div class="card-title">
          <a href="{v.get("url","#")}" target="_blank">{v.get("id","")} — {v.get("title","")}</a>
        </div>
        <div class="card-desc">{v.get("description","")[:300]}{"…" if len(v.get("description","")) > 300 else ""}</div>
        <div class="card-footer">
          {score_bar(v.get("score"))}
          <div class="refs">{refs_html}</div>
        </div>
      </div>
    </div>'''


def build_summary(vulns):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    cats   = {"linux": 0, "kubernetes": 0, "openshift": 0}
    for v in vulns:
        sev = v.get("severity", "UNKNOWN")
        counts[sev] = counts.get(sev, 0) + 1
        for c in v.get("categories", []):
            if c in cats:
                cats[c] += 1
    return counts, cats


def generate(vulns, meta):
    total = len(vulns)
    generated = meta.get("generated", "")[:19].replace("T", " ")
    days_back  = meta.get("days_back", 7)
    counts, cats = build_summary(vulns)

    cards_html = "\n".join(render_card(v) for v in vulns)

    stat_boxes = ""
    for sev, color in SEVERITY_COLOR.items():
        n = counts.get(sev, 0)
        stat_boxes += f'''
        <div class="stat-box" data-filter-sev="{sev}">
          <div class="stat-num" style="color:{color}">{n}</div>
          <div class="stat-label">{sev}</div>
        </div>'''

    cat_boxes = ""
    for c, icon in CATEGORY_ICON.items():
        if c == "other":
            continue
        n = cats.get(c, 0)
        cat_boxes += f'''
        <div class="cat-box" data-filter-cat="{c}">
          <div class="cat-icon">{icon}</div>
          <div class="cat-num">{n}</div>
          <div class="cat-label">{c.capitalize()}</div>
        </div>'''

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>Weekly Vulnerability Report</title>
<link rel="preconnect" href="https://fonts.googleapis.com"/>
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet"/>
<style>
  :root {{
    --bg:       #0d0f14;
    --surface:  #13161e;
    --surface2: #1a1e28;
    --border:   #252a38;
    --text:     #e2e6f0;
    --muted:    #6b7491;
    --accent:   #4f8ef7;
    --radius:   10px;
  }}
  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background: var(--bg);
    color: var(--text);
    font-family: 'Syne', sans-serif;
    min-height: 100vh;
    padding: 0 0 60px;
  }}

  /* ─ Header ─ */
  .header {{
    background: linear-gradient(135deg, #0d1526 0%, #0d0f14 60%);
    border-bottom: 1px solid var(--border);
    padding: 36px 48px 28px;
    position: relative;
    overflow: hidden;
  }}
  .header::before {{
    content: '';
    position: absolute;
    inset: 0;
    background: radial-gradient(ellipse 60% 80% at 80% 50%, rgba(79,142,247,.07) 0%, transparent 70%);
  }}
  .header-top {{
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 12px;
  }}
  .header h1 {{
    font-size: 2rem;
    font-weight: 800;
    letter-spacing: -0.5px;
    line-height: 1.1;
  }}
  .header h1 span {{ color: var(--accent); }}
  .header-meta {{
    font-family: 'JetBrains Mono', monospace;
    font-size: .75rem;
    color: var(--muted);
    line-height: 1.8;
    text-align: right;
  }}
  .header-sub {{
    margin-top: 6px;
    color: var(--muted);
    font-size: .9rem;
    font-weight: 400;
  }}

  /* ─ Stats ─ */
  .stats-section {{
    padding: 28px 48px 0;
  }}
  .stats-row {{
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
    margin-bottom: 16px;
  }}
  .stat-box, .cat-box {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 16px 22px;
    cursor: pointer;
    transition: border-color .18s, transform .18s;
    min-width: 90px;
    text-align: center;
  }}
  .stat-box:hover, .cat-box:hover {{
    border-color: var(--accent);
    transform: translateY(-2px);
  }}
  .stat-box.active, .cat-box.active {{
    border-color: var(--accent);
    background: rgba(79,142,247,.08);
  }}
  .stat-num {{ font-size: 1.8rem; font-weight: 800; line-height: 1; }}
  .stat-label {{ font-size: .7rem; color: var(--muted); margin-top: 4px; letter-spacing: .08em; text-transform: uppercase; }}
  .cat-icon {{ font-size: 1.4rem; }}
  .cat-num {{ font-size: 1.4rem; font-weight: 700; margin-top: 4px; }}
  .cat-label {{ font-size: .7rem; color: var(--muted); margin-top: 2px; text-transform: uppercase; letter-spacing: .08em; }}

  /* ─ Toolbar ─ */
  .toolbar {{
    padding: 20px 48px;
    display: flex;
    gap: 12px;
    align-items: center;
    flex-wrap: wrap;
    border-bottom: 1px solid var(--border);
  }}
  .total-tag {{
    font-family: 'JetBrains Mono', monospace;
    font-size: .8rem;
    color: var(--muted);
    margin-left: auto;
  }}
  .filter-btn {{
    background: var(--surface2);
    border: 1px solid var(--border);
    color: var(--text);
    border-radius: 6px;
    padding: 6px 14px;
    font-family: 'Syne', sans-serif;
    font-size: .8rem;
    cursor: pointer;
    transition: background .15s, border-color .15s;
  }}
  .filter-btn:hover {{ border-color: var(--accent); }}
  .filter-btn.active {{
    background: var(--accent);
    border-color: var(--accent);
    color: #fff;
  }}
  input[type=search] {{
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 6px;
    color: var(--text);
    font-family: 'JetBrains Mono', monospace;
    font-size: .8rem;
    padding: 6px 14px;
    width: 220px;
    outline: none;
  }}
  input[type=search]:focus {{ border-color: var(--accent); }}

  /* ─ Cards ─ */
  .cards-wrap {{ padding: 24px 48px; display: flex; flex-direction: column; gap: 14px; }}
  .card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    display: flex;
    overflow: hidden;
    transition: border-color .18s, transform .18s;
    animation: fadeIn .3s ease both;
  }}
  .card:hover {{ border-color: rgba(79,142,247,.4); transform: translateX(3px); }}
  @keyframes fadeIn {{ from {{ opacity:0; transform:translateY(8px) }} to {{ opacity:1; transform:none }} }}
  .card-stripe {{ width: 4px; flex-shrink: 0; }}
  .card-body {{ padding: 16px 20px; flex: 1; min-width: 0; }}
  .card-header {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    margin-bottom: 8px;
  }}
  .card-left {{ display: flex; gap: 6px; align-items: center; flex-wrap: wrap; }}
  .card-meta {{ display: flex; gap: 8px; font-size: .72rem; color: var(--muted); font-family: 'JetBrains Mono', monospace; }}
  .badge {{
    font-size: .68rem;
    font-weight: 700;
    padding: 2px 8px;
    border-radius: 4px;
    color: #fff;
    letter-spacing: .06em;
    font-family: 'JetBrains Mono', monospace;
  }}
  .pill {{
    font-size: .7rem;
    padding: 2px 8px;
    border-radius: 20px;
    font-weight: 600;
    background: var(--surface2);
    border: 1px solid var(--border);
    color: var(--muted);
  }}
  .pill-linux     {{ border-color: #f7c94f44; color: #f7c94f; }}
  .pill-kubernetes {{ border-color: #4f8ef744; color: #4f8ef7; }}
  .pill-openshift {{ border-color: #ff6b3544; color: #ff6b35; }}
  .card-title {{
    font-size: .92rem;
    font-weight: 700;
    margin-bottom: 6px;
    line-height: 1.4;
  }}
  .card-title a {{ color: var(--text); text-decoration: none; }}
  .card-title a:hover {{ color: var(--accent); }}
  .card-desc {{
    font-size: .8rem;
    color: var(--muted);
    line-height: 1.6;
    margin-bottom: 10px;
    font-family: 'JetBrains Mono', monospace;
  }}
  .card-footer {{ display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }}
  .score-wrap {{
    display: flex; align-items: center; gap: 8px;
    flex: 0 0 160px;
  }}
  .score-bar {{
    height: 4px;
    border-radius: 2px;
    transition: width .4s ease;
  }}
  .score-num {{ font-family: 'JetBrains Mono', monospace; font-size: .78rem; color: var(--muted); white-space: nowrap; }}
  .score-na {{ font-family: 'JetBrains Mono', monospace; font-size: .78rem; color: var(--border); }}
  .refs {{ display: flex; gap: 8px; flex-wrap: wrap; }}
  .ref-link {{
    font-family: 'JetBrains Mono', monospace;
    font-size: .7rem;
    color: var(--accent);
    text-decoration: none;
    border: 1px solid rgba(79,142,247,.25);
    border-radius: 4px;
    padding: 1px 6px;
  }}
  .ref-link:hover {{ background: rgba(79,142,247,.1); }}

  /* ─ Empty state ─ */
  .empty {{ text-align: center; padding: 60px; color: var(--muted); font-size: .9rem; }}

  /* ─ Footer ─ */
  .footer {{
    text-align: center;
    padding: 20px;
    font-size: .75rem;
    color: var(--muted);
    font-family: 'JetBrains Mono', monospace;
    border-top: 1px solid var(--border);
    margin-top: 20px;
  }}

  @media(max-width:640px) {{
    .header, .stats-section, .toolbar, .cards-wrap {{ padding-left: 20px; padding-right: 20px; }}
    .header h1 {{ font-size: 1.4rem; }}
  }}
</style>
</head>
<body>

<div class="header">
  <div class="header-top">
    <div>
      <h1>Weekly <span>Vulnerability</span> Report</h1>
      <div class="header-sub">Linux · Kubernetes · OpenShift — last {days_back} days</div>
    </div>
    <div class="header-meta">
      Generated: {generated} UTC<br/>
      Sources: NVD, Kubernetes CVE Feed, Red Hat RHSA
    </div>
  </div>
</div>

<div class="stats-section">
  <div class="stats-row">{stat_boxes}</div>
  <div class="stats-row">{cat_boxes}</div>
</div>

<div class="toolbar">
  <button class="filter-btn active" data-sev="ALL">All Severities</button>
  <button class="filter-btn" data-sev="CRITICAL">Critical</button>
  <button class="filter-btn" data-sev="HIGH">High</button>
  <button class="filter-btn" data-sev="MEDIUM">Medium</button>
  <input type="search" id="search" placeholder="Search CVE, keyword…"/>
  <span class="total-tag" id="count-label">{total} entries</span>
</div>

<div class="cards-wrap" id="cards">
{cards_html}
</div>

<div class="empty" id="empty-state" style="display:none">No vulnerabilities match your filters.</div>

<div class="footer">
  Auto-generated by vuln-report · Data from NVD, Kubernetes Security Committee, Red Hat
</div>

<script>
  let activeSev = 'ALL';
  let activeCat = null;
  let searchQ   = '';

  const cards = Array.from(document.querySelectorAll('.card'));

  function applyFilters() {{
    let visible = 0;
    cards.forEach(c => {{
      const sev  = c.dataset.severity;
      const cats = c.dataset.cats.split(' ');
      const text = c.innerText.toLowerCase();
      const sevOk  = activeSev === 'ALL' || sev === activeSev;
      const catOk  = !activeCat || cats.includes(activeCat);
      const searchOk = !searchQ || text.includes(searchQ);
      const show = sevOk && catOk && searchOk;
      c.style.display = show ? '' : 'none';
      if (show) visible++;
    }});
    document.getElementById('count-label').textContent = visible + ' entries';
    document.getElementById('empty-state').style.display = visible === 0 ? '' : 'none';
  }}

  // Severity filter buttons
  document.querySelectorAll('.filter-btn[data-sev]').forEach(btn => {{
    btn.addEventListener('click', () => {{
      document.querySelectorAll('.filter-btn[data-sev]').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      activeSev = btn.dataset.sev;
      applyFilters();
    }});
  }});

  // Stat boxes (severity)
  document.querySelectorAll('.stat-box[data-filter-sev]').forEach(box => {{
    box.addEventListener('click', () => {{
      const sev = box.dataset.filterSev;
      activeSev = activeSev === sev ? 'ALL' : sev;
      document.querySelectorAll('.stat-box').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.filter-btn[data-sev]').forEach(b => b.classList.remove('active'));
      if (activeSev !== 'ALL') box.classList.add('active');
      else document.querySelector('.filter-btn[data-sev="ALL"]').classList.add('active');
      applyFilters();
    }});
  }});

  // Cat boxes
  document.querySelectorAll('.cat-box[data-filter-cat]').forEach(box => {{
    box.addEventListener('click', () => {{
      const cat = box.dataset.filterCat;
      activeCat = activeCat === cat ? null : cat;
      document.querySelectorAll('.cat-box').forEach(b => b.classList.remove('active'));
      if (activeCat) box.classList.add('active');
      applyFilters();
    }});
  }});

  // Search
  document.getElementById('search').addEventListener('input', e => {{
    searchQ = e.target.value.toLowerCase().trim();
    applyFilters();
  }});
</script>
</body>
</html>"""

    with open(HTML_FILE, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"  Report saved to {HTML_FILE} ({total} entries)")


if __name__ == "__main__":
    if not JSON_FILE.exists():
        print(f"ERROR: {JSON_FILE} not found. Run fetch_vulns.py first.")
        raise SystemExit(1)

    with open(JSON_FILE) as f:
        data = json.load(f)

    vulns = data.get("vulnerabilities", [])
    generate(vulns, data)
    print("Done.")
