"""
keysentry/report.py
───────────────────
Export audit results to JSON, CSV, and HTML.

Author: Prasad
"""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from keysentry.core import SSHKey, summary_stats


# ─────────────────────────────────────────────────────────────────────────────
# JSON
# ─────────────────────────────────────────────────────────────────────────────

def export_json(keys: list[SSHKey], output: Optional[Path] = None) -> str:
    stats = summary_stats(keys)
    data = {
        "generated_at": datetime.now().isoformat(),
        "summary": stats,
        "keys": [k.to_dict() for k in keys],
    }
    text = json.dumps(data, indent=2)
    if output:
        output.write_text(text, encoding="utf-8")
    return text


# ─────────────────────────────────────────────────────────────────────────────
# CSV
# ─────────────────────────────────────────────────────────────────────────────

def export_csv(keys: list[SSHKey], output: Optional[Path] = None) -> str:
    buf = io.StringIO()
    fields = [
        "path", "key_type", "algorithm", "bits",
        "fingerprint_sha256", "fingerprint_md5",
        "comment", "has_passphrase",
        "age_days", "last_modified", "risk", "issues",
    ]
    writer = csv.DictWriter(buf, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    for k in keys:
        d = k.to_dict()
        d["issues"] = "; ".join(d["issues"])
        writer.writerow({f: d[f] for f in fields})
    text = buf.getvalue()
    if output:
        output.write_text(text, encoding="utf-8")
    return text


# ─────────────────────────────────────────────────────────────────────────────
# HTML
# ─────────────────────────────────────────────────────────────────────────────

_RISK_COLOR = {
    "LOW":      "#3fb950",
    "MEDIUM":   "#d29922",
    "HIGH":     "#f0883e",
    "CRITICAL": "#f85149",
}


def export_html(keys: list[SSHKey], output: Optional[Path] = None) -> str:
    stats = summary_stats(keys)
    now   = datetime.now().strftime("%Y-%m-%d %H:%M")

    def _badge(risk: str) -> str:
        color = _RISK_COLOR.get(risk, "#888")
        return f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:.8rem;font-weight:bold">{risk}</span>'

    def _issues_html(issues: list[str]) -> str:
        if not issues:
            return '<span style="color:#3fb950">No issues</span>'
        items = "".join(f"<li>{i}</li>" for i in issues)
        return f'<ul style="margin:0;padding-left:1.2rem;color:#e3b341">{items}</ul>'

    rows = ""
    for k in keys:
        bits_str   = str(k.bits) if k.bits else "—"
        pass_str   = ("✗ None" if k.has_passphrase is False
                      else "✓ Yes" if k.has_passphrase
                      else "—")
        pass_color = "#f85149" if k.has_passphrase is False else "#3fb950"
        rows += f"""
<tr>
  <td style="word-break:break-all;max-width:260px;font-size:.8rem">{k.path}</td>
  <td>{k.key_type}</td>
  <td>{k.algorithm}</td>
  <td>{bits_str}</td>
  <td style="font-family:monospace;font-size:.75rem">{k.fingerprint_sha256[:30]}…</td>
  <td style="color:{pass_color}">{pass_str}</td>
  <td>{k.age_label}</td>
  <td>{_badge(k.risk)}</td>
  <td>{_issues_html(k.issues)}</td>
</tr>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>KeySentry — SSH Key Audit Report</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:system-ui,sans-serif;background:#0d1117;color:#c9d1d9;padding:2rem}}
  h1{{color:#58a6ff;margin-bottom:.25rem}}
  .sub{{color:#8b949e;font-size:.9rem;margin-bottom:2rem}}
  .cards{{display:flex;gap:1rem;flex-wrap:wrap;margin-bottom:2rem}}
  .card{{background:#161b22;border:1px solid #30363d;border-radius:8px;
         padding:1rem 1.5rem;min-width:130px;text-align:center}}
  .card .num{{font-size:2rem;font-weight:700}}
  .card .lbl{{color:#8b949e;font-size:.8rem;margin-top:.2rem}}
  table{{width:100%;border-collapse:collapse;font-size:.85rem}}
  th{{background:#161b22;padding:.6rem 1rem;text-align:left;color:#8b949e;
      border-bottom:1px solid #30363d}}
  td{{padding:.55rem 1rem;border-bottom:1px solid #21262d;vertical-align:top}}
  tr:hover td{{background:#161b22}}
</style>
</head>
<body>
<h1>🔑 KeySentry — SSH Key Audit Report</h1>
<p class="sub">Generated: {now}</p>

<div class="cards">
  <div class="card"><div class="num">{stats['total']}</div><div class="lbl">Total Keys</div></div>
  <div class="card"><div class="num" style="color:#f85149">{stats['critical']}</div><div class="lbl">Critical</div></div>
  <div class="card"><div class="num" style="color:#f0883e">{stats['high']}</div><div class="lbl">High</div></div>
  <div class="card"><div class="num" style="color:#d29922">{stats['medium']}</div><div class="lbl">Medium</div></div>
  <div class="card"><div class="num" style="color:#3fb950">{stats['low']}</div><div class="lbl">Low</div></div>
  <div class="card"><div class="num" style="color:#f85149">{stats['no_passphrase']}</div><div class="lbl">No Passphrase</div></div>
  <div class="card"><div class="num" style="color:#d29922">{stats['old_keys']}</div><div class="lbl">Old (&gt;1yr)</div></div>
  <div class="card"><div class="num" style="color:#f85149">{stats['dsa_keys']}</div><div class="lbl">DSA (Weak)</div></div>
</div>

<table>
<thead><tr>
  <th>Path</th><th>Type</th><th>Algorithm</th><th>Bits</th>
  <th>Fingerprint (SHA256)</th><th>Passphrase</th>
  <th>Age</th><th>Risk</th><th>Issues</th>
</tr></thead>
<tbody>{rows}</tbody>
</table>
</body>
</html>"""

    if output:
        output.write_text(html, encoding="utf-8")
    return html
