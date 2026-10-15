import json, sys
from datetime import date
from html import escape
from pathlib import Path

OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("output")
ORDER = ["Critical", "High", "Medium", "Low"]

CSS = """
body{font-family:Segoe UI,Arial,sans-serif;margin:0;background:#f5f6f8;color:#1f2933}
main{max-width:1000px;margin:0 auto;padding:32px 20px}
h1{margin:0 0 4px;font-size:26px} h2{margin:32px 0 12px;font-size:18px}
.sub{color:#52606d;font-size:14px}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-top:20px}
.card{background:#fff;border:1px solid #e4e7eb;border-radius:8px;padding:14px 16px}
.card b{display:block;font-size:28px} .card span{font-size:13px;color:#52606d}
table{width:100%;border-collapse:collapse;background:#fff;border:1px solid #e4e7eb;font-size:14px}
th,td{text-align:left;padding:9px 10px;border-bottom:1px solid #e4e7eb;vertical-align:top}
th{background:#f0f2f5;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:12px;font-weight:600;color:#fff}
.critical{background:#c0392b}.high{background:#d35400}.medium{background:#b7791f}.low{background:#2e86c1}
.bar{display:flex;align-items:center;gap:10px;margin:6px 0;font-size:14px}
.bar .lbl{width:70px}.bar .fill{height:16px;border-radius:3px}.bar .n{font-weight:600}
.alert{background:#fff4e5;border:1px solid #f5c57a;border-radius:8px;padding:10px 14px;margin-top:16px;font-size:14px}
.muted{color:#52606d;font-size:13px}
@media print{body{background:#fff}.card,table{border-color:#999}}
"""


def load(name, default):
    p = OUT / name
    return json.loads(p.read_text(encoding="utf-8")) if p.exists() else default


def badge(sev):
    return f'<span class="badge {sev.lower()}">{escape(sev)}</span>'


def evidence(f):
    return "<br>".join(
        f"{escape(p)} &larr; {escape(', '.join(r))}"
        for p, r in f["granted_by_roles"].items()
    )


def sort_key(f):
    s = f["severity"]
    return (ORDER.index(s) if s in ORDER else 9, f["user_id"], f["rule_id"])


def finding_row(f):
    inherent = f.get("inherent_severity", f["severity"])
    sev = badge(f["severity"])
    if inherent != f["severity"]:
        sev = badge(inherent) + " &rarr; " + sev
    status = escape(f.get("status", "Open"))
    if f.get("control"):
        status += "<br><span class='muted'>" + escape(f["control"]) + "</span>"
    return (
        "<tr>"
        f"<td>{escape(f['user_id'])}<br><span class='muted'>{escape(f['department'])}</span></td>"
        f"<td>{escape(f['rule_id'])}<br><span class='muted'>{escape(f['description'])}</span></td>"
        f"<td>{sev}</td><td>{status}</td><td>{evidence(f)}</td>"
        "</tr>"
    )


def bars(by_sev):
    top = max(by_sev.values(), default=1) or 1
    out = []
    for s in ORDER:
        n = by_sev.get(s, 0)
        out.append(
            f"<div class='bar'><span class='lbl'>{s}</span>"
            f"<span class='fill {s.lower()}' style='width:{n / top * 300:.0f}px'></span>"
            f"<span class='n'>{n}</span></div>"
        )
    return "".join(out)


def main():
    findings = sorted(load("findings.json", []), key=sort_key)
    summary = load("summary.json", {})
    suppressed = load("suppressed.json", [])
    by_status = summary.get("by_status", {})
    expired = [f for f in findings if f.get("status") == "Exception expired"]

    cards = [
        (summary.get("users_analyzed", 0), "Users analyzed"),
        (summary.get("users_with_findings", 0), "Users with findings"),
        (summary.get("total_findings", len(findings)), "Total findings"),
        (by_status.get("Mitigated", 0), "Mitigated by control"),
        (len(expired), "Expired exceptions"),
        (len(suppressed), "Suppressed (no shared org unit)"),
    ]
    cards_html = "".join(
        f"<div class='card'><b>{n}</b><span>{label}</span></div>" for n, label in cards
    )

    alert = ""
    if expired:
        items = ", ".join(
            f"{escape(f['user_id'])} / {escape(f['rule_id'])} ({escape(f.get('control', ''))})"
            for f in expired
        )
        alert = (
            "<div class='alert'><b>Action needed:</b> exception expired for "
            + items + ". Severity reverted to its original level.</div>"
        )

    if findings:
        findings_html = (
            "<table><tr><th>User</th><th>Rule</th><th>Severity</th>"
            "<th>Status / control</th><th>Evidence (permission &larr; role)</th></tr>"
            + "".join(finding_row(f) for f in findings) + "</table>"
        )
    else:
        findings_html = "<p>No findings.</p>"

    ranked = summary.get("riskiest_users", [])
    ranked_html = ""
    if ranked:
        rows = "".join(
            f"<tr><td>{escape(r['user_id'])}</td><td>{r['risk_score']}</td></tr>" for r in ranked
        )
        ranked_html = (
            "<h2>Riskiest users</h2><table><tr><th>User</th><th>Risk score</th></tr>"
            + rows + "</table>"
        )

    supp_html = ""
    if suppressed:
        rows = "".join(
            f"<tr><td>{escape(f['user_id'])}</td><td>{escape(f['rule_id'])}</td>"
            f"<td>{evidence(f)}</td></tr>"
            for f in suppressed
        )
        supp_html = (
            "<h2>Suppressed findings</h2>"
            "<p class='muted'>Both permissions exist, but never in the same organizational "
            "unit, so the rule's same-org condition is not met. Listed for audit transparency.</p>"
            "<table><tr><th>User</th><th>Rule</th><th>Evidence</th></tr>" + rows + "</table>"
        )

    bars_html = bars(summary.get("by_severity", {}))
    page = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SoD Analysis Report</title><style>{CSS}</style></head><body><main>
<h1>Segregation of Duties Analysis Report</h1>
<div class="sub">Generated {date.today().isoformat()} from {escape(str(OUT))}/ &middot; synthetic demonstration data</div>
<div class="cards">{cards_html}</div>
{alert}
<h2>Findings by effective severity</h2>{bars_html}
<h2>Findings</h2>{findings_html}
{ranked_html}
{supp_html}
<h2>Method and limitations</h2>
<p class="muted">Effective permissions are the union of all assigned roles. A rule fires when all
its permissions are present (and, where required, share an organizational unit). Compensating
controls can lower severity but never raise it; expired controls revert. Rules, permission names
and risk-score weights are illustrative and must be validated against the organization's
processes and risk policy before any real use.</p>
</main></body></html>"""

    (OUT / "report.html").write_text(page, encoding="utf-8")
    print(f"Report written to {OUT / 'report.html'}")


if __name__ == "__main__":
    main()