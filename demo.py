"""Compile audit-period evidence from a continuous-testing record; score against planted gaps; replay month by month.

    python demo.py      # console summary + out/auditor_view.html + out/controls.csv + out/evidence_manifest.csv
"""
from __future__ import annotations

import csv
import html
import json
import sys
import time
from datetime import date, timedelta
from pathlib import Path

from auditpack.evaluate import Record, evaluate, fieldwork_list, manifest

HERE = Path(__file__).parent
OUT = HERE / "out"
COL = {"MET": "#1f7a4d", "AT_RISK": "#a86400", "GAP": "#b3261e", "ok": "#1f7a4d", "at_risk": "#a86400", "gap": "#b3261e"}


def month_ends(start: date, end: date) -> list[date]:
    out, d = [], start
    while d <= end:
        nxt = (d.replace(day=28) + timedelta(days=4)).replace(day=1)
        out.append(min(nxt - timedelta(days=1), end))
        d = nxt
    return out


def score(results, labels):
    tp = fp = fn = 0
    for r in results:
        got = {i.ref: i.status for i in r.items if i.status != "ok"}
        want = labels[r.control]
        tp += sum(1 for k, v in got.items() if want.get(k) == v)
        fp += sum(1 for k, v in got.items() if want.get(k) != v)
        fn += sum(1 for k, v in want.items() if got.get(k) != v)
    return tp, fp, fn


def auditor_view(rec, results, todo, timeline, root, bench) -> str:
    tp, fp, fn = bench
    names = {f["id"]: f"{f['title']} ({f['cwe']}, {f['asset']})" for f in rec.findings}
    rows = []
    for r in results:
        bad = [i for i in r.items if i.status != "ok"]
        good = len(r.items) - len(bad)
        li = "".join(f"<li><b style='color:{COL[i.status]}'>{i.status.upper()}</b> <span class=mono>{html.escape(i.ref)}</span>"
                     f"{(' ' + html.escape(names[i.ref])) if i.ref in names else ''} — {html.escape(i.detail)} "
                     f"<span class=ev>{' '.join(i.evidence)}</span></li>" for i in bad)
        rows.append(f"<tr><td class=nw>{r.framework}</td><td class=nw><b>{html.escape(r.control)}</b><div class=t>{html.escape(r.title)}</div></td>"
                    f"<td><span class=pill style='background:{COL[r.status]}'>{r.status.replace('_', ' ')}</span></td>"
                    f"<td><ul>{li}{f'<li class=ok>{good} item(s) evidenced OK</li>' if good else ''}</ul></td></tr>")
    tl = "".join(f"<tr><td class=nw>{d}</td>" + "".join(f"<td style='color:{COL[k]}'>{c[k]}</td>" for k in ("MET", "AT_RISK", "GAP")) + "</tr>"
                 for d, c in timeline)
    fix = "".join(f"<li><b>{a}</b> · <b class=mono>{html.escape(ref)}</b> — {html.escape(d)}<div class=t>affects {len(c)}: {html.escape(', '.join(c))}</div></li>"
                  for ref, c, d, a in todo)
    return f"""<!doctype html><meta charset=utf-8><title>Audit-period evidence</title>
<style>body{{font:14px/1.45 'Segoe UI',system-ui,sans-serif;margin:30px;color:#1d1d1f;background:#fafaf8;max-width:1500px}}
h1{{font-size:23px;margin:0 0 4px}}h2{{font-size:18px;margin:26px 0 8px}}.sub{{color:#666}}table{{border-collapse:collapse;width:100%;background:#fff}}
td,th{{border-top:1px solid #e5e5e0;padding:8px 10px;vertical-align:top;text-align:left}}ul{{margin:0;padding-left:18px}}
.pill{{color:#fff;border-radius:999px;padding:2px 10px;font-size:12px;font-weight:600;white-space:nowrap}}.t{{color:#777;font-size:12px}}
.ev{{font:11px Consolas,monospace;color:#777}}.ok{{color:#1f7a4d}}.nw{{white-space:nowrap}}.mono{{font-family:Consolas,monospace}}
.cols{{display:grid;grid-template-columns:1.25fr 1fr;gap:26px}}</style>
<h1>Audit-period evidence · {rec.start} → {rec.end}</h1>
<div class=sub>Fictional fintech "Ledgerline" · {len(rec.findings)} findings, {len(rec.changes)} changes, {len(rec.runs)} test runs, {len(rec.prs)} PRs ·
benchmark vs planted issues: {tp} found, {fp} false, {fn} missed · evidence root hash <span class=mono>{root[:16]}…</span></div>
<h2>Controls</h2><table>{''.join(rows)}</table>
<div class=cols><div><h2>Before fieldwork: {len(todo)} records to act on</h2><ol>{fix}</ol></div>
<div><h2>Control health, month by month (as-of replay)</h2><table><tr><th>as of</th><th>MET</th><th>AT RISK</th><th>GAP</th></tr>{tl}</table></div></div>
<p class=sub>Control mapping is an engineering aid, not an audit opinion. Synthetic data. Unofficial prototype by Kushagra Pratap Singh. Not affiliated with Parameter.</p>"""


def main() -> int:
    t0 = time.perf_counter()
    rec = Record(HERE / "data")
    labels = json.loads((HERE / "data" / "labels.json").read_text(encoding="utf-8"))
    results = evaluate(rec)

    print(f"\n== audit period {rec.start} → {rec.end}: {len(rec.findings)} findings · {len(rec.changes)} changes · "
          f"{len(rec.runs)} test runs · {len(rec.prs)} PRs\n")
    for r in results:
        print(f"  {r.framework:<15} {r.control:<22} {r.status:<8} {r.title}")
        for i in r.items:
            if i.status != "ok":
                print(f"  {'':47}{i.status.upper():<8} {i.detail}")

    tp, fp, fn = score(results, labels)
    print(f"\n== benchmark vs {tp + fn} planted control issues: {tp} found, {fp} false, {fn} missed")

    todo = fieldwork_list(results)
    print(f"\n== before fieldwork: {len(todo)} underlying records behind every open item in {len(results)} controls")
    for ref, ctrls, detail, action in todo:
        print(f"  {action:<30} {ref:<26} affects {len(ctrls)}: {', '.join(ctrls)}")

    timeline = []
    for d in month_ends(rec.start, rec.end):
        c = {"MET": 0, "AT_RISK": 0, "GAP": 0}
        for r in evaluate(rec, d):
            c[r.status] += 1
        timeline.append((d, c))
    print("\n== as-of replay (MET / AT_RISK / GAP):  " + "  ".join(f"{d:%b} {c['MET']}/{c['AT_RISK']}/{c['GAP']}" for d, c in timeline))

    OUT.mkdir(exist_ok=True)
    rows, root = manifest(rec)
    with open(OUT / "evidence_manifest.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["evidence_id", "kind", "sha256"])
        w.writerows(rows)
        w.writerow(["ROOT", "", root])
    with open(OUT / "controls.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["framework", "control", "title", "status", "item", "item_status", "detail", "evidence"])
        for r in results:
            for i in r.items:
                w.writerow([r.framework, r.control, r.title, r.status, i.ref, i.status, i.detail, " ".join(i.evidence)])
    (OUT / "auditor_view.html").write_text(auditor_view(rec, results, todo, timeline, root, (tp, fp, fn)), encoding="utf-8")
    print(f"\nevidence: {len(rows)} records, root {root[:16]}…  →  out/auditor_view.html, out/controls.csv, out/evidence_manifest.csv"
          f"  ({time.perf_counter() - t0:.2f}s)")
    return 0 if fp == fn == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
