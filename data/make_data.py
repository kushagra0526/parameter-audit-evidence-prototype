"""Synthetic continuous-testing record for a fictional fintech ("Ledgerline"), with planted control gaps (labels.json).

Finding titles are generic weakness names with CWE ids only.
"""
import json
from datetime import date, timedelta
from pathlib import Path

HERE = Path(__file__).parent
START, END = date(2026, 1, 1), date(2026, 9, 30)

policy = {"audit_period": [str(START), str(END)], "sla_days": {"critical": 15, "high": 30, "medium": 90, "low": 180},
          "retest_after_change_days": 30, "test_cadence_days": 30, "patch_critical_days": 30, "due_soon_days": 7}

assets = [
    {"id": "payments-api", "pci": True, "in_scope": True},
    {"id": "card-vault", "pci": True, "in_scope": True},
    {"id": "checkout-web", "pci": True, "in_scope": True},
    {"id": "admin-portal", "in_scope": True},
    {"id": "claims-api", "in_scope": True},
    {"id": "marketing-site"},  # out of scope: anything here must be ignored
]


def f(id, asset, source, title, cwe, sev, found, fixed=None, retests=(), **kw):
    return {"id": id, "asset": asset, "source": source, "title": title, "cwe": cwe, "severity": sev, "found": found,
            "fixed": fixed, "retests": [{"date": d, "result": r} for d, r in retests], **kw}


findings = [
    f("F-01", "payments-api", "pentest", "Broken object-level authorization on order lookup", "CWE-639", "critical", "2026-02-20", "2026-02-24", [("2026-02-25", "pass")]),
    f("F-02", "card-vault", "pentest", "Missing rate limiting on verification endpoint", "CWE-307", "high", "2026-03-10", "2026-03-28",
      [("2026-03-29", "fail"), ("2026-04-05", "pass")]),                     # failed retest, then passed → fine
    f("F-03", "checkout-web", "pentest", "Injection in search filter", "CWE-89", "critical", "2026-06-02", "2026-06-06"),  # no retest
    f("F-04", "payments-api", "pentest", "Improper access control on refund endpoint", "CWE-284", "high", "2026-07-01"),  # open 91 d
    f("F-05", "admin-portal", "pentest", "Cross-site request forgery on settings form", "CWE-352", "high", "2026-09-04"),  # due in 4 d
    f("F-06", "admin-portal", "pentest", "Verbose error messages", "CWE-209", "medium", "2026-03-01", risk_accepted={"by": None, "date": "2026-03-15"}),
    f("F-07", "claims-api", "pentest", "Missing clickjacking protection", "CWE-1021", "medium", "2026-04-01",
      risk_accepted={"by": "CISO (J. Rivera)", "date": "2026-04-03"}),
    f("F-08", "marketing-site", "pentest", "Cross-site scripting in comments", "CWE-79", "critical", "2026-05-01"),  # out of scope
    f("F-09", "claims-api", "pentest", "Missing authorization on claim export", "CWE-862", "high", "2026-05-05", "2026-06-04",
      [("2026-06-05", "pass")]),                                              # fixed on exactly day 30 → within SLA
    f("F-10", "checkout-web", "pr_review", "Unvalidated input in coupon handler", "CWE-20", "medium", "2026-04-12", "2026-04-12"),
    f("F-11", "card-vault", "cloud", "Storage bucket allows public read", "CWE-732", "critical", "2026-08-20"),  # open 41 d
    f("F-12", "payments-api", "cloud", "Network rule open to the internet on admin port", "CWE-284", "high", "2026-01-15", "2026-01-20"),
    f("F-13", "payments-api", "secrets", "Hard-coded database password in config", "CWE-798", "high", "2026-03-03", "2026-03-04", rotated=False),
    f("F-14", "claims-api", "secrets", "API key in repository history", "CWE-798", "high", "2026-05-20", "2026-05-21", rotated=True),
    f("F-15", "checkout-web", "dependency", "Image library with critical CVE", "CWE-1395", "critical", "2026-04-01", "2026-05-15"),  # 44 d
    f("F-16", "payments-api", "dependency", "HTTP client with critical CVE", "CWE-1395", "critical", "2026-08-01", "2026-08-20"),  # 19 d: PCI ok, policy SLA 15 not
    f("F-17", "claims-api", "dependency", "XML parser with high CVE", "CWE-1395", "high", "2026-06-10", "2026-06-30"),
]

changes = [
    {"id": "C-PAY-1", "asset": "payments-api", "date": "2026-02-15", "significant": True, "desc": "new payout provider"},
    {"id": "C-PAY-2", "asset": "payments-api", "date": "2026-05-12", "significant": True, "desc": "auth service migration"},
    {"id": "C-PAY-3", "asset": "payments-api", "date": "2026-06-01", "significant": False, "desc": "copy change"},
    {"id": "C-VLT-1", "asset": "card-vault", "date": "2026-08-01", "significant": True, "desc": "HSM key rotation flow"},
    {"id": "C-CHK-1", "asset": "checkout-web", "date": "2026-09-05", "significant": True, "desc": "new wallet checkout"},
    {"id": "C-CLM-1", "asset": "claims-api", "date": "2026-06-15", "significant": True, "desc": "bulk export"},
    {"id": "C-MKT-1", "asset": "marketing-site", "date": "2026-04-01", "significant": True, "desc": "CMS upgrade"},
]


def schedule(asset, first, skip=None, extra=(), stop=None):
    d, out = first, []
    while d <= END:
        if not (skip and skip[0] < d < skip[1]) and not (stop and d > stop):
            out.append(d)
        d += timedelta(days=14)
    out = sorted(set(out) | set(extra))
    return [{"id": f"R-{asset[:3].upper()}-{i:02d}", "asset": asset, "date": str(x), "kind": "continuous"} for i, x in enumerate(out, 1)]


runs = (schedule("payments-api", date(2026, 1, 2), skip=(date(2026, 5, 8), date(2026, 7, 31)))
        + schedule("card-vault", date(2026, 1, 9))
        + schedule("checkout-web", date(2026, 1, 7), stop=date(2026, 8, 26), extra=[date(2026, 9, 3)])
        + schedule("admin-portal", date(2026, 1, 5), skip=(date(2026, 6, 20), date(2026, 9, 3)))
        + schedule("claims-api", date(2026, 1, 12)))


def prev_run(asset, before):
    return max(date.fromisoformat(r["date"]) for r in runs if r["asset"] == asset and date.fromisoformat(r["date"]) < before)


prs, n = [], 800
for a in ["payments-api", "card-vault", "checkout-web", "admin-portal", "claims-api", "marketing-site"]:
    for k in range(8):
        n += 1
        prs.append({"id": f"PR-{n}", "asset": a, "merged": str(START + timedelta(days=11 + 31 * k)), "reviewed_by": "sentinel"})
for i, d in enumerate(["2026-07-14", "2026-07-15", "2026-08-02"], 1):
    prs.append({"id": f"PR-90{i}", "asset": "checkout-web", "merged": d, "reviewed_by": None})   # merged unreviewed
prs.append({"id": "PR-904", "asset": "marketing-site", "merged": "2026-07-20", "reviewed_by": None})  # out of scope

pay_gap = f"payments-api:{prev_run('payments-api', date(2026, 7, 31))}"
adm_gap = f"admin-portal:{prev_run('admin-portal', date(2026, 9, 3))}"
labels = {  # control → {ref: expected status} for every non-ok item
    "11.4.2/11.4.3": {"C-PAY-2": "gap", "C-CHK-1": "at_risk"},
    "11.4.4": {"F-03": "gap", "F-04": "gap"},
    "6.3.3": {"F-15": "gap"},
    "8.6.2": {"F-13": "gap"},
    "6.2.3": {"PR-901": "gap", "PR-902": "gap", "PR-903": "gap"},
    "2.2": {"F-11": "gap"},
    "A.8.8": {"F-04": "gap", "F-05": "at_risk", "F-06": "gap", "F-11": "gap", "F-15": "gap", "F-16": "gap"},
    "A.8.9": {"F-11": "gap"},
    "A.8.29": {"PR-901": "gap", "PR-902": "gap", "PR-903": "gap"},
    "A.5.17": {"F-13": "gap"},
    "CC7.1": {pay_gap: "gap", adm_gap: "gap"},
    "CC8.1": {"C-PAY-2": "gap", "C-CHK-1": "at_risk"},
    "§164.308(a)(1)(ii)(B)": {"F-04": "gap", "F-05": "at_risk", "F-11": "gap", "F-15": "gap", "F-16": "gap"},
    "§164.308(a)(8)": {pay_gap: "gap", adm_gap: "gap"},
}

if __name__ == "__main__":
    for name, obj in [("policy", policy), ("assets", assets), ("findings", findings), ("changes", changes),
                      ("test_runs", runs), ("prs", prs), ("labels", labels)]:
        (HERE / f"{name}.json").write_text(json.dumps(obj, indent=1), encoding="utf-8")
    print(f"{len(findings)} findings, {len(changes)} changes, {len(runs)} test runs, {len(prs)} PRs, "
          f"{sum(len(v) for v in labels.values())} planted control issues")
