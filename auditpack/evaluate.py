"""Evaluate controls over an audit period from a continuous-testing record stream.

Every input record gets an evidence id (hash of its canonical JSON), and each control item cites the records behind it.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path

from .controls import CONTROLS, SEVERITY

D = date.fromisoformat


@dataclass
class Item:
    status: str  # ok | at_risk | gap
    ref: str
    detail: str
    evidence: list[str] = field(default_factory=list)
    action: str = ""  # fix now | due soon | document exception


@dataclass
class ControlResult:
    framework: str
    control: str
    title: str
    status: str  # MET | AT_RISK | GAP
    items: list[Item]


def ev_id(record: dict) -> str:
    return "EV-" + hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest()[:10]


class Record:
    def __init__(self, data_dir: Path):
        load = lambda n: json.loads((data_dir / f"{n}.json").read_text(encoding="utf-8"))
        self.policy = load("policy")
        self.assets = {a["id"]: a for a in load("assets")}
        self.findings = load("findings")
        self.changes = load("changes")
        self.runs = load("test_runs")
        self.prs = load("prs")
        self.start, self.end = map(D, self.policy["audit_period"])

    def scope(self, name: str) -> set[str]:
        return {k for k, a in self.assets.items() if a.get(name)}

    def evidence_index(self) -> dict[str, tuple[str, dict]]:
        idx = {}
        for kind, recs in (("finding", self.findings), ("change", self.changes), ("test_run", self.runs), ("pr", self.prs)):
            for r in recs:
                idx[ev_id(r)] = (kind, r)
        return idx


# ------------------------------------------------------------------ period checks

def _open_item(rec: Record, f: dict, as_of: date, evidence: list[str]) -> Item:
    sla = rec.policy["sla_days"][f["severity"]]
    age = (as_of - D(f["found"])).days
    if f.get("risk_accepted"):
        if f["risk_accepted"].get("by"):
            return Item("ok", f["id"], f"risk accepted by {f['risk_accepted']['by']} on {f['risk_accepted']['date']}", evidence)
        return Item("gap", f["id"], f"marked risk-accepted on {f['risk_accepted']['date']} with no named approver", evidence, "get sign-off")
    if age > sla:
        return Item("gap", f["id"], f"{f['severity']} open {age} days (SLA {sla})", evidence, "fix now")
    left = sla - age
    st = "at_risk" if left <= rec.policy["due_soon_days"] else "ok"
    return Item(st, f["id"], f"{f['severity']} open {age} days — SLA breach in {left} days", evidence, "due soon" if st == "at_risk" else "")


def _findings(rec, scope, as_of, sources=None, min_sev="low"):
    for f in rec.findings:
        if f["asset"] in scope and D(f["found"]) <= as_of and SEVERITY[f["severity"]] >= SEVERITY[min_sev] \
                and (sources is None or f["source"] in sources):
            yield f


def check_sla(rec, scope, as_of, sources=None, min="low"):
    out = []
    for f in _findings(rec, scope, as_of, sources, min):
        ev = [ev_id(f)]
        fixed = f.get("fixed") and D(f["fixed"]) <= as_of
        if not fixed:
            out.append(_open_item(rec, f, as_of, ev))
            continue
        took, sla = (D(f["fixed"]) - D(f["found"])).days, rec.policy["sla_days"][f["severity"]]
        out.append(Item("ok" if took <= sla else "gap", f["id"], f"{f['severity']} fixed in {took} days (SLA {sla})", ev, "" if took <= sla else "document exception"))
    return out


def check_retest(rec, scope, as_of):
    out = []
    for f in _findings(rec, scope, as_of, ["pentest"], "high"):
        ev = [ev_id(f)]
        if not (f.get("fixed") and D(f["fixed"]) <= as_of):
            out.append(_open_item(rec, f, as_of, ev))
            continue
        passes = [r for r in f.get("retests", []) if r["result"] == "pass" and D(f["fixed"]) <= D(r["date"]) <= as_of]
        if passes:
            out.append(Item("ok", f["id"], f"fixed {f['fixed']}, passing retest {passes[0]['date']}", ev))
        else:
            fails = [r["date"] for r in f.get("retests", []) if r["result"] == "fail"]
            why = f" (failed retests: {', '.join(fails)})" if fails else ""
            out.append(Item("gap", f["id"], f"fixed {f['fixed']} but no passing retest on record{why}", ev, "retest now"))
    return out


def check_patch(rec, scope, as_of):
    out, limit = [], rec.policy["patch_critical_days"]
    for f in _findings(rec, scope, as_of, ["dependency"], "critical"):
        ev = [ev_id(f)]
        end = D(f["fixed"]) if f.get("fixed") and D(f["fixed"]) <= as_of else None
        days = ((end or as_of) - D(f["found"])).days
        if end:
            out.append(Item("ok" if days <= limit else "gap", f["id"], f"critical patch applied after {days} days (limit {limit})", ev, "" if days <= limit else "document exception"))
        else:
            st = "gap" if days > limit else "at_risk" if limit - days <= rec.policy["due_soon_days"] else "ok"
            out.append(Item(st, f["id"], f"critical patch outstanding for {days} days (limit {limit})", ev, "fix now"))
    return out


def check_secrets(rec, scope, as_of):
    out = []
    for f in _findings(rec, scope, as_of, ["secrets"]):
        ev = [ev_id(f)]
        if not (f.get("fixed") and D(f["fixed"]) <= as_of):
            out.append(Item("gap", f["id"], "exposed credential still present", ev, "fix now"))
        elif not f.get("rotated"):
            out.append(Item("gap", f["id"], f"removed from code on {f['fixed']}, but no rotation of the credential on record", ev, "rotate now"))
        else:
            out.append(Item("ok", f["id"], f"removed {f['fixed']} and credential rotated", ev))
    return out


def check_pr_review(rec, scope, as_of):
    out = []
    for p in rec.prs:
        if p["asset"] in scope and rec.start <= D(p["merged"]) <= as_of:
            ok = bool(p.get("reviewed_by"))
            out.append(Item("ok" if ok else "gap", p["id"],
                            f"merged {p['merged']}, reviewed by {p['reviewed_by']}" if ok else f"merged {p['merged']} with no review on record",
                            [ev_id(p)], "" if ok else "retro-review + document"))
    return out


def _runs(rec, asset, as_of):
    return sorted((r for r in rec.runs if r["asset"] == asset and D(r["date"]) <= as_of), key=lambda r: r["date"])


def check_after_change(rec, scope, as_of):
    out, window = [], rec.policy["retest_after_change_days"]
    for c in rec.changes:
        if c["asset"] not in scope or not c.get("significant") or not (rec.start <= D(c["date"]) <= as_of):
            continue
        after = [r for r in _runs(rec, c["asset"], as_of) if D(c["date"]) <= D(r["date"]) <= D(c["date"]) + timedelta(days=window)]
        if after:
            out.append(Item("ok", c["id"], f"{c['asset']}: '{c['desc']}' ({c['date']}) → tested {after[0]['date']}", [ev_id(c), ev_id(after[0])]))
            continue
        due = D(c["date"]) + timedelta(days=window)
        if due < as_of:
            out.append(Item("gap", c["id"], f"{c['asset']}: '{c['desc']}' ({c['date']}) not tested within {window} days", [ev_id(c)], "test now + document exception"))
        else:
            left = (due - as_of).days
            st = "at_risk" if left <= rec.policy["due_soon_days"] else "ok"
            out.append(Item(st, c["id"], f"{c['asset']}: '{c['desc']}' ({c['date']}) — test due by {due} ({left} days)", [ev_id(c)], "due soon" if st == "at_risk" else ""))
    return out


def check_cadence(rec, scope, as_of):
    out, limit = [], rec.policy["test_cadence_days"]
    for a in sorted(scope):
        runs = _runs(rec, a, as_of)
        marks = [rec.start] + [D(r["date"]) for r in runs if D(r["date"]) >= rec.start] + [as_of]
        worst = None
        for prev, nxt in zip(marks, marks[1:]):
            if (nxt - prev).days > limit:
                ev = [ev_id(r) for r in runs if D(r["date"]) in (prev, nxt)]
                out.append(Item("gap", f"{a}:{prev}", f"{a}: no testing from {prev} to {nxt} ({(nxt - prev).days} days, limit {limit})", ev, "document exception"))
                worst = True
        if not worst:
            out.append(Item("ok", a, f"{a}: {len(runs)} test runs, longest gap ≤ {limit} days", [ev_id(r) for r in runs[-1:]]))
    return out


CHECKS = {"sla": check_sla, "retest": check_retest, "patch": check_patch, "secrets": check_secrets,
          "pr_review": check_pr_review, "after_change": check_after_change, "cadence": check_cadence}


def evaluate(rec: Record, as_of: date | None = None) -> list[ControlResult]:
    as_of = as_of or rec.end
    out = []
    for fw, cid, title, check, scope, opts in CONTROLS:
        items = CHECKS[check](rec, rec.scope(scope), as_of, **opts)
        st = "GAP" if any(i.status == "gap" for i in items) else "AT_RISK" if any(i.status == "at_risk" for i in items) else "MET"
        out.append(ControlResult(fw, cid, title, st, items))
    return out


ACTION_ORDER = ["fix now", "rotate now", "retest now", "due soon", "get sign-off", "test now + document exception",
                "retro-review + document", "document exception"]


def fieldwork_list(results: list[ControlResult]) -> list[tuple[str, list[str], str, str]]:
    """One line per underlying record (ref, controls it affects, detail, action), most urgent and widest first."""
    by: dict[str, tuple[list[str], str, str]] = {}
    for r in results:
        for i in r.items:
            if i.status != "ok":
                ctrls, detail, action = by.setdefault(i.ref, ([], i.detail, i.action))
                ctrls.append(f"{r.framework.split()[0]} {r.control}")
    return sorted(((ref, c, d, a) for ref, (c, d, a) in by.items()), key=lambda x: (ACTION_ORDER.index(x[3]), -len(x[1])))


def manifest(rec: Record) -> tuple[list[tuple[str, str, str]], str]:
    """Evidence rows (id, kind, sha256) and a root hash over all of them, so the pack is tamper-evident."""
    rows = []
    for eid, (kind, r) in sorted(rec.evidence_index().items()):
        rows.append((eid, kind, hashlib.sha256(json.dumps(r, sort_keys=True).encode()).hexdigest()))
    root = hashlib.sha256("".join(h for _, _, h in rows).encode()).hexdigest()
    return rows, root
