import copy
import json
from datetime import date
from pathlib import Path

from auditpack.evaluate import Record, evaluate, ev_id, fieldwork_list, manifest
from demo import score

DATA = Path(__file__).parent.parent / "data"
LABELS = json.loads((DATA / "labels.json").read_text(encoding="utf-8"))


def rec():
    return Record(DATA)


def by_control(results):
    return {r.control: r for r in results}


def items(results, control):
    return {i.ref: i for i in by_control(results)[control].items}


def test_all_planted_issues_found_no_false():
    assert score(evaluate(rec()), LABELS) == (32, 0, 0)


def test_failed_then_passed_retest_counts():
    assert items(evaluate(rec()), "11.4.4")["F-02"].status == "ok"


def test_fix_on_exact_sla_day_is_within_sla():
    assert items(evaluate(rec()), "A.8.8")["F-09"].status == "ok"


def test_same_finding_different_frameworks():
    res = evaluate(rec())
    assert items(res, "6.3.3")["F-16"].status == "ok"      # 19 days ≤ PCI one month
    assert items(res, "A.8.8")["F-16"].status == "gap"     # policy SLA for critical is 15 days


def test_out_of_scope_and_non_significant_ignored():
    res = evaluate(rec())
    refs = {i.ref for r in res for i in r.items}
    assert not {"F-08", "PR-904", "C-MKT-1", "C-PAY-3"} & refs


def test_risk_acceptance_needs_named_approver():
    a = items(evaluate(rec()), "A.8.8")
    assert a["F-07"].status == "ok" and a["F-06"].status == "gap"


def test_as_of_replay_before_issues_is_clean():
    assert all(r.status == "MET" for r in evaluate(rec(), date(2026, 2, 28)))


def test_fixing_moves_items_to_the_right_state():
    r = rec()
    for f in r.findings:
        if f["id"] in ("F-05", "F-11"):
            f.update(fixed="2026-09-29", retests=[{"date": "2026-09-30", "result": "pass"}])
    a = items(evaluate(r), "A.8.8")
    assert a["F-05"].status == "ok"                                    # fixed inside its SLA
    assert (a["F-11"].status, a["F-11"].action) == ("gap", "document exception")  # fixed, but 40 days late


def test_rotation_required_not_just_removal():
    assert items(evaluate(rec()), "8.6.2")["F-13"].action == "rotate now"


def test_fieldwork_list_is_one_line_per_record_urgent_first():
    todo = fieldwork_list(evaluate(rec()))
    assert len({t[0] for t in todo}) == len(todo) == 15
    assert todo[0][3] == "fix now" and todo[-1][3] == "document exception"


def test_evidence_hash_detects_tampering():
    r = rec()
    _, root = manifest(r)
    r.findings[0]["fixed"] = "2026-02-23"
    assert manifest(r)[1] != root
    assert ev_id(r.findings[0]) != ev_id(rec().findings[0])
