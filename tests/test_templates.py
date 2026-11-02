"""Trusted prompt templates: the segment's template, residual scoring, the full-text backstop."""
import hashlib
import json

import pytest
import yaml
from fastapi.testclient import TestClient

from test_service import AUTH, ROOT, body, make
from wolfguard import policy as policymod
from wolfguard import store, templates
from wolfguard.scorer import ALLOW, BLOCK, CRITICAL, REVIEW, Scorer
from wolfguard.segments import Item, type_call

TR_QS = {"injection.indirect_presence": {"type": "noul", "instructions": "qa", "block": 0.7, "review": 0.5, "critical": 0.95},
         "content.role": {"type": "choice", "instructions": "qb", "criteria": {"data": "d", "command": "c", "example": "e"}, "risk": "command",
                          "block": 0.7, "review": 0.5, "critical": 0.95}}
UM_QS = {"manipulation.any": {"type": "choice", "instructions": "m", "criteria": {"benign": "b", "attack": "a"}, "risk": "attack", "block": 0.9, "review": 0.5}}


def pol(untrusted=True, **extra):
    """An app that scores its user messages as untrusted content (a bot around third-party text), or a standard one."""
    doc = {"version": "t", "model_revision": "r", "stages": {
        "tool_result": {"block_when": "all", "agree": "window", "window": {"tokens": 10, "overlap": 2}, "questions": TR_QS},
        "user_message": {"window": {"tokens": 10, "overlap": 2}, "questions": UM_QS}},
        "default_app": {"user_messages": "untrusted" if untrusted else "standard"}}
    doc.update(extra)
    return policymod.parse(doc)


def words(n, tag):
    return " ".join(f"{tag}{i}" for i in range(n))


def seg(parts, backstop="log", index=0, **tpl):
    """A user segment for parts [("c", constant) | ("s", slot)], as a gateway sends it."""
    full, exempt, residual, at = "", [], "", 0
    for kind, text in parts:
        b = text.encode()
        if kind == "c":
            exempt.append({"start": at, "end": at + len(b)})
            residual += templates.PLACEHOLDER
        else:
            residual += text
        full += text
        at += len(b)
    t = dict({"id": "pr-review", "version": 3, "full_text": full, "exempt": exempt, "backstop": backstop}, **tpl)
    return {"index": index, "role": "user", "text": residual, "template": t}


def score(stub, *segs, p=None, app_id=3):
    typed = type_call({"direction": "request", "segments": list(segs), "meta": {"app_id": app_id}})
    res, _ = Scorer(stub, p or pol()).score(typed)
    return res


def scored_texts(stub):
    return [scene for batch in stub.batches for scene, _ in batch]


HEAD = "You are reviewing a pull request. " + words(30, "rule") + "\n<diff>\n"
TAIL = "\n</diff>\n" + words(30, "report") + " Report only real defects, one per line."


# ---- parsing --------------------------------------------------------------------------------
def test_no_template_is_unchanged(stub):
    s = {"index": 0, "role": "user", "text": "plain words INJECT"}
    typed = type_call({"direction": "request", "segments": [s], "meta": {"app_id": 3}})
    assert typed.items == [Item("user_message", "plain words INJECT", 0)]
    it = typed.items[0]
    old = hashlib.sha256(json.dumps(["v", "app:3", it.stage, it.tool_name, it.text, it.goal, it.system], ensure_ascii=False).encode()).hexdigest()
    assert store.item_key("v", "app:3", it) == old                                # the store key of today
    r = score(stub, s, p=pol(untrusted=False))[0]
    assert r.scored_as == "" and r.backstop is None and r.decision != ALLOW       # the user-message questions, as before


def test_a_valid_template_parses():
    p = templates.parse(seg([("c", HEAD), ("s", "+ x := 1"), ("c", TAIL)]))
    t = p.template
    assert p.invalid == "" and p.text.startswith(templates.PLACEHOLDER) and p.text.endswith(templates.PLACEHOLDER)
    assert t.ref == "pr-review@3" and t.backstop == "log" and t.min_score is None and 0.9 < t.exempt_share < 1 and not t.mimicry


def test_offsets_are_bytes_on_utf8_boundaries():
    p = templates.parse(seg([("c", "Prüfe den Pull Request sorgfältig. " + words(5, "ä")), ("s", "naïve 日本語 slot"), ("c", "Ende der Prüfung, bitte gründlich.")]))
    assert p.template is not None
    full = p.template.full_text
    for (a, b), (s, e) in zip(p.template.exempt_chars, p.template.exempt):
        assert full[a:b].encode() == full.encode()[s:e]


@pytest.mark.parametrize("mutate,why", [
    (lambda t: t["exempt"].__setitem__(0, {"start": 0, "end": 10 ** 6}), "exempt offsets"),
    (lambda t: t["exempt"].__setitem__(1, {"start": 5, "end": 9}), "exempt offsets"),              # overlapping / unsorted
    (lambda t: t["exempt"].reverse(), "exempt offsets"),
    (lambda t: t["exempt"].__setitem__(0, {"start": 0, "end": 0}), "exempt offsets"),              # empty
    (lambda t: t["exempt"].__setitem__(0, {"start": 0, "end": 1}), "UTF-8"),                       # splits "é"
    (lambda t: t.__setitem__("backstop", "maybe"), "backstop mode"),
    (lambda t: t.__setitem__("backstop_min_score", 2), "backstop_min_score"),
    (lambda t: t.__setitem__("exempt", []), "no exempt range"),
    (lambda t: t.__setitem__("id", ""), "id or version"),
])
def test_invalid_templates_fail_closed(stub, mutate, why):
    s = seg([("c", "é" + HEAD), ("s", "slot text"), ("c", TAIL)])
    mutate(s["template"])
    p = templates.parse(s)
    assert p.template is None and why in p.invalid and p.text == s["template"]["full_text"]


def test_a_residual_that_does_not_match_fails_closed_and_scores_the_full_text(stub):
    s = seg([("c", "INJECT " + HEAD), ("s", "slot text"), ("c", TAIL)])
    s["text"] = s["text"].replace("slot text", "other text")            # the residual is not the full text minus the constants
    r = score(stub, s)[0]
    assert r.item.template is None and r.item.template_invalid == "residual does not match"
    assert r.item.text == s["template"]["full_text"] and "template.invalid" in [x.name for x in r.rules]
    assert r.decision != ALLOW                                          # INJECT in the "constant" is scored: nothing exempt


def test_a_template_on_a_tool_result_is_not_honoured(stub):
    s = dict(seg([("c", HEAD), ("s", "out"), ("c", TAIL)]), kind="tool_result", role="tool", tool_name="read")
    it = type_call({"direction": "request", "segments": [s]}).items[0]
    assert it.template is None and it.template_invalid == "not a user message" and it.text == s["template"]["full_text"]


# ---- scoring ----------------------------------------------------------------------------------
def test_the_residual_is_scored_as_untrusted_and_the_template_never_alone(stub):
    s = seg([("c", "INJECT " + HEAD), ("s", "+ x := 1"), ("c", TAIL)], backstop="off")
    r = score(stub, s)[0]
    assert r.scored_as == "tool_result" and r.decision == ALLOW and r.backstop is None
    texts = scored_texts(stub)
    assert texts and all("INJECT" not in t and "rule5" not in t for t in texts)  # no approved byte reached the model
    assert any(templates.PLACEHOLDER in t for t in texts)


def test_an_attack_in_a_slot_is_caught_by_the_residual(stub):
    r = score(stub, seg([("c", HEAD), ("s", "+ x := 1 INJECT"), ("c", TAIL)]))[0]
    assert r.decision == CRITICAL
    assert r.backstop is not None and r.backstop.decision == CRITICAL       # seen in both; reported once (service)


def test_backstop_skips_windows_of_approved_text_only(stub):
    # INJECT sits in the first constant, tens of tokens from any slot byte: only template windows see it.
    r = score(stub, seg([("c", "INJECT " + HEAD), ("s", "+ x := 1"), ("c", TAIL)]))[0]
    scored, skipped = r.backstop_windows
    assert skipped > 0 and scored > 0 and r.backstop.decision == ALLOW and r.decision == ALLOW
    assert all("INJECT" not in t for t in scored_texts(stub))


def test_backstop_scores_windows_that_straddle_a_slot(stub):
    # The same text next to the slot: a window holds both, so it counts.
    r = score(stub, seg([("c", HEAD + "INJECT"), ("s", " + x := 1"), ("c", TAIL)]))[0]
    assert r.decision == ALLOW and r.backstop.decision == CRITICAL


def test_slots_of_an_untrusted_app_are_untrusted_content(stub):
    p = pol()
    assert p.app(3).user_messages == "untrusted"
    r = score(stub, seg([("c", HEAD), ("s", "+ x := 1 LIKELY"), ("c", TAIL)]), p=p)[0]
    assert r.scored_as == "tool_result" and r.decision == REVIEW           # block demoted: only critical stops
    assert {q for b in stub.batches for _, q in b} == set(TR_QS)


def test_slots_of_a_standard_app_are_a_plain_user_message(stub):
    p = pol(untrusted=False)
    assert p.app(3).user_messages == "standard"
    r = score(stub, seg([("c", HEAD), ("s", "+ x := 1 INJECT"), ("c", TAIL)]), p=p)[0]
    assert r.scored_as == "" and r.decision == BLOCK                       # the user-message questions and tiers, not demoted
    assert {q for b in stub.batches for _, q in b} == set(UM_QS)
    assert all("rule5" not in t for t in scored_texts(stub))               # still no approved text on its own
    # The backstop follows suit: the user-message questions over windows holding slot bytes.
    r = score(stub, seg([("c", HEAD + "INJECT"), ("s", " + x := 1"), ("c", TAIL)]), p=p)[0]
    assert r.decision == ALLOW and r.backstop.scored_as == "" and r.backstop.decision == BLOCK


def test_a_standard_app_gets_user_message_backstop_findings(tmp_path):
    app, _, _ = svc(tmp_path, untrusted=False)
    c = TestClient(app)
    assert post(c, seg([("c", HEAD + "INJECT"), ("s", " + x := 1"), ("c", TAIL)])) == [("user_message.block", True, 0.95)]
    assert post(c, seg([("c", HEAD), ("s", "+ x := 1 INJECT"), ("c", TAIL)])) == [("user_message.block", False, 0.95)]


def test_mimicry_is_flagged_and_changes_nothing(stub):
    s = seg([("c", HEAD), ("s", "+ // " + HEAD[:40]), ("c", TAIL)])
    assert templates.parse(s).template.mimicry
    r = score(stub, s)[0]
    assert "template.mimicry" in [x.name for x in r.rules] and r.decision == ALLOW
    assert not templates.parse(seg([("c", HEAD), ("s", "+ // " + HEAD[:31]), ("c", TAIL)])).template.mimicry


def test_store_keys_follow_the_template():
    def key(s):
        return store.item_key("v", "app:3", type_call({"direction": "request", "segments": [s]}).items[0])
    base = seg([("c", HEAD), ("s", "+ x := 1"), ("c", TAIL)])
    k = key(base)
    assert k != key({"index": 0, "role": "user", "text": base["text"]})           # never the unmatched message's verdict
    for change in ({"version": 4}, {"backstop": "enforce"}, {"backstop_min_score": 0.9}):
        s = json.loads(json.dumps(base))
        s["template"].update(change)
        assert key(s) != k, change
    assert key(json.loads(json.dumps(base))) == k


# ---- the service: findings marked backstop, min score, the decision log -------------------------
def svc(tmp_path, untrusted=True):
    def edit(doc):
        for st in ("tool_result", "user_message"):
            doc["stages"][st]["window"] = {"tokens": 10, "overlap": 2}
        doc["default_app"] = dict(doc.get("default_app") or {}, user_messages="untrusted" if untrusted else "standard")
    return make(tmp_path, critical=True, edit=edit)


def post(c, s):
    r = c.post("/v1/classify", json=dict(body(s), detectors=["*"]), headers=AUTH)
    assert r.status_code == 200, r.text
    return [(f["detector"], f.get("backstop", False), f["score"]) for f in r.json()["findings"]]


def test_backstop_findings_are_marked_and_not_double_counted(tmp_path):
    app, _, logf = svc(tmp_path)
    c = TestClient(app)
    straddle = [("c", HEAD + "INJECT"), ("s", " + x := 1"), ("c", TAIL)]
    assert post(c, seg(straddle)) == [("user_message.critical", True, 0.95)]
    assert post(c, seg(straddle, backstop="off")) == []
    in_slot = [("c", HEAD), ("s", "+ x := 1 INJECT"), ("c", TAIL)]
    assert post(c, seg(in_slot)) == [("user_message.critical", False, 0.95)]            # once, by the residual
    rec = [json.loads(x) for x in logf.read_text().splitlines()][0]
    t = rec["template"]
    assert t["id"] == "pr-review@3" and t["backstop"] == "log" and t["backstop_finding"] == "critical" and t["backstop_windows"][0] > 0
    assert 0 < t["exempt_share"] < 1 and "preview" not in rec


def test_backstop_min_score_applies_to_enforced_findings(tmp_path):
    app, _, _ = svc(tmp_path)
    c = TestClient(app)
    straddle = [("c", HEAD + "INJECT"), ("s", " + x := 1"), ("c", TAIL)]
    assert post(c, seg(straddle, backstop="enforce", backstop_min_score=0.96)) == []
    assert post(c, seg(straddle, backstop="enforce", backstop_min_score=0.9)) == [("user_message.critical", True, 0.95)]
    assert post(c, seg(straddle, backstop="log", backstop_min_score=0.96)) == [("user_message.critical", True, 0.95)]   # logged anyway


def test_an_enforced_backstop_over_the_size_limit_is_unscanned(tmp_path):
    app, _, logf = svc(tmp_path)
    c = TestClient(app)
    big = [("c", HEAD + words(9000, "w")), ("s", " + x := 1"), ("c", TAIL)]
    assert post(c, seg(big, backstop="enforce")) == [("user_message.critical", True, 1.0)]
    assert post(c, seg(big, backstop="log")) == []
    assert json.loads(logf.read_text().splitlines()[-1])["template"]["backstop_unscanned"] is True


def test_an_invalid_template_is_logged(tmp_path):
    app, _, logf = svc(tmp_path)
    s = seg([("c", HEAD), ("s", "slot"), ("c", TAIL)])
    s["template"]["exempt"][0]["end"] += 1
    TestClient(app).post("/v1/classify", json=dict(body(s), detectors=["*"]), headers=AUTH)
    rec = json.loads(logf.read_text().splitlines()[-1])
    assert rec["template_invalid"] and "template.invalid" in rec["rules"] and "template" not in rec


# ---- the ack: "templates_handled" -----------------------------------------------------------------
def classify(c, *segs, detectors=("*",), app_id=3):
    b = dict(body(*segs, app_id=app_id), detectors=list(detectors))
    r = c.post("/v1/classify", json=b, headers=AUTH)
    assert r.status_code == 200, r.text
    return r.json()


CLEAN = [("c", HEAD), ("s", "+ x := 1"), ("c", TAIL)]
STRADDLE = [("c", HEAD + "INJECT"), ("s", " + x := 1"), ("c", TAIL)]


def test_no_template_no_ack_field(tmp_path):
    app, _, _ = svc(tmp_path)
    j = classify(TestClient(app), {"role": "user", "text": "plain words"})
    assert j == {"flagged": False, "findings": []}                      # byte for byte what it was


def test_handled_templates_are_acknowledged_even_when_clean_or_off(tmp_path):
    app, _, _ = svc(tmp_path)
    c = TestClient(app)
    j = classify(c, {"role": "user", "text": "plain"}, seg(CLEAN), seg(CLEAN, backstop="off"))
    assert j["templates_handled"] == [1, 2] and j["findings"] == []
    j = classify(c, seg(STRADDLE, backstop="enforce", backstop_min_score=0.9))
    assert j["templates_handled"] == [0] and [(f["segment_index"], f.get("backstop")) for f in j["findings"]] == [(0, True)]


def test_an_invalid_template_is_not_acknowledged_and_its_findings_are_ordinary(tmp_path):
    app, _, _ = svc(tmp_path, untrusted=False)
    s = seg(STRADDLE)
    s["template"]["exempt"][0]["end"] -= 1                               # the residual no longer matches
    j = classify(TestClient(app), s)
    assert j["templates_handled"] == []
    assert [(f["detector"], "backstop" in f) for f in j["findings"]] == [("user_message.block", False)]   # the full text, scored as today


def test_unscored_templates_are_not_acknowledged(tmp_path):
    app, _, _ = svc(tmp_path)
    c = TestClient(app)
    assert classify(c, seg(STRADDLE), detectors=["tool_result.block"]) == {"flagged": False, "findings": [], "templates_handled": []}

    def skip(doc):
        doc["apps"] = {"9": {"skip": True}}
    app2, _, _ = make(tmp_path / "skip", critical=True, edit=skip)
    assert classify(TestClient(app2), seg(STRADDLE), app_id=9)["templates_handled"] == []


def test_store_hits_are_acknowledged_and_pending_ones_are_not(tmp_path):
    from test_deferred import settle

    def deferred(doc):
        for st in ("tool_result", "user_message"):
            doc["stages"][st]["window"] = {"tokens": 10, "overlap": 2}
        doc["default_app"] = dict(doc.get("default_app") or {}, user_messages="untrusted")
        doc["enforcement"]["stages"]["user_message"] = {"mode": "deferred", "when_busy": "pass"}
        doc["enforcement"]["pending_min_age"] = 60
    app, _, _ = make(tmp_path, store=":memory:", critical=True, edit=deferred)
    with TestClient(app) as c:
        j = classify(c, seg(STRADDLE))
        assert j["templates_handled"] == [] and j["findings"] == []       # answered clean now, scored in the background
        settle(app)
        j = classify(c, seg(STRADDLE))                                    # from the store: the backstop ran
        assert j["templates_handled"] == [0] and [f.get("backstop") for f in j["findings"]] == [True]
