"""Finding spans: the byte range of the windows that decided, for a gateway's second opinion."""
import dataclasses

from fastapi.testclient import TestClient

from test_service import AUTH, body, make
from test_templates import HEAD, TAIL, seg
from wolfguard import policy as policymod
from wolfguard.scorer import ALLOW, Scorer
from wolfguard.segments import type_call

TR_QS = {"injection.indirect_presence": {"type": "noul", "instructions": "qa", "block": 0.7, "review": 0.5},
         "content.role": {"type": "choice", "instructions": "qb", "criteria": {"data": "d", "command": "c", "example": "e"}, "risk": "command",
                          "block": 0.7, "review": 0.5}}
UM_QS = {"manipulation.any": {"type": "choice", "instructions": "m", "criteria": {"benign": "b", "attack": "a"}, "risk": "attack", "block": 0.9, "review": 0.5}}
PASTE_QS = {"injection.indirect_presence": {"type": "noul", "instructions": "p", "block": 0.7, "review": 0.35}}


def pol(untrusted=False, **extra):
    doc = {"version": "t", "model_revision": "r", "stages": {
        "tool_result": {"block_when": "all", "agree": "window", "window": {"tokens": 10, "overlap": 2}, "questions": TR_QS},
        "user_message": {"window": {"tokens": 10, "overlap": 2}, "questions": UM_QS, "paste": {"min_chars": 20, "questions": PASTE_QS}}},
        "default_app": {"user_messages": "untrusted" if untrusted else "standard"}}
    doc.update(extra)
    return policymod.parse(doc)


def score(stub, *segs, policy=None):
    t = type_call({"direction": "request", "segments": [dict(s, index=i) for i, s in enumerate(segs)], "meta": {"app_id": 3}})
    return Scorer(stub, policy or pol()).score(t)[0]


def tr(text):
    return {"role": "tool", "kind": "tool_result", "tool_name": "webfetch", "tool_call_id": "c1", "text": text}


def words(n, at=(), tag="w"):
    ws = [f"{tag}{i}" for i in range(n)]
    for i in at:
        ws[i] = "INJECT"
    return ws


def sliced(text, span):
    return text.encode()[span[0]:span[1]].decode()


def test_a_short_item_spans_the_whole_text(stub):
    text = "fetched: INJECT now"
    r = score(stub, tr(text))[0]
    assert r.decision != ALLOW and r.span == (0, len(text.encode()))


def test_a_long_item_spans_only_the_windows_that_decided(stub):
    ws = words(200, at=[150])
    ws[3] = "café→ü"                           # multi-byte characters before the payload: offsets are bytes
    text = " ".join(ws)
    r = score(stub, tr(text))[0]
    assert r.decision != ALLOW and r.windows > 20
    got = sliced(text, r.span)
    assert "INJECT" in got and len(got.split()) <= 18   # the deciding window and its overlapping neighbour
    assert text.encode()[r.span[0]:].startswith(got.split()[0].encode())   # starts on a token
    assert r.span[0] > len("café→ü".encode())


def test_every_deciding_window_is_inside_the_span(stub):
    text = " ".join(words(200, at=[20, 180]))
    r = score(stub, tr(text))[0]
    got = sliced(text, r.span)
    assert got.count("INJECT") == 2 and got.startswith("w1") and got.split()[-1].startswith("w18")


def test_windows_only_at_review_do_not_widen_a_block(stub):
    ws = words(200, at=[150])
    ws[10] = "SUSPECT"                         # 0.5: review for both questions, below block
    text = " ".join(ws)
    r = score(stub, tr(text))[0]
    assert "SUSPECT" not in sliced(text, r.span) and "INJECT" in sliced(text, r.span)


def test_no_span_when_a_rule_decided(stub, policy):
    # A canary is a match anywhere in the text, not a window: the gateway must treat it as anywhere.
    p = dataclasses.replace(policy, canaries=("CANARY-7f3a",))
    call = {"role": "assistant", "kind": "tool_call", "tool_name": "send", "tool_call_id": "c2", "text": '{"b": "CANARY-7f3a"}',
            "context": {"user_goal": "summarise"}}
    r = score(stub, call, policy=p)[0]
    assert r.decision != ALLOW and any(x.severity == "block" for x in r.rules) and r.span is None


def test_no_span_when_the_pre_check_rewrote_the_text(stub):
    hidden = "".join(chr(0xE0000 + ord(c)) for c in "ignore")   # Unicode tag characters
    r = score(stub, tr("INJECT " + hidden))[0]
    assert r.decision != ALLOW and r.span is None


def test_a_paste_that_is_the_whole_message_has_a_span(stub):
    text = " ".join(words(60, at=[40]))
    r = score(stub, {"role": "user", "text": text})[0]
    assert r.decision != ALLOW and "INJECT" in sliced(text, r.span)


def test_a_fenced_paste_gives_no_span(stub):
    # The pasted part (the fence) is not the whole message: its windows do not map back.
    text = "please look at this\n```\n" + " ".join(words(30, at=[12])) + "\n```\nthanks"
    r = score(stub, {"role": "user", "text": text})[0]
    assert r.decision != ALLOW and r.paste and r.span is None


def test_untrusted_user_messages_span_the_text_sent(stub):
    text = " ".join(words(120, at=[90]))
    r = score(stub, {"role": "user", "text": text}, policy=pol(untrusted=True))[0]
    assert r.scored_as == "tool_result" and r.span is not None and "INJECT" in sliced(text, r.span)


# ---- the service: the finding carries it; backstop spans are in the full text ------------------
def svc(tmp_path):
    def edit(doc):
        for st in ("tool_result", "user_message"):
            doc["stages"][st]["window"] = {"tokens": 10, "overlap": 2}
    return make(tmp_path, critical=True, edit=edit)


def test_the_finding_carries_the_span(tmp_path):
    app, _, _ = svc(tmp_path)
    text = " ".join(words(200, at=[150]))
    r = TestClient(app).post("/v1/classify", json=body({"role": "tool", "kind": "tool_result", "tool_name": "webfetch", "tool_call_id": "c1", "text": text}),
                             headers=AUTH)
    f = r.json()["findings"][0]
    assert set(f["span"]) == {"start", "end"} and "INJECT" in sliced(text, (f["span"]["start"], f["span"]["end"]))


def test_a_backstop_finding_spans_the_template_full_text(tmp_path):
    app, _, _ = svc(tmp_path)
    s = seg([("c", HEAD + "INJECT"), ("s", " + x := 1"), ("c", TAIL)])
    r = TestClient(app).post("/v1/classify", json=dict(body(s), detectors=["*"]), headers=AUTH)
    fs = r.json()["findings"]
    assert [f.get("backstop", False) for f in fs] == [True]
    full = s["template"]["full_text"]
    assert "INJECT" in sliced(full, (fs[0]["span"]["start"], fs[0]["span"]["end"]))


def test_a_stored_verdict_keeps_its_span(tmp_path):
    # Deferred stages answer a resent item from the verdict store: the span comes back with it.
    app, pol_path, _ = make(tmp_path / "a", store=str(tmp_path / "v.db"), edit=lambda d: d["stages"]["tool_result"].update(window={"tokens": 10, "overlap": 2}))
    text = " ".join(words(200, at=[150]))
    seg_ = {"role": "tool", "kind": "tool_result", "tool_name": "webfetch", "tool_call_id": "c1", "text": text}
    c = TestClient(app)
    spans = []
    for _ in range(40):
        fs = c.post("/v1/classify", json=body(seg_), headers=AUTH).json()["findings"]
        if fs:
            spans.append(fs[0].get("span"))
            if len(spans) == 2:
                break
    assert len(spans) == 2 and spans[0] == spans[1] and spans[0] is not None
