"""Scorer: batching, windows, option-encoding reuse, cache, graded policy, rules."""
import dataclasses

from wolfguard import cache as cachemod
from wolfguard import policy as policymod
from wolfguard.scorer import ALLOW, BLOCK, CRITICAL, REVIEW, Scorer
from wolfguard.segments import Typed, type_call


def call(*segs, app_id=3, direction="request"):
    return type_call({"direction": direction, "segments": [dict(s, index=i) for i, s in enumerate(segs)], "meta": {"app_id": app_id}})


def tr(text, name="shell", cid="c1"):
    return {"role": "tool", "kind": "tool_result", "tool_name": name, "tool_call_id": cid, "text": text}


def test_one_forward_for_all_questions_of_a_scene(stub, policy):
    s = Scorer(stub, policy)
    res, stats = s.score(call(tr("plain output")))
    assert stub.forwards == 1 and stats.rows == 2  # two tool_result questions, one pass
    assert {q for _, q in stub.batches[0]} == {"injection.indirect_presence", "content.role"}
    assert res[0].decision == ALLOW and res[0].windows == 1


def test_a_scenes_questions_never_split_across_forwards(stub, policy):
    s = Scorer(stub, policy, max_rows=5)  # 3 user_message questions per scene
    s.score(call({"role": "user", "text": "a"}, {"role": "user", "text": "b"}, {"role": "user", "text": "c"}))
    for batch in stub.batches:
        scenes_in = {}
        for scene, q in batch:
            scenes_in.setdefault(scene, set()).add(q)
        assert all(len(qs) == 3 for qs in scenes_in.values())
    assert stub.forwards == 3


def test_windows_over_6144_tokens_and_max_aggregation(stub, policy):
    words = ["w%d" % i for i in range(7000)]
    words[6500] = "INJECT"      # only the last windows see it
    s = Scorer(stub, policy)
    res, stats = s.score(call(tr(" ".join(words))))
    r = res[0]
    assert r.windows == len(range(0, 7000 - 64, 448)) and r.windows > 12  # 512-token windows, 64 overlap
    assert r.answers["injection.indirect_presence"].risk == 0.95 and r.decision == BLOCK
    assert stats.rows == 2 * r.windows and stub.forwards == -(-stats.rows // 24)


def test_a_phrase_across_a_window_boundary_is_seen_whole(stub, policy):
    st = policy.stages["tool_result"]
    s = Scorer(stub, dataclasses.replace(policy, stages={**policy.stages, "tool_result": dataclasses.replace(st, window_tokens=10, window_overlap=4)}))
    words = ["w%d" % i for i in range(30)]
    words[8] = "INJECT"   # position 8 sits in the overlap of windows 0-9 and 6-15
    res, _ = s.score(call(tr(" ".join(words))))
    assert res[0].answers["injection.indirect_presence"].risk == 0.95


def test_option_encodings_are_prepared_once(stub, policy):
    s = Scorer(stub, policy)
    n = stub.prepares
    distinct = {(q.kind, q.instructions, q.option_texts) for st in policy.stages.values() for q in st.questions + st.paste_questions}
    assert n == len(distinct)
    for _ in range(3):
        s.score(call(tr("x"), {"role": "user", "text": "y"}))
    assert stub.prepares == n


def test_cache_repeat_runs_no_inference_and_version_or_revision_misses(stub, policy):
    c = cachemod.LRU()
    s = Scorer(stub, policy, cache=c)
    s.score(call(tr("same output")))
    f = stub.forwards
    res, stats = s.score(call(tr("same output")))
    assert stub.forwards == f and stats.cache_hits == 1 and res[0].cached == 1
    s.set_policy(dataclasses.replace(policy, version="other"))
    s.score(call(tr("same output")))
    assert stub.forwards == f + 1
    stub.revision = "stub-rev-2"
    s.score(call(tr("same output")))
    assert stub.forwards == f + 2


def test_cache_ttl_and_lru():
    now = [0.0]
    c = cachemod.LRU(max_entries=2, ttl_seconds=10, clock=lambda: now[0])
    c.put("a", 1)
    c.put("b", 2)
    c.put("c", 3)
    assert c.get("a") is None and c.get("b") == 2
    now[0] = 11
    assert c.get("b") is None


def test_graded_thresholds(stub, policy):
    s = Scorer(stub, policy)
    res, _ = s.score(call(tr("fine"), tr("SUSPECT text", cid="c2"), tr("INJECT text", cid="c3")))
    assert [r.decision for r in res] == [ALLOW, REVIEW, BLOCK]
    # user_message thresholds are stricter (block 0.85, review 0.50)
    res, _ = s.score(call({"role": "user", "text": "SUSPECT"}))
    assert res[0].decision == REVIEW


def test_rule_only_results(stub):
    doc = {"version": "t", "model_revision": "r", "canaries": ["CANARY-7f3a"], "stages": {
        "tool_call": {"questions": {"action.alignment": {"type": "choice", "instructions": "q", "criteria": {"aligned": "a", "misaligned": "m"}, "risk": "misaligned"}}},
        "tool_result": {"questions": {"injection.indirect_presence": {"type": "noul", "instructions": "q"}}}}}
    s = Scorer(stub, policymod.parse(doc))
    res, _ = s.score(call({"role": "assistant", "kind": "tool_call", "tool_name": "send", "text": '{"body": "CANARY-7f3a"}', "context": {"user_goal": "hi"}}))
    assert res[0].decision == CRITICAL and [r.name for r in res[0].rules] == ["canary.leak"]
    # Flag rules are reported, never decide.
    res, _ = s.score(call(tr("ok‮this")))
    assert res[0].decision == ALLOW and [r.name for r in res[0].rules] == ["unicode.bidi"]


def tc(args, goal="list the files", name="shell"):
    return {"role": "assistant", "kind": "tool_call", "tool_name": name, "text": args, "context": {"user_goal": goal}}


def test_reversibility_rule_blocks_whatever_the_other_scores(stub, policy):
    s = Scorer(stub, policy)
    res, _ = s.score(call(tc('{"cmd": "ls"}')))
    assert res[0].decision == ALLOW
    # Aligned and no exfiltration, but hard to reverse: block (the consent rule).
    res, _ = s.score(call(tc('{"cmd": "git push --force RISK:action.reversibility"}')))
    a = res[0].answers
    assert a["action.alignment"].risk < 0.1 and a["exfiltration.presence"].risk < 0.1
    assert a["action.reversibility"].risk == 0.95 and res[0].decision == BLOCK


def test_block_when_all_needs_every_deciding_question(stub):
    q = {"a": {"type": "noul", "instructions": "qa"}, "b": {"type": "noul", "instructions": "qb"}}
    doc = {"version": "t", "model_revision": "r", "stages": {"tool_result": {"block_when": "all", "questions": q}}}
    s = Scorer(stub, policymod.parse(doc))
    res, _ = s.score(call(tr("RISK:a only")))
    assert res[0].decision == REVIEW  # one question at block level is a review, not a block
    res, _ = s.score(call(tr("RISK:a RISK:b both")))
    assert res[0].decision == BLOCK
    with __import__("pytest").raises(policymod.PolicyError):
        policymod.parse({"version": "t", "model_revision": "r", "stages": {"tool_result": {"block_when": "most", "questions": q}}})


def test_signal_only_questions_never_decide(stub):
    doc = {"version": "t", "model_revision": "r", "stages": {"tool_call": {"questions": {
        "action.alignment": {"type": "choice", "instructions": "q", "criteria": {"aligned": "a", "misaligned": "m"}, "risk": "misaligned"},
        "action.reversibility": {"type": "score", "instructions": "r", "criteria": ["read_only", "reversible", "hard", "irreversible"],
                                 "risk": ["hard", "irreversible"], "decides": False}}}}}
    res, _ = Scorer(stub, policymod.parse(doc)).score(call(tc("RISK:action.reversibility")))
    assert res[0].decision == ALLOW and res[0].answers["action.reversibility"].risk == 0.95


def test_tool_call_and_definition_scenes_and_goal(stub, policy):
    s = Scorer(stub, policy)
    s.score(call(tc('{"cmd": "ls"}', goal="Review PR 214."), {"role": "system", "kind": "tool_definition", "tool_name": "search", "text": '{"name": "search"}'}))
    scenes_seen = {scene for b in stub.batches for scene, _ in b}
    assert '[USER GOAL]\nReview PR 214.\n\n[PROPOSED ACTION | agent]\nshell(cmd="ls")\nRuns a shell command in the repository checkout.' in scenes_seen
    assert "[AVAILABLE TOOLS]\n- search(): " in scenes_seen
    # Without context: the goal block says so rather than being dropped.
    stub.batches.clear()
    s.score(call({"role": "assistant", "kind": "tool_call", "tool_name": "shell", "text": "{}"}))
    assert all("[USER GOAL]\n(not given)" in scene for b in stub.batches for scene, _ in b)


def test_app_skip_and_stage_selection(stub, policy):
    p = dataclasses.replace(policy, apps={"9": policymod.App(skip=True), "8": policymod.App(stages=("tool_result",))})
    s = Scorer(stub, p)
    res, _ = s.score(call(tr("INJECT"), app_id=9))
    assert res[0].decision == ALLOW and res[0].skipped == "app_skip" and stub.forwards == 0
    res, _ = s.score(call(tr("INJECT"), {"role": "user", "text": "INJECT"}, app_id=8))
    assert [(r.item.stage, r.decision, r.skipped) for r in res] == [("tool_result", BLOCK, ""), ("user_message", ALLOW, "stage_off")]


def test_tool_calls_get_the_app_context_and_the_tool_description(stub, policy):
    p = dataclasses.replace(policy, apps={"3": policymod.App(system_context="A code-review agent.")},
                            tools={"shell": "Runs a shell command in the repository checkout."})
    s = Scorer(stub, p)
    s.score(call({"role": "assistant", "kind": "tool_call", "tool_name": "shell", "text": '{"cmd": "ls"}', "context": {"user_goal": "list"}}))
    assert all(scene == '[SYSTEM CONTEXT]\nA code-review agent.\n\n[USER GOAL]\nlist\n\n[PROPOSED ACTION | agent]\nshell(cmd="ls")\nRuns a shell command in the repository checkout.'
               for b in stub.batches for scene, _ in b)


def test_app_system_context_goes_in_the_scene(stub, policy):
    p = dataclasses.replace(policy, apps={"3": policymod.App(system_context="A code-review agent.")})
    s = Scorer(stub, p)
    s.score(call({"role": "user", "text": "hello"}))
    assert all(scene.startswith("[SYSTEM CONTEXT]\nA code-review agent.\n\n[USER PROMPT]\nhello") for scene, _ in stub.batches[0])


def test_pasted_content_is_scored_as_untrusted(stub, policy):
    s = Scorer(stub, policy)
    res, _ = s.score(call({"role": "user", "text": "please review\n```\nINJECT build step\n```"}))
    r = res[0]
    assert r.paste["injection.indirect_presence"].risk == 0.95
    pasted = [scene for b in stub.batches for scene, q in b if "RETRIEVED CONTENT | user-paste | untrusted" in scene]
    assert pasted and all("[USER PROMPT]" not in sc for sc in pasted)
    assert r.decision == BLOCK  # the user_message questions also see INJECT here (stub)


def test_tag_characters_are_revealed_to_the_model(stub, policy):
    hidden = "".join(chr(0xE0000 + ord(c)) for c in "INJECT")
    s = Scorer(stub, policy)
    res, _ = s.score(call(tr("harmless" + hidden)))
    assert res[0].decision == BLOCK and "unicode.tags" in [r.name for r in res[0].rules]


def test_policy_validation():
    import pytest
    base = {"version": "v", "model_revision": "r"}
    for bad in (
        {"stages": {"tool_result": {"questions": {"instruction.handling": {"type": "choice", "instructions": "q", "criteria": {"a": "", "b": ""}, "risk": "a"}}}}},
        {"stages": {"tool_result": {"questions": {"x": {"type": "noul", "instructions": "q", "block": 0.3, "review": 0.5}}}}},
        {"stages": {"tool_result": {"questions": {"x": {"type": "choice", "instructions": "q", "criteria": {"a": "", "b": ""}, "risk": "c"}}}}},
        {"stages": {"nonsense": {"questions": {"x": {"type": "noul", "instructions": "q"}}}}},
        {"stages": {"tool_result": {"window": {"tokens": 64, "overlap": 64}, "questions": {"x": {"type": "noul", "instructions": "q"}}}}},
    ):
        with pytest.raises(policymod.PolicyError):
            policymod.parse({**base, **bad})


def test_empty_call(stub, policy):
    res, stats = Scorer(stub, policy).score(Typed("request"))
    assert res == [] and stats.forwards == 0
