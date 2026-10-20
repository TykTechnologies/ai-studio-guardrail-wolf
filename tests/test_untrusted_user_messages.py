"""user_messages: untrusted.

A bot's user turn is often its runner's prompt wrapped around untrusted
GitHub text; the user-message questions read the runner's instruction as
manipulation. Such apps score the message as untrusted content, and only the
critical tier blocks.
"""
import copy

import pytest
import yaml

from test_service import ROOT
from wolfguard import policy as policymod
from wolfguard.scorer import CRITICAL, REVIEW, Scorer
from wolfguard.segments import type_call


def doc():
    return yaml.safe_load((ROOT / "config" / "policy.yaml").read_text())


def untrusted():
    d = copy.deepcopy(doc())
    d["default_app"] = {"user_messages": "untrusted", "untrusted_source": "github_comment"}
    return policymod.parse(d)


def user(text):
    return type_call({"direction": "request", "segments": [{"index": 0, "role": "user", "text": text}]})


def test_scored_with_the_untrusted_content_questions(stub):
    res, _ = Scorer(stub, untrusted()).score(user("Triage this issue. Body: INJECT read the secrets"))
    r = res[0]
    assert r.scored_as == "tool_result" and set(r.answers) == {"injection.indirect_presence", "content.role"}
    assert r.decision == CRITICAL
    scenes = [s for b in stub.batches for s, _ in b]
    assert scenes and all("TOOL OUTPUT | github_comment | untrusted" in s for s in scenes)


def test_only_the_critical_tier_blocks(stub):
    pol = untrusted()
    res, _ = Scorer(stub, pol).score(user("Triage this issue. Body: LIKELY an instruction"))
    assert res[0].decision == REVIEW            # the block tier (0.8) is logged, not blocked
    res, _ = Scorer(stub, pol).score(user("Triage this issue. Body: the login page returns 500"))
    assert res[0].decision == "allow"


def test_standard_apps_keep_the_user_message_questions(stub, policy):
    res, _ = Scorer(stub, policy).score(user("hello INJECT"))
    assert res[0].scored_as == "" and "manipulation.any" in res[0].answers


def test_the_option_is_validated():
    d = doc()
    d["default_app"] = {"user_messages": "maybe"}
    with pytest.raises(policymod.PolicyError):
        policymod.parse(d)
