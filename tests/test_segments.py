"""Segment typing over every 2.3 segment shape captured from AI Studio 2.3 (fixtures/captures)."""
from wolfguard.segments import type_call


def items_of(capture, direction="request"):
    out = []
    for call in capture["calls"]:
        if call["direction"] == direction:
            out.extend(type_call(call).items)
    return out


def test_tool_results_with_names_ids_and_decoded_views(captures):
    items = [i for i in items_of(captures["openai_rest_hub_turn2"]) if i.stage == "tool_result"]
    assert len(items) == 2  # raw JSON and its decoded view
    assert {i.tool_name for i in items} == {"shell"}
    assert {i.tool_call_id for i in items} == {"call_cap1"}
    assert any(i.text.startswith("stdout\n") for i in items)


def test_gemini_tool_results_have_names_but_no_ids(captures):
    items = [i for i in items_of(captures["google_rest_hub_turn2"]) if i.stage == "tool_result"]
    assert items and all(i.tool_name == "shell" and i.tool_call_id == "" for i in items)


def test_pieces_of_one_long_tool_result(captures):
    items = [i for i in items_of(captures["openai_large_tool_result_hub"]) if i.stage == "tool_result"]
    sizes = sorted(len(i.text) for i in items)
    assert len(items) >= 7 and max(sizes) == 32768 and 1024 in sizes  # pieces plus overlap windows
    assert {i.tool_call_id for i in items} == {"call_cap1"}


def test_user_text_with_no_kind(captures):
    items = items_of(captures["openai_rest_hub_turn1"])
    users = [i for i in items if i.stage == "user_message"]
    assert len(users) == 1 and users[0].text.startswith("Review pull request 12")


def test_tool_calls_carry_the_goal_on_requests_and_responses(captures):
    req = [i for i in items_of(captures["openai_rest_hub_turn2"]) if i.stage == "tool_call"]
    resp = [i for i in items_of(captures["openai_rest_hub_turn1"], "response") if i.stage == "tool_call"]
    for items in (req, resp):
        assert items and all(i.goal.startswith("Review pull request 12") and i.tool_name == "shell" for i in items)


def test_tool_definitions(captures):
    items = [i for i in items_of(captures["anthropic_rest_hub_turn1"]) if i.stage == "tool_definition"]
    assert {i.tool_name for i in items} == {"shell", "read"} and len(items) == 4  # raw + decoded each


def test_studio_chat_shapes(captures):
    items = items_of(captures["studio_chat_hub"])
    stages = {i.stage for i in items}
    assert stages == {"user_message", "tool_definition", "tool_call", "tool_result"}


def test_system_text_becomes_context_and_assistant_text_is_skipped():
    t = type_call({"direction": "request", "segments": [
        {"index": 0, "role": "system", "text": "You review code."},
        {"index": 1, "role": "user", "text": "review it"},
        {"index": 2, "role": "assistant", "text": "sure"},
        {"index": 3, "role": "tool", "kind": "tool_result", "text": " "},
        {"index": 4, "role": "tool", "kind": "future_kind", "text": "x"}]})
    assert [(i.stage, i.system) for i in t.items] == [("user_message", "You review code.")]
    assert t.skipped == {"system_context": 1, "role:assistant": 1, "empty": 1, "kind:future_kind": 1}


def test_response_text_is_not_scored(captures):
    t = items_of(captures["openai_rest_hub_turn2"], "response")
    assert t == []
