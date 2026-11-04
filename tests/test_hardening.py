"""Connection and load hardening: keep-alive, identical calls at once, a restarting worker."""
import asyncio
import threading
import time

import httpx
import yaml

from conftest import block_tier_only
from test_service import AUTH, ROOT, body, make, tr
from wolfguard.pool import Lane, ThreadWorker, WorkerFailed, WARM_UP
from wolfguard.service import Settings, uvicorn_config


def test_keep_alive_outlasts_the_proxy(tmp_path, monkeypatch):
    # uvicorn's own default closes an idle connection after 5 s; a proxy in front
    # (Runpod's) that reuses it just then answers its caller 502.
    s = Settings(policy_path="p", token="t")
    assert uvicorn_config(None, s).timeout_keep_alive == 75
    monkeypatch.setenv("WOLFGUARD_KEEP_ALIVE", "120")
    assert uvicorn_config(None, Settings.from_env()).timeout_keep_alive == 120


def count_calls(lane):
    calls = []
    for w in lane.workers:
        real = w.call

        def call(b, doc, real=real):
            calls.append(len(b["segments"]))
            return real(b, doc)
        w.call = call
    return calls


async def at_once(app, bodies):
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://t") as c:
        return await asyncio.gather(*[c.post("/v1/classify", json=b, headers=AUTH) for b in bodies])


def test_identical_calls_at_once_are_scored_once(tmp_path):
    # AI Studio sends the same content through every guardrail filter at once:
    # one scoring answers them all.
    app, _, _ = make(tmp_path, delay=0.002, small=False)
    calls = count_calls(app.state.lanes["large"])
    text = "INJECT " + " ".join(["word"] * 200)
    rs = asyncio.run(at_once(app, [body(tr(text)) for _ in range(4)]))
    assert [r.status_code for r in rs] == [200] * 4
    assert len({r.text for r in rs}) == 1 and rs[0].json()["flagged"] is True
    assert len(calls) == 1
    assert not app.state.inflight


def test_shared_calls_are_counted(tmp_path):
    from fastapi.testclient import TestClient
    app, _, _ = make(tmp_path, delay=0.002, small=False)
    text = " ".join(["word"] * 200)
    asyncio.run(at_once(app, [body(tr(text)) for _ in range(3)]))
    m = TestClient(app).get("/metrics", headers=AUTH).text
    assert "wolfguard_shared_total 2.0" in m


def test_only_the_same_content_for_the_same_app_is_shared(tmp_path):
    # A verdict belongs to its app (the verdict store's key): another app's call,
    # or other content, is scored on its own.
    app, _, _ = make(tmp_path, delay=0.002, small=False)
    calls = count_calls(app.state.lanes["large"])
    text = " ".join(["word"] * 200)
    rs = asyncio.run(at_once(app, [body(tr(text), app_id=3), body(tr(text), app_id=4), body(tr(text + " more"), app_id=3)]))
    assert [r.status_code for r in rs] == [200] * 3
    assert len(calls) == 3


def test_a_call_whose_scoring_failed_leaves_the_others_to_score_it(tmp_path):
    # The first call's worker fails: the calls that waited for it are not
    # failed with it, they score the content themselves.
    app, _, _ = make(tmp_path, delay=0.002, small=False)
    lane = app.state.lanes["large"]
    calls = count_calls(lane)
    w = lane.workers[0]
    counted = w.call

    def fail_first(b, doc, n=[0]):
        n[0] += 1
        counted(b, doc)
        if n[0] == 1:
            raise WorkerFailed("worker died")
        return w.engine.run(b, doc)
    w.call = fail_first
    text = "INJECT " + " ".join(["word"] * 200)
    rs = asyncio.run(at_once(app, [body(tr(text)) for _ in range(3)]))
    codes = sorted(r.status_code for r in rs)
    assert codes == [200, 200, 503]            # the policy's when_busy is error for the failed call itself
    assert all(r.json()["flagged"] for r in rs if r.status_code == 200)
    assert len(calls) == 2                     # the failed scoring, then one more for both followers
    assert not app.state.inflight


class Restarting:
    """A worker that dies on its first call and is ready again after `load` seconds."""

    def __init__(self, doc, load):
        self.name, self.failed, self.load = "restarting", None, load
        self.inner = ThreadWorker({"kind": "stub"}, doc, "inner")
        self.ready = self.inner.ready
        self.calls = 0

    def call(self, b, doc):
        self.calls += 1
        if self.calls == 1:
            self.ready = threading.Event()          # as ProcessWorker._start does
            threading.Timer(self.load, self.ready.set).start()
            raise WorkerFailed("worker died")
        return self.inner.call(b, doc)

    def close(self):
        pass


def test_a_restarting_worker_is_not_handed_calls_until_it_is_ready():
    doc = block_tier_only(yaml.safe_load((ROOT / "config" / "policy.yaml").read_text()))
    sick = Restarting(doc, load=1.0)
    healthy = ThreadWorker({"kind": "stub"}, doc, "healthy")
    lane = Lane("large", [sick, healthy], 8, 5.0)
    for _ in range(200):
        if lane.ready():
            break
        time.sleep(0.01)

    async def run():
        try:
            await lane.run(WARM_UP, doc)
        except WorkerFailed:
            pass
        t = time.perf_counter()
        await lane.run(WARM_UP, doc)               # not the restarting worker: no wait for its load
        await lane.run(WARM_UP, doc)
        took = time.perf_counter() - t
        assert sick.calls == 1 and took < 0.5
        for _ in range(100):                       # back in the lane once ready
            if sick in lane._idle:
                break
            await asyncio.sleep(0.05)
        assert sick in lane._idle
        lane._idle.remove(healthy)
        await lane.run(WARM_UP, doc)
        assert sick.calls == 2
    asyncio.run(run())
