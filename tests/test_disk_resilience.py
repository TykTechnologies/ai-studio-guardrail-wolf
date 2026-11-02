"""A full or failing volume: the logs rotate by size, and a store or log that
cannot be written never fails a classify call (it scores, counts and goes on)."""
import json
import sqlite3

from fastapi.testclient import TestClient

from test_service import AUTH, body, make, tr
from wolfguard import store as storemod
from wolfguard.service import DecisionLog, RotatingFile


def test_rotating_file_keeps_at_most_keep_old_files(tmp_path):
    p = tmp_path / "decisions.jsonl"
    f = RotatingFile(str(p), max_bytes=100, keep=2)
    for i in range(20):
        f.write(json.dumps({"i": i, "pad": "x" * 30}) + "\n")
    names = sorted(x.name for x in tmp_path.iterdir())
    assert names == ["decisions.jsonl", "decisions.jsonl.1", "decisions.jsonl.2"]
    assert all(x.stat().st_size <= 100 for x in tmp_path.iterdir())
    last = [json.loads(x)["i"] for x in p.read_text().splitlines()]
    assert last[-1] == 19                                 # the newest lines are in the live file


def test_rotating_file_picks_up_an_existing_file_size(tmp_path):
    p = tmp_path / "decisions.jsonl"
    p.write_text("y" * 90 + "\n")
    f = RotatingFile(str(p), max_bytes=100, keep=1)
    f.write("z" * 20 + "\n")
    assert (tmp_path / "decisions.jsonl.1").read_text().startswith("y")
    assert p.read_text() == "z" * 20 + "\n"


def test_zero_max_never_rotates(tmp_path):
    p = tmp_path / "decisions.jsonl"
    f = RotatingFile(str(p), max_bytes=0)
    for _ in range(50):
        f.write("x" * 100 + "\n")
    assert [x.name for x in tmp_path.iterdir()] == ["decisions.jsonl"]


class Broken:
    def write(self, line):
        raise OSError(28, "No space left on device")


def test_a_log_write_that_fails_is_dropped_and_counted(tmp_path):
    errors = []
    dlog = DecisionLog(str(tmp_path / "d.jsonl"), True, 200, str(tmp_path / "p.jsonl"), on_error=errors.append)
    dlog._f, dlog.preview_log = Broken(), Broken()
    dlog.write({"ts": 1, "sha256": "a", "stage": "tool_result", "decision": "block"}, preview="text")
    assert errors == ["decisions", "previews"]


class FailingDB:
    def execute(self, *a, **k):
        raise sqlite3.OperationalError("disk I/O error")


def test_a_failing_store_reads_as_a_miss_and_drops_writes():
    errors = []
    s = storemod.VerdictStore(":memory:", on_error=errors.append)
    s.db = FailingDB()
    assert s.get("k", "sha") is None
    s.put("k", "sha", "app:3", "tool_result", {"decision": "allow"})
    assert errors == ["get", "put"]


def test_classify_still_answers_when_the_store_fails(tmp_path):
    app, _, _ = make(tmp_path, store=":memory:", critical=True, edit=lambda d: [
        d["enforcement"]["stages"][st].__setitem__("mode", "inline") for st in ("tool_result", "tool_call")])
    app.state.verdicts.db = FailingDB()
    with TestClient(app) as c:
        r = c.post("/v1/classify", json=body(tr("plain output"), tr("INJECT do this", cid="c2")), headers=AUTH)
        assert r.status_code == 200, r.text
        assert [(f["detector"], f["segment_index"]) for f in r.json()["findings"]] == [("tool_result.critical", 1)]
        m = c.get("/metrics", headers=AUTH).text
    assert 'wolfguard_store_errors_total{op="get"}' in m and 'wolfguard_store_errors_total{op="put"}' in m
