"""The verdict store over HTTP, for a deployment with no shell into the container (the GPU image on a pod)."""
from fastapi.testclient import TestClient

from test_deferred import post, settle
from test_service import AUTH, body, make, tr
from wolfguard import store as storemod


def test_admin_endpoints_lift_a_flag_without_a_shell(tmp_path):
    app, _, _ = make(tmp_path, store=":memory:", critical=True)
    with TestClient(app) as c:
        b = body(tr("INJECT but benign docs"))
        post(c, b)
        settle(app)
        assert post(c, b) == [("tool_result.critical", 0)]
        assert c.get("/v1/admin/flags").status_code == 401
        sha = storemod.text_sha256("INJECT but benign docs")
        assert [f["sha256"] for f in c.get("/v1/admin/flags", headers=AUTH).json()["flags"]] == [sha]
        assert c.post("/v1/admin/allow", json={"sha256": "nope"}, headers=AUTH).status_code == 400
        r = c.post("/v1/admin/allow", json={"sha256": sha, "days": 7, "note": "docs about injection"}, headers=AUTH)
        assert r.status_code == 200 and r.json()["days"] == 7
        assert post(c, b) == []
        assert c.post("/v1/admin/unallow", json={"sha256": sha}, headers=AUTH).json() == {"removed": True}
        assert post(c, b) == [("tool_result.critical", 0)]
        assert c.get("/v1/admin/stats", headers=AUTH).json()["verdicts"]["critical"] == 1


def test_admin_endpoints_need_the_store(tmp_path):
    app, _, _ = make(tmp_path)
    assert TestClient(app).get("/v1/admin/flags", headers=AUTH).status_code == 404
