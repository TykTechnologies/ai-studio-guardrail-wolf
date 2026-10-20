"""The client-IP allowlist (a sidecar on a GPU pod behind Runpod's HTTPS proxy)."""
import pytest
from fastapi.testclient import TestClient

from test_service import AUTH, body, tr
from wolfguard.service import client_ip, parse_allowlist


def build(tmp_path, allow, header, proxies=""):
    import shutil

    import yaml

    from test_service import ROOT, TOKEN, wait_ready
    from wolfguard.pool import Lane, ThreadWorker
    from wolfguard.service import Settings, create_app
    tmp_path.mkdir(parents=True, exist_ok=True)
    pol = tmp_path / "policy.yaml"
    shutil.copy(ROOT / "config" / "policy.yaml", pol)
    s = Settings(policy_path=str(pol), token=TOKEN, backend={"kind": "stub"}, workers="thread", decision_log=str(tmp_path / "d.jsonl"),
                 reload_interval=3600, allow_ips=allow, client_ip_header=header, trusted_proxies=proxies)
    doc = yaml.safe_load(pol.read_text())
    lanes = {"large": Lane("large", [ThreadWorker(s.backend, doc, "l")]), "small": Lane("small", [ThreadWorker(s.backend, doc, "s")])}
    wait_ready(lanes)
    return create_app(s, lanes=lanes)


def post(c, headers):
    return c.post("/v1/classify", json=body(tr("plain")), headers=dict(AUTH, **headers)).status_code


def test_header_mode_admits_only_listed_addresses(tmp_path):
    c = TestClient(build(tmp_path, "203.0.113.7, 198.51.100.0/24", "cf-connecting-ip"))
    assert post(c, {"cf-connecting-ip": "203.0.113.7"}) == 200
    assert post(c, {"cf-connecting-ip": "198.51.100.42"}) == 200
    assert post(c, {"cf-connecting-ip": "192.0.2.1"}) == 403
    assert post(c, {}) == 403                                    # no client address: refused
    assert post(c, {"cf-connecting-ip": "not-an-ip"}) == 403


def test_the_allowlist_comes_before_the_token(tmp_path):
    c = TestClient(build(tmp_path, "203.0.113.7", "cf-connecting-ip"))
    r = c.post("/v1/classify", json=body(tr("x")), headers={"Authorization": "Bearer wrong", "cf-connecting-ip": "192.0.2.1"})
    assert r.status_code == 403
    r = c.post("/v1/classify", json=body(tr("x")), headers={"Authorization": "Bearer wrong", "cf-connecting-ip": "203.0.113.7"})
    assert r.status_code == 401


def test_the_header_is_believed_only_from_the_proxy(tmp_path):
    # Starlette's test client's peer is "testclient": not in any proxy range.
    c = TestClient(build(tmp_path, "203.0.113.7", "cf-connecting-ip", proxies="100.64.0.0/10"))
    assert post(c, {"cf-connecting-ip": "203.0.113.7"}) == 403


def test_off_by_default(tmp_path):
    c = TestClient(build(tmp_path, "", ""))
    assert post(c, {}) == 200


def test_peer_mode_uses_the_tcp_address(tmp_path):
    # Starlette's test client connects from "testclient", which is not an address.
    c = TestClient(build(tmp_path, "203.0.113.7", ""))
    assert post(c, {"cf-connecting-ip": "203.0.113.7"}) == 403   # the header is ignored without client_ip_header


def test_helpers():
    assert client_ip({"x-forwarded-for": "203.0.113.7, 10.0.0.1"}, "10.0.0.2", "x-forwarded-for") == "203.0.113.7"
    assert client_ip({}, "10.0.0.2", "") == "10.0.0.2"
    assert [str(n) for n in parse_allowlist("203.0.113.7, 198.51.100.0/24")] == ["203.0.113.7/32", "198.51.100.0/24"]
    with pytest.raises(ValueError):
        parse_allowlist("nope")
