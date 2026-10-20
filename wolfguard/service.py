"""The sidecar service: AI Studio 2.3's HTTP guardrail contract over HTTP (Unix socket or TCP).

    python -m wolfguard.service --policy config/policy.yaml --model models/jev-5ed7c44d \\
        --socket /run/wolfguard/wolfguard.sock          # or --host 127.0.0.1 --port 18900

    POST /v1/classify (and /classify)   the contract: segments in, findings out
    GET  /healthz                       the process is up
    GET  /readyz                        weights loaded, options encoded, warm-up scored, policy loaded
    GET  /metrics                       Prometheus (bearer auth)

Findings: one per segment decided review, block or critical, never for
clean text (the gateway counts any finding as a hit). The detector is
"<stage>.<level>" (tool_result.block, user_message.review, ...): the highest
level the filter's detectors list asks for that the segment reaches, so a
filter asking for tool_result.block also acts on a critical segment, and two
filters (critical: block the request; block: quarantine the result) split
the tiers. The score is the deciding probability,
segment_index the segment. The thresholds live in the policy YAML, the
single source of truth (set Studio's detector thresholds low, see README).

Enforcement modes (policy `enforcement`, docs/ARCHITECTURE.md): with the verdict
store on (WOLFGUARD_STORE), every segment's verdict is kept, and a segment
already decided is answered from the store without a worker. A stage in
deferred mode answers content it has not seen as clean at once and scores
it in the background, at a lower priority than inline calls; the client's
next request resends it and gets the stored verdict. A segment that cannot
be scored in time gets its stage's when_busy: an error (503), a pass, or an
"unscanned" finding at the top tier.

Settings come from flags or WOLFGUARD_* environment variables; the bearer
token from WOLFGUARD_TOKEN or WOLFGUARD_TOKEN_FILE (the service will not
start without one).
"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

import yaml
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from prometheus_client import CONTENT_TYPE_LATEST, CollectorRegistry, Counter, Gauge, Histogram, generate_latest

from wolfguard import policy as policymod
from wolfguard import precheck
from wolfguard import store as storemod
from wolfguard.pool import BACKGROUND, INLINE, Abandoned, Lane, ProcessWorker, Saturated, ThreadWorker, WorkerFailed
from wolfguard.redact import redact
from wolfguard.scorer import ALLOW, BLOCK, CRITICAL, RANK
from wolfguard.segments import STAGES, stage_of, type_call

log = logging.getLogger("wolfguard")


@dataclass
class Settings:
    policy_path: str = "config/policy.yaml"
    token: str = ""
    backend: dict = field(default_factory=lambda: {"kind": "jev", "model_dir": "models/jev-5ed7c44d"})
    workers: str = "process"            # process | thread
    large_workers: int = 2
    small_workers: int = 1
    threads: int = 2
    small_threads: int = 1
    small_chars: int = 1500             # a call with at most this much text to score takes the small lane
    # Shadow can wait: bursts are queued, not refused (docs/BENCHMARKS.md).
    # Under enforcement keep queue_wait below the filter's timeout_ms.
    queue_max: int = 32
    queue_wait: float = 20.0
    max_body_bytes: int = 4 << 20
    decision_log: str = "-"             # a path, or "-" for stdout
    preview: bool = False               # log a truncated preview of flagged segments
    preview_chars: int = 200
    preview_log: str = ""               # previews in their own file (shorter retention); "" = in the decision line
    reload_interval: float = 2.0
    debug_delay_ms: int = 0             # test only: delay every classify call
    # The verdict store (deferred enforcement): "" off, ":memory:", or a SQLite path on the log volume.
    store: str = ""
    flagged_ttl: float = storemod.FLAGGED_TTL
    clean_ttl: float = storemod.CLEAN_TTL
    # Background (deferred) scoring: how many wait per lane, and for how long.
    bg_queue_max: int = 256
    bg_queue_wait: float = 300.0
    # Client-IP allowlist (a sidecar reached over a network, e.g. on a GPU pod behind
    # Runpod's HTTPS proxy): comma-separated addresses or CIDRs; empty = off. Behind a
    # proxy, the client's address is read from client_ip_header (the proxy sets it;
    # a request without it is refused), else from the TCP peer.
    allow_ips: str = ""
    client_ip_header: str = ""
    # The proxy's own addresses: the header is believed only from these peers (Runpod's
    # proxy connects from 100.64.0.0/10). Empty: any peer (not recommended).
    trusted_proxies: str = ""

    @staticmethod
    def from_env(**over) -> "Settings":
        s = Settings()
        env = os.environ
        s.policy_path = env.get("WOLFGUARD_POLICY", s.policy_path)
        s.token = env.get("WOLFGUARD_TOKEN", "")
        if not s.token and env.get("WOLFGUARD_TOKEN_FILE"):
            s.token = Path(env["WOLFGUARD_TOKEN_FILE"]).read_text().strip()
        s.backend = {"kind": "jev", "model_dir": env.get("WOLFGUARD_MODEL", s.backend["model_dir"]),
                     "revision": env.get("WOLFGUARD_MODEL_REVISION", ""), "device": env.get("WOLFGUARD_DEVICE", "cpu")}
        for name, cast in (("large_workers", int), ("small_workers", int), ("threads", int), ("small_threads", int),
                           ("small_chars", int), ("queue_max", int), ("queue_wait", float), ("max_body_bytes", int),
                           ("preview_chars", int), ("reload_interval", float), ("debug_delay_ms", int),
                           ("flagged_ttl", float), ("clean_ttl", float), ("bg_queue_max", int), ("bg_queue_wait", float)):
            v = env.get("WOLFGUARD_" + name.upper())
            if v:
                setattr(s, name, cast(v))
        s.decision_log = env.get("WOLFGUARD_DECISION_LOG", s.decision_log)
        s.preview_log = env.get("WOLFGUARD_PREVIEW_LOG", s.preview_log)
        s.preview = env.get("WOLFGUARD_PREVIEW", "") in ("1", "true", "yes")
        s.workers = env.get("WOLFGUARD_WORKERS", s.workers)
        # WOLFGUARD_STATE_DIR (the GPU image: a pod's persistent volume) holds the store and the logs
        # unless they are set one by one.
        state = env.get("WOLFGUARD_STATE_DIR", "")
        if state:
            s.store = str(Path(state) / "verdicts.db")
            s.decision_log = env.get("WOLFGUARD_DECISION_LOG", str(Path(state) / "decisions.jsonl"))
            s.preview_log = env.get("WOLFGUARD_PREVIEW_LOG", str(Path(state) / "previews.jsonl"))
        s.store = env.get("WOLFGUARD_STORE", s.store)
        s.allow_ips = env.get("WOLFGUARD_ALLOW_IPS", s.allow_ips)
        s.client_ip_header = env.get("WOLFGUARD_CLIENT_IP_HEADER", s.client_ip_header)
        s.trusted_proxies = env.get("WOLFGUARD_TRUSTED_PROXIES", s.trusted_proxies)
        for k, v in over.items():
            if v is not None:
                setattr(s, k, v)
        return s


class PolicyStore:
    """The policy file, hot-reloaded: an invalid file keeps the last good policy."""

    def __init__(self, path: str, on_reload=None):
        self.path, self.on_reload = Path(path), on_reload
        self.doc = yaml.safe_load(self.path.read_text())
        self.policy = policymod.parse(self.doc)
        if not self.policy.version:
            raise policymod.PolicyError("the policy needs a version")
        self.version = self.policy.version
        self.mtime = self.path.stat().st_mtime_ns
        self.last_error = ""

    def reload(self) -> bool:
        try:
            mtime = self.path.stat().st_mtime_ns
        except OSError as e:
            self.last_error = str(e)
            return False
        if mtime == self.mtime:
            return False
        self.mtime = mtime
        try:
            doc = yaml.safe_load(self.path.read_text())
            p = policymod.parse(doc)
            if not p.version:
                raise policymod.PolicyError("the policy needs a version")
        except Exception as e:  # noqa: BLE001
            self.last_error = str(e)
            log.error("policy reload rejected, keeping version %s: %s", self.version, e)
            if self.on_reload:
                self.on_reload(False)
            return False
        self.doc, self.policy, self.version, self.last_error = doc, p, p.version, ""
        log.info("policy reloaded: version %s", self.version)
        if self.on_reload:
            self.on_reload(True)
        return True


class Metrics:
    def __init__(self):
        self.registry = CollectorRegistry()
        r = self.registry
        self.decisions = Counter("wolfguard_decisions_total", "Decisions per segment", ["stage", "app", "tool", "decision"], registry=r)
        self.latency = Histogram("wolfguard_latency_seconds", "Scoring time per call", ["stage", "size"], registry=r,
                                 buckets=(0.025, 0.05, 0.1, 0.2, 0.3, 0.5, 1, 2, 4, 8, 16))
        self.cache = Counter("wolfguard_cache_total", "Scene cache lookups", ["result"], registry=r)
        self.rejected = Counter("wolfguard_rejected_total", "Calls refused", ["code", "reason"], registry=r)
        self.reloads = Counter("wolfguard_policy_reloads_total", "Policy reloads", ["result"], registry=r)
        self.invalid = Gauge("wolfguard_policy_invalid", "1 while the policy file on disk is invalid (the last good one is in use)", registry=r)
        self.mismatch = Counter("wolfguard_policy_version_mismatch_total", "Calls naming a policy version the sidecar is not running", registry=r)
        self.skipped = Counter("wolfguard_skipped_total", "Segments not scored", ["reason"], registry=r)
        self.denied = Counter("wolfguard_denied_total", "Requests refused by the client-IP allowlist", ["reason"], registry=r)
        self.store = Counter("wolfguard_store_total", "Verdict store lookups", ["result"], registry=r)
        self.deferred = Counter("wolfguard_deferred_total", "Deferred (background) scoring per segment", ["outcome"], registry=r)
        self.busy = Counter("wolfguard_busy_total", "Segments that could not be scored in time, by when_busy", ["stage", "outcome"], registry=r)
        self._tools = set()

    def tool(self, name: str) -> str:
        name = (name or "")[:48]
        if name in self._tools or len(self._tools) < 200:
            self._tools.add(name)
            return name
        return "other"


def wanted(detector: str, requested) -> bool:
    """Whether a finding's detector is among the filter's detectors: exact
    names, "<stage>.*" or "*". A list naming none of the sidecar's
    detectors (a filter written before them, e.g. ["prompt_attack"]) asks
    for everything."""
    names = [str(n) for n in requested or [] if n]
    from wolfguard.segments import STAGES
    ours = [n for n in names if n == "*" or n.split(".", 1)[0] in STAGES]
    if not ours:
        return True
    stage = detector.split(".", 1)[0]
    return detector in ours or f"{stage}.*" in ours or "*" in ours


LEVELS = ("review", "block", "critical")
UNSCANNED = "unscanned"     # a verdict for content not scored in time (when_busy: unscanned); ranks as critical


def _ours(requested) -> bool:
    return any(str(n) == "*" or str(n).split(".", 1)[0] in STAGES for n in requested or [] if n)


def finding_for(stage: str, segment_index: int, verdict: dict, requested) -> dict | None:
    """The finding for a segment's verdict, at the highest level the filter
    asks for that the verdict reaches; None when it asks for none."""
    d = verdict.get("decision", ALLOW)
    if d == ALLOW:
        return None
    rank = RANK[CRITICAL] if d == UNSCANNED else RANK[d]
    if _ours(requested):
        hits = [lv for lv in LEVELS if RANK[lv] <= rank and wanted(f"{stage}.{lv}", requested)]
        if not hits:
            return None
        level = hits[-1]
    else:
        level = d
    return {"detector": f"{stage}.{level}", "category": "injection", "label": verdict.get("label", d), "score": verdict.get("score", 1.0),
            "severity": "warning" if level == "review" else "critical", "segment_index": segment_index}


def verdict_of(r) -> dict:
    """What is kept of a scored item: its decision and the deciding question."""
    if r.decision == ALLOW:
        return {"decision": ALLOW}
    deciding = list(r.answers.items()) + [("paste:" + k, v) for k, v in r.paste.items()]
    label, score = max(deciding, key=lambda qa: qa[1].risk, default=("rule", None))
    s = round(score.risk, 4) if score is not None else 1.0
    if any(x.severity == "block" for x in r.rules) and RANK[r.decision] >= RANK[BLOCK] and (score is None or s < 0.5):
        label, s = next(x.name for x in r.rules if x.severity == "block"), 1.0
    return {"decision": r.decision, "label": label, "score": s}


def parse_allowlist(spec: str):
    """Networks from "203.0.113.7, 198.51.100.0/24"; raises ValueError on a bad entry."""
    return [ipaddress.ip_network(x.strip(), strict=False) for x in (spec or "").split(",") if x.strip()]


def client_ip(headers, peer: str, header: str) -> str:
    """The client's address: the first entry of `header` when set, else the TCP
    peer. Use a header the proxy sets and the client cannot: behind Runpod's
    proxy (Cloudflare) that is cf-connecting-ip, which Cloudflare refuses from
    clients. Never X-Forwarded-For there: the proxy appends to the client's
    value, so its first entry is the client's to choose (tested 2026-10-20)."""
    if header:
        v = headers.get(header, "")
        return v.split(",")[0].strip() if v else ""
    return peer or ""


def size_bucket(chars: int) -> str:
    for limit, label in ((2000, "le_500tok"), (8000, "le_2ktok"), (24000, "le_6ktok")):
        if chars <= limit:
            return label
    return "gt_6ktok"


class DecisionLog:
    """One line per segment, never with text. Previews of flagged segments
    (behind the preview flag) go to a separate preview log when one is set,
    so they can be kept for less time; without one, into the decision line."""

    def __init__(self, target: str, preview: bool, preview_chars: int, preview_target: str = ""):
        self.preview, self.preview_chars = preview, preview_chars
        self._lock = threading.Lock()
        self._f = sys.stdout if target == "-" else open(target, "a", buffering=1)
        self.preview_log = open(preview_target, "a", buffering=1) if preview_target else None

    def write(self, rec: dict, preview: str = ""):
        preview = redact(preview)[: self.preview_chars] if preview else ""
        if preview and self.preview_log is None:
            rec = dict(rec, preview=preview)
        line = json.dumps(rec, ensure_ascii=False, separators=(",", ":"))
        with self._lock:
            self._f.write(line + "\n")
            self._f.flush()
            if preview and self.preview_log is not None:
                p = {"ts": rec["ts"], "sha256": rec["sha256"], "request_id": rec.get("request_id"), "app_id": rec.get("app_id"),
                     "stage": rec["stage"], "decision": rec["decision"], "preview": preview}
                self.preview_log.write(json.dumps(p, ensure_ascii=False, separators=(",", ":")) + "\n")
                self.preview_log.flush()


def create_app(settings: Settings, lanes: dict | None = None) -> FastAPI:
    if not settings.token:
        raise SystemExit("wolfguard: no bearer token (set WOLFGUARD_TOKEN or WOLFGUARD_TOKEN_FILE)")
    metrics = Metrics()
    store = PolicyStore(settings.policy_path, on_reload=lambda ok: (metrics.reloads.labels("ok" if ok else "invalid").inc(), metrics.invalid.set(0 if ok else 1)))
    dlog = DecisionLog(settings.decision_log, settings.preview, settings.preview_chars, settings.preview_log)
    verdicts = storemod.VerdictStore(settings.store, settings.flagged_ttl, settings.clean_ttl) if settings.store else None
    pending: dict[str, asyncio.Future] = {}     # store key -> its background scoring under way (.started: when)
    background: set = set()                     # running background tasks (kept referenced)
    if lanes is None:
        Worker = ProcessWorker if settings.workers == "process" else ThreadWorker
        lanes = {
            "large": Lane("large", [Worker(dict(settings.backend, threads=settings.threads), store.doc, f"large-{i}") for i in range(settings.large_workers)],
                          settings.queue_max, settings.queue_wait, settings.bg_queue_max, settings.bg_queue_wait),
            "small": Lane("small", [Worker(dict(settings.backend, threads=settings.small_threads), store.doc, f"small-{i}") for i in range(settings.small_workers)],
                          settings.queue_max, settings.queue_wait, settings.bg_queue_max, settings.bg_queue_wait),
        }
    stop = threading.Event()

    @contextlib.asynccontextmanager
    async def lifespan(_app):
        yield
        stop.set()
        for lane in lanes.values():
            lane.close()

    app = FastAPI(title="wolfguard", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.store, app.state.lanes, app.state.metrics, app.state.dlog = store, lanes, metrics, dlog
    app.state.verdicts, app.state.pending, app.state.background = verdicts, pending, background

    def watch():
        while not stop.wait(settings.reload_interval):
            store.reload()
    threading.Thread(target=watch, daemon=True, name="wolfguard-policy").start()

    allowed_nets = parse_allowlist(settings.allow_ips)
    proxy_nets = parse_allowlist(settings.trusted_proxies)

    if allowed_nets:
        @app.middleware("http")
        async def allowlist(request: Request, call_next):
            peer = request.client.host if request.client else ""
            # Local callers pass: the Unix socket (no peer address) and the container's
            # own health check on loopback.
            try:
                loopback = ipaddress.ip_address(peer).is_loopback if peer else False
            except ValueError:
                loopback = False
            if not peer or (loopback and request.url.path in ("/healthz", "/readyz")):
                return await call_next(request)
            if settings.client_ip_header and proxy_nets:
                try:
                    from_proxy = any(ipaddress.ip_address(peer) in n for n in proxy_nets)
                except ValueError:
                    from_proxy = False
                if not from_proxy:
                    metrics.denied.labels("not_via_proxy").inc()
                    return JSONResponse({"error": "forbidden"}, status_code=403)
            ip = client_ip(request.headers, peer, settings.client_ip_header)
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                metrics.denied.labels("no_client_ip").inc()
                return JSONResponse({"error": "forbidden"}, status_code=403)
            if not any(addr in n for n in allowed_nets):
                metrics.denied.labels("not_allowed").inc()
                log.warning("refused a request from %s (not in WOLFGUARD_ALLOW_IPS)", addr)
                return JSONResponse({"error": "forbidden"}, status_code=403)
            return await call_next(request)

    def authorised(request: Request) -> bool:
        got = request.headers.get("authorization", "")
        want = "Bearer " + settings.token
        return hmac.compare_digest(got.encode(), want.encode())

    @app.get("/healthz")
    def healthz():
        return {"ok": True}

    @app.get("/readyz")
    def readyz():
        failed = {n: l.failed() for n, l in lanes.items() if l.failed()}
        ready = all(l.ready() for l in lanes.values()) and not failed
        body = {"ready": ready, "policy_version": store.version, "lanes": {n: l.ready() for n, l in lanes.items()}}
        if failed:
            body["failed"] = failed
        return JSONResponse(body, status_code=200 if ready else 503)

    @app.get("/metrics")
    def prom(request: Request):
        if not authorised(request):
            return JSONResponse({"error": "unauthorised"}, status_code=401)
        return PlainTextResponse(generate_latest(metrics.registry), media_type=CONTENT_TYPE_LATEST)

    def reject(code, reason, msg):
        metrics.rejected.labels(str(code), reason).inc()
        return JSONResponse({"error": msg}, status_code=code)

    async def classify(request: Request):
        if not authorised(request):
            return JSONResponse({"error": "unauthorised"}, status_code=401)
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > settings.max_body_bytes:
            return reject(413, "body", "request body too large")
        raw = await request.body()
        if len(raw) > settings.max_body_bytes:
            return reject(413, "body", "request body too large")
        try:
            body = json.loads(raw)
            segs = body.get("segments") or []
            if not isinstance(segs, list):
                raise ValueError("segments must be a list")
        except (ValueError, AttributeError) as e:
            return reject(400, "invalid", f"invalid request: {e}")
        pol = store.policy
        if len(segs) > pol.max_segments:
            return reject(413, "segments", f"more than {pol.max_segments} segments")
        if any(len(str((s or {}).get("text") or "")) > pol.max_segment_chars for s in segs if isinstance(s, dict)):
            return reject(413, "segment_size", f"a segment longer than {pol.max_segment_chars} characters")
        want = request.query_params.get("policy")
        if want and want != store.version:
            metrics.mismatch.inc()
            log.warning("called with policy version %s, running %s", want, store.version)
        if settings.debug_delay_ms:
            # Test only (WOLFGUARD_DEBUG_DELAY_MS): a slow sidecar, for the shadow-latency E2E check.
            await asyncio.sleep(settings.debug_delay_ms / 1000)
        # Only what would be scored takes a worker: the stages the filter asks
        # for, of an app that is not skipped. The gateway sends a tool-result
        # filter the user's text too, and every app on the LLM; scoring or
        # queueing those costs a worker, and a 503 on them is decided by the
        # filter's fail mode (closed blocks the request).
        # Nothing left: answered at once.
        app = pol.app((body.get("meta") or {}).get("app_id"))
        requested = {st for st in STAGES if any(wanted(f"{st}.{lv}", body.get("detectors")) for lv in LEVELS)}
        stages = set() if app.skip else requested & set(app.stages)
        if stages != set(STAGES):
            dicts = [s for s in segs if isinstance(s, dict)]
            kept = [s for s in dicts if stage_of(s) in stages or ("user_message" in stages and not s.get("kind") and s.get("role") == "system")]
            for s in dicts:
                st = stage_of(s)
                if st and st not in stages:
                    metrics.skipped.labels("app_skip" if app.skip else "not_requested" if st not in requested else "stage_off").inc()
            if not any(stage_of(s) for s in kept):
                return JSONResponse({"flagged": False, "findings": []})
            segs = kept
            body = dict(body, segments=kept)
        meta = body.get("meta") or {}
        requested_detectors = body.get("detectors")
        dicts = [x for x in segs if isinstance(x, dict)]
        system_segs = [x for x in dicts if not x.get("kind") and x.get("role") == "system"]
        by_index = {int(x.get("index", 0)): x for x in dicts}
        items = type_call(body).items
        enf = app.enforcement
        tenant = storemod.tenant_of(meta)
        doc, version = store.doc, store.version

        def base_rec(it, decision):
            return {"ts": round(time.time(), 3), "request_id": meta.get("request_id", ""), "app_id": meta.get("app_id"), "llm_id": meta.get("llm_id"),
                    "direction": body.get("direction"), "stage": it.stage, "tool_name": it.tool_name, "segment_index": it.segment_index,
                    "decision": decision, "sha256": storemod.text_sha256(it.text), "policy_version": version}

        # Each distinct item once: identical segments (a decoded view equal to its raw form) share a verdict.
        keyed: dict[str, list] = {}
        for it in items:
            k = storemod.item_key(version, tenant, it) if verdicts is not None else f"#{it.segment_index}"
            keyed.setdefault(k, []).append(it)
        decided: dict[str, dict] = {}
        inline, deferred, waits = [], [], []
        for k, its in keyed.items():
            it = its[0]
            if verdicts is not None:
                v = verdicts.get(k, storemod.text_sha256(it.text))
                if v is not None:
                    decided[k] = v
                    metrics.store.labels("allowed" if v.get("allowed") else "hit" if v.get("decision") == ALLOW else "hit_flagged").inc()
                    if v.get("decision") != ALLOW:
                        dlog.write(dict(base_rec(it, v["decision"]), from_store=True, label=v.get("label"), score=v.get("score")))
                    continue
                metrics.store.labels("miss").inc()
            mode = enf.mode_of(it.stage, it.tool_name) if verdicts is not None else "inline"
            if mode == "deferred" and it.stage == "tool_call" and pol.secret_rules and precheck.secret_access(it.text):
                # A call that reads secrets is decided now, whatever the tool: deferring it
                # would let the read happen.
                mode = "inline"
            if mode == "inline":
                inline.append(k)
            elif k in pending:
                waits.append(k)
            else:
                deferred.append(k)

        def busy(ks, why):
            """when_busy for items that could not be scored; returns an error response or None."""
            for k in ks:
                it = keyed[k][0]
                wb = enf.stage(it.stage).when_busy if verdicts is not None else "error"
                metrics.busy.labels(it.stage, wb).inc()
                if wb == "error":
                    return why()
                decided[k] = {"decision": UNSCANNED, "label": "unscanned", "score": 1.0} if wb == UNSCANNED else {"decision": ALLOW}
                if wb == UNSCANNED:
                    dlog.write(dict(base_rec(it, UNSCANNED), mode=enf.mode_of(it.stage, it.tool_name)))
            return None

        def sub_body(ks):
            return dict(body, segments=system_segs + [by_index[keyed[k][0].segment_index] for k in ks])

        def lane_for(ks):
            chars = sum(len(keyed[k][0].text) for k in ks)
            return lanes["small"] if chars <= settings.small_chars and lanes.get("small") and lanes["small"].workers else lanes["large"]

        def record(ks, results, stats, ms, lane, mode):
            """Log, count and keep the verdicts of a scoring run; returns them by key."""
            by_seg = {keyed[k][0].segment_index: k for k in ks}
            out = {}
            pol_now = store.policy
            for r in results:
                k = by_seg.get(r.item.segment_index)
                if k is None:
                    continue
                if r.skipped:
                    metrics.skipped.labels(r.skipped).inc()
                metrics.decisions.labels(r.item.stage, str(meta.get("app_id", "")), metrics.tool(r.item.tool_name), r.decision).inc()
                v = verdict_of(r)
                out[k] = v
                if verdicts is not None and not r.skipped:
                    verdicts.put(k, storemod.text_sha256(r.item.text), tenant, r.item.stage, v)
                rec = dict(base_rec(r.item, r.decision), skipped=r.skipped or None,
                           scores={q: round(a.risk, 4) for q, a in r.answers.items()} | {"paste:" + q: round(a.risk, 4) for q, a in r.paste.items()},
                           rules=[x.name for x in r.rules], windows=r.windows, cached_windows=r.cached, latency_ms=round(ms, 1),
                           chars=len(r.item.text), model_revision=pol_now.model_revision, lane=lane.name, mode=mode)
                dlog.write(rec, r.item.text if dlog.preview and r.decision != ALLOW else "")
            metrics.cache.labels("hit").inc(stats.cache_hits)
            metrics.cache.labels("miss").inc(stats.scenes - stats.cache_hits)
            return out

        # Deferred: answered clean now, scored in the background (lower priority than any caller).
        if deferred:
            lane = lane_for(deferred)
            if lane.full(BACKGROUND):
                err = busy(deferred, lambda: reject(503, "saturated", f"{lane.name} lane: background queue full"))
                if err is not None:
                    return err
            else:
                loop = asyncio.get_running_loop()
                futs = {k: loop.create_future() for k in deferred}
                for f in futs.values():
                    f.started = time.monotonic()
                pending.update(futs)
                bbody = sub_body(deferred)

                async def score_later(ks=tuple(deferred), lane=lane, bbody=bbody, futs=futs):
                    got = {}
                    try:
                        (results, stats), ms = await lane.run(bbody, doc, priority=BACKGROUND)
                        got = record(ks, results, stats, ms, lane, "deferred")
                        metrics.deferred.labels("scored").inc(len(ks))
                    except (Saturated, WorkerFailed) as e:
                        metrics.deferred.labels("dropped").inc(len(ks))
                        log.warning("deferred scoring dropped (%d segments): %s", len(ks), e)
                    finally:
                        for k, f in futs.items():
                            if pending.get(k) is f:
                                del pending[k]
                            if not f.done():
                                f.set_result(got.get(k))
                task = asyncio.create_task(score_later())
                background.add(task)
                task.add_done_callback(background.discard)
                metrics.deferred.labels("queued").inc(len(deferred))
                # This call's own content is answered clean now, without waiting for it.
                for k in deferred:
                    decided[k] = {"decision": ALLOW, "pending": True}

        # Inline: scored now, ahead of background work.
        if inline:
            lane = lane_for(inline)
            try:
                (results, stats), ms = await lane.run(sub_body(inline), doc, gone=request.is_disconnected, priority=INLINE)
                decided.update(record(inline, results, stats, ms, lane, "inline"))
                stage_label = results[0].item.stage if results else "none"
                metrics.latency.labels(stage_label, size_bucket(sum(len(keyed[k][0].text) for k in inline))).observe(ms / 1000)
            except Abandoned as e:
                return reject(499, "abandoned", str(e))
            except Saturated as e:
                err = busy(inline, lambda e=e: reject(503, "saturated", str(e)))
                if err is not None:
                    return err
            except WorkerFailed as e:
                err = busy(inline, lambda e=e: reject(503, "worker", f"scoring failed: {e}"))
                if err is not None:
                    return err

        # Content an earlier call is still scoring (a client's next request racing
        # its background score): a short wait for it, else clean for now.
        if waits:
            futs = {k: pending.get(k) for k in waits}
            # Only a score started a while ago is a previous turn's; a younger one
            # is this request's other filter calling, which must not wait for it.
            old = time.monotonic() - enf.pending_min_age
            live = {f for f in futs.values() if f is not None and not f.done() and f.started <= old}
            if live and enf.pending_wait > 0:
                await asyncio.wait(live, timeout=enf.pending_wait)
            for k, f in futs.items():
                v = f.result() if f is not None and f.done() else None
                if v is None and verdicts is not None:
                    v = verdicts.get(k, storemod.text_sha256(keyed[k][0].text))
                metrics.store.labels("pending_scored" if v is not None else "pending_open").inc()
                decided[k] = v if v is not None else {"decision": ALLOW, "pending": True}

        findings = []
        for k, its in keyed.items():
            v = decided.get(k) or {"decision": ALLOW}
            for it in its:
                f = finding_for(it.stage, it.segment_index, v, requested_detectors)
                if f is not None:
                    findings.append(f)
        return JSONResponse({"flagged": bool(findings), "findings": findings})

    # The verdict store's operations over HTTP (the same as python -m wolfguard.store), for a
    # deployment with no shell into the container, such as the GPU image on a Runpod pod.
    # Behind the bearer token and the client-IP allowlist like everything else.
    async def admin(request: Request):
        if not authorised(request):
            return JSONResponse({"error": "unauthorised"}, status_code=401)
        if verdicts is None:
            return JSONResponse({"error": "the verdict store is off (WOLFGUARD_STORE)"}, status_code=404)
        op = request.path_params["op"]
        if request.method == "GET" and op == "flags":
            return JSONResponse({"flags": verdicts.flags(int(request.query_params.get("limit", "50")))})
        if request.method == "GET" and op == "stats":
            return JSONResponse(verdicts.stats())
        if request.method == "POST" and op in ("allow", "unallow"):
            try:
                req = json.loads(await request.body() or b"{}")
                sha = str(req["sha256"]).lower()
                if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha):
                    raise ValueError("sha256 must be 64 hex characters")
            except (ValueError, KeyError, TypeError) as e:
                return reject(400, "invalid", f"invalid request: {e}")
            if op == "unallow":
                return JSONResponse({"removed": verdicts.unallow(sha)})
            days = float(req.get("days", 30))
            verdicts.allow(sha, days, str(req.get("note", ""))[:500])
            log.warning("flag lifted for %s for %g days: %s", sha, days, str(req.get("note", ""))[:200])
            return JSONResponse({"allowed": sha, "days": days})
        return JSONResponse({"error": "not found"}, status_code=404)

    app.add_api_route("/v1/admin/{op}", admin, methods=["GET", "POST"])
    app.add_api_route("/v1/classify", classify, methods=["POST"])
    app.add_api_route("/classify", classify, methods=["POST"])
    return app


def unix_socket(path: str, mode: int = 0o660, gid: int | None = None) -> socket.socket:
    """A listening Unix socket at path, mode 0660 (group = the gateway's), created by us so the mode is right."""
    p = Path(path)
    if p.exists() or p.is_symlink():
        p.unlink()
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old = os.umask(0o177)
    try:
        s.bind(path)
    finally:
        os.umask(old)
    if gid is not None:
        os.chown(path, -1, gid)
    os.chmod(path, mode)
    s.listen(128)
    return s


def main(argv=None):
    import uvicorn
    ap = argparse.ArgumentParser(prog="wolfguard")
    ap.add_argument("--policy")
    ap.add_argument("--model")
    ap.add_argument("--socket", default=os.environ.get("WOLFGUARD_SOCKET", ""))
    ap.add_argument("--socket-gid", type=int, default=int(os.environ["WOLFGUARD_SOCKET_GID"]) if os.environ.get("WOLFGUARD_SOCKET_GID") else None)
    ap.add_argument("--host", default=os.environ.get("WOLFGUARD_HOST", "127.0.0.1"))
    ap.add_argument("--port", type=int, default=int(os.environ.get("WOLFGUARD_PORT", "0")))
    ap.add_argument("--stub", action="store_true", help="no model: the stub backend (dry runs and E2E)")
    a = ap.parse_args(argv)
    logging.basicConfig(level=os.environ.get("WOLFGUARD_LOG_LEVEL", "INFO"), stream=sys.stderr, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    s = Settings.from_env(policy_path=a.policy)
    if a.model:
        s.backend["model_dir"] = a.model
    if a.stub:
        s.backend = {"kind": "stub"}
    app = create_app(s)
    cfg = uvicorn.Config(app, log_level="warning", access_log=False, lifespan="on")
    server = uvicorn.Server(cfg)
    if a.socket:
        sock = unix_socket(a.socket, gid=a.socket_gid)
        log.info("listening on unix:%s", a.socket)
        server.run(sockets=[sock])
    else:
        if not a.port:
            raise SystemExit("wolfguard: give --socket or --port")
        cfg.host, cfg.port = a.host, a.port
        log.info("listening on %s:%d", a.host, a.port)
        server.run()


if __name__ == "__main__":
    main()
