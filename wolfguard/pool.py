"""Model workers and lanes.

A worker is a process with its own model (or, in tests, a thread with a stub
backend). It is ready once the model is loaded and one dummy scene per
stage has been scored (warm-up). A lane is a set of workers behind a
bounded queue: a request waits at most `queue_wait` seconds for a free
worker, and at most `queue_max` requests wait at a time; beyond either,
the lane answers Saturated at once (the service returns 503).

The service runs two lanes: "large" (2 workers x 2 torch threads by
default) and "small" (1 worker), so a short user message is never stuck
behind a 6,000-token tool result.
"""
from __future__ import annotations

import asyncio
import logging
import multiprocessing as mp
import threading
import time

log = logging.getLogger("wolfguard.pool")


class Saturated(Exception):
    pass


class WorkerFailed(Exception):
    pass


class Abandoned(Exception):
    pass


WARM_UP = {"direction": "request", "meta": {}, "segments": [
    {"index": 0, "role": "tool", "kind": "tool_result", "tool_name": "warmup", "text": "warm up"},
    {"index": 1, "role": "user", "text": "warm up"},
    {"index": 2, "role": "assistant", "kind": "tool_call", "tool_name": "warmup", "text": "{}", "context": {"user_goal": "warm up"}},
    {"index": 3, "role": "system", "kind": "tool_definition", "tool_name": "warmup", "text": "{}"}]}


def make_backend(spec: dict):
    if spec["kind"] == "jev":
        from wolfguard.jev import JevBackend
        return JevBackend(spec["model_dir"], threads=spec.get("threads"), revision=spec.get("revision", ""), device=spec.get("device", "cpu"))
    if spec["kind"] == "stub":
        from wolfguard.stub import StubBackend
        return StubBackend(delay_per_token=spec.get("delay_per_token", 0.0))
    raise ValueError(f"unknown backend {spec['kind']!r}")


class _Engine:
    """A backend and a scorer, re-parsing the policy only when its version changes."""

    def __init__(self, spec, policy_doc):
        from wolfguard import policy as policymod
        from wolfguard.scorer import Scorer
        self.policymod = policymod
        self.backend = make_backend(spec)
        self.policy_version = None
        self.scorer = Scorer(self.backend, policymod.parse(policy_doc), max_rows=spec.get("max_rows", 24))
        self.policy_version = policy_doc.get("version")
        self.run(WARM_UP, policy_doc)
        _trim()

    def run(self, body, policy_doc):
        from wolfguard.segments import type_call
        if policy_doc.get("version") != self.policy_version:
            self.scorer.set_policy(self.policymod.parse(policy_doc))
            self.policy_version = policy_doc.get("version")
        return self.scorer.score(type_call(body))


def _trim():
    """Hand freed loading and warm-up buffers back to the OS (glibc keeps them otherwise: ~350 MB per worker)."""
    try:
        import ctypes
        ctypes.CDLL("libc.so.6").malloc_trim(0)
    except (OSError, AttributeError):
        pass


def _process_main(conn, spec, policy_doc):
    try:
        engine = _Engine(spec, policy_doc)
    except Exception as e:  # noqa: BLE001
        conn.send(("failed", repr(e)))
        return
    conn.send(("ready", None))
    while True:
        try:
            msg = conn.recv()
        except EOFError:
            return
        if msg is None:
            return
        body, doc = msg
        try:
            conn.send(("ok", engine.run(body, doc)))
        except Exception as e:  # noqa: BLE001
            conn.send(("error", repr(e)))


class ProcessWorker:
    # Workers load the model one at a time: loading and warm-up peak at about
    # twice a worker's steady memory, so two loading together needed more
    # than 3 GB where the running sidecar holds about 2 (docs/BENCHMARKS.md).
    _start_gate = threading.Lock()

    def __init__(self, spec, policy_doc, name=""):
        self.spec, self.name = spec, name
        self._start(policy_doc)

    def _start(self, policy_doc):
        ctx = mp.get_context("spawn")
        self.conn, child = ctx.Pipe()
        self.proc = ctx.Process(target=_process_main, args=(child, self.spec, policy_doc), daemon=True, name=f"wolfguard-{self.name}")
        self.ready = threading.Event()
        self.failed = None
        self._policy_doc = policy_doc
        threading.Thread(target=self._start_when_free, daemon=True).start()

    def _start_when_free(self):
        with ProcessWorker._start_gate:
            self.proc.start()
            self._await_ready()

    def _await_ready(self):
        try:
            kind, detail = self.conn.recv()
        except EOFError:
            kind, detail = "failed", "worker exited during start"
        if kind == "ready":
            self.ready.set()
        else:
            self.failed = detail
            log.error("worker %s failed to start: %s", self.name, detail)

    def call(self, body, policy_doc):
        try:
            self.conn.send((body, policy_doc))
            kind, value = self.conn.recv()
        except (EOFError, BrokenPipeError, OSError) as e:
            log.error("worker %s died (%s); restarting", self.name, e)
            self._start(policy_doc)
            raise WorkerFailed(str(e)) from e
        if kind != "ok":
            raise WorkerFailed(value)
        return value

    def close(self):
        try:
            self.conn.send(None)
        except Exception:  # noqa: BLE001
            pass
        if self.proc.pid is None:           # never started (still waiting for the start gate)
            return
        self.proc.join(timeout=5)
        if self.proc.is_alive():
            self.proc.terminate()


class ThreadWorker:
    """In-process worker (tests, and a single-process dev mode)."""

    def __init__(self, spec, policy_doc, name=""):
        self.name = name
        self.ready = threading.Event()
        self.failed = None
        self._lock = threading.Lock()

        def start():
            try:
                self.engine = _Engine(spec, policy_doc)
                self.ready.set()
            except Exception as e:  # noqa: BLE001
                self.failed = repr(e)
        threading.Thread(target=start, daemon=True).start()

    def call(self, body, policy_doc):
        with self._lock:
            return self.engine.run(body, policy_doc)

    def close(self):
        pass


INLINE, BACKGROUND = 0, 1


class Lane:
    """Workers behind a queue with two classes of waiter: inline calls (a
    caller is waiting) and background ones (deferred scoring). A freed worker
    goes to the oldest inline waiter first, so background work never delays
    a caller. Each class has its own cap and wait."""

    def __init__(self, name, workers, queue_max=8, queue_wait=2.0, bg_queue_max=256, bg_queue_wait=300.0):
        self.name, self.workers = name, workers
        self.queue_max, self.queue_wait = queue_max, queue_wait
        self.bg_queue_max, self.bg_queue_wait = bg_queue_max, bg_queue_wait
        self._idle: list | None = None
        self._waiters: list[list] = [[], []]      # per class: futures, oldest first

    def ready(self) -> bool:
        return all(w.ready.is_set() for w in self.workers)

    def failed(self):
        return [w.failed for w in self.workers if w.failed]

    def _cap(self, priority):
        return self.queue_max if priority == INLINE else self.bg_queue_max

    def full(self, priority=INLINE) -> bool:
        """Whether a call of this class would be refused at once."""
        if self._idle is None:
            return not self.workers
        live = [f for f in self._waiters[priority] if not f.done()]
        return not self._idle and len(live) >= self._cap(priority)

    def waiting(self, priority=BACKGROUND) -> int:
        return sum(1 for f in self._waiters[priority] if not f.done())

    async def _acquire(self, priority, wait):
        if self._idle is None:
            self._idle = list(self.workers)
        if self._idle and not any(not f.done() for q in self._waiters for f in q):
            return self._idle.pop(0)
        self._waiters[priority] = [f for f in self._waiters[priority] if not f.done()]
        if len(self._waiters[priority]) >= self._cap(priority):
            raise Saturated(f"{self.name} lane: queue full")
        fut = asyncio.get_running_loop().create_future()
        self._waiters[priority].append(fut)
        await asyncio.wait({fut}, timeout=wait)
        if fut.done() and not fut.cancelled():
            return fut.result()
        fut.cancel()
        raise Saturated(f"{self.name} lane: no worker within {wait}s")

    def _release(self, worker):
        for q in self._waiters:
            while q:
                fut = q.pop(0)
                if not fut.done():
                    fut.set_result(worker)
                    return
        self._idle.append(worker)

    async def run(self, body, policy_doc, gone=None, priority=INLINE):
        """Score on a free worker. `gone` (async, optional) says whether the
        caller has left: checked once a worker is free, so a call the gateway
        gave up on while it waited is not scored (a worker cannot be stopped
        once it runs, and that work would delay every call behind it)."""
        wait = self.queue_wait if priority == INLINE else self.bg_queue_wait
        worker = await self._acquire(priority, wait)
        if gone is not None:
            try:
                left = await gone()
            except Exception:
                left = False
            if left:
                self._release(worker)
                raise Abandoned(f"{self.name} lane: the caller left while the call waited")
        try:
            t = time.perf_counter()
            out = await asyncio.get_running_loop().run_in_executor(None, worker.call, body, policy_doc)
            return out, (time.perf_counter() - t) * 1000
        finally:
            self._release(worker)

    def close(self):
        for w in self.workers:
            w.close()
