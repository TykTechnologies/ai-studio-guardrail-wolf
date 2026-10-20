#!/usr/bin/env python3
"""The sidecar alone, per stage x size x concurrency, over its socket.

Standard library only, so it runs with the image's own Python next to the
sidecar (bench/x86.sh does that on any docker host):

    python3 bench/sidecar_bench.py --socket /run/wolfguard/wolfguard.sock --token-file /run/secrets/wolfguard_token

Calls are shaped as the 2.3 gateway sends them (fixtures/captures): one
segment per call, the code-review app (app 1). Every text is unique, so the
sidecar's scene cache never answers. Prints one JSON document: per cell,
client latency (it includes queueing for a worker, as the gateway sees it),
status counts and the sidecar's own scoring time.
"""
import argparse
import http.client
import json
import platform
import socket
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

LINES = [
    "diff --git a/src/cache/lru.go b/src/cache/lru.go",
    "@@ -41,9 +41,12 @@ func (c *LRU) Put(key string, v []byte) {",
    "+\tif c.size+len(v) > c.max { c.evictOldest() }",
    "-\tc.items[key] = v",
    "+\tc.items[key] = entry{v: v, at: time.Now()}",
    "--- PASS: TestLRUEvictsOldest (0.03s)",
    "ok  \tgithub.com/acme/widgets/src/cache\t0.412s",
    "[0042] Running go vet ./...",
    "README.md: Build with make; run make test before pushing.",
    "func (c *LRU) evictOldest() { oldest := c.order.Back(); c.remove(oldest) }",
]


def text_of(chars, nonce):
    """Clean diff and log text, about 2.75 characters per token, with a run id
    every ~1,000 characters so no window repeats."""
    out, n, k = [], 0, 0
    while n < chars:
        block = f"[{nonce}:{k}]\n" + "\n".join(LINES[(k + i) % len(LINES)] for i in range(12))
        out.append(block)
        n += len(block) + 1
        k += 1
    return "\n".join(out)[:chars]


GOAL = "Review PR 214 and summarise the risks."


def body(stage, chars, nonce):
    meta = {"app_id": 1, "llm_id": 1, "model": "bench", "request_id": nonce, "vendor": "openai", "is_chat": False}
    if stage == "user_message":
        seg = {"index": 0, "role": "user", "text": f"@bot can you explain the cache change in PR {nonce[:6]}? Does it still evict the oldest entry first?"}
    elif stage == "tool_result":
        seg = {"index": 0, "role": "tool", "kind": "tool_result", "tool_name": "shell", "tool_call_id": "call_1", "text": text_of(chars, nonce)}
    elif stage == "tool_call":
        seg = {"index": 0, "role": "assistant", "kind": "tool_call", "tool_name": "shell", "tool_call_id": "call_1",
               "text": json.dumps({"cmd": f"git diff origin/main...HEAD -- src/cache/ # {nonce[:6]}"})}
    else:
        seg = {"index": 0, "role": "system", "kind": "tool_definition", "tool_name": "read",
               "text": json.dumps({"type": "function", "function": {"name": f"read_{nonce[:6]}", "description": "Read a file from the checkout.",
                                                                   "parameters": {"type": "object", "properties": {"path": {"type": "string", "description": "The file path."}}}}})}
    return {"direction": "request", "detectors": ["*"], "redact": False, "segments": [seg], "meta": meta, "context": {"user_goal": GOAL}}


class Conn(http.client.HTTPConnection):
    def __init__(self, path, timeout):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def call(args, payload):
    c = Conn(args.socket, args.timeout) if args.socket else http.client.HTTPConnection(args.host, args.port, timeout=args.timeout)
    t = time.perf_counter()
    try:
        c.request("POST", "/v1/classify", json.dumps(payload), {"Authorization": "Bearer " + args.token, "Content-Type": "application/json"})
        r = c.getresponse()
        r.read()
        return r.status, time.perf_counter() - t
    except OSError:
        return 0, time.perf_counter() - t
    finally:
        c.close()


def pct(xs, p):
    xs = sorted(xs)
    if not xs:
        return None
    k = (len(xs) - 1) * p
    lo = int(k)
    return round((xs[lo] + (xs[min(lo + 1, len(xs) - 1)] - xs[lo]) * (k - lo)) * 1000, 1)


CELLS = [("user_message", 0), ("tool_call", 0), ("tool_definition", 0),
         ("tool_result", 275), ("tool_result", 2750), ("tool_result", 8250), ("tool_result", 16500), ("tool_result", 32768)]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--socket", default="")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18900)
    ap.add_argument("--token-file", required=True)
    ap.add_argument("--concurrency", default="1,4,16")
    ap.add_argument("--n", type=int, default=12, help="calls per cell at concurrency 1 (more at higher concurrency)")
    ap.add_argument("--timeout", type=float, default=60)
    args = ap.parse_args()
    args.token = open(args.token_file).read().strip()
    for st in ("user_message", "tool_result"):        # first calls per stage pay one-off costs
        call(args, body(st, 300, uuid.uuid4().hex))
    out = {"host": {"machine": platform.machine(), "processor": platform.processor(), "python": platform.python_version()}, "cells": []}
    for conc in [int(c) for c in args.concurrency.split(",")]:
        for stage, chars in CELLS:
            n = args.n if conc == 1 else conc * 3
            if chars > 16500 and conc > 4:
                n = conc * 2
            res, lock = [], threading.Lock()

            def one(_):
                st_, s = call(args, body(stage, chars, uuid.uuid4().hex))
                with lock:
                    res.append((st_, s))

            t0 = time.perf_counter()
            with ThreadPoolExecutor(conc) as ex:
                list(ex.map(one, range(n)))
            wall = time.perf_counter() - t0
            ok = [s for st_, s in res if st_ == 200]
            cellr = {"stage": stage, "chars": chars, "concurrency": conc, "n": n, "wall_s": round(wall, 2),
                     "p50_ms": pct(ok, .5), "p95_ms": pct(ok, .95), "p99_ms": pct(ok, .99), "max_ms": pct(ok, 1),
                     "status": {str(k): sum(1 for st_, _ in res if st_ == k) for k in sorted({st_ for st_, _ in res})}}
            out["cells"].append(cellr)
            print(json.dumps(cellr), flush=True)
    print(json.dumps(out))


if __name__ == "__main__":
    main()
