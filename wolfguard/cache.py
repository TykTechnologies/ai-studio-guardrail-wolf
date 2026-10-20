"""The sidecar's own verdict cache: an in-memory LRU with a TTL.

Secondary to the gateway's verdict cache; it helps when two
filters, or a hub and an edge on the same host, ask about the same scene.
The key covers everything a verdict depends on: the stage, the exact scene
text, the question-set version and the model revision.
"""
from __future__ import annotations

import hashlib
import threading
import time
from collections import OrderedDict


def key(stage: str, scene: str, question_version: str, model_revision: str) -> str:
    h = hashlib.sha256()
    for part in (stage, question_version, model_revision, scene):
        h.update(part.encode("utf-8"))
        h.update(b"\x00")
    return h.hexdigest()


class LRU:
    def __init__(self, max_entries: int = 50_000, ttl_seconds: float = 600.0, clock=time.monotonic):
        self.max, self.ttl, self.clock = max_entries, ttl_seconds, clock
        self._d: OrderedDict[str, tuple[float, object]] = OrderedDict()
        self._lock = threading.Lock()
        self.hits = self.misses = 0

    def get(self, k: str):
        with self._lock:
            v = self._d.get(k)
            if v is None or self.clock() - v[0] > self.ttl:
                if v is not None:
                    del self._d[k]
                self.misses += 1
                return None
            self._d.move_to_end(k)
            self.hits += 1
            return v[1]

    def put(self, k: str, value) -> None:
        if self.max <= 0:
            return
        with self._lock:
            self._d[k] = (self.clock(), value)
            self._d.move_to_end(k)
            while len(self._d) > self.max:
                self._d.popitem(last=False)

    def __len__(self) -> int:
        return len(self._d)
