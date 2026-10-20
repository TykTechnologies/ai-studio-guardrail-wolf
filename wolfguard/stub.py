"""A stub backend for tests and dry runs: no model, no weights.

Whitespace tokens. A row's attack-side probability is 0.95 when its scene
holds INJECT, 0.8 for LIKELY, 0.5 for SUSPECT, else 0.02. `delay_per_token` makes a forward
sleep in proportion to its tokens, to test lanes and timeouts. Counts
forwards, rows and prepares.
"""
from __future__ import annotations

import threading
import time


class StubBackend:
    revision = "stub-rev-1"

    def __init__(self, delay_per_token: float = 0.0):
        self.delay = delay_per_token
        self.vocab, self.words = {}, []
        self.forwards = self.rows = self.prepares = 0
        self.batches = []
        self._lock = threading.Lock()

    def tokenize(self, text):
        out = []
        with self._lock:
            for w in text.split():
                if w not in self.vocab:
                    self.vocab[w] = len(self.words)
                    self.words.append(w)
                out.append(self.vocab[w])
        return out

    def detokenize(self, ids):
        return " ".join(self.words[i] for i in ids)

    def prepare(self, question):
        self.prepares += 1
        return question

    def forward(self, rows):
        self.forwards += 1
        self.rows += len(rows)
        self.batches.append([(scene, q.name) for scene, q in rows])
        if self.delay:
            time.sleep(self.delay * sum(len(scene.split()) for scene, _ in rows))
        out = []
        for scene, q in rows:
            r = 0.95 if "INJECT" in scene or f"RISK:{q.name}" in scene else 0.8 if "LIKELY" in scene else 0.5 if "SUSPECT" in scene else 0.02
            n = len(q.option_ids)
            risky = [i for i, o in enumerate(q.option_ids) if o in q.risk]
            safe = n - len(risky)
            out.append([(r / len(risky)) if i in risky else ((1 - r) / safe if safe else 0) for i in range(n)])
        return out
