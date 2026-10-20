"""The verdict store: what the sidecar has already decided (docs/ARCHITECTURE.md, deferred enforcement).

Deferred enforcement answers content it has not seen as clean and scores it
in the background; the verdict lands here, and the client's next request,
which resends that content in its history, is answered from it at once. A
flagged verdict is what keeps a poisoned conversation stopped, so it is kept
longer (7 days by default) than a clean one (24 hours).

Keys cover the policy version, the tenant (app, else LLM), the stage, the
tool name, the text and the scene context (goal, system), so a policy
version bump starts afresh. Rows also carry the text's SHA-256, the hash
the decision log records, which is how an operator lifts a false flag:

    python -m wolfguard.store --db /var/log/wolfguard/verdicts.db allow <sha256> [--days 30] [--note why]
    python -m wolfguard.store --db ... flags [--limit 50]
    python -m wolfguard.store --db ... unallow <sha256>
    python -m wolfguard.store --db ... stats

An allowed hash is answered clean whatever its verdict, until it expires.
The store is SQLite (WAL) on the log volume, so it survives restarts and
the CLI can write while the service runs; ":memory:" for tests and dev.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
import threading
import time

FLAGGED_TTL = 7 * 86400
CLEAN_TTL = 86400

_SCHEMA = """
CREATE TABLE IF NOT EXISTS verdicts (
    key TEXT PRIMARY KEY, text_sha256 TEXT NOT NULL, tenant TEXT NOT NULL, stage TEXT NOT NULL,
    decision TEXT NOT NULL, verdict TEXT NOT NULL, at REAL NOT NULL, expires REAL NOT NULL);
CREATE INDEX IF NOT EXISTS verdicts_sha ON verdicts (text_sha256);
CREATE INDEX IF NOT EXISTS verdicts_expires ON verdicts (expires);
CREATE TABLE IF NOT EXISTS allows (text_sha256 TEXT PRIMARY KEY, at REAL NOT NULL, expires REAL NOT NULL, note TEXT NOT NULL DEFAULT '');
"""


def text_sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def item_key(policy_version: str, tenant: str, item) -> str:
    """The store key of a scoring item (segments.Item)."""
    parts = [policy_version, tenant, item.stage, item.tool_name, item.text, item.goal, item.system]
    return hashlib.sha256(json.dumps(parts, ensure_ascii=False).encode()).hexdigest()


def tenant_of(meta: dict) -> str:
    """Whom a call's verdicts belong to: its app, else its LLM (the gateway
    sends app_id 0 on response calls), else nobody in particular."""
    app = meta.get("app_id")
    if app not in (None, "", 0, "0"):
        return f"app:{app}"
    llm = meta.get("llm_id")
    if llm not in (None, "", 0, "0"):
        return f"llm:{llm}"
    return "-"


class VerdictStore:
    def __init__(self, path: str = ":memory:", flagged_ttl: float = FLAGGED_TTL, clean_ttl: float = CLEAN_TTL):
        self.path, self.flagged_ttl, self.clean_ttl = path, flagged_ttl, clean_ttl
        self._lock = threading.Lock()
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None, timeout=5)
        if path != ":memory:":
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=NORMAL")
        self.db.executescript(_SCHEMA)
        self._purged = time.time()

    def get(self, key: str, sha: str) -> dict | None:
        """The verdict for key, or None. An allowed hash reads as clean."""
        now = time.time()
        with self._lock:
            if self.db.execute("SELECT 1 FROM allows WHERE text_sha256 = ? AND expires > ?", (sha, now)).fetchone():
                return {"decision": "allow", "allowed": True}
            row = self.db.execute("SELECT verdict FROM verdicts WHERE key = ? AND expires > ?", (key, now)).fetchone()
        return json.loads(row[0]) if row else None

    def put(self, key: str, sha: str, tenant: str, stage: str, verdict: dict) -> None:
        now = time.time()
        ttl = self.clean_ttl if verdict.get("decision") == "allow" else self.flagged_ttl
        with self._lock:
            self.db.execute("INSERT OR REPLACE INTO verdicts VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                            (key, sha, tenant, stage, verdict.get("decision", ""), json.dumps(verdict), now, now + ttl))
            if now - self._purged > 3600:
                self._purged = now
                self.db.execute("DELETE FROM verdicts WHERE expires <= ?", (now,))
                self.db.execute("DELETE FROM allows WHERE expires <= ?", (now,))

    def allow(self, sha: str, days: float = 30, note: str = "") -> None:
        now = time.time()
        with self._lock:
            self.db.execute("INSERT OR REPLACE INTO allows VALUES (?, ?, ?, ?)", (sha, now, now + days * 86400, note))

    def unallow(self, sha: str) -> bool:
        with self._lock:
            return self.db.execute("DELETE FROM allows WHERE text_sha256 = ?", (sha,)).rowcount > 0

    def flags(self, limit: int = 50) -> list[dict]:
        with self._lock:
            rows = self.db.execute("SELECT text_sha256, tenant, stage, decision, at, expires FROM verdicts WHERE decision != 'allow' AND expires > ? "
                                   "ORDER BY at DESC LIMIT ?", (time.time(), limit)).fetchall()
        return [dict(zip(("sha256", "tenant", "stage", "decision", "at", "expires"), r)) for r in rows]

    def stats(self) -> dict:
        now = time.time()
        with self._lock:
            by = self.db.execute("SELECT decision, count(*) FROM verdicts WHERE expires > ? GROUP BY decision", (now,)).fetchall()
            allows = self.db.execute("SELECT count(*) FROM allows WHERE expires > ?", (now,)).fetchone()[0]
        return {"verdicts": dict(by), "allows": allows}


def main(argv=None):
    ap = argparse.ArgumentParser(prog="wolfguard.store", description="Inspect the verdict store; lift a false flag.")
    ap.add_argument("--db", required=True)
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("allow", help="answer this text hash clean (lifts a flag)")
    a.add_argument("sha256")
    a.add_argument("--days", type=float, default=30)
    a.add_argument("--note", default="")
    u = sub.add_parser("unallow", help="remove an allow")
    u.add_argument("sha256")
    f = sub.add_parser("flags", help="the latest flagged verdicts")
    f.add_argument("--limit", type=int, default=50)
    sub.add_parser("stats")
    args = ap.parse_args(argv)
    st = VerdictStore(args.db)
    if args.cmd == "allow":
        st.allow(args.sha256, args.days, args.note)
        print(f"allowed {args.sha256} for {args.days:g} days")
    elif args.cmd == "unallow":
        print("removed" if st.unallow(args.sha256) else "not allowed")
    elif args.cmd == "flags":
        for r in st.flags(args.limit):
            print(json.dumps(r))
    else:
        print(json.dumps(st.stats()))


if __name__ == "__main__":
    sys.exit(main())
