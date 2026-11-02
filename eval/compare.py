"""Decisions of policies on the labelled sets, side by side (tuning a policy version).

    .venv/bin/python eval/compare.py --baseline <old policy.yaml> --policy <new.yaml> [<step.yaml> ...] [--sets eval/sets/*.jsonl]

Every policy scores through the service's own scorer. When their question
sets and windows are the same, the model runs once per scene: the
scorers share one cache (the decision rules differ, the model's answers do
not). Per set: stop (critical: the conversation ends), removed (block or
critical: the content never reaches the model; for a user message scored as
untrusted content only critical), and flagged (anything but allow). For an
attack set "removed" is the TPR; for a benign set, the FPR. Records with
"anchor": true are listed one by one.
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wolfguard import cache as cachemod  # noqa: E402
from wolfguard import policy as policymod  # noqa: E402
from wolfguard.scorer import ALLOW, BLOCK, CRITICAL, Scorer  # noqa: E402
from wolfguard.segments import Item, Typed  # noqa: E402


def load(paths):
    out = []
    for p in paths:
        out += [json.loads(line) for line in open(p) if line.strip()]
    return out


def decide(scorer, r):
    item = Item(r["stage"], r["text"], 0, r.get("tool_name") or "tool", "", goal=r.get("goal") or "", call=r.get("call") or "")
    app = r.get("app_id")
    res, _ = scorer.score(Typed("request", [item], meta={"app_id": app} if app else {}))
    x = res[0]
    removed = x.decision == CRITICAL or (x.decision == BLOCK and not x.scored_as)
    return {"decision": x.decision, "removed": removed, "windows": x.windows, "source": x.source, "read_only": x.read_only,
            "corroborated": list(x.corroborated), "skipped": x.skipped,
            "scores": {q: round(a.risk, 4) for q, a in x.answers.items()}}


BUCKETS = ("1", "2-3", "4-10", "11-30", ">30")


def bucket(n):
    return "1" if n <= 1 else "2-3" if n <= 3 else "4-10" if n <= 10 else "11-30" if n <= 30 else ">30"


def rates(rows, key):
    n = len(rows)
    return {"n": n, "stop": sum(r[key]["decision"] == CRITICAL for r in rows) / n, "removed": sum(r[key]["removed"] for r in rows) / n,
            "flagged": sum(r[key]["decision"] != ALLOW for r in rows) / n}


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", required=True)
    ap.add_argument("--policy", required=True, nargs="+")
    ap.add_argument("--model", default=str(ROOT / "models" / "jev-5ed7c44d"))
    ap.add_argument("--sets", nargs="*", default=sorted(str(p) for p in (ROOT / "eval" / "sets").glob("*.jsonl")))
    ap.add_argument("--threads", type=int, default=8)
    ap.add_argument("--out", default=str(ROOT / "eval" / "results"))
    a = ap.parse_args(argv)
    from wolfguard.jev import JevBackend
    backend = JevBackend(a.model, threads=a.threads)
    pols = [policymod.load(p) for p in [a.baseline] + a.policy]
    names = [p.version for p in pols]

    def scoring(p):
        return ({n: (s.questions, s.paste_questions, s.window_tokens, s.window_overlap, s.with_tool_call, s.goal_tokens) for n, s in p.stages.items()},
                p.apps, p.default_app, p.tools)
    shared = all(scoring(p) == scoring(pols[0]) for p in pols)
    cache = cachemod.LRU(max_entries=1_000_000, ttl_seconds=1e9)
    scorers = [Scorer(backend, dataclasses.replace(p, version="compare") if shared else p, cache) for p in pols]
    rows, t0 = [], time.time()
    for r in load(a.sets):
        rows.append({"id": r["id"], "set": r["set"], "stage": r["stage"], "label": r["label"], "shape": r.get("shape") or r.get("technique") or "",
                     "anchor": bool(r.get("anchor")), "tool": r.get("tool_name") or "", "by": {n: decide(s, r) for n, s in zip(names, scorers)}})
    report = {"policies": names, "shared_cache": shared, "seconds": round(time.time() - t0, 1), "sets": {}}
    for name in sorted({r["set"] for r in rows}):
        for label in (1, 0):
            rs = [r for r in rows if r["set"] == name and r["label"] == label]
            if rs:
                report["sets"][f"{name}/{'attack' if label else 'benign'}"] = {n: rates([x["by"] for x in rs], n) for n in names}
    # Stratified by window count: each window is another chance for a benign item to score high.
    report["by_windows"] = {}
    for label in (0, 1):
        for b in BUCKETS:
            rs = [r for r in rows if r["label"] == label and bucket(r["by"][names[0]]["windows"]) == b]
            if rs:
                report["by_windows"][f"{'attack' if label else 'benign'} {b}"] = {n: rates([x["by"] for x in rs], n) for n in names}
    Path(a.out).mkdir(parents=True, exist_ok=True)
    out = Path(a.out) / f"compare-{names[0]}-vs-{names[-1]}.json"
    json.dump({"report": report, "rows": rows}, open(out, "w"), indent=1)

    pct = lambda x: f"{100 * x:.1f}%"  # noqa: E731
    print("| Set | n | " + " | ".join(f"{n}: stop / removed / flagged" for n in names) + " |")
    print("|---|---|" + "---|" * len(names))
    for k, v in report["sets"].items():
        print(f"| {k} | {v[names[0]]['n']} | " + " | ".join(f"{pct(v[n]['stop'])} / {pct(v[n]['removed'])} / {pct(v[n]['flagged'])}" for n in names) + " |")
    print("\n| Windows (all sets) | n | " + " | ".join(names) + " |")
    print("|---|---|" + "---|" * len(names))
    for k, v in report["by_windows"].items():
        print(f"| {k} | {v[names[0]]['n']} | " + " | ".join(f"{pct(v[n]['stop'])} / {pct(v[n]['removed'])}" for n in names) + " |")
    for r in rows:
        if r["anchor"]:
            print(f"anchor {r['id']} ({r['shape']}): " + " -> ".join(r["by"][n]["decision"] for n in names) + f" {r['by'][names[-1]]['scores']}")
    print(f"wrote {out} ({report['seconds']} s)")


if __name__ == "__main__":
    main()
