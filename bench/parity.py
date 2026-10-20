"""Score every eval-set item on one device and write the per-question risks (GPU vs CPU parity).

    python -I bench/parity.py --device cpu  > cpu.json
    python -I bench/parity.py --device cuda > gpu.json
    python -I bench/parity.py --compare cpu.json gpu.json

Run from the repository root. The model stays fp32 on both (TF32 off on a GPU, wolfguard/jev.py),
so differences should be float noise and no decision should change.
"""
import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def score(device):
    from wolfguard import policy as policymod
    from wolfguard.eval import load_sets
    from wolfguard.jev import JevBackend
    from wolfguard.scorer import Scorer
    from wolfguard.segments import type_call

    pol = policymod.load(ROOT / "config" / "policy.yaml")
    sc = Scorer(JevBackend(ROOT / "models" / "jev-5ed7c44d", threads=4, device=device), pol)
    out = {}
    for item in load_sets(sorted((ROOT / "eval" / "sets").glob("*.jsonl"))):
        stage = item["stage"]
        if stage == "tool_result":
            seg = {"index": 0, "role": "tool", "kind": "tool_result", "tool_name": item.get("tool_name") or "read", "text": item["text"]}
        elif stage == "user_message":
            seg = {"index": 0, "role": "user", "text": item["text"]}
        else:
            continue
        res, _ = sc.score(type_call({"direction": "request", "segments": [seg]}))
        r = res[0]
        out[item["id"]] = {"decision": r.decision, "risk": {q: a.risk for q, a in r.answers.items()}}
    return out


def compare(a, b):
    worst, changed = 0.0, []
    for k, x in a.items():
        y = b.get(k)
        if y is None:
            continue
        for q, r in x["risk"].items():
            worst = max(worst, abs(r - y["risk"][q]))
        if x["decision"] != y["decision"]:
            changed.append((k, x["decision"], y["decision"]))
    return {"items": len(a), "max_abs_risk_diff": worst, "decisions_changed": changed}


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--device", default="cpu")
    ap.add_argument("--compare", nargs=2)
    a = ap.parse_args()
    if a.compare:
        print(json.dumps(compare(*(json.load(open(p)) for p in a.compare)), indent=1))
    else:
        print(json.dumps(score(a.device)))
