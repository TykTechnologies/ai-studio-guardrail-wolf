"""Eval CLI: replay labelled sets through the service's own scoring core and policy.

    python -m wolfguard.eval --model models/jev-5ed7c44d [--public] [--baseline models/wdpi-a77e7b66] [--out eval/results]

Sets: eval/sets/*.jsonl (versioned: benign, redteam, hard_benign, adaptive),
plus with --public deepset/prompt-injections (test split; direct) and
NotInject (hard benign, three splits) fetched from the Hugging Face
datasets server into eval/cache/.

Per stage, for the stage risk (the highest deciding question's risk, what
decides block) and per question: AUROC, TPR at 1% and 5% FPR (negatives
= benign + hard benign), TPR/FPR at the policy's block and review
thresholds, calibration (ECE, 10 bins), per-set rates, and latency by
length. Comparisons: the 2.3-constrained tool_result scene with and
without the name-only [TOOL CALL] against the full evaluated format; a
per-app [SYSTEM CONTEXT] against none for user_message; the binary Wolf
Defender as a baseline (--baseline). Ends with a threshold proposal per
question (block at FPR <= 1%, review at FPR <= 5%).
"""
from __future__ import annotations

import argparse
import dataclasses
import json
import os
import statistics
import time
import urllib.request
from pathlib import Path

from wolfguard import policy as policymod
from wolfguard.scorer import Scorer
from wolfguard.segments import Item, Typed

ROOT = Path(__file__).resolve().parents[1]


# ---- data -----------------------------------------------------------------------------------
def load_sets(paths):
    recs = []
    for p in paths:
        for line in open(p):
            if line.strip():
                recs.append(json.loads(line))
    return recs


def _rows(dataset, split, cache):
    f = cache / f"{dataset.replace('/', '__')}__{split}.jsonl"
    if f.exists():
        return [json.loads(l) for l in open(f)]
    out, offset = [], 0
    while True:
        url = f"https://datasets-server.huggingface.co/rows?dataset={dataset}&config=default&split={split}&offset={offset}&length=100"
        with urllib.request.urlopen(url, timeout=60) as r:
            page = json.load(r)
        rows = [x["row"] for x in page.get("rows", [])]
        out += rows
        offset += len(rows)
        if not rows or offset >= page.get("num_rows_total", 0):
            break
    cache.mkdir(parents=True, exist_ok=True)
    with open(f, "w") as fh:
        for r in out:
            fh.write(json.dumps(r) + "\n")
    return out


def public_sets(cache):
    recs = []
    for r in _rows("deepset/prompt-injections", "test", cache):
        recs.append({"id": f"deepset-{len(recs)}", "set": "deepset", "stage": "user_message", "label": int(r["label"]), "text": r["text"], "lang": ""})
    for split in ("NotInject_one", "NotInject_two", "NotInject_three"):
        for r in _rows("leolee99/NotInject", split, cache):
            text = r.get("prompt") or r.get("text") or ""
            if text:
                recs.append({"id": f"notinject-{len(recs)}", "set": "notinject", "stage": "user_message", "label": 0, "text": text, "lang": ""})
    return recs


# ---- scoring --------------------------------------------------------------------------------
def score_all(scorer: Scorer, recs, app_id=None):
    out = []
    for r in recs:
        item = Item(r["stage"], r["text"], 0, r.get("tool_name") or "tool", "", goal=r.get("goal") or "", call=r.get("call") or "")
        typed = Typed("request", [item], meta={"app_id": app_id} if app_id else {})
        t = time.perf_counter()
        res, _ = scorer.score(typed)
        ms = (time.perf_counter() - t) * 1000
        st = scorer.policy.stages[r["stage"]]
        res = res[0]
        q_risk = {q.name: res.answers[q.name].risk for q in st.questions}
        q_risk |= {"paste:" + k: a.risk for k, a in res.paste.items()}
        deciding = [res.answers[q.name].risk for q in st.questions if q.decides] + [a.risk for a in res.paste.values()]
        out.append({"id": r["id"], "set": r["set"], "stage": r["stage"], "label": r["label"], "risk": max(deciding),
                    "q": q_risk, "decision": res.decision, "ms": ms, "tokens": len(scorer.backend.tokenize(r["text"]))})
    return out


# ---- metrics --------------------------------------------------------------------------------
def auroc(pos, neg):
    if not pos or not neg:
        return None
    wins = 0.0
    for p in pos:
        for n in neg:
            wins += 1.0 if p > n else 0.5 if p == n else 0.0
    return wins / (len(pos) * len(neg))


def threshold_at_fpr(neg, fpr):
    """The lowest threshold with false positive rate <= fpr on neg."""
    s = sorted(neg, reverse=True)
    k = int(fpr * len(s))          # how many negatives may be at or above it
    if k >= len(s):
        return 0.0
    return min(1.0, s[k] + 1e-9)


def rate(xs, t):
    return sum(1 for x in xs if x >= t) / len(xs) if xs else None


def ece(scored, key="risk", bins=10):
    total, err = len(scored), 0.0
    for b in range(bins):
        lo, hi = b / bins, (b + 1) / bins
        inb = [s for s in scored if lo <= s[key] < hi or (b == bins - 1 and s[key] == 1.0)]
        if inb:
            err += len(inb) / total * abs(statistics.mean(s["label"] for s in inb) - statistics.mean(s[key] for s in inb))
    return err


def stage_report(scored, policy, stage, questions=True):
    rows = [s for s in scored if s["stage"] == stage]
    pos = [s for s in rows if s["label"] == 1]
    neg = [s for s in rows if s["label"] == 0]
    st = policy.stages[stage]
    out = {"n_pos": len(pos), "n_neg": len(neg)}
    keys = [("stage_risk", lambda s: s["risk"])]
    if questions:
        keys += [(q.name, (lambda name: lambda s: s["q"][name])(q.name)) for q in st.questions]
    for name, get in keys:
        P, N = [get(s) for s in pos], [get(s) for s in neg]
        t1, t5 = threshold_at_fpr(N, 0.01), threshold_at_fpr(N, 0.05)
        out[name] = {"auroc": auroc(P, N), "tpr_at_fpr1": rate(P, t1), "thr_fpr1": t1, "tpr_at_fpr5": rate(P, t5), "thr_fpr5": t5}
        q = next((q for q in st.questions if q.name == name), None)
        if q:
            out[name] |= {"tpr_at_block": rate(P, q.block), "fpr_at_block": rate(N, q.block), "tpr_at_review": rate(P, q.review), "fpr_at_review": rate(N, q.review)}
    out["ece"] = ece(rows) if rows else None
    if not questions:
        return out
    out["per_set"] = {}
    for name in sorted({s["set"] for s in rows}):
        r = [s for s in rows if s["set"] == name]
        out["per_set"][name] = {"n": len(r), "label": r[0]["label"], "block_rate": sum(s["decision"] == "block" for s in r) / len(r),
                                "flag_rate": sum(s["decision"] != "allow" for s in r) / len(r)}
    lat = {}
    for s in rows:
        b = "<=500" if s["tokens"] <= 500 else "<=2k" if s["tokens"] <= 2000 else "<=6k" if s["tokens"] <= 6000 else ">6k"
        lat.setdefault(b, []).append(s["ms"])
    out["latency_ms_p50"] = {b: round(statistics.median(v), 1) for b, v in lat.items()}
    return out


def baseline_scores(model_dir, recs):
    import torch
    from transformers import AutoModelForSequenceClassification, AutoTokenizer
    tok = AutoTokenizer.from_pretrained(model_dir)
    m = AutoModelForSequenceClassification.from_pretrained(model_dir, use_safetensors=True).eval()
    labels = {v.lower(): int(k) for k, v in m.config.id2label.items()}
    inj = next((i for name, i in labels.items() if "inject" in name or name in ("1", "label_1", "malicious", "unsafe")), 1)
    out = []
    with torch.no_grad():
        for r in recs:
            x = tok(r["text"], truncation=True, max_length=512, return_tensors="pt")
            p = m(**x).logits.softmax(-1)[0, inj].item()
            out.append({"set": r["set"], "stage": r["stage"], "label": r["label"], "risk": p, "q": {}, "decision": "", "ms": 0, "tokens": 0})
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(prog="wolfguard-eval")
    ap.add_argument("--model", default=str(ROOT / "models" / "jev-5ed7c44d"))
    ap.add_argument("--policy", default=str(ROOT / "config" / "policy.yaml"))
    ap.add_argument("--sets", nargs="*", default=sorted(str(p) for p in (ROOT / "eval" / "sets").glob("*.jsonl")))
    ap.add_argument("--public", action="store_true")
    ap.add_argument("--baseline", default="")
    ap.add_argument("--threads", type=int, default=4)
    ap.add_argument("--out", default=str(ROOT / "eval" / "results"))
    ap.add_argument("--system-context", default="A code-review agent for public GitHub repositories. It reads pull requests with shell, read and edit tools and comments on them.")
    a = ap.parse_args(argv)
    from wolfguard.jev import JevBackend
    backend = JevBackend(a.model, threads=a.threads)
    pol = policymod.load(a.policy)
    recs = load_sets(a.sets)
    if a.public:
        recs += public_sets(ROOT / "eval" / "cache")
    report = {"policy_version": pol.version, "model_revision": pol.model_revision, "sets": sorted({r["set"] for r in recs}), "n": len(recs)}

    def variant(stage, **changes):
        return dataclasses.replace(pol, stages={**pol.stages, stage: dataclasses.replace(pol.stages[stage], **changes)})

    t0 = time.time()
    main_scores = score_all(Scorer(backend, pol), recs)
    os.makedirs(a.out, exist_ok=True)
    json.dump(main_scores, open(Path(a.out) / f"scores-{pol.version}.json", "w"))
    report["stages"] = {st: stage_report(main_scores, pol, st) for st in sorted({r["stage"] for r in recs})}
    # Format check (tool_result) and system-context effect (user_message).
    tr = [r for r in recs if r["stage"] == "tool_result"]
    um = [r for r in recs if r["stage"] == "user_message"]
    report["format_check"] = {
        "constrained_with_call": report["stages"].get("tool_result", {}).get("stage_risk"),
        "constrained_no_call": stage_report(score_all(Scorer(backend, variant("tool_result", with_tool_call=False)), tr), pol, "tool_result")["stage_risk"] if tr else None,
        "full_goal_and_args": stage_report(score_all(Scorer(backend, variant("tool_result", full_scene=True)), tr), pol, "tool_result")["stage_risk"] if tr else None,
    }
    if um:
        ctx = dataclasses.replace(pol, apps={"1": policymod.App(system_context=a.system_context)})
        report["system_context"] = {"without": report["stages"]["user_message"]["stage_risk"],
                                    "with": stage_report(score_all(Scorer(backend, ctx), um, app_id=1), pol, "user_message")["stage_risk"]}
    if a.baseline:
        b = baseline_scores(a.baseline, recs)
        report["baseline_binary"] = {st: {"auroc": auroc([s["risk"] for s in b if s["stage"] == st and s["label"] == 1], [s["risk"] for s in b if s["stage"] == st and s["label"] == 0]),
                                          "tpr_at_fpr1": stage_report(b, pol, st, questions=False)["stage_risk"]["tpr_at_fpr1"],
                                          "tpr_at_fpr5": stage_report(b, pol, st, questions=False)["stage_risk"]["tpr_at_fpr5"]} for st in report["stages"]}
    # Threshold proposal per question.
    prop = {}
    for st, rep in report["stages"].items():
        for q in pol.stages[st].questions:
            m = rep[q.name]
            prop[f"{st}/{q.name}"] = {"block": round(m["thr_fpr1"], 3), "block_tpr": m["tpr_at_fpr1"], "review": round(m["thr_fpr5"], 3), "review_tpr": m["tpr_at_fpr5"],
                                      "current_block": q.block, "current_review": q.review}
    report["threshold_proposal"] = prop
    report["seconds"] = round(time.time() - t0, 1)
    os.makedirs(a.out, exist_ok=True)
    out = Path(a.out) / f"eval-{pol.version}.json"
    json.dump(report, open(out, "w"), indent=1)
    json.dump(main_scores, open(Path(a.out) / f"scores-{pol.version}.json", "w"))
    print(json.dumps({k: report[k] for k in ("n", "sets", "seconds")}))
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
