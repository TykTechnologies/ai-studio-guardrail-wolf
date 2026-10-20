"""The scorer: items -> windows -> scenes -> batched model passes -> graded decisions.

    scorer = Scorer(backend, policy)
    results = scorer.score(segments.type_call(body))

A segment's content is cut into windows of `window_tokens` (with overlap);
each window is a scene with the stage's other blocks. All of a scene's
questions go through the model in the same forward, and forwards carry at
most `max_rows` rows. Per question, the window with the highest attack-side
probability ("risk") is the item's answer. A scene seen before (same stage,
text, question-set version and model revision) is answered from the cache
without inference.

Decisions: critical when the deciding questions with a critical threshold
reach it (by the stage's block_when) or a pre-check rule blocks; block when a
deciding question's risk reaches its block threshold; review when one reaches
its review threshold; allow otherwise. Rules of severity "flag" are reported
only.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Protocol

from wolfguard import cache as cachemod
from wolfguard import precheck, scenes
from wolfguard.policy import Policy, Question, Stage
from wolfguard.segments import Item, Typed

ALLOW, REVIEW, BLOCK, CRITICAL = "allow", "review", "block", "critical"
RANK = {ALLOW: 0, REVIEW: 1, BLOCK: 2, CRITICAL: 3}


class Backend(Protocol):
    revision: str

    def tokenize(self, text: str) -> list[int]: ...

    def detokenize(self, ids: list[int]) -> str: ...

    def prepare(self, question: Question) -> object:
        """Whatever the model needs per question (option encodings); called once per question."""
        ...

    def forward(self, rows: list[tuple[str, object]]) -> list[list[float]]:
        """One model pass over (scene, prepared question) rows: option probabilities per row."""
        ...


@dataclass
class Answer:
    risk: float
    probabilities: dict


@dataclass
class ItemResult:
    item: Item
    decision: str
    answers: dict = field(default_factory=dict)      # question -> Answer (the riskiest window)
    rules: tuple = ()
    windows: int = 0
    cached: int = 0                                  # windows answered from the cache
    skipped: str = ""                                # why the item was not scored ("" = scored)
    paste: dict = field(default_factory=dict)        # user_message: the pasted part's answers
    scored_as: str = ""                              # user_message scored as untrusted content: "tool_result"


@dataclass
class Stats:
    forwards: int = 0
    rows: int = 0
    scenes: int = 0
    cache_hits: int = 0
    ms: float = 0.0


class Scorer:
    def __init__(self, backend: Backend, policy: Policy, cache: cachemod.LRU | None = None, max_rows: int = 24):
        self.backend, self.max_rows = backend, max_rows
        self.cache = cache if cache is not None else cachemod.LRU()
        self.set_policy(policy)

    def set_policy(self, policy: Policy) -> None:
        """Swap the policy (hot reload): option encodings for its questions are prepared first."""
        prepared = {}
        for st in policy.stages.values():
            for q in st.questions + st.paste_questions:
                k = (q.kind, q.instructions, q.option_texts)
                if k not in prepared:
                    prepared[k] = self.backend.prepare(q)
        self.policy, self._prepared = policy, prepared

    # -- windows and scenes ---------------------------------------------------------------
    def windows(self, text: str, tokens: int, overlap: int) -> list[str]:
        ids = self.backend.tokenize(text)
        if len(ids) <= tokens:
            return [text]
        step = tokens - overlap
        return [self.backend.detokenize(ids[i : i + tokens]) for i in range(0, len(ids) - overlap, step)]

    def _clip(self, text: str, tokens: int) -> str:
        ids = self.backend.tokenize(text)
        if len(ids) <= tokens:
            return text
        head = tokens // 3
        return self.backend.detokenize(ids[:head]) + " … " + self.backend.detokenize(ids[-(tokens - head):])

    def _scenes(self, st: Stage, item: Item, text: str, system: str) -> list[str]:
        out = []
        for w in self.windows(text, st.window_tokens, st.window_overlap):
            if item.stage == "tool_result" and st.full_scene:
                out.append(scenes.tool_result_full(w, item.tool_name, item.call, self._clip(item.goal, st.goal_tokens)))
            elif item.stage == "tool_result":
                out.append(scenes.tool_result(w, item.tool_name, st.with_tool_call))
            elif item.stage == "user_message":
                out.append(scenes.user_message(w, system))
            elif item.stage == "tool_call":
                out.append(scenes.tool_call(w, item.tool_name, self._clip(item.goal, st.goal_tokens), self._clip(system, st.goal_tokens) if system else "",
                                            self.policy.tools.get(item.tool_name, "")))
            else:
                out.append(scenes.tool_definition(w))
        return out

    # -- scoring ----------------------------------------------------------------------------
    def score(self, typed: Typed) -> tuple[list[ItemResult], Stats]:
        t0 = time.perf_counter()
        stats = Stats()
        app = self.policy.app(typed.meta.get("app_id"))
        results: list[ItemResult] = []
        plans = []      # (result, kind: "main"|"paste", questions, [scenes])
        for item in typed.items:
            st = self.policy.stages.get(item.stage)
            if app.skip:
                results.append(ItemResult(item, ALLOW, skipped="app_skip"))
                continue
            if st is None or item.stage not in app.stages:
                results.append(ItemResult(item, ALLOW, skipped="stage_off"))
                continue
            checked = precheck.check(item.stage, item.text, self.policy.canaries, self.policy.secret_rules)
            res = ItemResult(item, ALLOW, rules=checked.rules)
            system = app.system_context or item.system
            tst = self.policy.stages.get("tool_result")
            if item.stage == "user_message" and app.user_messages == "untrusted" and tst is not None:
                # A runner's prompt around untrusted text: score it as untrusted content.
                res.scored_as = "tool_result"
                sc = [scenes.tool_result(w, app.untrusted_source, tst.with_tool_call)
                      for w in self.windows(checked.text, tst.window_tokens, tst.window_overlap)]
                res.windows = len(sc)
                plans.append((res, "main", tst.questions, sc))
                results.append(res)
                continue
            sc = self._scenes(st, item, checked.text, system)
            res.windows = len(sc)
            plans.append((res, "main", st.questions, sc))
            if item.stage == "user_message" and st.paste_questions:
                part = scenes.pasted_part(checked.text, st.paste_min_chars)
                if part:
                    psc = [scenes.pasted(w, system) for w in self.windows(part, st.window_tokens, st.window_overlap)]
                    plans.append((res, "paste", st.paste_questions, psc))
            results.append(res)

        # Cache lookups; what misses becomes rows, a scene's questions together.
        answers: dict[tuple[int, str], list] = {}      # (plan index, scene index) -> probs per question
        pending = []                                   # (plan index, scene index, scene, questions)
        for pi, (res, kind, qs, sc) in enumerate(plans):
            stage = self._cache_stage(res, kind)
            for si, s in enumerate(sc):
                stats.scenes += 1
                hit = self.cache.get(cachemod.key(stage, s, self.policy.version, self.backend.revision))
                if hit is not None:
                    answers[(pi, si)] = hit
                    stats.cache_hits += 1
                    if kind == "main":
                        res.cached += 1
                else:
                    pending.append((pi, si, s, qs))
        batch: list = []
        for entry in pending:
            if batch and sum(len(e[3]) for e in batch) + len(entry[3]) > self.max_rows:
                self._run(batch, plans, answers, stats)
                batch = []
            batch.append(entry)
        if batch:
            self._run(batch, plans, answers, stats)

        # Aggregate: the riskiest window per question; then decide.
        for pi, (res, kind, qs, sc) in enumerate(plans):
            target = res.answers if kind == "main" else res.paste
            for qi, q in enumerate(qs):
                best = None
                for si in range(len(sc)):
                    probs = answers[(pi, si)][qi]
                    r = q.risk_of(probs)
                    if best is None or r > best.risk:
                        best = Answer(r, dict(zip(q.option_ids, probs)))
                target[q.name] = best
        for res in results:
            if res.skipped:
                continue
            res.decision = self._decide(res)
            if res.scored_as and res.decision == BLOCK:
                res.decision = REVIEW        # untrusted user messages: only the critical tier blocks
        stats.ms = (time.perf_counter() - t0) * 1000
        return results, stats

    def _run(self, batch, plans, answers, stats):
        rows = []
        for pi, si, s, qs in batch:
            for q in qs:
                rows.append((s, self._prepared[(q.kind, q.instructions, q.option_texts)]))
        out = self.backend.forward(rows)
        stats.forwards += 1
        stats.rows += len(rows)
        k = 0
        for pi, si, s, qs in batch:
            probs = out[k : k + len(qs)]
            k += len(qs)
            answers[(pi, si)] = probs
            res, kind = plans[pi][0], plans[pi][1]
            stage = self._cache_stage(res, kind)
            self.cache.put(cachemod.key(stage, s, self.policy.version, self.backend.revision), probs)

    @staticmethod
    def _cache_stage(res: ItemResult, kind: str) -> str:
        return res.item.stage + ("/paste" if kind == "paste" else "") + ("/untrusted" if res.scored_as else "")

    def _decide(self, res: ItemResult) -> str:
        if any(r.severity == "block" for r in res.rules):
            return CRITICAL      # a canary or a hard rule: certain, not a score
        decision = ALLOW
        st = self.policy.stages[res.scored_as or res.item.stage]
        agree = all if st.block_when == "all" else any
        for qs, answers in ((st.questions, res.answers), (st.paste_questions, res.paste)):
            deciding = [(q, answers[q.name]) for q in qs if q.decides and q.name in answers]
            if not deciding:
                continue
            tiered = [(q, a) for q, a in deciding if q.critical is not None]
            if tiered and agree(a.risk >= q.critical for q, a in tiered):
                return CRITICAL
            if agree(a.risk >= q.block for q, a in deciding):
                decision = BLOCK
            elif decision == ALLOW and any(a.risk >= q.review for q, a in deciding):
                decision = REVIEW
        return decision
