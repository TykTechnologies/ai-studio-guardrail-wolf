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
only. With block_when all and agree: window, the questions must reach a tier
together in one window (a long item's questions can each peak somewhere,
in different windows, on ordinary text). A repo-local tool result (the
policy's tool_sources) reaches critical only when that window also breaks a
corroborating content rule, else it is a block. On a read-only tool call,
questions marked read_only: report do not decide. Tool definitions on the
policy's allowlist are answered clean without scoring; built-in tools whose
definition is not listed are reported, not removed.

Trusted prompt templates (wolfguard/templates.py): a user message that
matched one is scored as its residual, as the app scores its user messages
(untrusted content for user_messages: untrusted, the user-message questions
and tiers otherwise). Unless the
template's backstop is off, its full text is scored too, over the windows
that hold at least one byte outside the approved ranges (a window of
approved text only is skipped), and decided on its own: res.backstop.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Protocol

from wolfguard import cache as cachemod
from wolfguard import precheck, scenes, store
from wolfguard import templates as tplmod
from wolfguard.policy import Policy, Question, Stage
from wolfguard.segments import Item, Typed

ALLOW, REVIEW, BLOCK, CRITICAL = "allow", "review", "block", "critical"
RANK = {ALLOW: 0, REVIEW: 1, BLOCK: 2, CRITICAL: 3}


class Backend(Protocol):
    revision: str

    def tokenize(self, text: str) -> list[int]: ...

    def detokenize(self, ids: list[int]) -> str: ...

    # Optional: spans(text) -> [(start, end)], each token's character span (the
    # tokens of tokenize(text)). Without it every backstop window is scored.

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
    peaks: dict = field(default_factory=dict)        # question -> the index of its riskiest window
    window_risks: list = field(default_factory=list) # per window: {question: risk} (main questions)
    paste_window_risks: list = field(default_factory=list)
    source: str = ""                                 # tool_result with tool_sources: "local" | "external"
    signals: list = field(default_factory=list)      # local items: the corroborating rules each window breaks
    corroborated: tuple = ()                         # the rules that let a local item reach critical
    read_only: bool = False                          # tool_call: the call only reads
    window_texts: list = field(default_factory=list) # the main windows' text (for a preview of the deciding one)
    at: int | None = None                            # the window that decided (agree: window), else None
    backstop: "ItemResult | None" = None             # template: the full text's decision over the windows it counts
    backstop_windows: tuple = (0, 0)                 # template: (windows scored, windows skipped as approved text only)
    backstop_unscanned: bool = False                 # template: the full text is over the size limit, not scored


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

    def backstop_windows(self, tpl: tplmod.Template, tokens: int, overlap: int) -> list[tuple[str, bool]]:
        """The full text's windows (the same cut as windows()), each with whether it
        counts: it holds a token outside the approved ranges. Without token spans
        from the backend every window counts."""
        ids = self.backend.tokenize(tpl.full_text)
        spans = self.backend.spans(tpl.full_text) if hasattr(self.backend, "spans") else None
        if spans is not None and len(spans) != len(ids):
            spans = None
        if len(ids) <= tokens:
            cuts = [(0, len(ids))]
        else:
            step = tokens - overlap
            cuts = [(i, min(i + tokens, len(ids))) for i in range(0, len(ids) - overlap, step)]
        out = []
        for a, b in cuts:
            text = tpl.full_text if (a, b) == (0, len(ids)) else self.backend.detokenize(ids[a:b])
            counts = spans is None or not all(tplmod.inside(sp, tpl.exempt_chars) for sp in spans[a:b])
            out.append((text, counts))
        return out

    def _backstop_plan(self, plans, res, st: Stage, scene) -> None:
        """A template's backstop: its full text's counted windows, as the residual's scenes."""
        tpl = res.item.template
        if tpl is None or tpl.backstop == "off":
            return
        if len(tpl.full_text) > self.policy.max_segment_chars:
            res.backstop_unscanned = True
            return
        bw = self.backstop_windows(tpl, st.window_tokens, st.window_overlap)
        counted = [w for w, c in bw if c]
        res.backstop_windows = (len(counted), len(bw) - len(counted))
        if counted:
            plans.append((res, "backstop", st.questions, [scene(w) for w in counted]))

    def _clip(self, text: str, tokens: int) -> str:
        ids = self.backend.tokenize(text)
        if len(ids) <= tokens:
            return text
        head = tokens // 3
        return self.backend.detokenize(ids[:head]) + " … " + self.backend.detokenize(ids[-(tokens - head):])

    def _scenes(self, st: Stage, item: Item, ws: list[str], system: str) -> list[str]:
        out = []
        for w in ws:
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
        defs = self.policy.tool_definitions
        for item in typed.items:
            st = self.policy.stages.get(item.stage)
            if item.stage == "tool_definition" and defs.allow_sha256 and store.text_sha256(item.text) in defs.allow_sha256:
                results.append(ItemResult(item, ALLOW, skipped="allowlisted"))
                continue
            if app.skip:
                results.append(ItemResult(item, ALLOW, skipped="app_skip"))
                continue
            if st is None or item.stage not in app.stages:
                results.append(ItemResult(item, ALLOW, skipped="stage_off"))
                continue
            checked = precheck.check(item.stage, item.text, self.policy.canaries, self.policy.secret_rules, self.policy.exfil_rules)
            tpl = item.template
            flags = (precheck.Rule("template.invalid", "flag", item.template_invalid),) if item.template_invalid else ()
            if tpl is not None and tpl.mimicry:
                flags += (precheck.Rule("template.mimicry", "flag"),)
            res = ItemResult(item, ALLOW, rules=checked.rules + flags)
            system = app.system_context or item.system
            tst = self.policy.stages.get("tool_result")
            if item.stage == "user_message" and app.user_messages == "untrusted" and tst is not None:
                # A runner's prompt around untrusted text: score it as untrusted content.
                res.scored_as = "tool_result"
                res.window_texts = self.windows(checked.text, tst.window_tokens, tst.window_overlap)
                sc = [scenes.tool_result(w, app.untrusted_source, tst.with_tool_call) for w in res.window_texts]
                res.windows = len(sc)
                plans.append((res, "main", tst.questions, sc))
                self._backstop_plan(plans, res, tst, lambda w: scenes.tool_result(w, app.untrusted_source, tst.with_tool_call))
                results.append(res)
                continue
            ws = res.window_texts = self.windows(checked.text, st.window_tokens, st.window_overlap)
            sc = self._scenes(st, item, ws, system)
            res.windows = len(sc)
            srcs = self.policy.tool_sources
            if item.stage == "tool_result" and srcs is not None:
                res.source = "local" if srcs.is_local(item.tool_name, checked.text) else "external"
                if res.source == "local":
                    res.signals = [precheck.content_signals(w) for w in ws]
            if item.stage == "tool_call" and (item.tool_name in st.read_only_tools or precheck.read_only_call(checked.text)):
                res.read_only = True
            plans.append((res, "main", st.questions, sc))
            if item.stage == "user_message" and st.paste_questions:
                part = scenes.pasted_part(checked.text, st.paste_min_chars)
                if part:
                    psc = [scenes.pasted(w, system) for w in self.windows(part, st.window_tokens, st.window_overlap)]
                    plans.append((res, "paste", st.paste_questions, psc))
            if item.stage == "user_message":
                self._backstop_plan(plans, res, st, lambda w: scenes.user_message(w, system))
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

        # Aggregate: the riskiest window per question (reported), and every window's risks (to decide).
        for pi, (res, kind, qs, sc) in enumerate(plans):
            if kind == "backstop":
                res.backstop = ItemResult(res.item, ALLOW, scored_as=res.scored_as, windows=len(sc))
            target = res.answers if kind == "main" else res.paste if kind == "paste" else res.backstop.answers
            per_window = [{q.name: q.risk_of(answers[(pi, si)][qi]) for qi, q in enumerate(qs)} for si in range(len(sc))]
            if kind == "main":
                res.window_risks = per_window
            elif kind == "paste":
                res.paste_window_risks = per_window
            else:
                res.backstop.window_risks = per_window
            for qi, q in enumerate(qs):
                best, at = None, 0
                for si in range(len(sc)):
                    probs = answers[(pi, si)][qi]
                    r = q.risk_of(probs)
                    if best is None or r > best.risk:
                        best, at = Answer(r, dict(zip(q.option_ids, probs))), si
                target[q.name] = best
                if kind == "main":
                    res.peaks[q.name] = at
        for res in results:
            if res.skipped:
                continue
            res.decision = self._decide(res)
            if res.scored_as and res.decision == BLOCK:
                res.decision = REVIEW        # untrusted user messages: only the critical tier blocks
            if res.backstop is not None:
                b = res.backstop
                b.decision = self._decide(b)
                if b.scored_as and b.decision == BLOCK:
                    b.decision = REVIEW
            if res.item.stage == "tool_definition" and res.item.tool_name in defs.builtin_names and RANK[res.decision] > RANK[REVIEW]:
                res.decision = REVIEW        # a built-in whose definition changed (a client upgrade): reported, not removed
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
        # A backstop window is scored as the same scene as a residual window: one cache.
        return res.item.stage + ("/paste" if kind == "paste" else "") + ("/untrusted" if res.scored_as else "")

    def _decide(self, res: ItemResult) -> str:
        if any(r.severity == "block" for r in res.rules):
            return CRITICAL      # a canary or a hard rule: certain, not a score
        decision = ALLOW
        st = self.policy.stages[res.scored_as or res.item.stage]
        agree = all if st.block_when == "all" else any
        for qs, answers, windows in ((st.questions, res.answers, res.window_risks), (st.paste_questions, res.paste, res.paste_window_risks)):
            deciding = [q for q in qs if q.decides and q.name in answers and not (res.read_only and q.read_only == "report")]
            if not deciding:
                continue
            if st.block_when == "all" and st.agree == "window":
                # A window index is kept for the main windows only (res.at names one of window_texts).
                rows = [(i if windows is res.window_risks else None, w) for i, w in enumerate(windows)]
            else:   # each question's riskiest window, wherever it is
                rows = [(None, {q.name: answers[q.name].risk for q in deciding})]
            tiered = [q for q in deciding if q.critical is not None]
            for wi, risks in rows:
                if tiered and agree(risks[q.name] >= st.critical_for(q, res.windows) for q in tiered):
                    if res.source != "local":
                        res.at = wi
                        return CRITICAL
                    sig = self._corroboration(res, wi)
                    if sig:
                        res.corroborated, res.at = sig, wi
                        return CRITICAL
                if agree(risks[q.name] >= q.block for q in deciding):
                    if decision != BLOCK:
                        res.at = wi
                    decision = BLOCK
            if decision == ALLOW and any(answers[q.name].risk >= q.review for q in deciding):
                decision = REVIEW
        return decision

    def _corroboration(self, res: ItemResult, window: int | None) -> tuple:
        """The corroborating rules a local item breaks: in the agreeing window,
        or in any window when the questions are not held to one."""
        want = set(self.policy.tool_sources.corroborate)
        found = res.signals if window is None else res.signals[window : window + 1]
        return tuple(sorted({r for sig in found for r in sig if r in want}))


def deciding_window(res: ItemResult) -> int:
    """The window to show for a flagged item: the one that decided, else the
    riskiest window of its riskiest question."""
    if res.at is not None:
        return res.at
    if not res.answers:
        return 0
    top = max(res.answers, key=lambda q: res.answers[q].risk)
    return res.peaks.get(top, 0)
