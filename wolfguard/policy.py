"""The versioned policy: question sets, thresholds, per-app settings (config/policy.yaml).

Per question:
    type          noul | choice | score
    instructions  the question (Patronus Protect concept wording, paraphrase allowed)
    criteria      noul: optional {"true", "false"} texts; choice: {id: description}; score: [levels, low to high]
    risk          which answer is the attack side: noul -> implicit (true);
                  choice -> an option id; score -> the list of levels that count
    block, review thresholds on the risk probability (graded policy: block >= 0.70, review >= 0.35)
    critical      optional, >= block: the top tier (tool_result.critical), for a filter that ends the
                  conversation where block only quarantines
    decides       false: reported, never decides (signal only). Default true.
    read_only     tool_call: decide (default) | report: on a read-only call (a read-only
                  tool, or a shell command made only of read-only programs, precheck.py)
                  the question is reported and does not decide. A call that only reads
                  cannot leak or change anything by itself.

Per stage: questions, window {tokens, overlap}, and stage options:
    block_when    any | all: one deciding question at a tier decides, or every one must
    agree         item (default) | window: with block_when all, whether the questions may
                  peak in different windows of a long item (item: the riskiest window per
                  question) or must reach the tier together in one window (window)
    read_only_tools  tool_call: tools that only read, whatever their arguments
    critical_by_windows  optional {N: threshold}: an item of N or more windows needs this
                  (or the question's own critical, if higher) to reach the critical tier.
                  Each window is another chance for ordinary text to score high, so a
                  stop on a long item asks for more (the max over N windows: 1-(1-p)^N)

tool_sources (optional): where a tool's output comes from. Tools named in
`local` (fnmatch patterns) return the repository checkout; any other tool
is external (unknown tools too), and so is an untrusted user message. A
local result whose text matches one of `external_markers` (regexes: an
Atlassian URL in a saved ticket, gh api JSON) counts as external. A local
result reaches the critical tier only when the window where the questions
agree also breaks one of the `corroborate` rules (precheck.content_signals);
otherwise it is a block (the result is removed, the conversation goes on).

tool_definitions (optional): `allow_sha256`, definitions of your own clients
answered clean without scoring (the SHA-256 of the definition text, as in
the decision log); `builtin_names`, the agents' built-in tool names: one
whose hash is not listed (a client upgrade) is reported (review), never
removed. Any other definition (MCP servers, unknown) is scored as before.
Per app (meta.app_id): system_context, skip (answer clean without scoring),
stages (the stages scored for the app; default all), enforcement (merged
over the top-level one), user_messages (standard | untrusted) and
untrusted_source.

user_messages: untrusted, for a bot whose "user" turn is its runner's
prompt wrapped around untrusted text (an issue, a PR, a comment): the
user-message questions read the runner's own instruction as manipulation
and flag ordinary issues (eval/RESULTS.md, wrapped prompts). Such a message
is scored as untrusted content instead, with the tool_result questions in a
TOOL OUTPUT block labelled untrusted_source, and only the critical tier
reaches block: a lower hit is reported as review (logged).

enforcement (docs/ARCHITECTURE.md), per stage:
    mode          inline: scored before the call is answered (default);
                  deferred: content the sidecar has not seen is answered clean at once
                  and scored in the background; once scored, its verdict is answered
                  from the verdict store, so a client that resends it (the history)
                  is stopped on its next request. Needs the verdict store.
    inline_tools  tool_call: tools scored inline even when the stage is deferred
    when_busy     what an item gets when it cannot be scored in time (queue full, no
                  worker, a failed worker): error (the call is answered 503, as before),
                  pass (clean) or unscanned (a finding at the top tier, never stored)
pending_wait      seconds a deferred item waits for its own scoring still under way
                  (a client's next request racing its background score)
pending_min_age   only scoring started at least this many seconds ago is waited for: a
                  request's other filters call within milliseconds of its first, and
                  should not wait for the score that call just started (0: they wait too,
                  which turns a deferred stage into inline-within-pending_wait)
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from wolfguard import precheck
from wolfguard.segments import STAGES

FORBIDDEN_CONCEPTS = {"instruction.handling"}  # always the same answer (model card)
NOUL_DEFAULT = {"false": "No.", "true": "Yes."}


class PolicyError(ValueError):
    pass


@dataclass(frozen=True)
class Question:
    name: str
    kind: str
    instructions: str
    option_ids: tuple[str, ...]
    option_texts: tuple[str, ...]
    risk: tuple[str, ...]           # option ids on the attack side
    block: float
    review: float
    decides: bool = True
    critical: float | None = None
    read_only: str = "decide"       # tool_call: decide | report on a read-only call

    def risk_of(self, probs: list[float]) -> float:
        return sum(p for i, p in zip(self.option_ids, probs) if i in self.risk)


@dataclass(frozen=True)
class Stage:
    name: str
    questions: tuple[Question, ...]
    window_tokens: int = 512
    window_overlap: int = 64
    with_tool_call: bool = True       # tool_result: name-only [TOOL CALL]
    paste_min_chars: int = 2000       # user_message: score the pasted part as untrusted content
    paste_questions: tuple[Question, ...] = ()
    goal_tokens: int = 512            # tool_call: goal clipped (head + tail)
    full_scene: bool = False          # tool_result, eval only: [USER GOAL] + the call with arguments
    block_when: str = "any"           # any: one deciding question at block decides; all: every one must (else review)
    agree: str = "item"               # block_when all: item (per-question peaks) | window (together in one window)
    read_only_tools: tuple[str, ...] = ()   # tool_call: tools that only read
    critical_by_windows: tuple[tuple[int, float], ...] = ()   # (min windows, critical threshold), ascending

    def critical_for(self, q: "Question", windows: int) -> float:
        t = q.critical
        for n, c in self.critical_by_windows:
            if windows >= n:
                t = max(t, c)
        return t


MODES = ("inline", "deferred")
WHEN_BUSY = ("error", "pass", "unscanned")


@dataclass(frozen=True)
class StageMode:
    mode: str = "inline"
    inline_tools: tuple[str, ...] = ()
    when_busy: str = "error"


@dataclass(frozen=True)
class Enforcement:
    stages: tuple[tuple[str, StageMode], ...] = ()
    pending_wait: float = 2.0
    pending_min_age: float = 1.0

    def stage(self, name: str) -> StageMode:
        return dict(self.stages).get(name, StageMode())

    def mode_of(self, stage: str, tool_name: str = "") -> str:
        m = self.stage(stage)
        if m.mode == "deferred" and stage == "tool_call" and tool_name in m.inline_tools:
            return "inline"
        return m.mode

    def deferred(self) -> bool:
        return any(m.mode == "deferred" for _, m in self.stages)


@dataclass(frozen=True)
class App:
    system_context: str = ""
    skip: bool = False
    stages: tuple[str, ...] = STAGES
    enforcement: Enforcement = Enforcement()
    user_messages: str = "standard"           # standard | untrusted
    untrusted_source: str = "message"         # the TOOL OUTPUT label for untrusted user messages


@dataclass(frozen=True)
class ToolSources:
    local: tuple[str, ...] = ()
    external_markers: tuple[str, ...] = ()
    corroborate: tuple[str, ...] = ()

    def is_local(self, tool: str, text: str) -> bool:
        if not any(fnmatch.fnmatchcase(tool, p) for p in self.local):
            return False
        return not any(re.search(m, text, re.IGNORECASE) for m in self.external_markers)


@dataclass(frozen=True)
class ToolDefinitions:
    allow_sha256: frozenset = frozenset()
    builtin_names: frozenset = frozenset()


@dataclass(frozen=True)
class Policy:
    version: str
    model_revision: str
    stages: dict
    apps: dict = field(default_factory=dict)
    default_app: App = App()
    canaries: tuple[str, ...] = ()
    tools: dict = field(default_factory=dict)   # tool name -> plain-language description for [PROPOSED ACTION]
    max_segment_chars: int = 40000
    max_segments: int = 64
    secret_rules: bool = True      # precheck secret.path / secret.env on tool calls (decided without the model)
    exfil_rules: bool = True       # precheck exfil.shell on tool calls (decided without the model)
    tool_sources: ToolSources | None = None     # None: every tool result is external
    tool_definitions: ToolDefinitions = ToolDefinitions()

    def app(self, app_id) -> App:
        return self.apps.get(str(app_id), self.default_app) if app_id not in (None, "", 0) else self.default_app


def _question(name: str, q: dict) -> Question:
    if name in FORBIDDEN_CONCEPTS:
        raise PolicyError(f"{name} always returns the same answer; use content.role or injection.indirect_presence")
    kind = q.get("type", "choice")
    instr = q.get("instructions") or ""
    if not instr:
        raise PolicyError(f"{name}: instructions are required")
    crit = q.get("criteria")
    if kind == "noul":
        c = {**NOUL_DEFAULT, **(crit or {})}
        ids, texts, risk = ("false", "true"), (c["false"], c["true"]), ("true",)
    elif kind == "choice":
        if not isinstance(crit, dict) or len(crit) < 2:
            raise PolicyError(f"{name}: a choice needs at least two criteria")
        ids = tuple(crit)
        texts = tuple(crit[i] or i for i in ids)
        r = q.get("risk")
        if r not in ids:
            raise PolicyError(f"{name}: risk must name one of {list(ids)}")
        risk = (r,)
    elif kind == "score":
        if not isinstance(crit, list) or len(crit) < 2:
            raise PolicyError(f"{name}: a score needs at least two levels")
        ids = texts = tuple(str(c) for c in crit)
        r = q.get("risk")
        risk = tuple(r) if isinstance(r, list) else ()
        if not risk or any(x not in ids for x in risk):
            raise PolicyError(f"{name}: risk must list levels from {list(ids)}")
    else:
        raise PolicyError(f"{name}: unknown type {kind!r}")
    block, review = float(q.get("block", 0.70)), float(q.get("review", 0.35))
    if not 0 < review <= block <= 1:
        raise PolicyError(f"{name}: need 0 < review <= block <= 1")
    critical = q.get("critical")
    if critical is not None:
        critical = float(critical)
        if not block <= critical <= 1:
            raise PolicyError(f"{name}: need block <= critical <= 1")
    ro = str(q.get("read_only", "decide"))
    if ro not in ("decide", "report"):
        raise PolicyError(f"{name}: read_only must be decide or report")
    return Question(name, kind, instr, ids, texts, risk, block, review, bool(q.get("decides", True)), critical, ro)


def _enforcement(d, base: Enforcement | None = None) -> Enforcement:
    """The enforcement section, merged over base (an app's over the top-level one)."""
    d = d or {}
    if not isinstance(d, dict):
        raise PolicyError("enforcement must be a mapping")
    stages = dict(base.stages) if base else {}
    for name, m in (d.get("stages") or {}).items():
        if name not in STAGES:
            raise PolicyError(f"enforcement: unknown stage {name!r}")
        m = m or {}
        prev = stages.get(name, StageMode())
        mode = str(m.get("mode", prev.mode))
        busy = str(m.get("when_busy", prev.when_busy))
        if mode not in MODES:
            raise PolicyError(f"enforcement.{name}: mode must be one of {list(MODES)}")
        if busy not in WHEN_BUSY:
            raise PolicyError(f"enforcement.{name}: when_busy must be one of {list(WHEN_BUSY)}")
        tools = m.get("inline_tools", prev.inline_tools)
        if not isinstance(tools, (list, tuple)):
            raise PolicyError(f"enforcement.{name}: inline_tools must be a list")
        stages[name] = StageMode(mode, tuple(str(t) for t in tools), busy)
    wait = float(d.get("pending_wait", base.pending_wait if base else 2.0))
    if not 0 <= wait <= 60:
        raise PolicyError("enforcement: pending_wait must be 0 to 60 seconds")
    age = float(d.get("pending_min_age", base.pending_min_age if base else 1.0))
    if not 0 <= age <= 60:
        raise PolicyError("enforcement: pending_min_age must be 0 to 60 seconds")
    return Enforcement(tuple(sorted(stages.items())), wait, age)


def _by_windows(stage: str, d) -> tuple:
    if not d:
        return ()
    if not isinstance(d, dict):
        raise PolicyError(f"{stage}: critical_by_windows must map a window count to a threshold")
    out = tuple(sorted((int(n), float(c)) for n, c in d.items()))
    if any(n < 1 or not 0 < c <= 1 for n, c in out):
        raise PolicyError(f"{stage}: critical_by_windows needs window counts >= 1 and thresholds in (0, 1]")
    return out


def parse(doc: dict) -> Policy:
    if not isinstance(doc, dict) or "stages" not in doc:
        raise PolicyError("a policy needs version, model_revision and stages")
    stages = {}
    for name, s in (doc.get("stages") or {}).items():
        if name not in STAGES:
            raise PolicyError(f"unknown stage {name!r}")
        qs = tuple(_question(qn, q) for qn, q in (s.get("questions") or {}).items())
        if not qs:
            raise PolicyError(f"{name}: no questions")
        w = s.get("window") or {}
        paste = tuple(_question(qn, q) for qn, q in ((s.get("paste") or {}).get("questions") or {}).items())
        bw = s.get("block_when", "any")
        if bw not in ("any", "all"):
            raise PolicyError(f"{name}: block_when must be any or all")
        agree = s.get("agree", "item")
        if agree not in ("item", "window"):
            raise PolicyError(f"{name}: agree must be item or window")
        stages[name] = Stage(name, qs, int(w.get("tokens", 512)), int(w.get("overlap", 64)),
                             bool(s.get("with_tool_call", True)), int((s.get("paste") or {}).get("min_chars", 2000)), paste,
                             int(s.get("goal_tokens", 512)), block_when=bw, agree=agree,
                             read_only_tools=tuple(str(t) for t in s.get("read_only_tools") or ()),
                             critical_by_windows=_by_windows(name, s.get("critical_by_windows")))
        st = stages[name]
        if not 0 <= st.window_overlap < st.window_tokens:
            raise PolicyError(f"{name}: need 0 <= overlap < window tokens")

    enforcement = _enforcement(doc.get("enforcement"))

    sources = None
    if doc.get("tool_sources") is not None:
        ts = doc["tool_sources"]
        if not isinstance(ts, dict):
            raise PolicyError("tool_sources must be a mapping")
        for m in ts.get("external_markers") or ():
            try:
                re.compile(m)
            except re.error as e:
                raise PolicyError(f"tool_sources.external_markers: {m!r}: {e}") from None
        known = set(precheck.CONTENT) | {"unicode.tags", "unicode.bidi", "unicode.invisible", "scene.header_spoof"}
        bad = [r for r in ts.get("corroborate") or () if r not in known]
        if bad:
            raise PolicyError(f"tool_sources.corroborate: unknown rule {bad[0]!r} (one of {sorted(known)})")
        sources = ToolSources(tuple(str(t) for t in ts.get("local") or ()), tuple(str(m) for m in ts.get("external_markers") or ()),
                              tuple(str(r) for r in ts.get("corroborate") or ()))
    td = doc.get("tool_definitions") or {}
    hashes = frozenset(str(h).lower() for h in td.get("allow_sha256") or ())
    if any(not re.fullmatch(r"[0-9a-f]{64}", h) for h in hashes):
        raise PolicyError("tool_definitions.allow_sha256: SHA-256 hex digests only")
    defs = ToolDefinitions(hashes, frozenset(str(n) for n in td.get("builtin_names") or ()))

    def app(d):
        d = d or {}
        sts = tuple(d.get("stages") or STAGES)
        bad = [x for x in sts if x not in STAGES]
        if bad:
            raise PolicyError(f"unknown stage {bad[0]!r} in an app")
        um = str(d.get("user_messages", "standard"))
        if um not in ("standard", "untrusted"):
            raise PolicyError("an app's user_messages must be standard or untrusted")
        return App(str(d.get("system_context") or ""), bool(d.get("skip", False)), sts, _enforcement(d.get("enforcement"), enforcement),
                   um, str(d.get("untrusted_source") or "message"))

    return Policy(
        version=str(doc.get("version") or ""), model_revision=str(doc.get("model_revision") or ""), stages=stages,
        apps={str(k): app(v) for k, v in (doc.get("apps") or {}).items()}, default_app=app(doc.get("default_app")),
        canaries=tuple(str(c) for c in doc.get("canaries") or ()),
        tools={str(k): str(v) for k, v in (doc.get("tools") or {}).items()},
        max_segment_chars=int((doc.get("limits") or {}).get("max_segment_chars", 40000)),
        max_segments=int((doc.get("limits") or {}).get("max_segments", 64)),
        secret_rules=bool((doc.get("rules") or {}).get("secret_access", True)),
        exfil_rules=bool((doc.get("rules") or {}).get("shell_exfil", True)),
        tool_sources=sources, tool_definitions=defs)


def load(path: str | Path) -> Policy:
    p = parse(yaml.safe_load(Path(path).read_text()))
    if not p.version:
        raise PolicyError("the policy needs a version")
    return p
