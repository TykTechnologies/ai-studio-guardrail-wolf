"""Segment typing: AI Studio 2.3 HTTP guardrail segments -> scoring items (docs/ARCHITECTURE.md, the contract).

The gateway sends one call per trust class. Each segment is typed by its
kind and role:

    kind tool_result                 -> stage tool_result (tool_name, tool_call_id)
    kind tool_call                   -> stage tool_call (context.user_goal, context.system)
    kind tool_definition             -> stage tool_definition
    no kind, role user               -> stage user_message
    no kind, role system             -> system context for the call's user messages (not scored)
    no kind, role assistant          -> not scored (requests: history; responses: model text)

Decoded views (a JSON unit's strings as "key\\nvalue" text) arrive as extra
segments of the same kind and are scored like any segment; a finding on
either flags the unit gateway-side.

A user message that matched a trusted prompt template carries its residual
as text and the template beside it (wolfguard/templates.py); the system
context of such a message is its full text. A template on anything else
(tool output, calls, definitions) is not honoured: the full text is scored.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from wolfguard import templates as tplmod

STAGES = ("tool_result", "tool_call", "user_message", "tool_definition")


@dataclass(frozen=True)
class Item:
    """One segment to score."""

    stage: str
    text: str
    segment_index: int
    tool_name: str = ""
    tool_call_id: str = ""
    goal: str = ""          # tool_call: the user's goal (context.user_goal)
    system: str = ""        # user_message / tool_call: system context
    pasted: bool = False    # user_message: the pasted part, scored as untrusted content
    call: str = ""          # tool_result, eval only: the call with its arguments (full scene)
    template: tplmod.Template | None = None   # user_message: a valid trusted template (text is its residual)
    template_invalid: str = ""                # why a template sent with the segment was refused (its full text is scored)


@dataclass
class Typed:
    """A call's segments, typed."""

    direction: str
    items: list[Item] = field(default_factory=list)
    skipped: dict[str, int] = field(default_factory=dict)  # reason -> count
    meta: dict = field(default_factory=dict)

    def skip(self, reason: str) -> None:
        self.skipped[reason] = self.skipped.get(reason, 0) + 1


def stage_of(seg: dict) -> str:
    """The stage a segment is scored in ("" when it is not scored: system
    context, assistant text, unknown kinds)."""
    kind = seg.get("kind") or ""
    if kind in ("tool_result", "tool_call", "tool_definition"):
        return kind
    if not kind and seg.get("role") == "user":
        return "user_message"
    return ""


def type_call(body: dict) -> Typed:
    """Type a classify request body ({"direction", "segments", "meta", ...})."""
    out = Typed(direction=str(body.get("direction") or "request"), meta=dict(body.get("meta") or {}))
    segs = [s for s in body.get("segments") or [] if isinstance(s, dict)]
    def full(s):
        p = tplmod.parse(s)
        return p.template.full_text if p.template else p.text

    system = "\n\n".join(full(s) for s in segs if not s.get("kind") and s.get("role") == "system").strip()
    for s in segs:
        kind = s.get("kind") or ""
        role = s.get("role") or ""
        parsed = tplmod.parse(s)
        text, tpl, invalid = parsed.text, parsed.template, parsed.invalid
        if tpl is not None and (kind or role != "user"):
            # Templates are matched on a request's own messages only: elsewhere, the full text.
            text, tpl, invalid = tpl.full_text, None, "not a user message"
        idx = int(s.get("index", 0))
        name = str(s.get("tool_name") or "")
        cid = str(s.get("tool_call_id") or "")
        if not text.strip():
            out.skip("empty")
            continue
        if kind == "tool_result":
            out.items.append(Item("tool_result", text, idx, name, cid, template_invalid=invalid))
        elif kind == "tool_call":
            ctx = s.get("context") or {}
            out.items.append(Item("tool_call", text, idx, name, cid, goal=str(ctx.get("user_goal") or ""), system=str(ctx.get("system") or ""),
                                  template_invalid=invalid))
        elif kind == "tool_definition":
            out.items.append(Item("tool_definition", text, idx, name, template_invalid=invalid))
        elif kind:
            out.skip(f"kind:{kind}")
        elif role == "user":
            out.items.append(Item("user_message", text, idx, system=system, template=tpl, template_invalid=invalid))
        elif role == "system":
            out.skip("system_context")
        else:
            out.skip(f"role:{role or 'none'}")
    return out
