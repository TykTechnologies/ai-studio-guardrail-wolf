"""Scene builder: the exact tagged-block format Jev was evaluated on (model card "Input format").

    tool_result      [TOOL CALL] <tool>(...)          (name only: 2.3 sends no arguments with results)
                     [TOOL OUTPUT | <tool> | untrusted]
    user_message     [SYSTEM CONTEXT] (per app, from the policy)   [USER PROMPT]
    pasted content   [RETRIEVED CONTENT | user-paste | untrusted]  (the pasted part of a user message)
    tool_call        [USER GOAL]  [PROPOSED ACTION | agent] (the call, then a one-line description)
    tool_definition  [AVAILABLE TOOLS] (one definition)

Rules (model card limitations): content questions never get a [PROPOSED
ACTION] block; untrusted text never goes in [USER PROMPT]. Text that could
pass for a block header (a line starting with "[SYSTEM CONTEXT]", "[USER
GOAL]", ...) is neutralised so untrusted content cannot fake the scene's
structure; neutralise() reports whether it did.
"""
from __future__ import annotations

import json
import re

HEADERS = ("SYSTEM CONTEXT", "AVAILABLE TOOLS", "USER GOAL", "USER PROMPT", "TOOL CALL", "TOOL OUTPUT",
           "RETRIEVED CONTENT", "PROPOSED ACTION", "SECURITY POLICY")
_HEADER_LINE = re.compile(r"^(\s*)\[(" + "|".join(re.escape(h) for h in HEADERS) + r")\b", re.IGNORECASE | re.MULTILINE)
_NAME = re.compile(r"[^A-Za-z0-9_.:\-]+")


def neutralise(text: str) -> tuple[str, bool]:
    """Turn header-like lines into "(HEADER" so they read as text, not structure."""
    out, n = _HEADER_LINE.subn(lambda m: f"{m.group(1)}({m.group(2)}", text)
    return out, n > 0


def tool_label(name: str) -> str:
    """A tool name safe inside a header: no "|", "]" or newlines; 64 characters."""
    return (_NAME.sub("_", name).strip("_") or "tool")[:64]


def _render(blocks: list[tuple[str, str]]) -> str:
    return "\n\n".join(f"[{h}]\n{b}" for h, b in blocks)


def tool_result(text: str, tool: str, with_call: bool = True) -> str:
    t = tool_label(tool)
    blocks = []
    if with_call:
        blocks.append(("TOOL CALL", f"{t}(...)"))
    blocks.append((f"TOOL OUTPUT | {t} | untrusted", neutralise(text)[0]))
    return _render(blocks)


def tool_result_full(text: str, tool: str, call: str, goal: str) -> str:
    """The full evaluated format (goal and the call with its arguments). The
    2.3 gateway cannot send these with a tool result; the eval uses this to
    measure what that costs."""
    t = tool_label(tool)
    blocks = []
    if goal:
        blocks.append(("USER GOAL", neutralise(goal)[0]))
    blocks.append(("TOOL CALL", neutralise(call)[0] if call else f"{t}(...)"))
    blocks.append((f"TOOL OUTPUT | {t} | untrusted", neutralise(text)[0]))
    return _render(blocks)


def user_message(text: str, system: str = "") -> str:
    blocks = []
    if system:
        blocks.append(("SYSTEM CONTEXT", neutralise(system)[0]))
    blocks.append(("USER PROMPT", neutralise(text)[0]))
    return _render(blocks)


def pasted(text: str, system: str = "") -> str:
    blocks = []
    if system:
        blocks.append(("SYSTEM CONTEXT", neutralise(system)[0]))
    blocks.append(("RETRIEVED CONTENT | user-paste | untrusted", neutralise(text)[0]))
    return _render(blocks)


def render_call(tool: str, arguments: str) -> str:
    """A call as code: tool(key="value", n=3). Arguments that are not a JSON
    object are kept as written. (A JSON blob in the action block made every
    call read as misaligned and exfiltrating; spike/RESULTS.md §7.)"""
    t = tool_label(tool)
    try:
        args = json.loads(arguments)
    except ValueError:
        return f"{t}({arguments})"
    if not isinstance(args, dict):
        return f"{t}({json.dumps(args, ensure_ascii=False)})"
    parts = [f"{_NAME.sub('_', str(k))}={json.dumps(v, ensure_ascii=False)}" for k, v in args.items()]
    return f"{t}({', '.join(parts)})"


def tool_call(arguments: str, tool: str, goal: str, system: str = "", description: str = "") -> str:
    """The model card's action shape: the call on one line, a plain-language
    description on the next (the policy's per-tool description, else
    generic), after the app's context and the user's goal."""
    t = tool_label(tool)
    blocks = []
    if system:
        blocks.append(("SYSTEM CONTEXT", neutralise(system)[0]))
    blocks.append(("USER GOAL", neutralise(goal)[0] if goal else "(not given)"))
    desc = description or f"Runs the {t} tool."
    blocks.append(("PROPOSED ACTION | agent", f"{neutralise(render_call(tool, arguments))[0]}\n{neutralise(desc)[0]}"))
    return _render(blocks)


def render_definition(definition: str) -> str:
    """A tool definition (OpenAI, Responses, Anthropic, Gemini or Bedrock
    shape) as a readable signature: "- name(arg: type, ...): description",
    then one line per described argument. Anything else is kept as written.
    (Raw JSON scored a poisoned definition 0.36, this 0.995; benign ones 0
    either way: spike/RESULTS.md §7.)"""
    try:
        d = json.loads(definition)
    except ValueError:
        return definition
    if not isinstance(d, dict):
        return definition
    f = d.get("function") if isinstance(d.get("function"), dict) else d.get("toolSpec") if isinstance(d.get("toolSpec"), dict) else d
    if not isinstance(f.get("name"), str):
        return definition
    schema = f.get("parameters") or f.get("input_schema") or (f.get("inputSchema") or {}).get("json") or {}
    props = schema.get("properties") if isinstance(schema, dict) and isinstance(schema.get("properties"), dict) else {}
    sig = ", ".join(f"{k}: {v.get('type', 'any') if isinstance(v, dict) else 'any'}" for k, v in props.items())
    lines = [f"- {f['name']}({sig}): {f.get('description') or ''}"]
    for k, v in props.items():
        if isinstance(v, dict) and v.get("description"):
            lines.append(f"    {k}: {v['description']}")
    return "\n".join(lines)


def tool_definition(definition: str) -> str:
    return _render([("AVAILABLE TOOLS", neutralise(render_definition(definition))[0])])


_FENCE = re.compile(r"```.*?(?:```|$)", re.DOTALL)
_QUOTE = re.compile(r"(?:^>.*(?:\n|$))+", re.MULTILINE)


def pasted_part(text: str, min_chars: int) -> str:
    """The part of a user message to score as pasted content: fenced and
    quoted blocks, or the whole message when it is longer than min_chars.
    "" when there is none."""
    parts = [m.group(0) for m in _FENCE.finditer(text)] + [m.group(0) for m in _QUOTE.finditer(text)]
    if parts:
        return "\n".join(parts)
    return text if len(text) >= min_chars else ""
