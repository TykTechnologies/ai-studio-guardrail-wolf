"""Trusted prompt templates on the wire: a segment's `template`, validated.

A gateway that matched an operator-approved template on a message sends the
message's residual as the segment's text (the slots in order, a placeholder
where each approved constant was) and the template beside it:

    {"index": 0, "role": "user", "text": "<residual>",
     "template": {"id": "pr-review", "version": 3, "full_text": "<the message>",
                  "exempt": [{"start": 0, "end": 812}, ...],     # UTF-8 byte offsets into full_text
                  "backstop": "log",                             # off | log | enforce
                  "backstop_min_score": 0.9}}                    # optional: enforced backstop findings below it are not reported

parse() checks it and returns what to score. Anything that does not check out
(offsets outside the text, overlapping or unsorted ranges, a range that splits
a UTF-8 character, a residual that is not the full text with each range
replaced by the placeholder, an unknown backstop mode) fails closed: the full
text is scored whole, as if no template had matched, and the segment is
flagged template.invalid.

A valid template's residual is scored as untrusted content (the slots are
third-party text by construction); the full text is scored as a backstop over
the windows that hold at least one byte outside the approved ranges.
"""
from __future__ import annotations

from dataclasses import dataclass

PLACEHOLDER = "[app template]"
BACKSTOP_MODES = ("off", "log", "enforce")
MIMICRY_BYTES = 32


@dataclass(frozen=True)
class Template:
    id: str
    version: str
    full_text: str
    exempt: tuple[tuple[int, int], ...]          # byte ranges, as sent
    exempt_chars: tuple[tuple[int, int], ...]    # the same ranges in characters of full_text
    backstop: str
    min_score: float | None
    exempt_share: float                          # characters of full_text left out of the residual
    mimicry: bool                                # a slot holds a 32-byte run of an approved constant

    @property
    def ref(self) -> str:
        return f"{self.id}@{self.version}"

    def key(self) -> list:
        """What a verdict on the segment depends on besides its residual (the store key)."""
        return [self.id, self.version, self.backstop, self.min_score, self.full_text, list(self.exempt)]


@dataclass(frozen=True)
class Parsed:
    text: str                   # what to score as the segment's text
    template: Template | None   # a valid template; None when absent or invalid
    invalid: str = ""           # why a template was refused ("" when none was sent or it is valid)


def _boundary(b: bytes, i: int) -> bool:
    return i == len(b) or (b[i] & 0xC0) != 0x80


def _char_offsets(b: bytes) -> list[int]:
    """Byte offset -> character offset, for every character boundary (and the end)."""
    out, c = {}, 0
    for i in range(len(b) + 1):
        if _boundary(b, i):
            out[i] = c
            c += 1
    return out


def _mimicry(full: bytes, exempt: tuple[tuple[int, int], ...]) -> bool:
    runs = set()
    for s, e in exempt:
        c = full[s:e]
        runs.update(c[i : i + MIMICRY_BYTES] for i in range(0, len(c) - MIMICRY_BYTES + 1))
    if not runs:
        return False
    prev = 0
    for s, e in list(exempt) + [(len(full), len(full))]:
        slot = full[prev:s]
        if any(slot[i : i + MIMICRY_BYTES] in runs for i in range(0, len(slot) - MIMICRY_BYTES + 1)):
            return True
        prev = e
    return False


def parse(seg: dict) -> Parsed:
    text = str(seg.get("text") or "")
    t = seg.get("template")
    if t is None:
        return Parsed(text, None)
    if not isinstance(t, dict) or not isinstance(t.get("full_text"), str):
        return Parsed(text, None, "no full_text")
    full = t["full_text"]

    def bad(why):
        return Parsed(full, None, why)

    tid, ver = t.get("id"), t.get("version")
    if not isinstance(tid, str) or not tid or isinstance(ver, bool) or not isinstance(ver, (int, str)) or ver == "":
        return bad("id or version")
    mode = t.get("backstop", "log")
    if mode not in BACKSTOP_MODES:
        return bad("backstop mode")
    ms = t.get("backstop_min_score")
    if ms is not None and (isinstance(ms, bool) or not isinstance(ms, (int, float)) or not 0 <= ms <= 1):
        return bad("backstop_min_score")
    try:
        b = full.encode("utf-8")
    except UnicodeEncodeError:
        return bad("full_text is not UTF-8")
    ranges, prev = [], 0
    for r in t.get("exempt") or []:
        if not isinstance(r, dict):
            return bad("exempt range")
        s, e = r.get("start"), r.get("end")
        if any(isinstance(x, bool) or not isinstance(x, int) for x in (s, e)):
            return bad("exempt range")
        if not prev <= s < e <= len(b):
            return bad("exempt offsets")
        if not (_boundary(b, s) and _boundary(b, e)):
            return bad("exempt offsets split a UTF-8 character")
        ranges.append((s, e))
        prev = e
    if not ranges:
        return bad("no exempt range")
    parts, prev = [], 0
    for s, e in ranges:
        parts += [b[prev:s], PLACEHOLDER.encode()]
        prev = e
    parts.append(b[prev:])
    if b"".join(parts).decode("utf-8") != text:
        return bad("residual does not match")
    co = _char_offsets(b)
    chars = tuple((co[s], co[e]) for s, e in ranges)
    share = sum(e - s for s, e in chars) / max(1, len(full))
    tpl = Template(tid, str(ver), full, tuple(ranges), chars, mode, None if ms is None else float(ms), share, _mimicry(b, tuple(ranges)))
    return Parsed(text, tpl)


def inside(span: tuple[int, int], ranges: tuple[tuple[int, int], ...]) -> bool:
    """Whether a character span lies within the (sorted) ranges, touching ranges joined."""
    s, e = span
    if s >= e:
        return True
    for a, b in _merged(ranges):
        if a <= s and e <= b:
            return True
    return False


def _merged(ranges):
    out = []
    for a, b in ranges:
        if out and a <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], b))
        else:
            out.append((a, b))
    return out
