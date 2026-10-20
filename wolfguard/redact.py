"""Masking secrets in previews before they are written.

A preview is the head of a flagged segment, and a flagged shell output or
file can carry credentials. Known key shapes, key/secret assignments and
long high-entropy tokens are replaced with [REDACTED:<kind>]. It errs on the
side of masking: a preview is for seeing why something was flagged, and an
over-masked hash costs nothing.
"""
from __future__ import annotations

import math
import re

_PATTERNS = [
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY-----|$)")),
    ("aws_key", re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[A-Z0-9]{16}\b")),
    ("github_token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b")),
    ("slack_token", re.compile(r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b")),
    ("api_key", re.compile(r"\b(?:sk|pk|rk)-(?:ant-|proj-|live-|test-)?[A-Za-z0-9_-]{20,}\b")),
    ("google_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")),
    ("url_credentials", re.compile(r"(?<=://)[^\s/:@]+:[^\s/@]+(?=@)")),
    # NAME=value / "name": "value" where the name says secret.
    ("assignment", re.compile(r"(?i)((?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key|auth|credential)s?[\"']?\s*[:=]\s*[\"']?)([^\s\"',;]{6,})")),
]
_TOKEN = re.compile(r"[A-Za-z0-9+/_=-]{32,}")


def _entropy(s: str) -> float:
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def _high_entropy(tok: str) -> bool:
    classes = sum(bool(re.search(p, tok)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]"))
    if re.fullmatch(r"[0-9a-f]+", tok):          # hex: digests, keys
        return len(tok) >= 32 and _entropy(tok) >= 3.0
    return classes >= 2 and _entropy(tok) >= 4.0


def redact(text: str) -> str:
    for kind, pat in _PATTERNS:
        if kind == "assignment":
            text = pat.sub(lambda m: m.group(1) + "[REDACTED:secret]", text)
        else:
            text = pat.sub(f"[REDACTED:{kind}]", text)
    return _TOKEN.sub(lambda m: "[REDACTED:token]" if _high_entropy(m.group(0)) else m.group(0), text)
