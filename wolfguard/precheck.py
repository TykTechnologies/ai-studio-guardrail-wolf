"""Deterministic pre-checks, run before any model call (build plan, step 2).

Rules are signals with a severity: "flag" rules are recorded and reported
but do not decide on their own; "block" rules decide without the model.

    unicode.bidi        bidirectional controls (Trojan Source)          flag
    unicode.invisible   zero-width and other invisible characters       flag
    unicode.tags        Unicode tag characters (invisible ASCII)        flag; their
                        text is revealed to the model ("ASCII smuggling")
    scene.header_spoof  a line that would pass for a scene block header flag
    canary.leak         a configured canary token in a tool call        block
    secret.path         a tool call naming a credentials file           block
                        (/proc/*/environ, .env, ~/.ssh, gh/hosts.yml, cloud credentials, ...)
    secret.env          a tool call reading a secret environment variable, or
                        dumping the environment (printenv, env)         block

In a red-team test, text in a GitHub issue told an agent to read
/proc/self/environ with its file tool and paste the result into its reply;
the model scored that call as aligned with triaging the issue. Reading a
credentials file is never part of reviewing code, so it is decided without
the model, whatever the tool is called.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

# Credentials files and process secrets. Matched on the tool call's arguments (JSON text).
SECRET_PATHS = (
    r"/proc/(?:self|thread-self|\d+)/(?:environ|cmdline|mem|maps|fd\b|task/\d+/environ)",
    r"(?:^|[\s\"'=:/(])\.env(?:\.(?!example\b|sample\b|template\b|dist\b|defaults?\b)[\w.-]+)?(?=$|[\s\"',;)}\]])",
    r"\.ssh/", r"\bid_(?:rsa|dsa|ecdsa|ed25519)\b",
    r"\.aws/(?:credentials|config)\b", r"\.config/gcloud/", r"application_default_credentials\.json",
    r"\.azure/(?:accessTokens|msal_token_cache|azureProfile)", r"\.kube/config\b", r"\.docker/config\.json",
    r"\.config/gh/hosts\.yml", r"\.git-credentials\b", r"\.netrc\b", r"\.npmrc\b", r"\.pypirc\b",
    r"/(?:var/)?run/secrets/", r"/etc/(?:shadow|gshadow|sudoers)\b",
)
# Reading secret variables, or the whole environment, in a command.
SECRET_ENV = (
    r"\$\{?(?:GITHUB_TOKEN|GH_TOKEN|ACTIONS_RUNTIME_TOKEN|ACTIONS_ID_TOKEN_REQUEST_(?:TOKEN|URL)|INPUT_[A-Z0-9_-]+|"
    r"[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|PRIVATE_KEY|API_KEY|ACCESS_KEY)[A-Z0-9_]*)\b",
    r"(?:^|[;&|`(\s\"'])(?:printenv|env|set|export\s+-p|declare\s+-x)(?=\s*(?:$|[;&|>`)\"']))",
    r"process\.env\b(?!\.(?:NODE_ENV|CI|HOME|PATH)\b)", r"os\.environ\b(?!\.get\(\s*[\"'](?:HOME|PATH|CI)[\"'])",
)
_SECRET_PATHS = re.compile("|".join(SECRET_PATHS))
_SECRET_ENV = re.compile("|".join(SECRET_ENV))

from wolfguard import scenes

BIDI = frozenset([0x061C, 0x200E, 0x200F, *range(0x202A, 0x202F), *range(0x2066, 0x206A)])
INVISIBLE = frozenset([0x00AD, 0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x180E, *range(0x200B, 0x200E),
                       *range(0x2060, 0x2065), 0x3164, 0xFEFF, 0xFFA0, *range(0xFE00, 0xFE10)])
TAGS = range(0xE0000, 0xE0080)
VARIATION_SUPPLEMENT = range(0xE0100, 0xE01F0)


@dataclass(frozen=True)
class Rule:
    name: str
    severity: str  # flag | block
    detail: str = ""


@dataclass(frozen=True)
class Checked:
    text: str           # the text to score (tag characters revealed)
    rules: tuple[Rule, ...]


def secret_access(text: str) -> Rule | None:
    """The secret rule a tool call's arguments break, if any."""
    m = _SECRET_PATHS.search(text)
    if m:
        return Rule("secret.path", "block", m.group(0).strip(" \"'=:/("))
    m = _SECRET_ENV.search(text)
    if m:
        return Rule("secret.env", "block", m.group(0).strip(" \"'(;&|`"))
    return None


def check(stage: str, text: str, canaries: tuple[str, ...] = (), secrets: bool = True) -> Checked:
    rules = []
    bidi = sum(1 for ch in text if ord(ch) in BIDI)
    invisible = sum(1 for ch in text if ord(ch) in INVISIBLE or ord(ch) in VARIATION_SUPPLEMENT)
    tags = [ch for ch in text if ord(ch) in TAGS]
    if bidi:
        rules.append(Rule("unicode.bidi", "flag", f"{bidi} characters"))
    if invisible:
        rules.append(Rule("unicode.invisible", "flag", f"{invisible} characters"))
    if tags:
        rules.append(Rule("unicode.tags", "flag", f"{len(tags)} characters"))
        hidden = "".join(chr(ord(ch) - 0xE0000) for ch in tags if 0xE0020 <= ord(ch) <= 0xE007E)
        if hidden.strip():
            text = "".join(ch for ch in text if ord(ch) not in TAGS) + f"\n(hidden text: {hidden})"
    if scenes.neutralise(text)[1]:
        rules.append(Rule("scene.header_spoof", "flag"))
    if stage == "tool_call":
        for c in canaries:
            if c and c in text:
                rules.append(Rule("canary.leak", "block", "a canary token in the arguments"))
                break
        hit = secret_access(text) if secrets else None
        if hit:
            rules.append(hit)
    return Checked(text, tuple(rules))
