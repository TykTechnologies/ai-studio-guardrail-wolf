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
    exfil.shell         a shell tool call that reads a file or the      block
                        environment and sends it over the network: a read
                        piped to curl/wget/nc/ssh, a $(...) read or $VAR in
                        a sender's arguments, curl -d @file / -T file /
                        -F x=@file, wget --post-file, scp/rsync to a host,
                        /dev/tcp
    content.*           content (a tool result, a user message) that    flag
                        carries an attack's working parts: an override
                        phrase, text addressed to the AI, hiding it from
                        the user, a credentials file, a download piped to
                        a shell, or secrets sent to an address. The
                        corroboration a repo-local tool result needs to
                        reach the critical tier (tool_sources in the policy)

In a red-team test, text in a GitHub issue told an agent to read
/proc/self/environ with its file tool and paste the result into its reply;
the model scored that call as aligned with triaging the issue. Reading a
credentials file is never part of reviewing code, so it is decided without
the model, whatever the tool is called.
"""
from __future__ import annotations

import json
import re
import shlex
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

# An attack's working parts in content, matched per window. Each is common in
# injections and rare in code, its output and docs; none decides alone (the
# model has to agree in the same window). Names of secret variables are left
# out on purpose: workflows and docs name GITHUB_TOKEN all the time.
_PREV = r"(?:previous|prior|above|earlier|preceding|original|system|existing)"
CONTENT = {
    "content.override": (
        rf"\b(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+|any\s+)?(?:of\s+)?(?:your\s+|the\s+|my\s+|these\s+|those\s+)?{_PREV}\s+"
        r"(?:instructions?|prompts?|directions?|rules|guidelines|guardrails|context)\b"),
    "content.addressed": (
        r"\b(?:note|message|instructions?)\s+(?:to|for)\s+(?:the\s+|any\s+|all\s+)?(?:AI|LLM|assistant|agent|review(?:er)?\s+bot|model)s?\b"
        r"|\b(?:AI|LLM)\s+(?:assistant|agent|reviewer)s?\s*[:,]"
        r"|\b(?:the\s+)?(?:review\s+)?(?:assistant|reviewer\s+bot|review\s+bot)\s*(?:,|:|\s+(?:must|should)\s+(?:now\s+)?)"),
    # Structure an attack fakes: chat-template role tokens, the closing or opening tag of
    # a system or tool block, an HTML comment that speaks to the AI. (Not "<instructions>":
    # runners' own templates use it.)
    "content.role_tokens": r"<\|(?:im_start|im_end|system|assistant|user|start_header_id|end_header_id|eot_id)\|>|\[/?INST\]|<<SYS>>|<start_of_turn>",
    "content.fake_tags": r"</?(?:system|system_prompt|tool_output|tool_result|function_results|assistant)>",
    "content.hidden_comment": r"(?s)<!--(?:(?!-->).){0,400}?\b(?:AI|LLM|assistant|agents?|bots?|reviewer)\b(?:(?!-->).){0,400}?-->",
    "content.conceal": r"\bdo\s+not\s+(?:tell|mention|inform|report|disclose|reveal)\b[^.\n]{0,40}\b(?:user|maintainers?|anyone|this|step|comment|change)",
    "content.secret_path": "|".join(p for p in SECRET_PATHS if ".env" not in p),
    "content.remote_exec": r"\b(?:curl|wget)\b[^|\n]{0,200}\|\s*(?:sudo\s+)?(?:ba|z)?sh\b",
    "content.exfil_sink": (
        r"\b(?:send|forward|post|upload|paste|email|leak|exfiltrate)\b[^.\n]{0,60}"
        r"\b(?:token|secret|key|credentials?|environ(?:ment)?|password|issues|id_rsa)\b[^.\n]{0,40}"
        r"\bto\s+(?:https?://|[\w.+-]+@[\w-]+\.)"),
}
_CONTENT = {name: re.compile(rx, re.IGNORECASE) for name, rx in CONTENT.items()}

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


# Read-only shell commands: a call made only of these (no writes, no redirects,
# no command substitution) cannot change anything or send data anywhere. Its
# output goes back to the agent, nowhere else.
READ_ONLY_PROGRAMS = frozenset({
    "cat", "head", "tail", "less", "grep", "egrep", "fgrep", "rg", "ag", "ls", "tree", "wc", "echo", "printf", "cd", "pwd",
    "jq", "yq", "sort", "uniq", "cut", "tr", "diff", "file", "stat", "du", "df", "basename", "dirname", "realpath",
    "readlink", "which", "type", "true", "nl", "column", "comm", "cmp", "md5sum", "sha256sum", "shasum", "date", "whoami"})
READ_ONLY_GIT = frozenset({"log", "diff", "show", "status", "blame", "rev-parse", "ls-files", "ls-tree", "grep", "describe",
                           "merge-base", "cat-file", "shortlog", "rev-list", "name-rev"})
READ_ONLY_GH = frozenset({("pr", "view"), ("pr", "diff"), ("pr", "list"), ("pr", "checks"), ("issue", "view"), ("issue", "list"),
                          ("repo", "view"), ("run", "view"), ("run", "list"), ("release", "view"), ("release", "list")})
_WRITES = re.compile(r"\$\(|`|<\(|>\(|(?<![0-9&])>>?(?!\s*/dev/null)|[0-9]>>?(?!\s*/dev/null|&[0-9])")


_FLAT_KEYS = frozenset({"workdir", "cwd", "timeout", "description", "env", "restart", "is_background", "run_in_background"})


def _command(arguments: str) -> str:
    """The shell command in a tool call's arguments ({"command": ...} or the
    flattened "command\\n<cmd>\\n..." some vendors send); "" when there is none."""
    try:
        a = json.loads(arguments)
        if isinstance(a, dict):
            c = a.get("command", a.get("cmd"))
            return c if isinstance(c, str) else ""
    except ValueError:
        pass
    lines = arguments.split("\n")
    if len(lines) < 2 or lines[0].strip() not in ("command", "cmd"):
        return ""
    # A multi-line command runs until the next argument's name.
    end = next((i for i in range(2, len(lines)) if lines[i].strip() in _FLAT_KEYS), len(lines))
    return "\n".join(lines[1:end])


def _read_only_part(words: list[str]) -> bool:
    while words and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", words[0]):
        words = words[1:]      # VAR=value prefixes
    if not words:
        return True
    prog, args = words[0].rsplit("/", 1)[-1], words[1:]
    if prog in READ_ONLY_PROGRAMS:
        return True
    if prog == "sed":
        return "-n" in args and not any(a.startswith(("-i", "--in-place")) for a in args)
    if prog == "find":
        return not any(a in ("-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprintf", "-fls") for a in args)
    if prog == "git":
        sub = next((a for a in args if not a.startswith("-")), "")
        return sub in READ_ONLY_GIT
    if prog == "gh":
        sub = [a for a in args if not a.startswith("-")][:2]
        if sub[:1] == ["api"]:
            return not any(a in ("-f", "-F", "--field", "--raw-field", "--input") or a.startswith(("-X", "--method"))
                           and not a.endswith(("GET", "get")) for a in args)
        return tuple(sub) in READ_ONLY_GH
    return False


def read_only_call(arguments: str) -> bool:
    """Whether a shell tool call only reads: every command in it (split on
    ;, &&, || and pipes) is a read-only program, and nothing is written."""
    cmd = _command(arguments)
    if not cmd.strip() or _WRITES.search(cmd):
        return False
    try:
        lex = shlex.shlex(cmd, posix=True, punctuation_chars=";&|")
        lex.whitespace_split = True
        tokens = list(lex)
    except ValueError:
        return False
    part: list[str] = []
    for t in tokens + [";"]:
        if t and set(t) <= set(";&|"):
            if t not in (";", "&&", "||", "|") or not _read_only_part(part):
                return False
            part = []
        else:
            part.append(t)
    return True


# ---- exfil.shell: file or environment content sent over the network by a shell call -------------
EXFIL_READS = frozenset({"cat", "head", "tail", "base64", "xxd", "od", "hexdump", "tar", "strings", "env", "printenv", "set",
                         "gzip", "zip"})
EXFIL_SENDERS = frozenset({"curl", "wget", "nc", "ncat", "netcat", "socat", "ssh", "scp", "rsync", "sftp", "telnet"})
STDIN_SENDERS = frozenset({"nc", "ncat", "netcat", "socat", "ssh", "telnet"})   # send what they read on stdin
WRAPPERS = frozenset({"sudo", "command", "exec", "nohup", "time", "nice", "stdbuf", "xargs", "builtin", "timeout"})
SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "ash"})
# Variables that are not secrets: sending one is not a leak (secret ones are secret.env's).
PLAIN_VARS = frozenset({"HOME", "PWD", "OLDPWD", "PATH", "TMPDIR", "PORT", "HOST", "HOSTNAME", "USER", "SHELL", "LANG", "CI",
                        "RUNNER_TEMP", "GITHUB_WORKSPACE", "GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_REF", "GITHUB_RUN_ID"})
_VAR = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)")
_REMOTE = re.compile(r"^(?:[\w.-]+@)?[\w.-]+:(?!//)|^rsync://|^[\w.-]+::")
_CURL_DATA = ("-d", "--data", "--data-binary", "--data-ascii", "--json")
# Options whose value is where the sender writes, not what it sends.
_OUT_OPTS = ("-o", "--output", "--output-dir", "-D", "--dump-header", "-c", "--cookie-jar", "-O", "-P", "--directory-prefix",
             "-a", "--append-output", "--trace", "--trace-ascii", "--stderr")
_HEREDOC = re.compile(r"<<-?\s*(['\"]?)(\w+)\1[^\n]*\n(.*?)(?:\n\s*\2\s*(?:\n|$)|$)", re.DOTALL)


def _script(cmd: str) -> str:
    """One logical script: heredoc bodies dropped (literal text, not commands), line
    continuations joined, newlines made command separators."""
    cmd = _HEREDOC.sub(lambda m: m.group(0)[: m.start(3) - m.start(0)].rstrip("\n") + " ;\n", cmd)
    return cmd.replace("\\\n", " ").replace("\n", " ; ")


def _substitutions(cmd: str) -> tuple[str, list[str]]:
    """$(...) and `...` replaced by placeholders (their text listed), outermost first."""
    subs: list[str] = []
    out, i = [], 0
    while i < len(cmd):
        if cmd.startswith("$(", i):
            depth, j = 1, i + 2
            while j < len(cmd) and depth:
                depth += {"(": 1, ")": -1}.get(cmd[j], 0)
                j += 1
            subs.append(cmd[i + 2 : j - 1])
            out.append(f"__SUB{len(subs) - 1}__")
            i = j
        elif cmd[i] == "`":
            j = cmd.find("`", i + 1)
            j = len(cmd) if j < 0 else j
            subs.append(cmd[i + 1 : j])
            out.append(f"__SUB{len(subs) - 1}__")
            i = j + 1
        else:
            out.append(cmd[i])
            i += 1
    return "".join(out), subs


def _stages(cmd: str) -> list[list[list[str]]] | None:
    """Pipelines (split on ; && || &) of stages (split on |), each a word list; None when it does not parse."""
    try:
        lex = shlex.shlex(cmd, posix=True, punctuation_chars=";&|<>()")
        lex.whitespace_split = True
        tokens = list(lex)
    except ValueError:
        return None
    pipelines, stages, words = [], [], []
    for t in tokens + [";"]:
        if t in (";", "&&", "||", "&", ";;"):
            stages.append(words)
            pipelines.append([w for w in stages if w])
            stages, words = [], []
        elif t in ("|", "|&"):
            stages.append(words)
            words = []
        elif t in ("(", ")", "((", "))", "{", "}"):
            continue
        else:
            words.append(t)
    return [p for p in pipelines if p]


def _program(words: list[str]) -> tuple[str, list[str]]:
    """The program and its arguments, past VAR=value prefixes and wrappers (env X= curl, sudo, xargs, ...)."""
    while words:
        w = words[0]
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", w):
            words = words[1:]
            continue
        prog = w.rsplit("/", 1)[-1]
        if prog == "env" and any(not re.fullmatch(r"-\S*|[A-Za-z_][A-Za-z0-9_]*=.*", x) for x in words[1:]):
            words = [x for x in words[1:] if not x.startswith("-")]
            continue
        if prog in WRAPPERS:
            words = words[1:]
            while words and (words[0].startswith("-") or (prog == "timeout" and re.fullmatch(r"[\d.]+[smhd]?", words[0]))):
                words = words[1:]
            continue
        return prog, words[1:]
    return "", []


def _redirects(words: list[str]) -> tuple[list[str], list[str], list[str]]:
    """Words without redirections, the files read with <, the targets written with > or >>."""
    plain, ins, outs, i = [], [], [], 0
    while i < len(words):
        w = words[i]
        if w in ("<", ">", ">>", "<>", ">&", "<<", "<<<") and i + 1 < len(words):
            (ins if w in ("<", "<>") else outs if w in (">", ">>", "<>", ">&") else []).append(words[i + 1])
            if w == "<>":
                outs.append(words[i + 1])
            i += 2
            continue
        plain.append(w)
        i += 1
    return plain, ins, outs


def _opt(args: list[str], names: tuple[str, ...]) -> list[str]:
    """The values of the named options (-d x, -dx, --data x, --data=x)."""
    out = []
    for i, a in enumerate(args):
        for n in names:
            if a == n and i + 1 < len(args):
                out.append(args[i + 1])
            elif n.startswith("--") and a.startswith(n + "="):
                out.append(a[len(n) + 1 :])
            elif not n.startswith("--") and a.startswith(n) and len(a) > len(n):
                out.append(a[len(n) :])
    return out


def _carries(args: list[str], subs: list[str], depth: int) -> str:
    """Why a sender's arguments carry read data ("" when they do not): a $(...) that reads, a non-plain $VAR."""
    skip = {i + 1 for i, a in enumerate(args) if a in _OUT_OPTS} | {i for i, a in enumerate(args) if a.startswith(tuple(o + "=" for o in _OUT_OPTS if o.startswith("--")))}
    for i, a in enumerate(args):
        if i in skip:
            continue
        for m in re.finditer(r"__SUB(\d+)__", a):
            if _reads_cmd(subs[int(m.group(1))], depth + 1):
                return "$(read)"
        for v in _VAR.findall(a):
            if v not in PLAIN_VARS:
                return f"${v}"
    return ""


def _payload(prog: str, args: list[str]) -> str:
    """A file the sender itself reads and sends ("-" for stdin); "" for none."""
    if prog == "curl":
        for v in _opt(args, _CURL_DATA):
            if v.startswith("@"):
                return v[1:] or "-"
        for v in _opt(args, ("--data-urlencode",)):
            m = re.match(r"[\w.-]*@(.*)", v)
            if m:
                return m.group(1) or "-"
        for v in _opt(args, ("-F", "--form")):
            m = re.search(r"=[@<](.*)", v)
            if m:
                return m.group(1).split(";")[0] or "-"
        for v in _opt(args, ("-T", "--upload-file")):
            return "-" if v in ("-", ".") else v
    if prog == "wget":
        for v in _opt(args, ("--post-file", "--body-file")):
            return "-" if v in ("-", "/dev/stdin") else v
    if prog in ("scp", "rsync", "sftp"):
        pos = [a for a in args if not a.startswith("-")]
        if len(pos) >= 2 and _REMOTE.match(pos[-1]) and any(not _REMOTE.match(a) for a in pos[:-1]):
            return next(a for a in pos[:-1] if not _REMOTE.match(a))
    if prog == "socat":
        if any(re.match(r"(?i)(?:FILE|OPEN|GOPEN|EXEC|SYSTEM):", a) for a in args) and any(re.match(r"(?i)(?:TCP|UDP|OPENSSL|SSL)", a) for a in args):
            return "socat address"
    return ""


def _reads(words: list[str], subs: list[str], depth: int) -> bool:
    """Whether a stage reads a file or the environment (or a $(...) read, a non-plain $VAR, a <file)."""
    plain, ins, _ = _redirects(words)
    if any(f not in ("/dev/null",) for f in ins):
        return True
    prog, args = _program(plain)
    if prog == "set":
        return not args                       # set alone lists the variables; set -e does not
    if prog in EXFIL_READS:
        heredoc = any(w in ("<<", "<<-", "<<<") for w in words)
        return not (heredoc and not [a for a in args if not a.startswith("-")])   # cat <<EOF: literal text
    return bool(prog) and prog in ("echo", "printf") and bool(_carries(args, subs, depth))


def _reads_cmd(cmd: str, depth: int) -> bool:
    if depth > 4:
        return True
    cmd, subs = _substitutions(_script(cmd))
    pipelines = _stages(cmd)
    return pipelines is None or any(_reads(st, subs, depth) for p in pipelines for st in p)


def _exfil(cmd: str, depth: int = 0) -> str:
    if depth > 4:
        return "nesting"
    cmd, subs = _substitutions(_script(cmd))
    pipelines = _stages(cmd)
    if pipelines is None:
        return ""
    net_dev = re.search(r"/dev/(?:tcp|udp)/", cmd)
    any_read = False
    for pipe in pipelines:
        upstream = ""
        for st in pipe:
            plain, ins, outs = _redirects(st)
            prog, args = _program(plain)
            if prog in SHELLS or prog == "eval":
                at = next((i for i, a in enumerate(args) if re.fullmatch(r"-[a-z]*c[a-z]*", a)), None)
                script = ([args[at + 1]] if at is not None and at + 1 < len(args) else []) if prog in SHELLS else [" ".join(args)]
                for sc in script:
                    for i, sub in enumerate(subs):
                        sc = sc.replace(f"__SUB{i}__", f"$({sub})")
                    why = _exfil(sc, depth + 1)
                    if why:
                        return why
            reads = _reads(st, subs, depth)
            any_read = any_read or reads
            if net_dev and any(re.match(r"/dev/(?:tcp|udp)/", o) for o in outs) and (reads or upstream):
                return f"{prog or upstream} > /dev/tcp"
            if prog in EXFIL_SENDERS:
                if upstream:
                    return f"{upstream} | {prog}"
                if ins and any(f != "/dev/null" for f in ins):
                    return f"{prog} < file"
                why = _carries(args, subs, depth)
                if why:
                    return f"{prog} {why}"
                pay = _payload(prog, args)
                if pay and pay != "-":
                    return f"{prog} {pay}"
            if reads and not upstream:
                upstream = prog or "<file"
    if net_dev and any_read:
        return "/dev/tcp"
    return ""


def shell_exfil(arguments: str) -> Rule | None:
    """The exfil.shell rule a shell tool call breaks, if any."""
    cmd = _command(arguments)
    why = _exfil(cmd) if cmd.strip() else ""
    return Rule("exfil.shell", "block", why) if why else None


def content_signals(text: str) -> tuple[str, ...]:
    """The content rules a text breaks (names), plus the unicode and header rules
    that mark hidden or spoofed text: what can corroborate a model hit."""
    out = [name for name, rx in _CONTENT.items() if rx.search(text)]
    if any(ord(ch) in TAGS for ch in text):
        out.append("unicode.tags")
    if any(ord(ch) in BIDI for ch in text):
        out.append("unicode.bidi")
    if any(ord(ch) in INVISIBLE or ord(ch) in VARIATION_SUPPLEMENT for ch in text):
        out.append("unicode.invisible")
    if scenes.neutralise(text)[1]:
        out.append("scene.header_spoof")
    return tuple(out)


def check(stage: str, text: str, canaries: tuple[str, ...] = (), secrets: bool = True, exfil: bool = True) -> Checked:
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
    if stage in ("tool_result", "user_message"):
        rules += [Rule(name, "flag") for name, rx in _CONTENT.items() if rx.search(text)]
    if stage == "tool_call":
        for c in canaries:
            if c and c in text:
                rules.append(Rule("canary.leak", "block", "a canary token in the arguments"))
                break
        hit = secret_access(text) if secrets else None
        if hit:
            rules.append(hit)
        hit = shell_exfil(text) if exfil else None
        if hit:
            rules.append(hit)
    return Checked(text, tuple(rules))
