# Changelog

## 0.2.1

A full or failing volume no longer takes the guardrail down.

- **The logs rotate by size.** `decisions.jsonl` and `previews.jsonl` rotate at
  `WOLFGUARD_LOG_MAX_MB` (default 256) into `.1` … `.<WOLFGUARD_LOG_KEEP>`
  (default 3), so together they take at most 2 GiB. Before, they grew until the
  volume was full.
- **A store or log failure no longer fails the call.** When SQLite cannot read
  or write the verdict store (`disk I/O error`, a full disk), the lookup is
  scored as a miss and the write is dropped; a log line that cannot be written is
  dropped. Before, the error failed `/v1/classify` with a 500, which a filter
  treats as unscanned. New metrics: `wolfguard_store_errors_total{op}` and
  `wolfguard_log_errors_total{log}`. While the store fails, deferred flags are
  not kept, so alert on them.

## 0.2.0

Fewer false stops on long content and on an agent's own repository, a
deterministic rule for shell exfiltration, and support for AI Studio's
trusted prompt templates. Policy keys are in [docs/REFERENCE.md](docs/REFERENCE.md).

Why: a pull-request bot's own instructions, code search over its repository
and agent tooling text (prompt templates, tool catalogs, skill docs) scored as
injection, and the false-positive rate grew with the number of windows a
segment spans. Raising thresholds does not help: those false positives score as
high as real attacks. What separates them is where the text came from, whether
the questions agree in one place, and the parts of an attack a rule can see.

### Scoring

- **Same-window agreement** (`stages.<stage>.agree: window`). With
  `block_when: all`, the deciding questions must reach a tier together in one
  window. Before, each question's riskiest window counted wherever it was, so on
  long content two unrelated peaks could make a hit.
- **Tool-source tiers** (`tool_sources`). Output of repository-local tools
  (`local`: read, search, shell, ...) reaches the critical tier only when the
  agreeing window also breaks a corroborating rule; otherwise it is `block`
  (removed, the agent goes on). Outside data, unknown tools and untrusted user
  messages keep the full tiers; `external_markers` reclassify a local result
  that carries outside data.
- **Structural corroboration.** New pre-check flags on tool results and user
  messages: `content.role_tokens` (chat-template tokens), `content.fake_tags`
  (fake system or tool-output tags), `content.hidden_comment` (an HTML comment
  addressed to the AI), and an attack's working parts (`content.override`,
  `content.addressed`, `content.conceal`, `content.secret_path`,
  `content.remote_exec`, `content.exfil_sink`). They never decide alone.
- **Read-only tool calls** (`stages.tool_call.read_only_tools`, per question
  `read_only: report`). On a call that only reads (a read-only tool, or a shell
  command made only of read-only programs such as `cat`, `grep`, `sed -n`,
  `git log`, `gh pr view`), exfiltration and reversibility are reported and do
  not decide. The default policy also logs reversibility at 0.65 instead of
  0.35.
- **Tool-definition allowlist** (`tool_definitions`). Definitions listed by
  SHA-256 are answered clean; a built-in tool whose definition changed is at
  most `review`, never removed.
- **A window-count-aware stop threshold** (`critical_by_windows`), off by
  default: injections planted in long content score just under such
  thresholds.

### Rules

- **`exfil.shell`** (`rules.shell_exfil`, on by default): a shell tool call
  that reads a file or the environment and sends it over the network (a read
  piped to `curl`/`wget`/`nc`/`ssh`, `$(cat f)` or a secret `$VAR` in a sender's
  arguments, `curl -d @file`, `-T file`, `-F x=@file`, `wget --post-file`,
  `scp f host:`, `/dev/tcp`) is critical without the model, and decided inline
  on a deferred stage. Quoting, paths, `env X=`, `sudo`, `xargs`, `sh -c`,
  `bash -c` and `eval` are seen through.
- **Multi-line commands.** The flattened tool-call shape (`command\n…\nworkdir\n…`)
  now keeps every line of a multi-line command, for the read-only test and the
  exfiltration rule.

### Trusted prompt templates

For AI Studio's approved app templates ([docs/TEMPLATES.md](docs/TEMPLATES.md)):
a user segment's `template` is validated, failing closed to scoring the full
text; the residual is scored as the app scores user messages; unless the
backstop is off, the full text is scored over the windows holding non-template
bytes and reported with `"backstop": true` when it shows more than the residual
(`backstop_min_score` honoured under enforce); the response acknowledges the
templated segments handled in `templates_handled`. Needs the filter's
connection setting `templates: "true"`.

### Logs

The decision log records each question's peak window and the deciding window
(previews now start there), the tool source, corroboration, read-only calls
and the template fields.

### Upgrading from 0.1.1

With **your own policy file, unchanged**:

- **`exfil.shell` is on**: a shell call that pipes or posts a file or the
  environment to the network is now critical. Set `rules.shell_exfil: false`
  to keep 0.1.1's behaviour.
- **Templates**: if a filter's connection sets `templates: "true"`, templated
  messages are now handled here (residual, backstop, acknowledgement) and the
  gateway stops making its second backstop call for them. A template on
  anything but a user message is not honoured: its full text is scored. Without
  the setting nothing changes.
- **Logs**: new `content.*` flags appear in `rules` on tool results and user
  messages (they decide nothing on their own), new fields appear, and previews
  of multi-window segments start at the window that decided.
- Everything else (`agree`, `tool_sources`, read-only calls, the definition
  allowlist, `critical_by_windows`) is off until your policy sets it.

With **the image's default policy** (`/etc/wolfguard/policy.yaml`, this
repository's `config/policy.yaml`), you also get, in policy version
`2026-11-02.1` (the verdict store starts afresh; update the filters'
`?policy=`):

- `agree: window` on tool results (and untrusted user messages);
- `tool_sources`: `read`, `search`, `extract`, `grep`, `glob`, `list`,
  `listFiles`, `searchFiles`, `symbols`, `shell`, `bash` and `execute` are
  local, so their uncorroborated hits are `block`, not `critical`;
- `read_only_tools` and `read_only: report` on exfiltration and
  reversibility, and reversibility's review at 0.65;
- empty `tool_definitions` lists, to fill with your agents' definitions.
