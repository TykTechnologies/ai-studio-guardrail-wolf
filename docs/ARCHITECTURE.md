# Architecture

## The contract

AI Studio's HTTP guardrail provider (Enterprise, 2.3+) sends one JSON call
per batch of text and reads findings back:

```json
POST /v1/classify
{"direction": "request" | "response",
 "detectors": ["tool_result.block", "user_message.block"], "redact": false,
 "segments": [{"index": 0, "role": "tool", "kind": "tool_result",
               "tool_name": "shell", "tool_call_id": "call_1", "text": "..."}],
 "meta": {"vendor": "openai", "model": "gpt-4.1", "llm_id": 7, "app_id": 3, "request_id": ""}}
→ 200 {"flagged": true, "findings": [{"detector": "tool_result.block", "category": "injection",
        "label": "injection.indirect_presence", "score": 0.98, "severity": "critical", "segment_index": 0}]}
```

What the gateway sends, and what that means here:

- **Segment kinds.** Plain text has no `kind` (`role` `user`, `system` or
  `assistant`); `tool_result` (`role` `tool`, with `tool_name` and
  `tool_call_id`); `tool_call` (the arguments as JSON, with
  `context.user_goal` and, when configured, `context.system`); and
  `tool_definition` (the definition's raw JSON). A JSON tool result, call or
  definition also arrives as a second segment of the same kind with its
  strings decoded (`key\nvalue`); a finding on either flags the unit.
- **Trust classes.** The user's own text, tool results, tool calls and tool
  definitions never share a call, and calls for one request arrive
  concurrently.
- **Pieces.** A segment over 32,768 characters arrives as pieces with
  1,024-character overlaps; a call carries at most 32,768 characters, so a
  history of short segments can arrive as one call of hundreds of segments.
- **Errors.** The gateway reads 400, 413 and 422 as *input rejected*: the
  text is unscanned and gets the filter's action whatever its fail mode.
  Timeouts and 5xx are provider failures, decided by the fail mode for small
  requests; in requests over the filter's `single_call_chars` the unscanned
  text gets the action too.
- **The gateway's verdict cache** keys a verdict on the filter's version and
  config, the segment and the tenant, for 10 minutes. With deferred
  enforcement (below) it must be off (`"cache": false`): it would keep the
  first "not scored yet" answer.
- **Response calls** carry `app_id` 0, so verdicts are scoped to the LLM there.

## Scoring

The model reads a *scene* (tagged blocks: the content, labelled untrusted
where it is, plus the stage's context) and a question, and returns
calibrated option probabilities. Each stage asks its own questions
(`config/policy.yaml`):

| Stage | Scene | Questions (the attack side) |
|---|---|---|
| `tool_result` | the output in a `TOOL OUTPUT … untrusted` block, with a name-only tool call | `injection.indirect_presence` (yes), `content.role` (command) |
| `tool_call` | the proposed action (a plain description of the tool plus the arguments), the user's goal | `action.alignment` (misaligned), `exfiltration.presence` (yes), `action.reversibility` (hard, irreversible) |
| `user_message` | the message, with the app's system context | `manipulation.any`, `jailbreak.presence`, `prompt_leak.attempt`; pasted content (fenced or long) is also scored as untrusted |
| `tool_definition` | the definition | `tool_metadata.poisoning` |

- **Windows.** Content is cut into 512-token windows with 64 overlapping;
  every window and question of a call goes through the model in batched
  forwards, and per question the riskiest window decides. Windows are both
  cheaper than whole long texts and better separated: long benign texts
  score lower as windows, injections do not.
- **Decisions.** Per question, `review` and `block` thresholds (and
  optionally `critical`). A stage decides `block` when its deciding
  questions reach `block` (`block_when: all` requires every one, which
  roughly halves false blocks on tool results), `critical` when those with a
  `critical` threshold all reach it, `review` when any reaches `review`.
- **Untrusted user messages.** A bot's "user" turn is often its runner's
  prompt wrapped around untrusted text (an issue, a pull request, a
  comment); the user-message questions read the runner's instruction as
  manipulation. Per app, `user_messages: untrusted` scores such a message
  with the tool-result questions in a `TOOL OUTPUT` block labelled
  `untrusted_source`, and only the critical tier blocks.
- **Pre-checks** run before the model on every segment: bidirectional
  controls, invisible characters, Unicode tag characters (their hidden text
  is revealed to the model) and spoofed scene headers are flagged. On tool
  calls, canary tokens and **secret access** (`/proc/*/environ`, `.env`,
  `~/.ssh`, cloud credential files, `$GITHUB_TOKEN`-style variables, `env`,
  `printenv`) are critical without the model.

## Findings

One finding per segment decided `review`, `block` or `critical`, never for
clean text. The detector is `<stage>.<level>`: the highest level the filter's
detectors name that the segment reaches. A filter naming `tool_result.block`
acts on block and critical segments; one naming `tool_result.critical` only
on critical ones. Two filters in order (critical: block the request; block:
quarantine the result) split the tiers. A filter naming none of these
detectors gets every finding.

The thresholds live in the policy; set every Studio detector's `threshold`
to `0.01`, since the gateway drops findings below a detector's threshold.

## Enforcement modes

Per stage (`enforcement` in the policy; per app overrides):

- **inline**: scored before the call is answered.
- **deferred**: content the sidecar has not seen is answered clean at once
  and scored in the background, at a lower priority than inline calls. Its
  verdict lands in the **verdict store** (SQLite; flags kept 7 days, clean
  verdicts 24 hours, keyed by the policy version, the tenant, the stage, the
  tool and the text). An agent's next request resends the content in its
  history and gets the stored verdict: a flagged tool result stops that
  request and every later one in the conversation. A request whose content
  an earlier call is still scoring waits `pending_wait` seconds for it.
  `inline_tools` keeps chosen tool calls inline (by default `shell`, `bash`,
  `execute`, `write`, `edit`), and a call that trips the secret-access rule
  is always decided inline.
- **when_busy**: what an item gets when it cannot be scored in time (queue
  full, no worker): `error` (503), `pass`, or `unscanned` (a finding at the
  top tier).

On a GPU, deferred scoring usually finishes before the request's next filter
calls, so a flagged tool result is often quarantined on its first appearance.

Without the store (`WOLFGUARD_STORE` unset) every stage is inline.

## Capacity

Two lanes of model workers behind bounded queues: **large** (long content)
and **small** (calls of at most `WOLFGUARD_SMALL_CHARS`), so a short message
never waits behind a long tool result. A call waits at most
`WOLFGUARD_QUEUE_WAIT` seconds, with at most `WOLFGUARD_QUEUE_MAX` waiting,
else 503; background scoring has its own queue behind inline calls. A queued
call whose caller has left is not scored (499). Only the stages a filter
asks for are scored, and a skipped app never waits for a worker. Workers
load the model one at a time.

## Security model

- **On the gateway's host:** a Unix socket, mode 0660, group 65532 (the
  distroless AI Studio images), no network, read-only, non-root, no
  capabilities. AI Studio only calls sockets listed in
  `GUARDRAIL_UNIX_SOCKET_ALLOWLIST`.
- **Over a network (a GPU host):** HTTPS terminated by a proxy you trust,
  the bearer token, and a **client-IP allowlist** checked before the token.
  Behind a proxy, the client address is read only from a header the proxy
  sets and clients cannot, and only from the proxy's own addresses
  (`WOLFGUARD_TRUSTED_PROXIES`). Behind Runpod's proxy (Cloudflare) that is
  `cf-connecting-ip`; `X-Forwarded-For` there keeps whatever the client sent
  as its first entry.
- **What is kept.** The decision log records hashes, sizes, scores, the
  policy and model versions, the app and the stage, never text. Previews of
  flagged segments (optional, 200 characters) have keys, tokens and
  high-entropy strings masked first, and can go to their own file for a
  shorter retention.
- **Kill switches.** In AI Studio: switch a filter to `log`, or detach it.
  In the policy (hot-reloaded within 2 seconds): skip an app, raise a
  threshold, change a stage's mode. A false flag is lifted by its text hash
  (`python -m wolfguard.store … allow <sha256>`, or `POST /v1/admin/allow`).
  A policy version bump starts the store afresh.

## Endpoints

| Path | |
|---|---|
| `POST /v1/classify` | the contract (also `/classify`) |
| `GET /readyz`, `GET /healthz` | ready once the weights are loaded, options encoded and one scene per stage scored |
| `GET /metrics` | Prometheus (bearer): decisions, latency, rejections, skips, the store, deferred scoring, busy items, allowlist denials |
| `GET /v1/admin/flags`, `GET /v1/admin/stats`, `POST /v1/admin/allow`, `POST /v1/admin/unallow` | the verdict store (bearer) |
