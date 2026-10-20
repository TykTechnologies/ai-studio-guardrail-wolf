# AI Studio filters

The guardrail is an Enterprise **HTTP guardrail** provider. Thresholds,
question sets and each stage's enforcement mode live in the guardrail's
policy (`config/policy.yaml`); AI Studio filters choose **which decisions to
act on**, by detector name, and **how**.

| Detector | Meaning |
|---|---|
| `tool_result.critical` | a tool result both questions put at ≥ 0.95, a hard rule, or one not scored in time (`when_busy: unscanned`) |
| `tool_result.block`, `tool_result.review` | the tiers below (both ≥ 0.70; either ≥ 0.50) |
| `user_message.block`, `user_message.review` | the user's own text (for `user_messages: untrusted` apps, `block` only at the critical tier) |
| `tool_call.block`, `tool_call.review` | a tool call (in the history, or the model's response); a secret-access or canary hit is `critical` |
| `tool_definition.block`, `tool_definition.review` | a tool definition |

A filter acts on the level it names **and above**: `tool_result.block` also
gets critical segments. Set every detector's `threshold` to `0.01` (the
gateway drops findings below it; the policy holds the real thresholds).

## Common settings

- **Endpoint.** Next to the gateway: `"endpoint": "unix:///run/wolfguard/wolfguard.sock"`
  with `"path": "/v1/classify?policy=<version>"`, and
  `GUARDRAIL_UNIX_SOCKET_ALLOWLIST=/run/wolfguard/` on every node. On a GPU
  host over HTTPS: the full URL, `"endpoint": "https://<host>/v1/classify?policy=<version>"`,
  no `path`.
- **`"api_key": "$SECRET/WOLFGUARD_TOKEN"`**, a Studio secret holding the
  guardrail's bearer token.
- **`?policy=<version>`** in the URL: a policy rollout is then a filter edit
  too, and the guardrail counts calls naming another version.
- **Attach the filters to the LLM your agent uses**, ideally an LLM entry
  only that agent uses: a filter applies to every app on its LLM.
- **With deferred enforcement** (the default policy's tool results, read
  calls and tool definitions): `"cache": false` (the guardrail's verdict
  store is the cache; the gateway's would keep the first "not scored yet"
  answer for 10 minutes) and `"budget": {"max_pieces": 2000}` (the whole
  history is sent every turn and answered from the store in milliseconds; a
  long conversation passes the default 256 pieces, and pieces beyond it are
  unscanned).
- **`"timeout_ms": 30000`, `"fail_mode": "open"`**, with the guardrail's
  `WOLFGUARD_QUEUE_WAIT` below the timeout so a busy guardrail answers its
  `when_busy` first. In requests over 32,768 characters the gateway applies
  the action to unscanned text whatever the fail mode, so an outage blocks
  tool results and passes the rest of a small request.

## 1. Shadow (log only)

Everything logged in the background, traffic never delayed or changed. Run
it for a couple of weeks and review the decisions before enforcing.

```json
{
  "provider": "http",
  "connection": {"endpoint": "unix:///run/wolfguard/wolfguard.sock", "path": "/v1/classify?policy=2026-10-20.2", "api_key": "$SECRET/WOLFGUARD_TOKEN"},
  "detectors": [
    {"name": "tool_result.critical", "threshold": 0.01}, {"name": "tool_result.block", "threshold": 0.01}, {"name": "tool_result.review", "threshold": 0.01},
    {"name": "user_message.block", "threshold": 0.01}, {"name": "user_message.review", "threshold": 0.01},
    {"name": "tool_call.block", "threshold": 0.01}, {"name": "tool_call.review", "threshold": 0.01},
    {"name": "tool_definition.block", "threshold": 0.01}, {"name": "tool_definition.review", "threshold": 0.01}
  ],
  "scope": "last_user",
  "on_detect": "log",
  "tool_results": {"on_detect": "log"},
  "tool_calls": {"scan": true},
  "tool_definitions": {"scan": true},
  "shadow": true,
  "cache": false,
  "budget": {"max_pieces": 2000},
  "timeout_ms": 30000,
  "fail_mode": "open"
}
```

Add a **response** filter for the model's tool calls: the same connection,
`"response_filter": true`, detectors `tool_call.block` and `tool_call.review`,
`"tool_calls": {"scan": true}`, `"on_detect": "log"`, `"shadow": true`,
`"cache": false`, `"timeout_ms": 30000`.

Studio records every decision as a compliance event (`metadata.shadow:
true`). Because the guardrail runs its enforcement modes in shadow too, the
events show what enforcement would do, including deferred decisions landing
on a conversation's next request.

## 2. Enforce

One step at a time, with a week of decisions in between where you can.
Filters run in their attached order on an LLM: put A before B.

**Filter A: stop the conversation** (critical tool results; user messages):

```json
{
  "provider": "http",
  "connection": {"endpoint": "unix:///run/wolfguard/wolfguard.sock", "path": "/v1/classify?policy=2026-10-20.2", "api_key": "$SECRET/WOLFGUARD_TOKEN"},
  "detectors": [{"name": "tool_result.critical", "threshold": 0.01}, {"name": "user_message.block", "threshold": 0.01}],
  "scope": "last_user",
  "on_detect": "block",
  "tool_results": {"on_detect": "block"},
  "block_message": "This conversation was stopped by the security guardrail.",
  "cache": false,
  "budget": {"max_pieces": 2000},
  "timeout_ms": 30000,
  "fail_mode": "open"
}
```

**Filter B: quarantine the rest** (block-tier tool results):

```json
{
  "provider": "http",
  "connection": {"endpoint": "unix:///run/wolfguard/wolfguard.sock", "path": "/v1/classify?policy=2026-10-20.2", "api_key": "$SECRET/WOLFGUARD_TOKEN"},
  "detectors": [{"name": "tool_result.block", "threshold": 0.01}],
  "on_detect": "log",
  "tool_results": {"on_detect": "quarantine"},
  "quarantine": {"placeholder": "[content removed by policy: {{tool_name}} returned text that looked like instructions to the AI]"},
  "cache": false,
  "budget": {"max_pieces": 2000},
  "timeout_ms": 30000,
  "fail_mode": "open"
}
```

**Filter C: tool calls** (a response filter; `shell`, `bash`, `execute`,
`write` and `edit` are held and scored inline, the rest deferred):

```json
{
  "provider": "http",
  "connection": {"endpoint": "unix:///run/wolfguard/wolfguard.sock", "path": "/v1/classify?policy=2026-10-20.2", "api_key": "$SECRET/WOLFGUARD_TOKEN"},
  "detectors": [{"name": "tool_call.block", "threshold": 0.01}],
  "on_detect": "log",
  "tool_calls": {"scan": true, "on_detect": "block"},
  "cache": false,
  "timeout_ms": 30000,
  "fail_mode": "open"
}
```

Tool definitions: add `{"name": "tool_definition.block"}` to filter B with
`"tool_definitions": {"scan": true, "on_detect": "remove"}`. Keep the shadow
request filter attached for the review band.

## 3. Check what leaves in the reply

The model scores inputs. For data leaving in the model's own text, add a
response filter with AI Studio's built-in library:

```json
{"provider": "builtin", "detectors": [{"name": "secrets"}, {"name": "leak"}], "on_detect": "block"}
```

`leak` catches system-prompt disclosure markers and markdown exfiltration
links; `secrets` catches credentials and high-entropy tokens. Shadow it first.

## Kill switches

- **AI Studio, immediate:** switch a filter's actions to `log` (or set
  `"shadow": true`), or detach it.
- **One false flag:** a flagged tool result keeps stopping its conversation
  for 7 days. Lift it by the `sha256` in the decision log:
  `python -m wolfguard.store --db <store> allow <sha256> --note why` inside
  the container, or `POST /v1/admin/allow` with the token.
- **All flags:** bump the policy version (and the filters' `?policy=`).
- **The policy:** `skip` an app, raise a threshold, or change a stage's
  `mode`; hot-reloaded within 2 seconds, effective on the next request.
