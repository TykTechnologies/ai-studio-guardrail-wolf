# Trusted prompt templates

An app that wraps third-party text in its own instructions (a code-review bot's
"You are reviewing this pull request..." around a diff) sends both in one user
message, and a prompt-injection classifier reads the app's own instructions as
instructions aimed at the model. AI Studio lets an administrator approve such an
app's template text once. The gateway then sends a matched message with the
approved text cut out, and the template beside it, to providers that read
templates. The sidecar is one (`wolfguard/templates.py`).

This is a false-positive control, not a security boundary. Only bytes an
administrator approved are left out, and anything that does not check out is
scored whole.

## What arrives

```json
{"index": 0, "role": "user", "text": "[app template]--- a/server.go\n...[app template]",
 "template": {"id": "pr-review", "version": 3,
              "full_text": "You are reviewing a pull request. ...",
              "exempt": [{"start": 0, "end": 812}, {"start": 1904, "end": 2310}],
              "backstop": "log", "backstop_min_score": 0.9}}
```

`text` is the **residual**: the slots in order, with `[app template]` where each
approved constant was. `exempt` are the constants' UTF-8 byte ranges in
`full_text`. `backstop` is the filter's `template_backstop` (`off`, `log` or
`enforce`; `enforce` for a message over the gateway's exemption cap).
`backstop_min_score` is optional.

## Turning it on

The gateway sends `template` to an HTTP classifier only when the filter's HTTP
connection sets `templates: "true"` (off by default). Without it the sidecar
gets plain segments: the residual as `text`, and no template; the gateway then
makes a second call with the full text for its own backstop. With it, the
sidecar does the backstop in the same call and acknowledges each segment it
handled (below).

## Backstop mode: `log` by default, `enforce` for untrusted authors

The filter's `template_backstop` defaults to `log`: what only the full text
shows is recorded, not acted on. For apps whose slots hold text from untrusted
authors (pull request text anyone on GitHub can write), set
`template_backstop: enforce`. In an evaluation on synthetic PR-review prompts
(the red-team payloads planted at the start, middle and end of slots, across
window boundaries and next to the template text; 48 attacks), the residual
caught more than the full text overall (24 against 21), but missed 2 that
scoring the full text caught; the enforced backstop recovered both (26). Under
`log` those two would only have been logged.

| Where in the slot | Full text | Residual | Residual + enforced backstop |
|---|---|---|---|
| start | 8/8 | 8/8 | 8/8 |
| middle | 4/8 | 4/8 | 5/8 |
| end | 1/8 | 0/8 | 1/8 |
| across a window boundary | 8/8 | 8/8 | 8/8 |
| right after template text | 0/8 | 4/8 | 4/8 |
| right before template text | 0/8 | 0/8 | 0/8 |

## What the sidecar does

1. **Checks the template.** The ranges must be inside `full_text`, sorted, not
   overlapping, not empty and on UTF-8 character boundaries; `backstop` must be
   one of the three modes; and `text` must be exactly `full_text` with each range
   replaced by the placeholder. Anything else fails closed: the template is
   ignored, `full_text` is scored whole as the user message (as with no template),
   and the decision log records `template.invalid` with the reason. A template on
   anything but a user message (tool output, calls, definitions) is not honoured
   either: its full text is scored.
2. **Scores the residual** with the usual windows, aggregation and same-window
   agreement, as the app scores its user messages. For an app with
   `user_messages: untrusted` (a bot whose user turn wraps third-party text) it is
   untrusted content: the tool-result questions in a `TOOL OUTPUT` block labelled
   with the app's `untrusted_source`, and only the critical tier acts. For a
   `standard` app it is a plain user message: the user-message questions, the
   pasted-content questions and their tiers. A template does not change how an
   app's messages are judged, only which bytes are scored.
3. **Backstop** (unless `off`): scores `full_text` too, with the same questions
   and tiers as the residual, over the windows that
   hold at least one byte outside the approved ranges; a window of approved text
   only is skipped. The windows are the same cut as the residual's (the
   tokenizer's character offsets tell which bytes a window holds; a backend
   without offsets scores every window). The backstop is decided on its own and
   returned as a second finding with `"backstop": true` only when it is **above**
   the residual's decision, so the same span is not counted twice. Under
   `enforce` with `backstop_min_score`, a finding scoring below it is not
   returned; under `log` it is (the gateway logs it). A `full_text` over the
   policy's `max_segment_chars` is not scored: under `enforce` that is an
   `unscanned` backstop finding, under `log` the decision log records it.
4. **Mimicry:** a slot holding any 32-byte run of an approved constant is
   flagged `template.mimicry` in the decision log; the verdict is unchanged (the
   gateway records mimicry itself).

## The acknowledgement

The gateway sends `template` only when the filter's HTTP connection sets
`templates: "true"`, and it makes its own second full-text (backstop) call for
every templated segment the service does not acknowledge. A response to a call
that carried templated segments therefore lists the ones the sidecar handled:

```json
{"flagged": true, "findings": [...], "templates_handled": [0, 3]}
```

A segment is listed when its template validated, its residual was scored and
its backstop ran, or was deliberately skipped (`backstop: "off"`), whether or
not anything was found; a verdict answered from the verdict store counts (it was
scored with the template). Not listed: a template that failed validation (its
full text was scored whole; findings on it are ordinary ones and the gateway's
own backstop call follows), and a segment not scored in this call (the stage not
asked for, the app skipped, deferred scoring still pending, no worker free). A
finding is marked `"backstop": true` only on a listed segment: the gateway
enforces backstop marks on an unlisted segment as ordinary findings. A response
to a call with no templated segment has no `templates_handled` at all.

The verdict store keys a matched message by its residual plus the template's
id, version, backstop mode, minimum score, full text and ranges, so a changed
template is scored again and a residual's verdict is never answered for the
message unmatched. Segments without a template keep their keys.

The decision log records `template` (`id@version`, `exempt_share`, the backstop
mode, the backstop's windows scored and skipped, its decision and scores, and
whether it was reported), and the `template.invalid` / `template.mimicry` flags.
No text beyond the usual preview of a flagged segment (the residual's deciding
window).
