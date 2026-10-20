# ai-studio-guardrail-wolf

A prompt-injection guardrail for [Tyk AI Studio](https://github.com/TykTechnologies/ai-studio)
2.3 and later. It runs [Patronus AI's Wolf Defender Jev](https://huggingface.co/patronus-studio/wolf-defender-jev)
behind AI Studio's **HTTP guardrail provider** (Enterprise) and scores what an
agent's traffic carries:

| Stage | What is scored | Typical action |
|---|---|---|
| `tool_result` | what a tool returned (a file, a page, a command's output), read as untrusted content | quarantine the result, or stop the conversation |
| `tool_call` | the arguments of a call the model wants to run, judged against the user's goal | block the call before the client runs it |
| `user_message` | the user's own text, or a bot runner's prompt around untrusted text | block |
| `tool_definition` | a tool's description and schema (poisoned MCP tools) | remove the tool |

Each stage reports graded detectors (`<stage>.review`, `<stage>.block`,
`<stage>.critical`) and AI Studio filters choose which to act on and how.

Images (public, with SBOM and build-provenance attestations; pin them by digest):

- **`tykio/ai-studio-guardrail-wolf`** (CPU, linux/amd64 and arm64): next to the
  gateway on a Unix socket, with no network, read-only, non-root.
- **`tykio/ai-studio-guardrail-wolf-gpu`** (NVIDIA, CUDA 12.6, linux/amd64): the same
  service on a GPU host, for example a Runpod pod, reached over HTTPS with a
  bearer token and a client-IP allowlist. About 20 ms for a short message and
  0.3 s for a 6,000-token tool result on an NVIDIA A40.

## What it adds beyond the model

- **Rules decided without the model.** A tool call that reads credentials
  (`/proc/*/environ`, `.env`, `~/.ssh`, cloud credential files, secret
  environment variables) or carries a planted canary token is critical at
  once, whatever the tool is called. Hidden text (Unicode tag characters,
  bidirectional controls, spoofed scene headers) is revealed to the model and
  flagged.
- **Deferred enforcement for agents.** Agents resend their whole history on
  every request. With the verdict store on, content the guardrail has not
  seen is answered at once and scored in the background; the next request
  that carries a flagged tool result is stopped, and so is every later one in
  that conversation. User messages and shell, execute, write and edit calls
  are scored inline. False flags are lifted by hash.
- **Windows, not truncation.** Long content is scored in 512-token windows
  (64 overlapping), all windows and questions batched, the riskiest window
  deciding.
- **Policy as code.** Thresholds, question sets, per-app system context,
  per-stage modes and kill switches live in a versioned YAML policy that is
  hot-reloaded.
- **Logs without content.** The decision log records hashes, sizes and
  scores; optional previews of flagged text have secrets masked before they
  are written.

## Quick start (CPU, next to AI Studio)

```bash
docker run -d --name wolfguard --network none --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges:true --cpus 4 --memory 4g \
  -e WOLFGUARD_TOKEN="$(openssl rand -base64 32)" \
  -v wolfguard-sock:/run/wolfguard tykio/ai-studio-guardrail-wolf:<version>
```

Mount the `wolfguard-sock` volume into AI Studio and the microgateway at
`/run/wolfguard`, set `GUARDRAIL_UNIX_SOCKET_ALLOWLIST=/run/wolfguard/` on
both, store the token as a Studio secret, and create the filters in
[docs/AI-STUDIO-FILTERS.md](docs/AI-STUDIO-FILTERS.md). A full compose example
is in [examples/compose.yaml](examples/compose.yaml); GPU and Runpod
deployment in [docs/DEPLOY.md](docs/DEPLOY.md).

Start in **shadow** (log-only) and review the decisions before enforcing
anything: thresholds should be tuned on your own traffic.

## Documentation

| | |
|---|---|
| **AI Studio guide** | step by step in AI Studio: **Wolf Defender guardrail** in the [AI Studio documentation](https://github.com/TykTechnologies/ai-studio/blob/main/docs/site/docs/guardrails-wolf-defender.md) (deploying, the secret, every filter field, testing, tuning, enforcing, operating, troubleshooting) |
| [docs/REFERENCE.md](docs/REFERENCE.md) | every policy field, environment variable, endpoint, metric and decision-log field |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | the contract, stages and questions, decisions, enforcement modes, security model |
| [docs/AI-STUDIO-FILTERS.md](docs/AI-STUDIO-FILTERS.md) | AI Studio filter configuration for shadow and enforcement |
| [docs/DEPLOY.md](docs/DEPLOY.md) | the CPU sidecar, a GPU host, Runpod, operations |
| [docs/IMAGE.md](docs/IMAGE.md) | what is in the images and how they run |
| [docs/BENCHMARKS.md](docs/BENCHMARKS.md) | latency on CPU and GPU, accuracy on the eval sets |
| [config/policy.yaml](config/policy.yaml) | the default policy, every field commented |

## Development

```bash
uv venv .venv --python 3.12 && uv pip install --python .venv/bin/python -e '.[model,dev]' fastapi uvicorn prometheus-client httpx
make model test             # fetch the pinned weights; unit tests (stub model)
make test-integration       # against the real model
make image image-gpu        # the CPU and GPU images
```

## Licence

MIT (see [LICENSE](LICENSE)). The model and its vendored inference code are
MIT, Copyright Patronus Protect; see [NOTICE.md](NOTICE.md).
