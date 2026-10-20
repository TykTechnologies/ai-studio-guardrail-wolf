# Deploying

Two shapes, the same service:

- **CPU, next to the gateway** (`tykio/ai-studio-guardrail-wolf`): a Unix socket
  shared with AI Studio and the microgateway, no network. Good for shadow
  rollouts and short content; long tool results take seconds (see
  [BENCHMARKS.md](BENCHMARKS.md)), which deferred enforcement absorbs.
- **GPU, over HTTPS** (`tykio/ai-studio-guardrail-wolf-gpu`): any NVIDIA host
  (driver 560 or later), for example a Runpod pod, behind a TLS proxy, with
  the bearer token and a client-IP allowlist. Every stage fits an inline
  budget.

Pin images by digest, never by a moving tag.

## CPU, next to the gateway

[examples/compose.yaml](../examples/compose.yaml) adds the guardrail to an AI
Studio compose project:

1. Create the token: `openssl rand -base64 32` into an env file read only by
   the guardrail (`WOLFGUARD_TOKEN`), and the same value as the Studio
   secret `WOLFGUARD_TOKEN`.
2. Create the state directory for the decision log and the verdict store,
   owned by uid 10001 group 65532: `install -d -o 10001 -g 65532 -m 0750 wolfguard-state`.
3. Mount the socket volume at `/run/wolfguard` in AI Studio and the
   microgateway, and set `GUARDRAIL_UNIX_SOCKET_ALLOWLIST=/run/wolfguard/` on
   both.
4. `docker compose up -d`; the guardrail is healthy in about 20–60 seconds
   (loading the model and scoring one scene per stage).
5. Create the filters ([AI-STUDIO-FILTERS.md](AI-STUDIO-FILTERS.md)), shadow
   first.

Give it 4 CPUs and 4 GB: one large worker with 4 threads and one small
worker. Fewer CPUs are markedly slower; less memory can kill the second
worker while it loads.

## GPU, any host

```bash
docker run -d --gpus all -p 127.0.0.1:8000:8000 -v wolfguard-state:/workspace \
  -e WOLFGUARD_TOKEN=... -e WOLFGUARD_ALLOW_IPS=<gateway egress IPs> \
  tykio/ai-studio-guardrail-wolf-gpu@sha256:<digest>
```

Put a TLS proxy in front (the HTTP provider trusts public certificates
only), and point the filters at `https://<host>/v1/classify?policy=<version>`.
If the proxy hides the client's address, set `WOLFGUARD_CLIENT_IP_HEADER` to
a header it sets and clients cannot, and `WOLFGUARD_TRUSTED_PROXIES` to the
proxy's own addresses.

The image starts as root only to hand `/workspace/wolfguard` (the store, the
decision log, the previews) to uid 10001, then runs as 10001 with no
capabilities. `WOLFGUARD_POLICY_YAML_B64` (a base64 policy) replaces the
image's default policy.

## GPU on Runpod

[deploy/runpod/create_pod.sh](../deploy/runpod/create_pod.sh) creates a pod in
Secure Cloud:

1. In the Runpod console, Settings → Secrets: create `wolfguard_token` with the
   bearer token (the script references it; it never passes on a command line).
2. ```bash
   IMAGE=tykio/ai-studio-guardrail-wolf-gpu@sha256:<digest> \
   ALLOW_IPS=<your gateway hosts' egress IPv4s, as /32s> \
   POLICY=config/policy.yaml \
     deploy/runpod/create_pod.sh
   ```
   It tries an RTX A4000, A4500, A5000 and 4000 Ada in that order (override
   with `GPUS`, `DATACENTERS`), with a 20 GB volume at `/workspace`, port 8000
   behind Runpod's HTTPS proxy, and no SSH.
3. Point the filters at `https://<pod id>-8000.proxy.runpod.net/v1/classify?policy=<version>`.
4. Check: `/readyz` from the gateway host is `{"ready": true, ...}`; from any
   other address every path is 403.

Behind Runpod's proxy (Cloudflare) the client address is `cf-connecting-ip`
from the proxy range `100.64.0.0/10`, which the script sets. Do not use
`X-Forwarded-For` there: the proxy keeps the client's own value as its first
entry. Cloudflare also refuses some default client user agents (Python's
`urllib`); AI Studio's Go client passes.

Find a gateway host's egress address with `curl -4 https://api.ipify.org`
on it; a floating or reserved IP is usually inbound only.

There is no shell into the pod: the verdict store's operations are
`GET /v1/admin/flags`, `GET /v1/admin/stats`, `POST /v1/admin/allow` and
`POST /v1/admin/unallow`, with the token, from an allowed address. A policy
change is a pod environment edit (the pod restarts) plus the filters'
`?policy=` bump.

Without a CPU fallback, a pod outage is a guardrail outage: alert on
`aistudio_guardrail_errors_total`, and either switch the filters to `log` or
point them at a CPU guardrail on the gateway host until the pod is back.

## Operating it

- **Metrics** (`/metrics`, bearer): `wolfguard_decisions_total{stage,app,tool,decision}`,
  `wolfguard_latency_seconds`, `wolfguard_rejected_total{code,reason}` (413
  too large, 503 saturated, 499 abandoned), `wolfguard_skipped_total`,
  `wolfguard_store_total`, `wolfguard_deferred_total` (`dropped`: content
  left unscored until it is sent again), `wolfguard_busy_total`,
  `wolfguard_denied_total`, `wolfguard_policy_invalid`,
  `wolfguard_policy_version_mismatch_total`. On the gateway:
  `aistudio_guardrail_latency_seconds`, `aistudio_guardrail_errors_total`,
  `aistudio_guardrail_shadow_dropped_total`.
- **Alert on** 503s, busy items, dropped deferred scoring, a rise in gateway
  guardrail errors, an invalid policy, and every user-message flag while you
  tune.
- **Logs.** Rotate `decisions.jsonl` and `previews.jsonl` (for example 30 and
  7 days, `copytruncate`). Never rotate or truncate the verdict store
  (`verdicts.db`, SQLite); it expires its own rows.
- **Policy rollout.** Edit the policy and bump `version`; it hot-reloads
  within 2 seconds (an invalid file is refused and the last good one kept).
  Bump the filters' `?policy=` too.
