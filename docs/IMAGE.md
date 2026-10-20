# The images

```bash
make image            # CPU, host architecture, loaded into docker as wolf-guard-sidecar:dev
make image-multi      # CPU, linux/amd64 + linux/arm64, OCI archive (rewritten timestamps) in out/
make image-gpu        # GPU (CUDA 12.6 torch), linux/amd64
make image-check      # the hardened run: non-root, read-only, no capabilities, no network; waits for /readyz and scores one request
make scan             # trivy: fails on fixable HIGH/CRITICAL
make sbom             # syft: SPDX JSON in out/
```

## What's in them

- `python:3.12-slim`, pinned by digest (`Dockerfile`, `PYTHON_IMAGE`).
- Dependencies from a hash-pinned lock, binary wheels only:
  `image/requirements.lock` (CPU torch `2.14.1+cpu`) or
  `image/requirements-gpu.lock` (`2.14.1+cu126`, the same torch; NVIDIA
  drivers 560 or later). Regenerate with `make lock` / `make lock-gpu`. The
  build fails unless torch, transformers and fastapi import.
- Wolf Defender Jev at revision `5ed7c44d…`, fetched at build time with the
  standard library and checked file by file against
  `vendor/wolf_defender_jev/SHA256SUMS`. A Hugging Face token, if ever
  needed, is a BuildKit secret (`--secret id=hf_token`) and never reaches a
  layer.
- The vendored inference code (unmodified, MIT), the default policy at
  `/etc/wolfguard/policy.yaml`, and the licences under
  `/usr/share/doc/wolfguard/`.
- OCI labels: source, git revision, model id and revision, policy version,
  variant.
- Offline at runtime: `HF_HUB_OFFLINE=1`, `TRANSFORMERS_OFFLINE=1`.

## How the CPU image runs

- **User:** uid 10001, primary group 65532, the group of the distroless AI
  Studio and microgateway images. The socket `/run/wolfguard/wolfguard.sock`
  is created **0660** with that group, so the gateway (uid/gid 65532) can use
  it and nothing else can. `/run/wolfguard` is the only writable path
  besides a tmpfs `/tmp` and the state directory.
- **Workers:** one large worker with 4 torch threads and one small worker
  (`WOLFGUARD_LARGE_WORKERS`, `WOLFGUARD_THREADS`, `WOLFGUARD_SMALL_*`). A call
  with at most `WOLFGUARD_SMALL_CHARS` (1,500) characters to score takes the
  small worker. Workers load the model one at a time, and warm-up runs before
  `/readyz`.
- **Queue:** per lane, at most `WOLFGUARD_QUEUE_MAX` (32) calls wait, each for
  at most `WOLFGUARD_QUEUE_WAIT` (20) seconds; beyond either a call gets 503.
  Under an enforcing filter keep the wait below the filter's `timeout_ms`.
  Background (deferred) scoring has its own queue behind inline calls
  (`WOLFGUARD_BG_QUEUE_MAX` 256, `WOLFGUARD_BG_QUEUE_WAIT` 300 s).
- **Verdict store:** `WOLFGUARD_STORE` (a SQLite path; or set
  `WOLFGUARD_STATE_DIR` for the store and the logs together). It turns on
  the policy's deferred stages; without it every stage is inline. Flags are
  kept `WOLFGUARD_FLAGGED_TTL` (7 days), clean verdicts `WOLFGUARD_CLEAN_TTL`
  (24 hours).
- **Health:** `HEALTHCHECK` runs `python -m wolfguard.healthcheck` against
  `/readyz`.
- **Token:** `WOLFGUARD_TOKEN` or `WOLFGUARD_TOKEN_FILE`; without one the
  service does not start.

## How the GPU image differs

- **TCP 8000 on all interfaces**, no socket, for a host reached over HTTPS.
  Protect it with the token and the **client-IP allowlist**:
  `WOLFGUARD_ALLOW_IPS` (addresses or CIDRs), and behind a proxy
  `WOLFGUARD_CLIENT_IP_HEADER` and `WOLFGUARD_TRUSTED_PROXIES`. The allowlist
  is checked before the token; the container's own health check on loopback
  passes.
- **`WOLFGUARD_DEVICE=cuda`**, fp32 with TF32 off (its scores match the CPU
  image's; `bench/parity.py`), two large workers.
- **State on a volume:** `WOLFGUARD_STATE_DIR=/workspace/wolfguard`. The image
  starts as root only to create that directory and hand it to uid 10001,
  then drops to 10001 with no capabilities and `no_new_privs`
  (`image/entrypoint.sh`). On a volume that refuses `chown` even to root
  (Runpod's `/workspace` is NFS), the directory is left writable instead,
  and the entrypoint checks that 10001 can write there before starting. On a
  network filesystem the verdict store uses SQLite's rollback journal.
- **Policy from the environment:** `WOLFGUARD_POLICY_YAML_B64`.

## Measured

| | |
|---|---|
| CPU image | 2.7 GB uncompressed; about 2.1 GiB of memory once running (two workers); ready in about 20 s on an arm64 laptop |
| GPU image | 4.4 GB uncompressed (linux/amd64); 2.4 GB of GPU memory |
| Vulnerabilities (trivy, fixable HIGH/CRITICAL) | none at release |
| Secrets in layers (trivy secret scanner) | none |
