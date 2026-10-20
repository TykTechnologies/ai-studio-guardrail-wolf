# syntax=docker/dockerfile:1.7
#
# The Wolf Defender Jev guardrail behind AI Studio's HTTP guardrail contract.
# Weights baked in and verified, hash-pinned dependencies, runs as uid 10001.
#
#   make image            # CPU, host architecture: a Unix socket, no network, read-only
#   make image-multi      # CPU, linux/amd64 + linux/arm64, OCI archive in out/
#   make image-gpu        # NVIDIA GPU (CUDA 12.6 torch), linux/amd64: TCP 8000 for an
#                         # owned GPU host such as a Runpod pod, reached over HTTPS
#                         # (its proxy) with the bearer token and a client-IP allowlist
#
ARG PYTHON_IMAGE=python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
ARG MODEL_REPO=patronus-studio/wolf-defender-jev
ARG MODEL_REVISION=5ed7c44d8ee16b0c517952ad58e264e00ec7bbac
# The variant: the CPU lock and PyTorch's CPU index, or the GPU lock and its CUDA 12.6 index.
ARG LOCK=image/requirements.lock
ARG TORCH_INDEX=https://download.pytorch.org/whl/cpu

# ---- weights: fetched at the pinned revision, every file's SHA-256 checked ----------------
FROM ${PYTHON_IMAGE} AS weights
ARG MODEL_REPO
ARG MODEL_REVISION
COPY image/fetch_weights.py vendor/wolf_defender_jev/SHA256SUMS /build/
RUN --mount=type=secret,id=hf_token,required=false \
    python /build/fetch_weights.py "${MODEL_REPO}" "${MODEL_REVISION}" /build/SHA256SUMS /models/jev

# ---- dependencies: hash-pinned wheels only (CPU torch) ------------------------------------
FROM ${PYTHON_IMAGE} AS deps
ARG LOCK
ARG TORCH_INDEX
COPY ${LOCK} /build/requirements.lock
RUN python -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --disable-pip-version-check --require-hashes --only-binary=:all: \
      --index-url https://pypi.org/simple --extra-index-url ${TORCH_INDEX} \
      -r /build/requirements.lock \
 && /opt/venv/bin/python -c "import torch, transformers, fastapi" \
 && { /opt/venv/bin/pip uninstall -y pip setuptools 2>/dev/null || true; }
COPY wolfguard /opt/app/wolfguard
COPY vendor /opt/app/vendor
RUN /opt/venv/bin/python -m compileall -q /opt/app /opt/venv/lib

# ---- runtime ----------------------------------------------------------------------------------
FROM ${PYTHON_IMAGE}
ARG MODEL_REPO
ARG MODEL_REVISION
ARG GIT_REVISION=unknown
ARG POLICY_VERSION=2026-10-20.2
ARG VARIANT=cpu
# Runtime defaults per variant (make image-gpu sets the GPU ones).
ARG IMAGE_USER=10001:65532
ARG WG_DEVICE=cpu
ARG WG_SOCKET=/run/wolfguard/wolfguard.sock
ARG WG_HOST=127.0.0.1
ARG WG_PORT=0
ARG WG_LARGE_WORKERS=1
ARG WG_STATE_DIR=
LABEL org.opencontainers.image.title="ai-studio-guardrail-wolf" \
      org.opencontainers.image.description="Wolf Defender Jev prompt-injection guardrail for Tyk AI Studio 2.3+ (HTTP guardrail provider; ${VARIANT})" \
      org.opencontainers.image.source="https://github.com/TykTechnologies/ai-studio-guardrail-wolf" \
      org.opencontainers.image.revision="${GIT_REVISION}" \
      org.opencontainers.image.licenses="MIT" \
      ai.tyk.wolfguard.model="${MODEL_REPO}" \
      ai.tyk.wolfguard.model-revision="${MODEL_REVISION}" \
      ai.tyk.wolfguard.policy-version="${POLICY_VERSION}" \
      ai.tyk.wolfguard.variant="${VARIANT}"

# uid 10001, primary group 65532: the group of the distroless AI Studio and
# microgateway images (uid/gid 65532), so the 0660 socket is theirs to use.
RUN groupadd --gid 65532 gateway \
 && useradd --uid 10001 --gid 65532 --no-create-home --home-dir /tmp --shell /usr/sbin/nologin wolfguard \
 && install -d -o 10001 -g 65532 -m 2770 /run/wolfguard \
 && rm -rf /var/lib/apt/lists/* /root/.cache
COPY --from=deps /opt/venv /opt/venv
COPY --from=deps /opt/app /opt/app
COPY --from=weights /models/jev /models/jev
COPY config/policy.yaml /etc/wolfguard/policy.yaml
COPY LICENSE NOTICE.md /usr/share/doc/wolfguard/
COPY vendor/wolf_defender_jev/LICENSE /usr/share/doc/wolfguard/wolf_defender_jev.LICENSE
COPY --chmod=0755 image/entrypoint.sh /usr/local/bin/wolfguard-entrypoint

ENV PATH=/opt/venv/bin:/usr/local/bin:/usr/bin:/bin \
    PYTHONPATH=/opt/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/tmp \
    HF_HOME=/tmp/hf \
    HF_HUB_OFFLINE=1 \
    TRANSFORMERS_OFFLINE=1 \
    TOKENIZERS_PARALLELISM=false \
    MALLOC_ARENA_MAX=2 \
    WOLFGUARD_MODEL=/models/jev \
    WOLFGUARD_MODEL_REVISION=${MODEL_REVISION} \
    WOLFGUARD_POLICY=/etc/wolfguard/policy.yaml \
    WOLFGUARD_DEVICE=${WG_DEVICE} \
    WOLFGUARD_SOCKET=${WG_SOCKET} \
    WOLFGUARD_SOCKET_GID=65532 \
    WOLFGUARD_HOST=${WG_HOST} \
    WOLFGUARD_PORT=${WG_PORT} \
    WOLFGUARD_STATE_DIR=${WG_STATE_DIR} \
    WOLFGUARD_LARGE_WORKERS=${WG_LARGE_WORKERS} \
    WOLFGUARD_THREADS=4 \
    WOLFGUARD_SMALL_WORKERS=1 \
    WOLFGUARD_SMALL_THREADS=1 \
    WOLFGUARD_SMALL_CHARS=1500 \
    WOLFGUARD_QUEUE_MAX=32 \
    WOLFGUARD_QUEUE_WAIT=20

USER ${IMAGE_USER}
VOLUME ["/run/wolfguard"]
HEALTHCHECK --interval=10s --timeout=5s --start-period=120s --retries=3 CMD ["python", "-m", "wolfguard.healthcheck"]
ENTRYPOINT ["/usr/local/bin/wolfguard-entrypoint"]
