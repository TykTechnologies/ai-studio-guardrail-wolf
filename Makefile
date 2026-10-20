# wolf-guard-sidecar
IMAGE        ?= wolf-guard-sidecar
TAG          ?= dev
GIT_REVISION ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null || echo unknown)
POLICY_VERSION ?= $(shell python3 -c "import yaml;print(yaml.safe_load(open('config/policy.yaml'))['version'])" 2>/dev/null || echo unknown)
# Reproducible builds: fixed timestamps from the last commit.
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null || echo 0)
TRIVY_IMAGE  ?= aquasec/trivy:0.58.1
SYFT_IMAGE   ?= anchore/syft:v1.18.1
PY           ?= .venv/bin/python
BUILD_ARGS    = --build-arg GIT_REVISION=$(GIT_REVISION) --build-arg POLICY_VERSION=$(POLICY_VERSION) --build-arg SOURCE_DATE_EPOCH=$(SOURCE_DATE_EPOCH)

.PHONY: test test-integration image image-multi image-gpu image-check scan sbom lock lock-gpu model

test:
	$(PY) -m pytest -q tests

test-integration:
	WOLFGUARD_INTEGRATION=1 $(PY) -m pytest -q tests/test_jev_integration.py

model:
	scripts/fetch_model.sh $(PY)

lock:
	uv pip compile image/requirements.in --python-version 3.12 --python-platform x86_64-manylinux_2_28 --generate-hashes \
	  --index-url https://pypi.org/simple --extra-index-url https://download.pytorch.org/whl/cpu --index-strategy unsafe-best-match \
	  --no-header -o image/requirements.lock

# The host architecture, loaded into the local docker.
image:
	docker buildx build $(BUILD_ARGS) --load -t $(IMAGE):$(TAG) .

# Both architectures, as an OCI archive with rewritten timestamps (reproducible).
image-multi:
	mkdir -p out
	docker buildx build $(BUILD_ARGS) --platform linux/amd64,linux/arm64 \
	  --output type=oci,dest=out/$(IMAGE)-$(TAG).oci.tar,rewrite-timestamp=true .

# NVIDIA GPU (linux/amd64, CUDA 12.6 torch): TCP 8000 on all interfaces, the store and logs under
# WOLFGUARD_STATE_DIR (a Runpod pod's /workspace volume); starts as root only to hand that directory
# to uid 10001, then drops to it (image/entrypoint.sh).
image-gpu:
	docker buildx build $(BUILD_ARGS) --platform linux/amd64 --load -t $(IMAGE):$(TAG)-gpu \
	  --build-arg VARIANT=gpu --build-arg LOCK=image/requirements-gpu.lock --build-arg TORCH_INDEX=https://download.pytorch.org/whl/cu126 \
	  --build-arg IMAGE_USER=0:0 --build-arg WG_DEVICE=cuda --build-arg WG_SOCKET= --build-arg WG_HOST=0.0.0.0 --build-arg WG_PORT=8000 \
	  --build-arg WG_LARGE_WORKERS=2 --build-arg WG_STATE_DIR=/workspace/wolfguard .

lock-gpu:
	uv pip compile image/requirements-gpu.in --python-version 3.12 --python-platform x86_64-manylinux_2_28 --generate-hashes \
	  --index-url https://pypi.org/simple --extra-index-url https://download.pytorch.org/whl/cu126 --index-strategy unsafe-best-match \
	  --no-header -o image/requirements-gpu.lock

# The hardened run: non-root, read-only, no capabilities, no network.
image-check:
	./image/check.sh $(IMAGE):$(TAG)

scan:
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock $(TRIVY_IMAGE) image --scanners vuln \
	  --severity CRITICAL,HIGH --ignore-unfixed --exit-code 1 $(IMAGE):$(TAG)

sbom:
	mkdir -p out
	docker run --rm -v /var/run/docker.sock:/var/run/docker.sock $(SYFT_IMAGE) $(IMAGE):$(TAG) -o spdx-json > out/$(IMAGE)-$(TAG).spdx.json
	@echo "SBOM: out/$(IMAGE)-$(TAG).spdx.json"
