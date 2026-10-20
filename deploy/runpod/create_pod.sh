#!/usr/bin/env bash
# Create the GPU guardrail pod on Runpod Secure Cloud (docs/DEPLOY.md).
#
#   IMAGE=tykio/ai-studio-guardrail-wolf-gpu@sha256:... \
#   ALLOW_IPS=<your gateway hosts' egress IPv4s, e.g. 203.0.113.10/32> \
#     (find one with curl -4 https://api.ipify.org on the host; a reserved or
#      floating IP is usually inbound only)
#   POLICY=config/policy.yaml \
#     deploy/runpod/create_pod.sh
#
# Before running it, in the Runpod console (Settings > Secrets) create the secret
# `wolfguard_token` holding the bearer token (openssl rand -base64 32); the same value
# goes into AI Studio as the secret WOLFGUARD_TOKEN. It is referenced here, never
# passed on the command line.
#
# The pod serves the guardrail on port 8000 behind Runpod's HTTPS proxy:
#   https://<pod id>-8000.proxy.runpod.net/v1/classify
# The service believes the client address only from Runpod's proxy range
# (100.64.0.0/10) and only in cf-connecting-ip, which Cloudflare refuses from clients;
# X-Forwarded-For is client-controlled there (docs/DEPLOY.md).
set -euo pipefail
: "${IMAGE:?IMAGE=<registry>/ai-studio-guardrail-wolf-gpu@sha256:...}"
: "${ALLOW_IPS:?ALLOW_IPS=<gateway egress IPs, comma-separated>}"
: "${POLICY:?POLICY=<the policy YAML for this deployment>}"
NAME=${NAME:-wolfguard-gpu}
GPUS=${GPUS:-"NVIDIA RTX A4000,NVIDIA RTX A4500,NVIDIA RTX A5000,NVIDIA RTX 4000 Ada Generation"}
DATACENTERS=${DATACENTERS:-"EU-SE-1,EU-RO-1,EU-CZ-1,EU-NL-1,EUR-IS-1,EUR-IS-2,EUR-NO-1"}
VOLUME_GB=${VOLUME_GB:-20}

python3 -c "import yaml,sys; yaml.safe_load(open(sys.argv[1]))" "$POLICY"   # a broken policy is refused here, not at start
policy_b64=$(base64 < "$POLICY" | tr -d '\n')
env_json=$(python3 - "$ALLOW_IPS" "$policy_b64" <<'PY'
import json, sys
print(json.dumps({
    "WOLFGUARD_TOKEN": "{{ RUNPOD_SECRET_wolfguard_token }}",
    "WOLFGUARD_ALLOW_IPS": sys.argv[1],
    "WOLFGUARD_CLIENT_IP_HEADER": "cf-connecting-ip",
    "WOLFGUARD_TRUSTED_PROXIES": "100.64.0.0/10",
    "WOLFGUARD_POLICY_YAML_B64": sys.argv[2],
    "WOLFGUARD_PREVIEW": "1",
}))
PY
)

IFS=',' read -r -a gpu_list <<< "$GPUS"
for gpu in "${gpu_list[@]}"; do
  echo "trying $gpu in $DATACENTERS ..." >&2
  if out=$(runpodctl pod create --name "$NAME" --image "$IMAGE" --gpu-id "$gpu" --cloud-type SECURE \
      --data-center-ids "$DATACENTERS" --container-disk-in-gb 30 --volume-in-gb "$VOLUME_GB" --volume-mount-path /workspace \
      --ports "8000/http" --env "$env_json" --ssh=false 2>&1) && ! grep -q '"error"' <<< "$out"; then
    id=$(python3 -c "import json,sys; print(json.loads(sys.argv[1])['id'])" "$out")
    echo "created pod $id ($gpu): https://$id-8000.proxy.runpod.net/v1/classify" >&2
    echo "$id"
    exit 0
  fi
  echo "  $(grep -o '"error":"[^"]*"' <<< "$out" | head -1)" >&2
done
echo "no GPU of [$GPUS] available in [$DATACENTERS]" >&2
exit 1
