#!/usr/bin/env bash
# The sidecar alone on this docker host, under the limits of a hardened deployment.
#
#   bench/x86.sh IMAGE [CPUS] [MEM]        # e.g. bench/x86.sh wolf-guard-sidecar@sha256:... 4 4g
#
# Runs the image hardened (no network, read-only, non-root, no
# capabilities) with a socket in a throwaway volume, then the client
# (bench/sidecar_bench.py, standard library only) in a second container of
# the same image on that volume. Prints the client's JSON and the host's CPU
# model; removes both containers and the volume. Nothing else on the host is
# touched, but the run does use CPUS cores for several minutes: on a shared
# host, run it in a quiet hour.
set -euo pipefail
IMAGE=${1:?usage: bench/x86.sh IMAGE [CPUS] [MEM]}
CPUS=${2:-4}
MEM=${3:-4g}
HERE=$(cd "$(dirname "$0")" && pwd)
RUN=wgbench-$$
WORK=$(mktemp -d)
trap 'docker rm -f "$RUN" "$RUN-client" >/dev/null 2>&1 || true; docker volume rm "$RUN-sock" >/dev/null 2>&1 || true; rm -rf "$WORK"' EXIT

head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$WORK/token"
chmod 644 "$WORK/token"
docker volume create "$RUN-sock" >/dev/null
docker run -d --name "$RUN" --network none --read-only --tmpfs /tmp:rw,noexec,nosuid,size=256m \
  --cap-drop ALL --security-opt no-new-privileges:true --cpus "$CPUS" --memory "$MEM" \
  -e WOLFGUARD_TOKEN_FILE=/run/secrets/wolfguard_token -e WOLFGUARD_DECISION_LOG=/tmp/decisions.jsonl \
  -v "$RUN-sock":/run/wolfguard -v "$WORK/token":/run/secrets/wolfguard_token:ro "$IMAGE" >/dev/null

echo "waiting for the sidecar to be ready..." >&2
for _ in $(seq 1 90); do
  [ "$(docker inspect -f '{{.State.Health.Status}}' "$RUN")" = healthy ] && break
  sleep 2
done
[ "$(docker inspect -f '{{.State.Health.Status}}' "$RUN")" = healthy ] || { docker logs "$RUN" | tail -20 >&2; exit 1; }

{
  echo "# host: $(uname -m), $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2- || sysctl -n machdep.cpu.brand_string), $(nproc 2>/dev/null || sysctl -n hw.ncpu) CPUs; sidecar --cpus $CPUS --memory $MEM"
  docker run --rm -i --name "$RUN-client" --network none --entrypoint python -v "$RUN-sock":/run/wolfguard -v "$WORK/token":/run/secrets/wolfguard_token:ro \
    "$IMAGE" -I - --socket /run/wolfguard/wolfguard.sock --token-file /run/secrets/wolfguard_token < "$HERE/sidecar_bench.py"
  echo "# sidecar memory: $(docker stats --no-stream --format '{{.MemUsage}}' "$RUN")"
}
