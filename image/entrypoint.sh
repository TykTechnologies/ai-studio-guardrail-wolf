#!/bin/sh
# The image's entrypoint. The service always runs as uid 10001 (gid 65532).
#
# The GPU image starts as root on hosts that mount a root-owned volume (a Runpod
# pod's /workspace): it creates WOLFGUARD_STATE_DIR there for the verdict store
# and the logs, hands it to 10001, and drops to 10001 with no capabilities
# before the service starts. The CPU image starts as 10001 and execs directly.
#
# WOLFGUARD_POLICY_YAML_B64 (a deployment's own policy, e.g. a Runpod pod's env) is
# written to $WOLFGUARD_STATE_DIR/policy.yaml at start and used instead of the
# image's; the service hot-reloads that file if it is edited in place.
set -eu
if [ "$(id -u)" = 0 ]; then
  if [ -n "${WOLFGUARD_STATE_DIR:-}" ]; then
    mkdir -p "$WOLFGUARD_STATE_DIR"
    if [ -n "${WOLFGUARD_POLICY_YAML_B64:-}" ]; then
      printf '%s' "$WOLFGUARD_POLICY_YAML_B64" | base64 -d > "$WOLFGUARD_STATE_DIR/policy.yaml"
      export WOLFGUARD_POLICY="$WOLFGUARD_STATE_DIR/policy.yaml"
    fi
    chown -R 10001:65532 "$WOLFGUARD_STATE_DIR"
    chmod 0750 "$WOLFGUARD_STATE_DIR"
  fi
  unset WOLFGUARD_POLICY_YAML_B64
  exec setpriv --reuid=10001 --regid=65532 --clear-groups --inh-caps=-all --bounding-set=-all --no-new-privs \
    python -m wolfguard.service "$@"
fi
exec python -m wolfguard.service "$@"
