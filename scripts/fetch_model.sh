#!/bin/sh
# Fetch Wolf Defender Jev at the pinned revision into models/jev-<rev>/ and
# verify it against vendor/wolf_defender_jev/REVISION.md.
#   scripts/fetch_model.sh [python]   (python with huggingface_hub; default .venv/bin/python)
set -eu
REV=5ed7c44d8ee16b0c517952ad58e264e00ec7bbac
HERE="$(cd "$(dirname "$0")/.." && pwd)"
PY="${1:-$HERE/.venv/bin/python}"
DEST="$HERE/models/jev-5ed7c44d"
mkdir -p "$DEST"
"$PY" -I -c "
from huggingface_hub import snapshot_download
snapshot_download('patronus-studio/wolf-defender-jev', revision='$REV', local_dir='$DEST',
    allow_patterns=['LICENSE','README.md','config.json','encoder/config.json','model.safetensors','special_tokens_map.json',
                    'tokenizer.json','tokenizer_config.json','wolf_defender_jev.py','wolf_defender_jev_onnx.py',
                    'onnx/onnx_fp32/*','onnx/quantization_manifest.json'])
"
# Verify every digest listed in REVISION.md.
grep -E '^\| `[^`]+` \| `[0-9a-f]{64}` \|$' "$HERE/vendor/wolf_defender_jev/REVISION.md" | while read -r line; do
  f=$(echo "$line" | cut -d'`' -f2)
  want=$(echo "$line" | cut -d'`' -f4)
  case "$f" in wolf_defender_jev*.py) path="$HERE/vendor/wolf_defender_jev/$f";; *) path="$DEST/$f";; esac
  got=$(shasum -a 256 "$path" | cut -d' ' -f1)
  [ "$got" = "$want" ] || { echo "digest mismatch: $f"; exit 1; }
done
echo "model at $DEST, digests verified"
