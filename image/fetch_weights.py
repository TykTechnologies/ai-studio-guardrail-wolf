"""Fetch the model files at a pinned revision and verify every SHA-256 (image build stage).

    python fetch_weights.py <repo> <revision> <SHA256SUMS> <dest>

Standard library only. SHA256SUMS lines are "<sha256>  <path in the repo>".
A Hugging Face token, if one is ever needed, comes from the BuildKit secret
/run/secrets/hf_token and never reaches a layer.
"""
import hashlib
import os
import sys
import urllib.request
from pathlib import Path

repo, rev, sums, dest = sys.argv[1:5]
token = ""
if os.path.exists("/run/secrets/hf_token"):
    token = Path("/run/secrets/hf_token").read_text().strip()
for line in Path(sums).read_text().splitlines():
    if not line.strip() or line.startswith("#"):
        continue
    want, path = line.split(None, 1)
    path = path.strip()
    out = Path(dest) / path
    out.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(f"https://huggingface.co/{repo}/resolve/{rev}/{path}")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    h = hashlib.sha256()
    with urllib.request.urlopen(req, timeout=600) as r, open(out, "wb") as f:
        while chunk := r.read(1 << 20):
            h.update(chunk)
            f.write(chunk)
    if h.hexdigest() != want:
        sys.exit(f"sha256 mismatch for {path}: got {h.hexdigest()}, want {want}")
    print(f"ok {path}")
