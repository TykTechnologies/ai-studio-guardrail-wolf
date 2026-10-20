import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from wolfguard import policy as policymod  # noqa: E402
from wolfguard.stub import StubBackend  # noqa: E402


@pytest.fixture
def stub():
    return StubBackend()


def block_tier_only(doc: dict) -> dict:
    """The shipped policy without its critical tier: the stub scores INJECT at
    exactly 0.95, so tests of the block tier drop the tier above it (the
    critical tier has tests of its own)."""
    for st in (doc.get("stages") or {}).values():
        for q in (st.get("questions") or {}).values():
            q.pop("critical", None)
    return doc


@pytest.fixture
def policy():
    import yaml
    return policymod.parse(block_tier_only(yaml.safe_load((ROOT / "config" / "policy.yaml").read_text())))


@pytest.fixture
def captures():
    d = ROOT / "fixtures" / "captures"
    return {p.stem: json.loads(p.read_text()) for p in d.glob("*.json") if p.stem != "summary"}
