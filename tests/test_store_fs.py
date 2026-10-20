"""The verdict store's journal mode: WAL locally, the rollback journal on a network filesystem (Runpod's /workspace is NFS)."""
from wolfguard import store as storemod

MOUNTS = """overlay / overlay rw,relatime 0 0
tmpfs /tmp tmpfs rw 0 0
ca-mtl-1.runpod.net:/runpodfs/podvolumes/x/y /workspace nfs4 rw,relatime,vers=4.1 0 0
/dev/sda1 /var/lib/wolfguard ext4 rw 0 0
"""


def test_network_fs_by_longest_mount_point(tmp_path):
    m = tmp_path / "mounts"
    m.write_text(MOUNTS)
    assert storemod.network_fs("/workspace/wolfguard/verdicts.db", str(m))
    assert not storemod.network_fs("/var/lib/wolfguard/verdicts.db", str(m))
    assert not storemod.network_fs("/tmp/x.db", str(m))
    assert not storemod.network_fs("/workspacex/verdicts.db", str(m))     # a prefix that is not the mount point
    assert not storemod.network_fs("/x.db", str(tmp_path / "missing"))     # no mounts file: assume local


def test_journal_mode_follows_the_filesystem_and_can_be_forced(tmp_path, monkeypatch):
    monkeypatch.setattr(storemod, "network_fs", lambda p: p.startswith("/workspace"))
    assert storemod.journal_mode("/workspace/wolfguard/verdicts.db") == "DELETE"
    assert storemod.journal_mode(str(tmp_path / "v.db")) == "WAL"
    monkeypatch.setenv("WOLFGUARD_STORE_JOURNAL", "wal")
    assert storemod.journal_mode("/workspace/wolfguard/verdicts.db") == "WAL"


def test_a_store_in_rollback_mode_works(tmp_path, monkeypatch):
    monkeypatch.setenv("WOLFGUARD_STORE_JOURNAL", "DELETE")
    st = storemod.VerdictStore(str(tmp_path / "v.db"))
    assert st.journal == "DELETE"
    st.put("k", "s", "app:1", "tool_result", {"decision": "critical"})
    assert st.get("k", "s")["decision"] == "critical"
