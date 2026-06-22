import os

import pytest

from nofault.client.repo import Repo
from nofault.client.safety import DeadManSwitch, panic


def test_panic_destroys_keystore_and_vault(tmp_path, alice):
    ks = str(tmp_path / "keystore.json")
    with open(ks, "wb") as f:
        f.write(b"encrypted-keystore")
    repo = Repo(str(tmp_path / "repo"), alice)
    enc = repo.create("s", "s", shreddable=True)
    doc_id = enc.manifest["doc_id"]

    result = panic(keystore_path=ks, repo=repo)
    assert "keystore" in result["destroyed"]
    assert not os.path.exists(ks)
    # shreddable doc is now unrecoverable
    with pytest.raises(KeyError):
        repo.open(repo.get_encrypted(doc_id))


def test_deadman_check_in_resets_deadline(tmp_path):
    dms = DeadManSwitch(str(tmp_path / "dms.json"))
    dms.arm(interval_seconds=100, release_bundle_path="/r.nfb", now=1000.0)
    assert dms.is_expired(now=1050.0) is False
    assert dms.fire(now=1050.0) is None
    dms.check_in(now=1050.0)  # resets deadline to 1150
    assert dms.is_expired(now=1149.0) is False


def test_deadman_fires_when_expired(tmp_path):
    dms = DeadManSwitch(str(tmp_path / "dms.json"))
    dms.arm(interval_seconds=100, release_bundle_path="/release.nfb", now=1000.0)
    assert dms.is_expired(now=1101.0) is True
    assert dms.fire(now=1101.0) == "/release.nfb"
