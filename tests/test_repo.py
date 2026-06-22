import pytest

from nofault.client.repo import Repo


def test_create_and_open(tmp_path, alice):
    repo = Repo(str(tmp_path / "repo"), alice)
    enc = repo.create("Title", "the body")
    doc = repo.open(repo.get_encrypted(enc.manifest["doc_id"]))
    assert doc.title == "Title"
    assert doc.body_markdown == "the body"


def test_edit_creates_version_chain(tmp_path, alice):
    repo = Repo(str(tmp_path / "repo"), alice)
    v1 = repo.create("T1", "b1")
    doc_id = v1.manifest["doc_id"]
    v2 = repo.edit(doc_id, title="T2", body_markdown="b2")
    assert v2.manifest["version"] == 2
    assert v2.manifest["prev_address"] == v1.manifest_address
    assert repo.open(repo.get_encrypted(doc_id)).title == "T2"


def test_list_docs(tmp_path, alice):
    repo = Repo(str(tmp_path / "repo"), alice)
    repo.create("A", "a")
    repo.create("B", "b")
    assert len(repo.list_docs()) == 2


def test_delete_returns_addresses(tmp_path, alice):
    repo = Repo(str(tmp_path / "repo"), alice)
    enc = repo.create("A", "a")
    doc_id = enc.manifest["doc_id"]
    addrs = repo.delete(doc_id)
    assert len(addrs) == 2
    assert repo.list_docs() == []


def test_shreddable_create_and_open(tmp_path, alice):
    repo = Repo(str(tmp_path / "repo"), alice)
    enc = repo.create("Secret", "sensitive", shreddable=True)
    doc_id = enc.manifest["doc_id"]
    # opens while DEK is in the vault
    assert repo.open(repo.get_encrypted(doc_id)).title == "Secret"


def test_crypto_shred_makes_unreadable(tmp_path, alice):
    repo = Repo(str(tmp_path / "repo"), alice)
    enc = repo.create("Secret", "sensitive", shreddable=True)
    doc_id = enc.manifest["doc_id"]
    assert repo.crypto_shred(doc_id) is True
    # the ciphertext blob is still on disk, but the key is gone forever
    with pytest.raises(KeyError):
        repo.open(repo.get_encrypted(doc_id))


def test_non_shreddable_cannot_be_shredded(tmp_path, alice):
    repo = Repo(str(tmp_path / "repo"), alice)
    enc = repo.create("Normal", "x", shreddable=False)
    assert repo.crypto_shred(enc.manifest["doc_id"]) is False


def test_index_holds_no_plaintext(tmp_path, alice):
    repo = Repo(str(tmp_path / "repo"), alice)
    repo.create("VerySecretTitle", "verySecretBody")
    with open(repo.index_path, "rb") as f:
        index_bytes = f.read()
    assert b"VerySecretTitle" not in index_bytes
    assert b"verySecretBody" not in index_bytes
