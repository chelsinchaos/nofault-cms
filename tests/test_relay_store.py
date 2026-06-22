from nofault.relay.store import BlobStore


def test_put_get_round_trip(tmp_path):
    store = BlobStore(str(tmp_path))
    addr = store.put(b"opaque ciphertext")
    assert addr.startswith("b2:")
    assert store.get(addr) == b"opaque ciphertext"
    assert store.has(addr)


def test_put_is_idempotent(tmp_path):
    store = BlobStore(str(tmp_path))
    a1 = store.put(b"same")
    a2 = store.put(b"same")
    assert a1 == a2


def test_get_missing_returns_none(tmp_path):
    store = BlobStore(str(tmp_path))
    assert store.get("b2:" + "0" * 64) is None
    assert not store.has("b2:" + "0" * 64)


def test_malformed_address_is_safe(tmp_path):
    store = BlobStore(str(tmp_path))
    # path-traversal style input must not escape the store or raise uncontrolled
    assert store.get("../../etc/passwd") is None
    assert store.has("../../etc/passwd") is False


def test_delete(tmp_path):
    store = BlobStore(str(tmp_path))
    addr = store.put(b"x")
    assert store.delete(addr) is True
    assert store.get(addr) is None
    assert store.delete(addr) is False
