from nofault.crypto.hashing import content_address, verify_address


def test_address_format_and_determinism():
    a = content_address(b"hello")
    assert a.startswith("b2:")
    assert len(a) == len("b2:") + 64
    assert a == content_address(b"hello")


def test_different_data_different_address():
    assert content_address(b"a") != content_address(b"b")


def test_verify_address():
    data = b"some ciphertext"
    addr = content_address(data)
    assert verify_address(data, addr)
    assert not verify_address(data + b"x", addr)
    assert not verify_address(data, "b2:" + "0" * 64)
