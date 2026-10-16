import hashlib
import hmac

import pytest

from kdf import derive_key


MASTER_KEY = bytes(range(32))


def test_same_context_same_key():
    first = derive_key(
        MASTER_KEY,
        "encryption",
        32,
    )

    second = derive_key(
        MASTER_KEY,
        "encryption",
        32,
    )

    assert first == second


def test_different_contexts():
    encryption_key = derive_key(
        MASTER_KEY,
        "encryption",
        32,
    )

    authentication_key = derive_key(
        MASTER_KEY,
        "authentication",
        32,
    )

    assert encryption_key != authentication_key


@pytest.mark.parametrize(
    "length",
    [1, 16, 31, 32, 33, 64, 100],
)
def test_derived_key_lengths(length):
    key = derive_key(
        MASTER_KEY,
        "testing",
        length,
    )

    assert len(key) == length


def test_key_hierarchy_reference():
    context = "authentication"
    length = 100

    expected = bytearray()

    for counter in range(1, 5):
        expected.extend(
            hmac.new(
                MASTER_KEY,
                context.encode("utf-8")
                + counter.to_bytes(4, "big"),
                hashlib.sha256,
            ).digest()
        )

    actual = derive_key(
        MASTER_KEY,
        context,
        length,
    )

    assert actual == bytes(expected[:length])


def test_different_master_keys():
    first = derive_key(
        b"A" * 32,
        "encryption",
        32,
    )

    second = derive_key(
        b"B" * 32,
        "encryption",
        32,
    )

    assert first != second


def test_unicode_context():
    actual = derive_key(
        MASTER_KEY,
        "шифрование",
        32,
    )

    expected = hmac.new(
        MASTER_KEY,
        "шифрование".encode("utf-8")
        + (1).to_bytes(4, "big"),
        hashlib.sha256,
    ).digest()

    assert actual == expected


def test_empty_context_rejected():
    with pytest.raises(ValueError):
        derive_key(
            MASTER_KEY,
            "",
            32,
        )


def test_invalid_length():
    with pytest.raises(ValueError):
        derive_key(
            MASTER_KEY,
            "encryption",
            0,
        )


def test_invalid_master_key():
    with pytest.raises(TypeError):
        derive_key(
            "master",
            "encryption",
            32,
        )