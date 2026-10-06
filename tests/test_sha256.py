import hashlib

import pytest

from hash import SHA256


@pytest.mark.parametrize(
    (
        "data",
        "expected",
    ),
    [
        (
            b"",
            (
                "e3b0c44298fc1c149afbf4c8996fb924"
                "27ae41e4649b934ca495991b7852b855"
            ),
        ),
        (
            b"abc",
            (
                "ba7816bf8f01cfea414140de5dae2223"
                "b00361a396177a9cb410ff61f20015ad"
            ),
        ),
        (
            (
                b"abcdbcdecdefdefgefghfghighijhijk"
                b"ijkljklmklmnlmnomnopnopq"
            ),
            (
                "248d6a61d20638b8e5c026930c3e6039"
                "a33ce45964ff2167f6ecedd419db06c1"
            ),
        ),
    ],
)
def test_sha256_known_vectors(
    data: bytes,
    expected: str,
) -> None:
    assert (
        SHA256.hash(data)
        == expected
    )


def test_sha256_one_million_a(
) -> None:
    data = (
        b"a" * 1_000_000
    )

    expected = (
        "cdc76e5c9914fb9281a1c7e284d73e67"
        "f1809a48a497200e046d39ccc7112cd0"
    )

    assert (
        SHA256.hash(data)
        == expected
    )


def test_sha256_incremental(
) -> None:
    data = (
        bytes(range(256))
        * 100
    )

    sha256 = SHA256()

    for index in range(
        0,
        len(data),
        37,
    ):
        sha256.update(
            data[
                index:index + 37
            ]
        )

    assert (
        sha256.hexdigest()
        == hashlib.sha256(
            data
        ).hexdigest()
    )


def test_sha256_digest_length(
) -> None:
    sha256 = SHA256()

    sha256.update(
        b"CryptoCore"
    )

    assert (
        len(sha256.digest())
        == 32
    )

    assert (
        len(sha256.hexdigest())
        == 64
    )


def test_sha256_lowercase_hex(
) -> None:
    result = SHA256.hash(
        b"CryptoCore"
    )

    assert (
        result
        == result.lower()
    )


def test_sha256_digest_does_not_reset_state(
) -> None:
    sha256 = SHA256()

    sha256.update(
        b"abc"
    )

    first = (
        sha256.hexdigest()
    )

    sha256.update(
        b"def"
    )

    second = (
        sha256.hexdigest()
    )

    assert (
        first
        == hashlib.sha256(
            b"abc"
        ).hexdigest()
    )

    assert (
        second
        == hashlib.sha256(
            b"abcdef"
        ).hexdigest()
    )


def test_sha256_invalid_input(
) -> None:
    sha256 = SHA256()

    with pytest.raises(
        TypeError
    ):
        sha256.update(
            "abc"
        )