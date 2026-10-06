import hashlib

import pytest

from hash import SHA3_256


@pytest.mark.parametrize(
    (
        "data",
        "expected",
    ),
    [
        (
            b"",
            (
                "a7ffc6f8bf1ed76651c14756a061d662"
                "f580ff4de43b49fa82d80a4b80f8434a"
            ),
        ),
        (
            b"abc",
            (
                "3a985da74fe225b2045c172d6bd390bd"
                "855f086e3e9d525b46bfe24511431532"
            ),
        ),
        (
            (
                b"The quick brown fox "
                b"jumps over the lazy dog"
            ),
            (
                "69070dda01975c8c120c3aada1b28239"
                "4e7f032fa9cf32f4cb2259a0897dfc04"
            ),
        ),
    ],
)
def test_sha3_256_known_vectors(
    data: bytes,
    expected: str,
) -> None:
    assert (
        SHA3_256.hash(data)
        == expected
    )


def test_sha3_256_incremental(
) -> None:
    data = (
        bytes(range(256))
        * 100
    )

    sha3 = SHA3_256()

    for index in range(
        0,
        len(data),
        37,
    ):
        sha3.update(
            data[
                index:index + 37
            ]
        )

    assert (
        sha3.hexdigest()
        == hashlib.sha3_256(
            data
        ).hexdigest()
    )


def test_sha3_256_block_boundaries(
) -> None:
    for size in (
        135,
        136,
        137,
        271,
        272,
        273,
    ):
        data = (
            b"a" * size
        )

        assert (
            SHA3_256.hash(data)
            == hashlib.sha3_256(
                data
            ).hexdigest()
        )


def test_sha3_256_one_million_a(
) -> None:
    data = (
        b"a" * 1_000_000
    )

    expected = (
        "5c8875ae474a3634ba4fd55ec85bffd6"
        "61f32aca75c6d699d0cdcb6c115891c1"
    )

    assert (
        SHA3_256.hash(data)
        == expected
    )


def test_sha3_256_digest_length(
) -> None:
    sha3 = SHA3_256()

    sha3.update(
        b"CryptoCore"
    )

    assert (
        len(sha3.digest())
        == 32
    )

    assert (
        len(sha3.hexdigest())
        == 64
    )


def test_sha3_256_lowercase_hex(
) -> None:
    result = SHA3_256.hash(
        b"CryptoCore"
    )

    assert (
        result
        == result.lower()
    )


def test_sha3_256_digest_does_not_reset_state(
) -> None:
    sha3 = SHA3_256()

    sha3.update(
        b"abc"
    )

    first = (
        sha3.hexdigest()
    )

    sha3.update(
        b"def"
    )

    second = (
        sha3.hexdigest()
    )

    assert (
        first
        == hashlib.sha3_256(
            b"abc"
        ).hexdigest()
    )

    assert (
        second
        == hashlib.sha3_256(
            b"abcdef"
        ).hexdigest()
    )


def test_sha3_256_invalid_input(
) -> None:
    sha3 = SHA3_256()

    with pytest.raises(
        TypeError
    ):
        sha3.update(
            "abc"
        )