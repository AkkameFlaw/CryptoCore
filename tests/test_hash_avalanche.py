from cryptocore.hashes import SHA256, SHA3_256


def count_different_bits(
    first_hash: str,
    second_hash: str,
) -> int:
    first = int(
        first_hash,
        16,
    )

    second = int(
        second_hash,
        16,
    )

    return (
        first ^ second
    ).bit_count()


def test_sha256_avalanche_effect(
) -> None:
    original = (
        b"Hello, world!"
    )

    modified = (
        b"Hello, world?"
    )

    first_hash = (
        SHA256.hash(
            original
        )
    )

    second_hash = (
        SHA256.hash(
            modified
        )
    )

    difference = (
        count_different_bits(
            first_hash,
            second_hash,
        )
    )

    assert (
        100
        < difference
        < 156
    )


def test_sha3_256_avalanche_effect(
) -> None:
    original = (
        b"Hello, world!"
    )

    modified = (
        b"Hello, world?"
    )

    first_hash = (
        SHA3_256.hash(
            original
        )
    )

    second_hash = (
        SHA3_256.hash(
            modified
        )
    )

    difference = (
        count_different_bits(
            first_hash,
            second_hash,
        )
    )

    assert (
        100
        < difference
        < 156
    )