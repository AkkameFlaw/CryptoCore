import os

import pytest

import cryptocore.csprng as csprng

from cryptocore.csprng import (
    generate_random_bytes,
)


def test_random_bytes_length() -> None:
    data = generate_random_bytes(16)

    assert len(data) == 16


def test_key_uniqueness() -> None:
    keys = {
        generate_random_bytes(16)
        for _ in range(1000)
    }

    assert len(keys) == 1000


def test_hamming_weight() -> None:
    data = b"".join(
        generate_random_bytes(16)
        for _ in range(1000)
    )

    ones = sum(
        byte.bit_count()
        for byte in data
    )

    total_bits = (
        len(data) * 8
    )

    ratio = (
        ones / total_bits
    )

    assert 0.45 <= ratio <= 0.55


def test_negative_size() -> None:
    with pytest.raises(
        ValueError
    ):
        generate_random_bytes(-1)


def test_invalid_size_type() -> None:
    with pytest.raises(
        TypeError
    ):
        generate_random_bytes(
            16.0
        )


def test_os_urandom_failure(
    monkeypatch,
) -> None:
    def fail(
        num_bytes: int,
    ) -> bytes:
        raise OSError(
            "random source unavailable"
        )

    monkeypatch.setattr(
        os,
        "urandom",
        fail,
    )

    with pytest.raises(
        RuntimeError,
        match="CSPRNG failure",
    ):
        csprng.generate_random_bytes(
            16
        )