import os

import pytest

from Crypto.Cipher import AES

from cryptocore.modes.ecb import (
    PaddingError,
    decrypt_ecb,
    encrypt_ecb,
    pkcs7_pad,
    pkcs7_unpad,
)


KEY = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
)


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"a",
        b"hello world",
        b"1234567890abcdef",
        b"x" * 31,
        os.urandom(257),
    ],
)
def test_encrypt_decrypt_roundtrip(
    payload: bytes,
) -> None:

    encrypted = encrypt_ecb(
        payload,
        KEY,
    )

    assert len(encrypted) % 16 == 0

    decrypted = decrypt_ecb(
        encrypted,
        KEY,
    )

    assert decrypted == payload


def test_matches_pycryptodome_reference() -> None:

    payload = b"CryptoCore ECB test"

    padded = pkcs7_pad(
        payload
    )

    reference_cipher = AES.new(
        KEY,
        AES.MODE_ECB,
    )

    expected = reference_cipher.encrypt(
        padded
    )

    actual = encrypt_ecb(
        payload,
        KEY,
    )

    assert actual == expected


def test_full_block_padding() -> None:

    payload = b"1234567890abcdef"

    padded = pkcs7_pad(
        payload
    )

    assert len(padded) == 32

    assert padded[-16:] == (
        bytes([16]) * 16
    )

    restored = pkcs7_unpad(
        padded
    )

    assert restored == payload


def test_invalid_padding() -> None:

    invalid = (
        b"A" * 15
        + b"\x00"
    )

    with pytest.raises(
        PaddingError
    ):
        pkcs7_unpad(
            invalid
        )


def test_invalid_key_length() -> None:

    with pytest.raises(
        ValueError
    ):
        encrypt_ecb(
            b"hello",
            b"short-key",
        )