import os

import pytest

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from cryptocore.modes import (
    decrypt_cbc,
    decrypt_cfb,
    decrypt_ctr,
    decrypt_ofb,
    encrypt_cbc,
    encrypt_cfb,
    encrypt_ctr,
    encrypt_ofb,
)


KEY = bytes.fromhex(
    "000102030405060708090a0b0c0d0e0f"
)

IV = bytes.fromhex(
    "aabbccddeeff00112233445566778899"
)


MODES = {
    "cbc": (
        encrypt_cbc,
        decrypt_cbc,
    ),
    "cfb": (
        encrypt_cfb,
        decrypt_cfb,
    ),
    "ofb": (
        encrypt_ofb,
        decrypt_ofb,
    ),
    "ctr": (
        encrypt_ctr,
        decrypt_ctr,
    ),
}


@pytest.mark.parametrize(
    "mode",
    MODES.keys(),
)
@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"a",
        b"123456789012345",
        b"1234567890123456",
        b"12345678901234567",
        os.urandom(31),
        os.urandom(32),
        os.urandom(257),
    ],
)
def test_roundtrip(
    mode: str,
    data: bytes,
) -> None:
    encrypt, decrypt = MODES[mode]

    encrypted = encrypt(
        data,
        KEY,
        IV,
    )

    decrypted = decrypt(
        encrypted,
        KEY,
        IV,
    )

    assert decrypted == data


def test_cbc_reference() -> None:
    data = b"CryptoCore Sprint 2"

    expected = AES.new(
        KEY,
        AES.MODE_CBC,
        IV,
    ).encrypt(
        pad(data, 16)
    )

    actual = encrypt_cbc(
        data,
        KEY,
        IV,
    )

    assert actual == expected


def test_cfb_reference() -> None:
    data = b"CryptoCore Sprint 2 CFB"

    expected = AES.new(
        KEY,
        AES.MODE_CFB,
        IV,
        segment_size=128,
    ).encrypt(
        data
    )

    actual = encrypt_cfb(
        data,
        KEY,
        IV,
    )

    assert actual == expected


def test_ofb_reference() -> None:
    data = b"CryptoCore Sprint 2 OFB"

    expected = AES.new(
        KEY,
        AES.MODE_OFB,
        IV,
    ).encrypt(
        data
    )

    actual = encrypt_ofb(
        data,
        KEY,
        IV,
    )

    assert actual == expected


def test_ctr_reference() -> None:
    data = b"CryptoCore Sprint 2 CTR"

    expected = AES.new(
        KEY,
        AES.MODE_CTR,
        nonce=b"",
        initial_value=int.from_bytes(
            IV,
            byteorder="big",
        ),
    ).encrypt(
        data
    )

    actual = encrypt_ctr(
        data,
        KEY,
        IV,
    )

    assert actual == expected


@pytest.mark.parametrize(
    "mode",
    MODES.keys(),
)
def test_invalid_iv(
    mode: str,
) -> None:
    encrypt, _ = MODES[mode]

    with pytest.raises(
        ValueError
    ):
        encrypt(
            b"hello",
            KEY,
            b"short",
        )