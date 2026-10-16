import hashlib
import hmac
from unittest.mock import patch

import pytest

from aead import EncryptThenMAC, EtMAuthenticationError
from cryptocore.modes import encrypt_ctr


MASTER_KEY = bytes(range(16))
NONCE = bytes(range(16, 32))


@pytest.mark.parametrize(
    "plaintext",
    [
        b"",
        b"A",
        b"123456789012345",
        b"1234567890123456",
        b"12345678901234567",
        b"CryptoCore Sprint 6",
        bytes(range(256)) * 16,
    ],
)
@pytest.mark.parametrize(
    "aad",
    [
        b"",
        b"metadata",
        b"authenticated associated data",
    ],
)
def test_etm_round_trip(plaintext, aad):
    encrypted = EncryptThenMAC(MASTER_KEY).encrypt(
        plaintext,
        aad,
    )

    decrypted = EncryptThenMAC(MASTER_KEY).decrypt(
        encrypted,
        aad,
    )

    assert decrypted == plaintext


def test_etm_output_format():
    plaintext = b"CryptoCore"
    aad = b"metadata"

    encrypted = EncryptThenMAC(MASTER_KEY).encrypt(
        plaintext,
        aad,
        nonce=NONCE,
    )

    assert encrypted[:16] == NONCE
    assert len(encrypted) == 16 + len(plaintext) + 32


def test_etm_independent_mac_reference():
    plaintext = b"Reference verification"
    aad = b"authenticated metadata"

    encrypted = EncryptThenMAC(MASTER_KEY).encrypt(
        plaintext,
        aad,
        nonce=NONCE,
    )

    encryption_key = hmac.new(
        MASTER_KEY,
        b"CryptoCore:EtM:v1:encryption",
        hashlib.sha256,
    ).digest()[:16]

    authentication_key = hmac.new(
        MASTER_KEY,
        b"CryptoCore:EtM:v1:authentication",
        hashlib.sha256,
    ).digest()

    ciphertext = encrypt_ctr(
        plaintext,
        encryption_key,
        NONCE,
    )

    authenticated_ciphertext = NONCE + ciphertext

    mac_input = (
        b"CryptoCore:EtM:v1"
        + len(authenticated_ciphertext).to_bytes(8, "big")
        + authenticated_ciphertext
        + len(aad).to_bytes(8, "big")
        + aad
    )

    expected_tag = hmac.new(
        authentication_key,
        mac_input,
        hashlib.sha256,
    ).digest()

    assert encrypted == authenticated_ciphertext + expected_tag
    assert encryption_key != authentication_key[:16]


def test_etm_wrong_aad():
    encrypted = EncryptThenMAC(MASTER_KEY).encrypt(
        b"Secret message",
        b"correct aad",
    )

    with pytest.raises(EtMAuthenticationError):
        EncryptThenMAC(MASTER_KEY).decrypt(
            encrypted,
            b"wrong aad",
        )


def test_etm_wrong_master_key():
    encrypted = EncryptThenMAC(MASTER_KEY).encrypt(
        b"Secret message",
        b"metadata",
    )

    wrong_key = bytes(range(1, 17))

    with pytest.raises(EtMAuthenticationError):
        EncryptThenMAC(wrong_key).decrypt(
            encrypted,
            b"metadata",
        )


@pytest.mark.parametrize(
    "position",
    [0, 16, -1],
)
def test_etm_detects_tampering(position):
    encrypted = bytearray(
        EncryptThenMAC(MASTER_KEY).encrypt(
            b"Secret message",
            b"metadata",
            nonce=NONCE,
        )
    )

    encrypted[position] ^= 1

    with pytest.raises(EtMAuthenticationError):
        EncryptThenMAC(MASTER_KEY).decrypt(
            bytes(encrypted),
            b"metadata",
        )


def test_etm_rejects_truncated_data():
    with pytest.raises(EtMAuthenticationError):
        EncryptThenMAC(MASTER_KEY).decrypt(
            b"short"
        )


def test_etm_authentication_before_decryption():
    encrypted = bytearray(
        EncryptThenMAC(MASTER_KEY).encrypt(
            b"Confidential data",
            b"metadata",
        )
    )

    encrypted[-1] ^= 1

    with patch(
        "aead.encrypt_then_mac.decrypt_ctr",
        side_effect=AssertionError(
            "Decryption must not be called"
        ),
    ) as decrypt_mock:
        with pytest.raises(EtMAuthenticationError):
            EncryptThenMAC(MASTER_KEY).decrypt(
                bytes(encrypted),
                b"metadata",
            )

        decrypt_mock.assert_not_called()


def test_etm_random_nonces():
    nonces = set()

    for _ in range(100):
        encrypted = EncryptThenMAC(MASTER_KEY).encrypt(
            b"message"
        )

        nonces.add(encrypted[:16])

    assert len(nonces) == 100


def test_etm_prevents_instance_reuse():
    instance = EncryptThenMAC(MASTER_KEY)

    instance.encrypt(b"First message")

    with pytest.raises(ValueError):
        instance.encrypt(b"Second message")


def test_etm_rejects_invalid_master_key():
    with pytest.raises(ValueError):
        EncryptThenMAC(b"short")


def test_etm_rejects_invalid_nonce():
    instance = EncryptThenMAC(MASTER_KEY)

    with pytest.raises(ValueError):
        instance.encrypt(
            b"message",
            nonce=b"short",
        )


def test_etm_large_message():
    plaintext = bytes(range(256)) * 256
    aad = b"large message metadata"

    encrypted = EncryptThenMAC(MASTER_KEY).encrypt(
        plaintext,
        aad,
    )

    decrypted = EncryptThenMAC(MASTER_KEY).decrypt(
        encrypted,
        aad,
    )

    assert decrypted == plaintext