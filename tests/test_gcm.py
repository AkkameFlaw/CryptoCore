import io

import pytest
from Crypto.Cipher import AES

from modes import AuthenticationError, GCM


@pytest.mark.parametrize(
    "plaintext, expected",
    [
        (
            b"",
            "58e2fccefa7e3061367f1d57a4e7455a",
        ),
        (
            bytes(16),
            (
                "0388dace60b6a392f328c2b971b2fe78"
                "ab6e47d42cec13bdf53a67b21257bddf"
            ),
        ),
    ],
)
def test_gcm_nist_zero_vectors(plaintext, expected):
    key = bytes(16)
    nonce = bytes(12)

    result = GCM(key, nonce).encrypt(plaintext)

    assert result == nonce + bytes.fromhex(expected)
    assert GCM(key, nonce).decrypt(result) == plaintext


def test_gcm_nist_aad_vector():
    key = bytes.fromhex(
        "feffe9928665731c6d6a8f9467308308"
    )

    nonce = bytes.fromhex(
        "cafebabefacedbaddecaf888"
    )

    aad = bytes.fromhex(
        "feedfacedeadbeeffeedfacedeadbeefabaddad2"
    )

    plaintext = bytes.fromhex(
        "d9313225f88406e5a55909c5aff5269a"
        "86a7a9531534f7da2e4c303d8a318a72"
        "1c3c0c95956809532fcf0e2449a6b525"
        "b16aedf5aa0de657ba637b39"
    )

    expected_ciphertext = bytes.fromhex(
        "42831ec2217774244b7221b784d0d49c"
        "e3aa212f2c02a4e035c17e2329aca12e"
        "21d514b25466931c7d8f6a5aac84aa05"
        "1ba30b396a0aac973d58e091"
    )

    expected_tag = bytes.fromhex(
        "5bc94fbc3221a5db94fae95ae7121a47"
    )

    encrypted = GCM(key, nonce).encrypt(plaintext, aad)

    assert encrypted == (
        nonce + expected_ciphertext + expected_tag
    )

    assert GCM(key, nonce).decrypt(encrypted, aad) == plaintext


@pytest.mark.parametrize("nonce_size", [8, 12, 16, 24])
@pytest.mark.parametrize("message_size", [0, 1, 15, 16, 17, 65])
def test_gcm_matches_pycryptodome(nonce_size, message_size):
    key = bytes(range(16))
    nonce = bytes(range(nonce_size))
    plaintext = bytes(range(message_size))
    aad = b"CryptoCore Sprint 6 associated data"

    implementation = GCM(key, nonce)
    encrypted = implementation.encrypt(plaintext, aad)

    reference = AES.new(
        key,
        AES.MODE_GCM,
        nonce=nonce,
        mac_len=16,
    )

    reference.update(aad)

    reference_ciphertext, reference_tag = (
        reference.encrypt_and_digest(plaintext)
    )

    assert encrypted == (
        nonce + reference_ciphertext + reference_tag
    )

    assert GCM(key, nonce).decrypt(encrypted, aad) == plaintext


def test_gcm_empty_aad():
    key = bytes(range(16))
    nonce = bytes(range(12))
    plaintext = b"CryptoCore GCM"

    encrypted = GCM(key, nonce).encrypt(plaintext)

    assert GCM(key, nonce).decrypt(encrypted, b"") == plaintext


def test_gcm_wrong_aad():
    key = bytes(range(16))
    nonce = bytes(range(12))

    encrypted = GCM(key, nonce).encrypt(
        b"Secret message",
        b"correct aad",
    )

    with pytest.raises(AuthenticationError):
        GCM(key, nonce).decrypt(
            encrypted,
            b"wrong aad",
        )


@pytest.mark.parametrize("position", [0, 12, -1])
def test_gcm_detects_tampering(position):
    key = bytes(range(16))
    nonce = bytes(range(12))

    encrypted = bytearray(
        GCM(key, nonce).encrypt(
            b"Secret authenticated message",
            b"metadata",
        )
    )

    encrypted[position] ^= 1

    with pytest.raises(AuthenticationError):
        GCM(key, nonce).decrypt(
            bytes(encrypted),
            b"metadata",
        )


def test_gcm_rejects_truncated_input():
    key = bytes(range(16))
    nonce = bytes(range(12))

    with pytest.raises(AuthenticationError):
        GCM(key, nonce).decrypt(b"short")


def test_gcm_explicit_nonce_payload():
    key = bytes(range(16))
    nonce = bytes(range(12))
    plaintext = b"Explicit nonce test"
    aad = b"metadata"

    encrypted = GCM(key, nonce).encrypt(plaintext, aad)

    payload = encrypted[len(nonce):]

    assert GCM(key, nonce).decrypt(
        payload,
        aad,
        includes_nonce=False,
    ) == plaintext


def test_gcm_streamed_aad():
    key = bytes(range(16))
    nonce = bytes(range(12))
    plaintext = b"Streaming AAD test"
    aad = bytes(range(256)) * 150

    encrypted = GCM(key, nonce).encrypt(
        plaintext,
        io.BytesIO(aad),
    )

    reference = AES.new(
        key,
        AES.MODE_GCM,
        nonce=nonce,
    )

    reference.update(aad)

    expected_ciphertext, expected_tag = (
        reference.encrypt_and_digest(plaintext)
    )

    assert encrypted == (
        nonce + expected_ciphertext + expected_tag
    )

    assert GCM(key, nonce).decrypt(
        encrypted,
        io.BytesIO(aad),
    ) == plaintext


def test_gcm_generates_nonce():
    key = bytes(range(16))

    first = GCM(key)
    second = GCM(key)

    assert len(first.nonce) == 12
    assert len(second.nonce) == 12
    assert first.nonce != second.nonce


def test_gcm_prevents_nonce_reuse():
    key = bytes(range(16))
    gcm = GCM(key, bytes(range(12)))

    gcm.encrypt(b"First message")

    with pytest.raises(ValueError):
        gcm.encrypt(b"Second message")


def test_gcm_invalid_key():
    with pytest.raises(ValueError):
        GCM(b"short", bytes(12))


def test_gcm_invalid_nonce():
    with pytest.raises(ValueError):
        GCM(bytes(16), b"")