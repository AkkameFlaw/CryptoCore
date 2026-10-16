import pytest
from Crypto.Cipher import AES

from modes import AuthenticationError, GCM


class GeneratedAAD:
    def __init__(self, length: int) -> None:
        self.remaining = length
        self.read_calls = 0
        self.max_requested = 0

    def read(self, size: int = -1) -> bytes:
        if size <= 0 or size > 8192:
            raise AssertionError(
                "AAD must be read in chunks of at most 8192 bytes"
            )

        self.read_calls += 1
        self.max_requested = max(self.max_requested, size)

        amount = min(self.remaining, size)
        self.remaining -= amount

        return b"\xa5" * amount


def test_1000_unique_gcm_nonces():
    key = bytes(range(16))
    nonces = set()

    for _ in range(1000):
        encrypted = GCM(key).encrypt(b"Nonce uniqueness test")

        nonce = encrypted[:12]

        assert len(nonce) == 12

        nonces.add(nonce)

    assert len(nonces) == 1000


@pytest.mark.parametrize(
    "aad_size",
    [0, 1, 15, 16, 17, 8191, 8192, 8193, 1048579],
)
def test_gcm_streaming_aad(aad_size):
    key = bytes(range(16))
    nonce = bytes(range(12))
    plaintext = b"CryptoCore Sprint 6"

    aad_stream = GeneratedAAD(aad_size)

    encrypted = GCM(key, nonce).encrypt(
        plaintext,
        aad_stream,
    )

    assert aad_stream.remaining == 0
    assert aad_stream.max_requested <= 8192

    reference = AES.new(
        key,
        AES.MODE_GCM,
        nonce=nonce,
    )

    remaining = aad_size

    while remaining:
        chunk = b"\xa5" * min(8192, remaining)
        reference.update(chunk)
        remaining -= len(chunk)

    ciphertext, tag = reference.encrypt_and_digest(
        plaintext
    )

    assert encrypted == nonce + ciphertext + tag

    decrypted = GCM(key, nonce).decrypt(
        encrypted,
        GeneratedAAD(aad_size),
    )

    assert decrypted == plaintext


def test_streamed_aad_change_rejected():
    key = bytes(range(16))
    nonce = bytes(range(12))
    plaintext = b"Authenticated data"

    encrypted = GCM(key, nonce).encrypt(
        plaintext,
        GeneratedAAD(1024 * 1024),
    )

    with pytest.raises(AuthenticationError):
        GCM(key, nonce).decrypt(
            encrypted,
            GeneratedAAD(1024 * 1024 + 1),
        )