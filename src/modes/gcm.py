"""Authenticated AES-128-GCM using the PyCryptodome backend.

The original pure-Python GHASH table has been removed from the runtime path.
The nonce reservation is shared with the streaming CLI and EtM library.
"""
from __future__ import annotations

import secrets
from typing import BinaryIO

from Crypto.Cipher import AES

from cryptocore.csprng import generate_random_bytes
from cryptocore.nonce_registry import register_nonce

NONCE_SIZE = 12
TAG_SIZE = 16
CHUNK_SIZE = 8192


class AuthenticationError(ValueError):
    """Invalid GCM framing or authentication tag."""


def _update_aad(cipher, aad: bytes | BinaryIO) -> None:
    """Stream authenticated metadata into the native GCM context."""
    if isinstance(aad, (bytes, bytearray, memoryview)):
        view = memoryview(aad)
        for start in range(0, len(view), CHUNK_SIZE):
            cipher.update(bytes(view[start:start + CHUNK_SIZE]))
        return

    if not hasattr(aad, "read"):
        raise TypeError("AAD must be bytes-like or a binary stream")
    while True:
        block = aad.read(CHUNK_SIZE)
        if not block:
            return
        if not isinstance(block, (bytes, bytearray, memoryview)):
            raise TypeError("AAD stream must return bytes")
        cipher.update(bytes(block))


class GCM:
    """One-use GCM encryption context; nonce reuse is rejected via SQLite.

    Encryption requires the local nonce registry to be available. Decryption
    does not reserve nonces and can be repeated. This class holds in-memory
    input/output; use cryptocore.streaming for large files.
    """

    tag_size = TAG_SIZE
    nonce_size = NONCE_SIZE

    def __init__(self, key: bytes, nonce: bytes | None = None) -> None:
        """Validate a 16-byte AES key and choose a fresh nonce if omitted."""
        if not isinstance(key, (bytes, bytearray, memoryview)):
            raise TypeError("key must be bytes-like")
        if len(key) != 16:
            raise ValueError("AES-128 key must be exactly 16 bytes")
        if nonce is None:
            nonce = generate_random_bytes(NONCE_SIZE)
        if not isinstance(nonce, (bytes, bytearray, memoryview)):
            raise TypeError("nonce must be bytes-like")
        if len(nonce) == 0:
            raise ValueError("nonce must not be empty")
        self._key = bytes(key)
        self.nonce = bytes(nonce)
        self._encryption_used = False

    def encrypt(self, plaintext: bytes, aad: bytes | BinaryIO = b"") -> bytes:
        """Return nonce || ciphertext || tag; persist nonce before encryption."""
        if self._encryption_used:
            raise ValueError("nonce has already been used for encryption")
        if not isinstance(plaintext, (bytes, bytearray, memoryview)):
            raise TypeError("plaintext must be bytes-like")
        cipher = AES.new(self._key, AES.MODE_GCM, nonce=self.nonce, mac_len=TAG_SIZE)
        _update_aad(cipher, aad)
        register_nonce(self._key, self.nonce, "gcm")
        self._encryption_used = True
        ciphertext, tag = cipher.encrypt_and_digest(bytes(plaintext))
        return self.nonce + ciphertext + tag

    def decrypt(
        self, data: bytes, aad: bytes | BinaryIO = b"", includes_nonce: bool = True
    ) -> bytes:
        """Verify GCM tag before returning plaintext; no nonce reservation."""
        if not isinstance(data, (bytes, bytearray, memoryview)):
            raise TypeError("data must be bytes-like")
        payload = bytes(data)
        if includes_nonce:
            if len(payload) < len(self.nonce) + TAG_SIZE:
                raise AuthenticationError("Authentication failed: invalid input length")
            if not secrets.compare_digest(payload[:len(self.nonce)], self.nonce):
                raise AuthenticationError("Authentication failed: nonce mismatch")
            payload = payload[len(self.nonce):]
        if len(payload) < TAG_SIZE:
            raise AuthenticationError("Authentication failed: missing tag")
        ciphertext, tag = payload[:-TAG_SIZE], payload[-TAG_SIZE:]
        cipher = AES.new(self._key, AES.MODE_GCM, nonce=self.nonce, mac_len=TAG_SIZE)
        _update_aad(cipher, aad)
        try:
            return cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError as exc:
            raise AuthenticationError(
                "Authentication failed: AAD mismatch or ciphertext tampered"
            ) from exc
