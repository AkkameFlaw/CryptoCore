"""Bounded-memory CLI file encryption with atomic destination replacement.

The CLI deliberately uses PyCryptodome's native AES-GCM backend. The original
pure-Python GHASH remains an educational library implementation, without a
constant-time security guarantee.
"""

from __future__ import annotations

import os
import secrets
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import BinaryIO, Iterator

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

from mac import HMAC

from .csprng import generate_random_bytes
from .nonce_registry import register_nonce

CHUNK = 64 * 1024
ETM_DOMAIN = b"CryptoCore:EtM:v1"


@contextmanager
def _atomic_target(destination: str | Path) -> Iterator[BinaryIO]:
    """Write into a private temporary file, publishing only on success."""
    destination = Path(destination)
    fd, name = tempfile.mkstemp(prefix=".cryptocore-", suffix=".tmp", dir=str(destination.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            yield stream
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, destination)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def _aad_update(callback, aad: bytes | BinaryIO) -> int:
    """Feed AAD incrementally and report its byte length."""
    size = 0
    if isinstance(aad, (bytes, bytearray, memoryview)):
        for index in range(0, len(aad), CHUNK):
            block = aad[index:index + CHUNK]
            callback(block)
            size += len(block)
    else:
        aad.seek(0)
        while block := aad.read(CHUNK):
            callback(block)
            size += len(block)
    return size


def _aad_length(aad: bytes | BinaryIO) -> int:
    if isinstance(aad, (bytes, bytearray, memoryview)):
        return len(aad)
    start = aad.tell()
    aad.seek(0, os.SEEK_END)
    length = aad.tell()
    aad.seek(start)
    return length


def _new_cipher(mode: str, key: bytes, iv: bytes | None):
    """Create an incremental AES context compatible with legacy file formats."""
    if mode == "ecb":
        return AES.new(key, AES.MODE_ECB)
    if mode == "cbc":
        return AES.new(key, AES.MODE_CBC, iv=iv)
    if mode == "cfb":
        return AES.new(key, AES.MODE_CFB, iv=iv, segment_size=128)
    if mode == "ofb":
        return AES.new(key, AES.MODE_OFB, iv=iv)
    if mode == "ctr":
        return AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=int.from_bytes(iv, "big"))
    raise ValueError("unsupported AES mode")


def _derive_etm_key(master: bytes, label: bytes) -> bytes:
    mac = HMAC(master)
    mac.update(ETM_DOMAIN)
    mac.update(b":")
    mac.update(label)
    return mac.digest()


def _consume_exact(source: BinaryIO, total: int, callback) -> None:
    remaining = total
    while remaining:
        chunk = source.read(min(CHUNK, remaining))
        if not chunk:
            raise ValueError("truncated ciphertext")
        callback(chunk)
        remaining -= len(chunk)


def encrypt_file(source_path: str | Path, destination: str | Path, key: bytes, mode: str, aad: bytes | BinaryIO = b"") -> None:
    """Encrypt an input file using bounded memory and record each generated IV."""
    with open(source_path, "rb") as source:
        size = os.fstat(source.fileno()).st_size
        if mode == "gcm":
            nonce = generate_random_bytes(12)
            register_nonce(key, nonce, mode)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce, mac_len=16)
            _aad_update(cipher.update, aad)
            with _atomic_target(destination) as target:
                target.write(nonce)
                while block := source.read(CHUNK):
                    target.write(cipher.encrypt(block))
                target.write(cipher.digest())
            return
        if mode == "etm":
            nonce = generate_random_bytes(16)
            register_nonce(key, nonce, mode)
            encryption_key = _derive_etm_key(key, b"encryption")[:16]
            authentication_key = _derive_etm_key(key, b"authentication")
            cipher = _new_cipher("ctr", encryption_key, nonce)
            mac = HMAC(authentication_key)
            mac.update(ETM_DOMAIN)
            mac.update((size + 16).to_bytes(8, "big"))
            mac.update(nonce)
            with _atomic_target(destination) as target:
                target.write(nonce)
                while block := source.read(CHUNK):
                    encrypted = cipher.encrypt(block)
                    mac.update(encrypted)
                    target.write(encrypted)
                aad_size = _aad_length(aad)
                mac.update(aad_size.to_bytes(8, "big"))
                _aad_update(mac.update, aad)
                target.write(mac.digest())
            return
        iv = None if mode == "ecb" else generate_random_bytes(16)
        if iv is not None:
            register_nonce(key, iv, mode)
        cipher = _new_cipher(mode, key, iv)
        with _atomic_target(destination) as target:
            if iv is not None:
                target.write(iv)
            if mode in {"ecb", "cbc"}:
                previous = b""
                while block := source.read(CHUNK):
                    previous += block
                    complete = len(previous) // 16 * 16
                    if complete:
                        target.write(cipher.encrypt(previous[:complete]))
                        previous = previous[complete:]
                target.write(cipher.encrypt(pad(previous, 16)))
            else:
                while block := source.read(CHUNK):
                    target.write(cipher.encrypt(block))


def decrypt_file(source_path: str | Path, destination: str | Path, key: bytes, mode: str, aad: bytes | BinaryIO = b"", iv: bytes | None = None, nonce: bytes | None = None) -> None:
    """Decrypt a file and publish plaintext only after successful validation."""
    with open(source_path, "rb") as source:
        length = os.fstat(source.fileno()).st_size
        if mode == "gcm":
            explicit = nonce if nonce is not None else iv
            stored_nonce = source.read(12) if explicit is None else explicit
            if len(stored_nonce) != 12:
                raise ValueError("invalid GCM nonce")
            head = 12 if explicit is None else 0
            source.seek(head)
            payload_size = length - head - 16
            if payload_size < 0:
                raise ValueError("invalid GCM ciphertext length")
            source.seek(-16, os.SEEK_END)
            tag = source.read(16)
            source.seek(head)
            from modes import AuthenticationError
            cipher = AES.new(key, AES.MODE_GCM, nonce=stored_nonce, mac_len=16)
            _aad_update(cipher.update, aad)
            _consume_exact(source, payload_size, lambda block: cipher.decrypt(block))
            try:
                cipher.verify(tag)
            except ValueError as exc:
                raise AuthenticationError("Authentication failed: AAD mismatch or ciphertext tampered") from exc
            source.seek(head)
            second = AES.new(key, AES.MODE_GCM, nonce=stored_nonce, mac_len=16)
            _aad_update(second.update, aad)
            with _atomic_target(destination) as target:
                _consume_exact(source, payload_size, lambda block: target.write(second.decrypt(block)))
                try:
                    second.verify(tag)
                except ValueError as exc:
                    raise AuthenticationError("Authentication failed: ciphertext changed during read") from exc
            return
        if mode == "etm":
            if length < 48:
                from aead import EtMAuthenticationError
                raise EtMAuthenticationError("Authentication failed: invalid input length")
            authenticated_size = length - 32
            source.seek(authenticated_size)
            tag = source.read(32)
            mac = HMAC(_derive_etm_key(key, b"authentication"))
            mac.update(ETM_DOMAIN)
            mac.update(authenticated_size.to_bytes(8, "big"))
            source.seek(0)
            _consume_exact(source, authenticated_size, mac.update)
            aad_size = _aad_length(aad)
            mac.update(aad_size.to_bytes(8, "big"))
            _aad_update(mac.update, aad)
            if not secrets.compare_digest(tag, mac.digest()):
                from aead import EtMAuthenticationError
                raise EtMAuthenticationError("Authentication failed: AAD mismatch or ciphertext tampered")
            source.seek(0)
            counter = source.read(16)
            cipher = _new_cipher("ctr", _derive_etm_key(key, b"encryption")[:16], counter)
            second_mac = HMAC(_derive_etm_key(key, b"authentication"))
            second_mac.update(ETM_DOMAIN)
            second_mac.update(authenticated_size.to_bytes(8, "big"))
            second_mac.update(counter)
            def checked_decrypt(block):
                second_mac.update(block)
                target.write(cipher.decrypt(block))
            with _atomic_target(destination) as target:
                _consume_exact(source, authenticated_size - 16, checked_decrypt)
                second_mac.update(aad_size.to_bytes(8, "big"))
                _aad_update(second_mac.update, aad)
                if not secrets.compare_digest(tag, second_mac.digest()):
                    from aead import EtMAuthenticationError
                    raise EtMAuthenticationError("Authentication failed: ciphertext changed during read")
            return
        if mode == "ecb":
            offset = 0
        elif iv is not None:
            offset = 0
        else:
            iv = source.read(16)
            offset = 16
            if len(iv) != 16:
                raise ValueError("input file is too short to contain a 16-byte IV")
        cipher = _new_cipher(mode, key, iv)
        with _atomic_target(destination) as target:
            if mode in {"ecb", "cbc"}:
                cipher_size = length - offset
                if cipher_size == 0 or cipher_size % 16:
                    raise ValueError("ciphertext must contain complete AES blocks")
                previous = b""
                while block := source.read(CHUNK):
                    previous += block
                    complete = (len(previous) - 16) // 16 * 16
                    if complete > 0:
                        target.write(cipher.decrypt(previous[:complete]))
                        previous = previous[complete:]
                try:
                    target.write(unpad(cipher.decrypt(previous), 16))
                except ValueError as exc:
                    from cryptocore.modes import PaddingError
                    raise PaddingError("invalid PKCS#7 padding") from exc
            else:
                while block := source.read(CHUNK):
                    target.write(cipher.decrypt(block))
