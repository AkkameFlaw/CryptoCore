"""Public exports of the aead package."""

from .encrypt_then_mac import (
    EncryptThenMAC,
    EtMAuthenticationError,
)


__all__ = [
    "EncryptThenMAC",
    "EtMAuthenticationError",
]