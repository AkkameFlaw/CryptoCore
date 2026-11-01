"""Shared validation and XOR helpers for AES-128 modes."""

BLOCK_SIZE = 16


def validate_key(key: bytes) -> None:
    """Require a 16-byte AES-128 key.
    
        Args:
            key: Secret key (16 bytes for AES-128; arbitrary bytes for HMAC).
    
        Returns:
            Nothing; raises on validation failure.
    
        Raises:
            ValueError or PaddingError on malformed keys, IVs or padding.
    """
    if len(key) != BLOCK_SIZE:
        raise ValueError(
            "AES-128 key must be exactly 16 bytes"
        )


def validate_iv(iv: bytes) -> None:
    """Require a 16-byte IV for classical AES modes.
    
        Args:
            iv: 16-byte initialization vector or CTR initial counter.
    
        Returns:
            Nothing; raises on validation failure.
    
        Raises:
            ValueError or PaddingError on malformed keys, IVs or padding.
    """
    if len(iv) != BLOCK_SIZE:
        raise ValueError(
            "IV must be exactly 16 bytes"
        )


def xor_bytes(
    left: bytes,
    right: bytes,
) -> bytes:
    """XOR corresponding bytes of two inputs; output length is the shorter input.
    
        Args:
            left: First byte sequence.
            right: Second byte sequence.
    
        Returns:
            Binary result.
    
        Raises:
            ValueError or PaddingError on malformed keys, IVs or padding.
    """
    return bytes(
        a ^ b
        for a, b in zip(left, right)
    )