"""AES-128 OFB mode without padding."""

from Crypto.Cipher import AES

from .common import (
    BLOCK_SIZE,
    validate_iv,
    validate_key,
    xor_bytes,
)


def process_ofb(
    data: bytes,
    key: bytes,
    iv: bytes,
) -> bytes:
    """Apply the symmetric AES-OFB keystream transform.
    
        Args:
            data: Binary input; for ciphertext, the format depends on the selected mode.
            key: Secret key (16 bytes for AES-128; arbitrary bytes for HMAC).
            iv: 16-byte initialization vector or CTR initial counter.
    
        Returns:
            Binary result.
    
        Raises:
            ValueError or PaddingError on malformed keys, IVs or padding.
    """
    validate_key(key)
    validate_iv(iv)

    cipher = AES.new(
        key,
        AES.MODE_ECB,
    )

    result = bytearray()

    feedback = iv

    for offset in range(
        0,
        len(data),
        BLOCK_SIZE,
    ):
        block = data[
            offset:offset + BLOCK_SIZE
        ]

        feedback = cipher.encrypt(
            feedback
        )

        result_block = xor_bytes(
            block,
            feedback[:len(block)],
        )

        result.extend(
            result_block
        )

    return bytes(result)


def encrypt_ofb(
    data: bytes,
    key: bytes,
    iv: bytes,
) -> bytes:
    """Encrypt any-length bytes with AES-128 OFB.
    
        Args:
            data: Binary input; for ciphertext, the format depends on the selected mode.
            key: Secret key (16 bytes for AES-128; arbitrary bytes for HMAC).
            iv: 16-byte initialization vector or CTR initial counter.
    
        Returns:
            Binary result.
    
        Raises:
            ValueError or PaddingError on malformed keys, IVs or padding.
    """
    return process_ofb(
        data,
        key,
        iv,
    )


def decrypt_ofb(
    data: bytes,
    key: bytes,
    iv: bytes,
) -> bytes:
    """Decrypt any-length bytes with AES-128 OFB.
    
        Args:
            data: Binary input; for ciphertext, the format depends on the selected mode.
            key: Secret key (16 bytes for AES-128; arbitrary bytes for HMAC).
            iv: 16-byte initialization vector or CTR initial counter.
    
        Returns:
            Binary result.
    
        Raises:
            ValueError or PaddingError on malformed keys, IVs or padding.
    """
    return process_ofb(
        data,
        key,
        iv,
    )