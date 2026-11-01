"""AES-128 CFB-128 mode without padding."""

from Crypto.Cipher import AES

from .common import (
    BLOCK_SIZE,
    validate_iv,
    validate_key,
    xor_bytes,
)


def encrypt_cfb(
    data: bytes,
    key: bytes,
    iv: bytes,
) -> bytes:
    """Encrypt any-length bytes with AES-128 CFB-128.
    
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

    encrypted = bytearray()

    feedback = iv

    for offset in range(
        0,
        len(data),
        BLOCK_SIZE,
    ):
        block = data[
            offset:offset + BLOCK_SIZE
        ]

        stream = cipher.encrypt(
            feedback
        )

        encrypted_block = xor_bytes(
            block,
            stream[:len(block)],
        )

        encrypted.extend(
            encrypted_block
        )

        feedback = encrypted_block

    return bytes(encrypted)


def decrypt_cfb(
    data: bytes,
    key: bytes,
    iv: bytes,
) -> bytes:
    """Decrypt any-length bytes with AES-128 CFB-128.
    
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

    decrypted = bytearray()

    feedback = iv

    for offset in range(
        0,
        len(data),
        BLOCK_SIZE,
    ):
        block = data[
            offset:offset + BLOCK_SIZE
        ]

        stream = cipher.encrypt(
            feedback
        )

        plaintext_block = xor_bytes(
            block,
            stream[:len(block)],
        )

        decrypted.extend(
            plaintext_block
        )

        feedback = block

    return bytes(decrypted)