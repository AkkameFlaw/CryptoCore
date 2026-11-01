"""AES-128 CTR mode with a 128-bit big-endian counter."""

from Crypto.Cipher import AES

from .common import (
    BLOCK_SIZE,
    validate_iv,
    validate_key,
    xor_bytes,
)


COUNTER_LIMIT = 1 << 128


def process_ctr(
    data: bytes,
    key: bytes,
    iv: bytes,
) -> bytes:
    """Apply the symmetric AES-CTR keystream transform.
    
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

    counter = int.from_bytes(
        iv,
        byteorder="big",
    )

    for offset in range(
        0,
        len(data),
        BLOCK_SIZE,
    ):
        block = data[
            offset:offset + BLOCK_SIZE
        ]

        counter_block = counter.to_bytes(
            BLOCK_SIZE,
            byteorder="big",
        )

        stream = cipher.encrypt(
            counter_block
        )

        result_block = xor_bytes(
            block,
            stream[:len(block)],
        )

        result.extend(
            result_block
        )

        counter = (
            counter + 1
        ) % COUNTER_LIMIT

    return bytes(result)


def encrypt_ctr(
    data: bytes,
    key: bytes,
    iv: bytes,
) -> bytes:
    """Encrypt any-length bytes with AES-128 CTR.
    
        Args:
            data: Binary input; for ciphertext, the format depends on the selected mode.
            key: Secret key (16 bytes for AES-128; arbitrary bytes for HMAC).
            iv: 16-byte initialization vector or CTR initial counter.
    
        Returns:
            Binary result.
    
        Raises:
            ValueError or PaddingError on malformed keys, IVs or padding.
    """
    return process_ctr(
        data,
        key,
        iv,
    )


def decrypt_ctr(
    data: bytes,
    key: bytes,
    iv: bytes,
) -> bytes:
    """Decrypt any-length bytes with AES-128 CTR.
    
        Args:
            data: Binary input; for ciphertext, the format depends on the selected mode.
            key: Secret key (16 bytes for AES-128; arbitrary bytes for HMAC).
            iv: 16-byte initialization vector or CTR initial counter.
    
        Returns:
            Binary result.
    
        Raises:
            ValueError or PaddingError on malformed keys, IVs or padding.
    """
    return process_ctr(
        data,
        key,
        iv,
    )