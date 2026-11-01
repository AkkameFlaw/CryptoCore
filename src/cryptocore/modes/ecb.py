"""AES-128 ECB mode and PKCS#7 encoding/decoding."""

from Crypto.Cipher import AES

from .common import (
    BLOCK_SIZE,
    validate_key,
)


class PaddingError(ValueError):
    """Raised when PKCS#7 padding is malformed.

    Notes:
        Consult docs/API.md for construction, safety, and examples.
    """
    pass


def pkcs7_pad(
    data: bytes,
    block_size: int = BLOCK_SIZE,
) -> bytes:
    """Append PKCS#7 padding so output is a multiple of block_size.
    
        Args:
            data: Binary input; for ciphertext, the format depends on the selected mode.
            block_size: PKCS#7 block width in bytes (1..255).
    
        Returns:
            Binary result.
    
        Raises:
            ValueError or PaddingError on malformed keys, IVs or padding.
    """
    if block_size <= 0 or block_size > 255:
        raise ValueError(
            "block_size must be in range 1..255"
        )

    padding_length = (
        block_size - len(data) % block_size
    )

    padding = bytes(
        [padding_length]
    ) * padding_length

    return data + padding


def pkcs7_unpad(
    data: bytes,
    block_size: int = BLOCK_SIZE,
) -> bytes:
    """Validate and strip PKCS#7 padding.
    
        Args:
            data: Binary input; for ciphertext, the format depends on the selected mode.
            block_size: PKCS#7 block width in bytes (1..255).
    
        Returns:
            Binary result.
    
        Raises:
            ValueError or PaddingError on malformed keys, IVs or padding.
    
        Security:
            Never log keys or passwords; see docs/SECURITY_AUDIT.md.
    """
    if not data:
        raise PaddingError(
            "invalid PKCS#7 padded data length"
        )

    if len(data) % block_size != 0:
        raise PaddingError(
            "invalid PKCS#7 padded data length"
        )

    padding_length = data[-1]

    if padding_length < 1:
        raise PaddingError(
            "invalid PKCS#7 padding length"
        )

    if padding_length > block_size:
        raise PaddingError(
            "invalid PKCS#7 padding length"
        )

    padding = data[-padding_length:]

    expected_padding = (
        bytes([padding_length])
        * padding_length
    )

    if padding != expected_padding:
        raise PaddingError(
            "invalid PKCS#7 padding bytes"
        )

    return data[:-padding_length]


def encrypt_ecb(
    data: bytes,
    key: bytes,
) -> bytes:
    """Encrypt a message with AES-128 ECB after PKCS#7 padding.
    
        Args:
            data: Binary input; for ciphertext, the format depends on the selected mode.
            key: Secret key (16 bytes for AES-128; arbitrary bytes for HMAC).
    
        Returns:
            Binary result.
    
        Raises:
            ValueError or PaddingError on malformed keys, IVs or padding.
    """
    validate_key(key)

    padded_data = pkcs7_pad(data)

    cipher = AES.new(
        key,
        AES.MODE_ECB,
    )

    encrypted = bytearray()

    for offset in range(
        0,
        len(padded_data),
        BLOCK_SIZE,
    ):
        block = padded_data[
            offset:offset + BLOCK_SIZE
        ]

        encrypted.extend(
            cipher.encrypt(block)
        )

    return bytes(encrypted)


def decrypt_ecb(
    data: bytes,
    key: bytes,
) -> bytes:
    """Decrypt AES-128 ECB and remove PKCS#7 padding.
    
        Args:
            data: Binary input; for ciphertext, the format depends on the selected mode.
            key: Secret key (16 bytes for AES-128; arbitrary bytes for HMAC).
    
        Returns:
            Binary result.
    
        Raises:
            ValueError or PaddingError on malformed keys, IVs or padding.
    """
    validate_key(key)

    if not data:
        raise ValueError(
            "ciphertext must not be empty"
        )

    if len(data) % BLOCK_SIZE != 0:
        raise ValueError(
            "ciphertext length must be "
            "a multiple of 16 bytes"
        )

    cipher = AES.new(
        key,
        AES.MODE_ECB,
    )

    decrypted = bytearray()

    for offset in range(
        0,
        len(data),
        BLOCK_SIZE,
    ):
        block = data[
            offset:offset + BLOCK_SIZE
        ]

        decrypted.extend(
            cipher.decrypt(block)
        )

    return pkcs7_unpad(
        bytes(decrypted)
    )