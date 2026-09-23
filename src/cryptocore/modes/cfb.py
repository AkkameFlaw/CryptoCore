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