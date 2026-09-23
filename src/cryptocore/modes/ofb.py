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
    return process_ofb(
        data,
        key,
        iv,
    )