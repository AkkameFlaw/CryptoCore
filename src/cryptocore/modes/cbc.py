from Crypto.Cipher import AES

from .common import (
    BLOCK_SIZE,
    validate_iv,
    validate_key,
    xor_bytes,
)

from .ecb import (
    pkcs7_pad,
    pkcs7_unpad,
)


def encrypt_cbc(
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

    data = pkcs7_pad(data)

    encrypted = bytearray()

    previous = iv

    for offset in range(
        0,
        len(data),
        BLOCK_SIZE,
    ):
        block = data[
            offset:offset + BLOCK_SIZE
        ]

        mixed = xor_bytes(
            block,
            previous,
        )

        encrypted_block = cipher.encrypt(
            mixed
        )

        encrypted.extend(
            encrypted_block
        )

        previous = encrypted_block

    return bytes(encrypted)


def decrypt_cbc(
    data: bytes,
    key: bytes,
    iv: bytes,
) -> bytes:
    validate_key(key)
    validate_iv(iv)

    if not data:
        raise ValueError(
            "ciphertext must not be empty"
        )

    if len(data) % BLOCK_SIZE != 0:
        raise ValueError(
            "CBC ciphertext length must be "
            "a multiple of 16 bytes"
        )

    cipher = AES.new(
        key,
        AES.MODE_ECB,
    )

    decrypted = bytearray()

    previous = iv

    for offset in range(
        0,
        len(data),
        BLOCK_SIZE,
    ):
        block = data[
            offset:offset + BLOCK_SIZE
        ]

        decrypted_block = cipher.decrypt(
            block
        )

        plaintext_block = xor_bytes(
            decrypted_block,
            previous,
        )

        decrypted.extend(
            plaintext_block
        )

        previous = block

    return pkcs7_unpad(
        bytes(decrypted)
    )