import pytest

from cryptocore.modes import (
    decrypt_cbc,
    decrypt_cfb,
    decrypt_ctr,
    decrypt_ecb,
    decrypt_ofb,
    encrypt_cbc,
    encrypt_cfb,
    encrypt_ctr,
    encrypt_ecb,
    encrypt_ofb,
)


KEY = bytes.fromhex(
    "2b7e151628aed2a6abf7158809cf4f3c"
)

PLAINTEXT = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172a"
)

ENCRYPTORS = {
    "ecb": encrypt_ecb,
    "cbc": encrypt_cbc,
    "cfb": encrypt_cfb,
    "ofb": encrypt_ofb,
    "ctr": encrypt_ctr,
}

DECRYPTORS = {
    "ecb": decrypt_ecb,
    "cbc": decrypt_cbc,
    "cfb": decrypt_cfb,
    "ofb": decrypt_ofb,
    "ctr": decrypt_ctr,
}


@pytest.mark.parametrize(
    "mode,iv_hex,expected",
    [
        (
            "ecb",
            None,
            "3ad77bb40d7a3660a89ecaf32466ef97",
        ),
        (
            "cbc",
            "000102030405060708090a0b0c0d0e0f",
            "7649abac8119b246cee98e9b12e9197d",
        ),
        (
            "cfb",
            "000102030405060708090a0b0c0d0e0f",
            "3b3fd92eb72dad20333449f8e83cfb4a",
        ),
        (
            "ofb",
            "000102030405060708090a0b0c0d0e0f",
            "3b3fd92eb72dad20333449f8e83cfb4a",
        ),
        (
            "ctr",
            "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
            "874d6191b620e3261bef6864990db6ce",
        ),
    ],
)
def test_nist_sp800_38a_first_block(
    mode,
    iv_hex,
    expected,
):
    encrypt = ENCRYPTORS[mode]
    decrypt = DECRYPTORS[mode]

    if mode == "ecb":
        ciphertext = encrypt(
            PLAINTEXT,
            KEY,
        )

        restored = decrypt(
            ciphertext,
            KEY,
        )

    else:
        iv = bytes.fromhex(iv_hex)

        ciphertext = encrypt(
            PLAINTEXT,
            KEY,
            iv,
        )

        restored = decrypt(
            ciphertext,
            KEY,
            iv,
        )

    assert ciphertext[:16].hex() == expected
    assert restored == PLAINTEXT