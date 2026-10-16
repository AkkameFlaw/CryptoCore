import hashlib

import pytest

from kdf import pbkdf2_hmac_sha256


@pytest.mark.parametrize(
    "iterations, expected",
    [
        (
            1,
            "120fb6cffcf8b32c43e7225256c4f837"
            "a86548c92ccc35480805987cb70be17b",
        ),
        (
            2,
            "ae4d0c95af6b46d32d0adff928f06dd0"
            "2a303f8ef3c251dfd6e2d85a95474c43",
        ),
        (
            4096,
            "c5e478d59288c841aa530db6845c4c8d"
            "962893a001ce4e11a4963873aa98134a",
        ),
    ],
)
def test_pbkdf2_sha256_vectors(iterations, expected):
    actual = pbkdf2_hmac_sha256(
        b"password",
        b"salt",
        iterations,
        32,
    )

    assert actual.hex() == expected


@pytest.mark.parametrize(
    "length",
    [1, 2, 15, 16, 20, 31, 32, 33, 64, 100],
)
def test_pbkdf2_key_lengths(length):
    password = b"password"
    salt = b"CryptoCore salt"

    actual = pbkdf2_hmac_sha256(
        password,
        salt,
        2,
        length,
    )

    expected = hashlib.pbkdf2_hmac(
        "sha256",
        password,
        salt,
        2,
        dklen=length,
    )

    assert len(actual) == length
    assert actual == expected


@pytest.mark.parametrize(
    "salt",
    [
        b"",
        b"a",
        b"1234567890123456",
        b"S" * 100,
    ],
)
def test_pbkdf2_salt_lengths(salt):
    actual = pbkdf2_hmac_sha256(
        b"secret",
        salt,
        3,
        32,
    )

    expected = hashlib.pbkdf2_hmac(
        "sha256",
        b"secret",
        salt,
        3,
        dklen=32,
    )

    assert actual == expected


def test_pbkdf2_deterministic():
    first = pbkdf2_hmac_sha256(
        b"password",
        b"salt",
        10,
        32,
    )

    second = pbkdf2_hmac_sha256(
        b"password",
        b"salt",
        10,
        32,
    )

    assert first == second


def test_pbkdf2_unicode_password():
    password = "Секретный пароль"
    salt = b"CryptoCore"

    actual = pbkdf2_hmac_sha256(
        password,
        salt,
        2,
        32,
    )

    expected = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        2,
        dklen=32,
    )

    assert actual == expected


def test_pbkdf2_long_password():
    password = b"P" * 100
    salt = b"S" * 32

    actual = pbkdf2_hmac_sha256(
        password,
        salt,
        3,
        64,
    )

    expected = hashlib.pbkdf2_hmac(
        "sha256",
        password,
        salt,
        3,
        dklen=64,
    )

    assert actual == expected


def test_pbkdf2_empty_password():
    actual = pbkdf2_hmac_sha256(
        b"",
        b"salt",
        2,
        32,
    )

    expected = hashlib.pbkdf2_hmac(
        "sha256",
        b"",
        b"salt",
        2,
        dklen=32,
    )

    assert actual == expected


@pytest.mark.parametrize("iterations", [0, -1])
def test_pbkdf2_invalid_iterations(iterations):
    with pytest.raises(ValueError):
        pbkdf2_hmac_sha256(
            b"password",
            b"salt",
            iterations,
            32,
        )


@pytest.mark.parametrize("length", [0, -1])
def test_pbkdf2_invalid_length(length):
    with pytest.raises(ValueError):
        pbkdf2_hmac_sha256(
            b"password",
            b"salt",
            2,
            length,
        )


def test_pbkdf2_invalid_salt():
    with pytest.raises(TypeError):
        pbkdf2_hmac_sha256(
            b"password",
            "salt",
            2,
            32,
        )