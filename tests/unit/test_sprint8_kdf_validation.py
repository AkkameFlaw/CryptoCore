import pytest

from kdf import derive_key, pbkdf2_hmac_sha256


@pytest.mark.parametrize(
    "password",
    [None, 123, 3.14, object()],
)
def test_pbkdf2_rejects_invalid_password_type(
    password,
):
    with pytest.raises(TypeError):
        pbkdf2_hmac_sha256(
            password,
            b"salt",
            1,
            32,
        )


@pytest.mark.parametrize(
    "iterations",
    ["2", 1.5, True, None],
)
def test_pbkdf2_rejects_invalid_iteration_type(
    iterations,
):
    with pytest.raises(TypeError):
        pbkdf2_hmac_sha256(
            b"password",
            b"salt",
            iterations,
            32,
        )


@pytest.mark.parametrize(
    "length",
    ["32", 3.14, True, None],
)
def test_pbkdf2_rejects_invalid_length_type(
    length,
):
    with pytest.raises(TypeError):
        pbkdf2_hmac_sha256(
            b"password",
            b"salt",
            1,
            length,
        )


@pytest.mark.parametrize(
    "master_key",
    [None, "secret", 123],
)
def test_hierarchy_rejects_invalid_master_key(
    master_key,
):
    with pytest.raises(TypeError):
        derive_key(
            master_key,
            "encryption",
            32,
        )


@pytest.mark.parametrize(
    "context",
    [None, b"encryption", 123],
)
def test_hierarchy_rejects_invalid_context_type(
    context,
):
    with pytest.raises(TypeError):
        derive_key(
            b"master-key",
            context,
            32,
        )


@pytest.mark.parametrize(
    "length",
    ["32", 1.5, True, None],
)
def test_hierarchy_rejects_invalid_length_type(
    length,
):
    with pytest.raises(TypeError):
        derive_key(
            b"master-key",
            "encryption",
            length,
        )


@pytest.mark.parametrize(
    "length",
    [0, -1],
)
def test_hierarchy_rejects_invalid_length(
    length,
):
    with pytest.raises(ValueError):
        derive_key(
            b"master-key",
            "encryption",
            length,
        )