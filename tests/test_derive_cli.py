import hashlib
from pathlib import Path

from cryptocore.cli import (
    build_derive_parser,
    resolve_salt,
    run,
)


def test_derive_known_answer(capsys):
    result = run([
        "derive",
        "--algorithm", "pbkdf2",
        "--password", "password",
        "--salt", "73616c74",
        "--iterations", "1",
        "--length", "32",
    ])

    expected = hashlib.pbkdf2_hmac(
        "sha256", b"password", b"salt", 1, 32
    )

    assert result == 0
    assert capsys.readouterr().out == (
        f"{expected.hex()}  73616c74\n"
    )


def test_derive_binary_output(tmp_path: Path, capsys):
    output = tmp_path / "derived.key"

    result = run([
        "derive",
        "--password", "password",
        "--salt", "73616c74",
        "--iterations", "2",
        "--length", "16",
        "--output", str(output),
    ])

    expected = hashlib.pbkdf2_hmac(
        "sha256", b"password", b"salt", 2, 16
    )

    assert result == 0
    assert output.read_bytes() == expected
    assert output.stat().st_size == 16
    assert capsys.readouterr().out == (
        f"{expected.hex()}  73616c74\n"
    )


def test_derive_generated_salt(capsys):
    result = run([
        "derive",
        "--password", "password",
        "--iterations", "1",
        "--length", "16",
    ])

    assert result == 0

    key_hex, salt_hex = (
        capsys.readouterr().out.strip().split()
    )

    assert len(bytes.fromhex(key_hex)) == 16
    assert len(bytes.fromhex(salt_hex)) == 16

    expected = hashlib.pbkdf2_hmac(
        "sha256",
        b"password",
        bytes.fromhex(salt_hex),
        1,
        16,
    )

    assert bytes.fromhex(key_hex) == expected


def test_1000_unique_salts():
    salts = [
        resolve_salt(None)
        for _ in range(1000)
    ]

    assert all(len(salt) == 16 for salt in salts)
    assert len(set(salts)) == 1000


def test_derive_password_environment(monkeypatch, capsys):
    monkeypatch.setenv(
        "CRYPTOCORE_TEST_PASSWORD",
        "Пароль!123",
    )

    assert run([
        "derive",
        "--password-env", "CRYPTOCORE_TEST_PASSWORD",
        "--salt", "00112233445566778899aabbccddeeff",
        "--iterations", "2",
        "--length", "32",
    ]) == 0

    expected = hashlib.pbkdf2_hmac(
        "sha256",
        "Пароль!123".encode("utf-8"),
        bytes.fromhex("00112233445566778899aabbccddeeff"),
        2,
        32,
    )

    assert (
        capsys.readouterr().out.split()[0]
        == expected.hex()
    )


def test_derive_password_file(tmp_path: Path, capsys):
    password_file = tmp_path / "password.bin"
    password_file.write_bytes(b"secret\x00password")

    assert run([
        "derive",
        "--password-file", str(password_file),
        "--salt", "73616c74",
        "--iterations", "2",
        "--length", "32",
    ]) == 0

    expected = hashlib.pbkdf2_hmac(
        "sha256",
        b"secret\x00password",
        b"salt",
        2,
        32,
    )

    assert (
        capsys.readouterr().out.split()[0]
        == expected.hex()
    )


def test_derive_invalid_hex_salt(capsys):
    assert run([
        "derive",
        "--password", "test",
        "--salt", "nothex",
        "--iterations", "1",
    ]) == 2

    assert "--salt" in capsys.readouterr().err


def test_derive_invalid_iterations(capsys):
    assert run([
        "derive",
        "--password", "test",
        "--iterations", "0",
    ]) == 2

    assert "--iterations" in capsys.readouterr().err


def test_derive_invalid_length(capsys):
    assert run([
        "derive",
        "--password", "test",
        "--iterations", "1",
        "--length", "0",
    ]) == 2

    assert "--length" in capsys.readouterr().err


def test_derive_requires_password(capsys):
    assert run([
        "derive",
        "--iterations", "1",
    ]) == 2

    assert "required" in capsys.readouterr().err


def test_derive_rejects_unknown_algorithm(capsys):
    assert run([
        "derive",
        "--algorithm", "hkdf",
        "--password", "test",
        "--iterations", "1",
    ]) == 2

    assert "invalid choice" in capsys.readouterr().err


def test_derive_parser_defaults():
    args = build_derive_parser().parse_args([
        "--password", "test",
    ])

    assert args.algorithm == "pbkdf2"
    assert args.iterations == 100_000
    assert args.length == 32