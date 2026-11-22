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
        "--allow-insecure-password-argv", "--show-key", "--password", "password",
        "--salt", "73616c74",
        "--iterations", "1",
        "--length", "32",
    ])

    expected = hashlib.pbkdf2_hmac(
        "sha256", b"password", b"salt", 1, 32
    )

    assert result == 0
    assert capsys.readouterr().out == (
        f"{expected.hex()} 73616c74\n"
    )


def test_derive_binary_output(tmp_path: Path, capsys):
    output = tmp_path / "derived.key"

    result = run([
        "derive",
        "--allow-insecure-password-argv", "--show-key", "--password", "password",
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
        f"{expected.hex()} 73616c74\n"
    )


def test_derive_generated_salt(capsys):
    result = run([
        "derive",
        "--allow-insecure-password-argv", "--show-key", "--password", "password",
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
        "--show-key", "--password-env", "CRYPTOCORE_TEST_PASSWORD",
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
        "--show-key", "--password-file", str(password_file),
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
        "--allow-insecure-password-argv", "--show-key", "--password", "test",
        "--salt", "nothex",
        "--iterations", "1",
    ]) == 2

    assert "--salt" in capsys.readouterr().err


def test_derive_invalid_iterations(capsys):
    assert run([
        "derive",
        "--allow-insecure-password-argv", "--show-key", "--password", "test",
        "--iterations", "0",
    ]) == 2

    assert "--iterations" in capsys.readouterr().err


def test_derive_invalid_length(capsys):
    assert run([
        "derive",
        "--allow-insecure-password-argv", "--show-key", "--password", "test",
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
        "--allow-insecure-password-argv", "--show-key", "--password", "test",
        "--iterations", "1",
    ]) == 2

    assert "invalid choice" in capsys.readouterr().err


def test_derive_parser_defaults():
    args = build_derive_parser().parse_args([
        "--allow-insecure-password-argv", "--show-key", "--password", "test",
    ])

    assert args.algorithm == "pbkdf2"
    assert args.iterations == 100_000
    assert args.length == 32

def test_derive_length_upper_bound(capsys):
    result = run([
        "derive",
        "--allow-insecure-password-argv", "--show-key", "--password", "password",
        "--salt", "73616c74",
        "--iterations", "1",
        "--length", "65537",
    ])

    captured = capsys.readouterr()

    assert result == 2
    assert "65536" in captured.err


def test_derive_zeroizes_password_and_key(
    monkeypatch,
    tmp_path: Path,
):
    captured = {}
    original_write = __import__("cryptocore.cli", fromlist=["_write_private_key"])._write_private_key

    def fake_pbkdf2(password, salt, iterations, dklen):
        captured["password"] = password
        return b"\xaa" * dklen

    def capture_private_write(path, data):
        captured["key"] = data
        return original_write(path, data)

    monkeypatch.setattr(
        "cryptocore.cli.pbkdf2_hmac_sha256",
        fake_pbkdf2,
    )
    monkeypatch.setattr(
        "cryptocore.cli._write_private_key",
        capture_private_write,
    )

    output = tmp_path / "key.bin"

    result = run([
        "derive",
        "--allow-insecure-password-argv", "--show-key", "--password", "SecretPassword123!",
        "--salt", "73616c74",
        "--iterations", "1",
        "--length", "16",
        "--output", str(output),
    ])

    assert result == 0
    assert output.read_bytes() == b"\xaa" * 16

    assert isinstance(captured["password"], bytearray)
    assert isinstance(captured["key"], bytearray)

    assert captured["password"] == b"\x00" * 18
    assert captured["key"] == b"\x00" * 16


def test_password_not_printed_on_error(
    monkeypatch,
    capsys,
):
    secret = "SecretPassword123!"

    def fake_pbkdf2(password, salt, iterations, dklen):
        raise ValueError("derivation failed")

    monkeypatch.setattr(
        "cryptocore.cli.pbkdf2_hmac_sha256",
        fake_pbkdf2,
    )

    result = run([
        "derive",
        "--allow-insecure-password-argv", "--show-key", "--password", secret,
        "--salt", "73616c74",
        "--iterations", "1",
        "--length", "16",
    ])

    captured = capsys.readouterr()

    assert result == 2
    assert secret not in captured.out
    assert secret not in captured.err