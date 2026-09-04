from pathlib import Path

from cryptocore.cli import run


KEY = (
    "000102030405060708090a0b0c0d0e0f"
)


def test_cli_encrypt_decrypt(
    tmp_path: Path,
) -> None:

    input_file = (
        tmp_path / "input.bin"
    )

    encrypted_file = (
        tmp_path / "encrypted.bin"
    )

    decrypted_file = (
        tmp_path / "decrypted.bin"
    )

    original_data = (
        bytes(range(256))
        + b"\x00\xff"
        + b"CryptoCore binary test"
    )

    input_file.write_bytes(
        original_data
    )

    encrypt_result = run(
        [
            "--algorithm",
            "aes",
            "--mode",
            "ecb",
            "--encrypt",
            "--key",
            KEY,
            "--input",
            str(input_file),
            "--output",
            str(encrypted_file),
        ]
    )

    assert encrypt_result == 0

    assert encrypted_file.exists()

    decrypt_result = run(
        [
            "--algorithm",
            "aes",
            "--mode",
            "ecb",
            "--decrypt",
            "--key",
            KEY,
            "--input",
            str(encrypted_file),
            "--output",
            str(decrypted_file),
        ]
    )

    assert decrypt_result == 0

    assert decrypted_file.exists()

    assert (
        decrypted_file.read_bytes()
        == original_data
    )


def test_invalid_key(
    tmp_path: Path,
    capsys,
) -> None:

    input_file = (
        tmp_path / "input.txt"
    )

    input_file.write_bytes(
        b"hello"
    )

    result = run(
        [
            "--algorithm",
            "aes",
            "--mode",
            "ecb",
            "--encrypt",
            "--key",
            "1234",
            "--input",
            str(input_file),
        ]
    )

    assert result != 0

    captured = capsys.readouterr()

    assert (
        "--key"
        in captured.err
    )


def test_invalid_algorithm(
    tmp_path: Path,
    capsys,
) -> None:

    input_file = (
        tmp_path / "input.txt"
    )

    input_file.write_bytes(
        b"hello"
    )

    result = run(
        [
            "--algorithm",
            "des",
            "--mode",
            "ecb",
            "--encrypt",
            "--key",
            KEY,
            "--input",
            str(input_file),
        ]
    )

    assert result != 0

    captured = capsys.readouterr()

    assert (
        "--algorithm"
        in captured.err
    )


def test_invalid_mode(
    tmp_path: Path,
    capsys,
) -> None:

    input_file = (
        tmp_path / "input.txt"
    )

    input_file.write_bytes(
        b"hello"
    )

    result = run(
        [
            "--algorithm",
            "aes",
            "--mode",
            "cbc",
            "--encrypt",
            "--key",
            KEY,
            "--input",
            str(input_file),
        ]
    )

    assert result != 0

    captured = capsys.readouterr()

    assert (
        "--mode"
        in captured.err
    )


def test_missing_input_file(
    tmp_path: Path,
    capsys,
) -> None:

    missing_file = (
        tmp_path / "missing.bin"
    )

    result = run(
        [
            "--algorithm",
            "aes",
            "--mode",
            "ecb",
            "--encrypt",
            "--key",
            KEY,
            "--input",
            str(missing_file),
        ]
    )

    assert result != 0

    captured = capsys.readouterr()

    assert (
        "error"
        in captured.err.lower()
    )


def test_default_output_name(
    tmp_path: Path,
) -> None:

    input_file = (
        tmp_path / "input.txt"
    )

    input_file.write_bytes(
        b"default output test"
    )

    result = run(
        [
            "--algorithm",
            "aes",
            "--mode",
            "ecb",
            "--encrypt",
            "--key",
            KEY,
            "--input",
            str(input_file),
        ]
    )

    assert result == 0

    expected_output = Path(
        str(input_file) + ".enc"
    )

    assert expected_output.exists()