from pathlib import Path

import pytest

from cryptocore.cli import run


KEY = (
    "000102030405060708090a0b0c0d0e0f"
)

IV = (
    "aabbccddeeff00112233445566778899"
)


@pytest.mark.parametrize(
    "mode",
    [
        "ecb",
        "cbc",
        "cfb",
        "ofb",
        "ctr",
    ],
)
def test_cli_roundtrip(
    tmp_path: Path,
    mode: str,
) -> None:
    source = (
        tmp_path / "input.bin"
    )

    encrypted = (
        tmp_path / "encrypted.bin"
    )

    decrypted = (
        tmp_path / "decrypted.bin"
    )

    original = (
        bytes(range(256))
        + b"CryptoCore Sprint 2"
    )

    source.write_bytes(
        original
    )

    encrypt_result = run(
        [
            "--algorithm",
            "aes",
            "--mode",
            mode,
            "--encrypt",
            "--key",
            KEY,
            "--input",
            str(source),
            "--output",
            str(encrypted),
        ]
    )

    assert encrypt_result == 0

    decrypt_result = run(
        [
            "--algorithm",
            "aes",
            "--mode",
            mode,
            "--decrypt",
            "--key",
            KEY,
            "--input",
            str(encrypted),
            "--output",
            str(decrypted),
        ]
    )

    assert decrypt_result == 0

    assert (
        decrypted.read_bytes()
        == original
    )


def test_iv_rejected_for_encrypt(
    tmp_path: Path,
    capsys,
) -> None:
    source = (
        tmp_path / "input.bin"
    )

    source.write_bytes(
        b"test"
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
            "--iv",
            IV,
            "--input",
            str(source),
        ]
    )

    assert result != 0

    captured = capsys.readouterr()

    assert "--iv" in captured.err


def test_short_iv_file(
    tmp_path: Path,
    capsys,
) -> None:
    source = (
        tmp_path / "input.bin"
    )

    source.write_bytes(
        b"short"
    )

    result = run(
        [
            "--algorithm",
            "aes",
            "--mode",
            "ctr",
            "--decrypt",
            "--key",
            KEY,
            "--input",
            str(source),
        ]
    )

    assert result != 0

    captured = capsys.readouterr()

    assert (
        "16-byte IV"
        in captured.err
    )


def test_invalid_iv(
    tmp_path: Path,
    capsys,
) -> None:
    source = (
        tmp_path / "input.bin"
    )

    source.write_bytes(
        b"data"
    )

    result = run(
        [
            "--algorithm",
            "aes",
            "--mode",
            "cfb",
            "--decrypt",
            "--key",
            KEY,
            "--iv",
            "1234",
            "--input",
            str(source),
        ]
    )

    assert result != 0

    captured = capsys.readouterr()

    assert "--iv" in captured.err