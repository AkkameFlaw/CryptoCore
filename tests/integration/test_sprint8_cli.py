import hashlib
import subprocess
import sys

from pathlib import Path

import pytest


AES_KEY = "00112233445566778899aabbccddeeff"
AAD = "aabbccddeeff"


def run_cli(*args):
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "cryptocore",
            *map(str, args),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )


@pytest.mark.parametrize(
    "mode",
    [
        "ecb",
        "cbc",
        "cfb",
        "ofb",
        "ctr",
        "gcm",
        "etm",
    ],
)
def test_all_aes_modes_end_to_end(
    tmp_path: Path,
    mode,
):
    original = tmp_path / "original.bin"
    encrypted = tmp_path / "encrypted.bin"
    decrypted = tmp_path / "decrypted.bin"

    payload = (
        b"CryptoCore Sprint 8 integration test"
        + bytes(range(256))
    )

    original.write_bytes(payload)

    additional_args = (
        ["--aad", AAD]
        if mode in {"gcm", "etm"}
        else []
    )

    encryption = run_cli(
        "--algorithm", "aes",
        "--mode", mode,
        "--encrypt",
        "--key", AES_KEY,
        "--input", original,
        "--output", encrypted,
        *additional_args,
    )

    assert encryption.returncode == 0, encryption.stderr
    assert encrypted.is_file()

    decryption = run_cli(
        "--algorithm", "aes",
        "--mode", mode,
        "--decrypt",
        "--key", AES_KEY,
        "--input", encrypted,
        "--output", decrypted,
        *additional_args,
    )

    assert decryption.returncode == 0, decryption.stderr
    assert decrypted.read_bytes() == payload


@pytest.mark.parametrize("mode", ["gcm", "etm"])
def test_authentication_failure_preserves_output(
    tmp_path: Path,
    mode,
):
    original = tmp_path / "original.bin"
    encrypted = tmp_path / "encrypted.bin"
    destination = tmp_path / "destination.bin"

    original.write_bytes(b"Important authenticated data")
    destination.write_bytes(b"DO NOT OVERWRITE")

    encryption = run_cli(
        "--algorithm", "aes",
        "--mode", mode,
        "--encrypt",
        "--key", AES_KEY,
        "--input", original,
        "--output", encrypted,
        "--aad", AAD,
    )

    assert encryption.returncode == 0, encryption.stderr

    corrupted = bytearray(encrypted.read_bytes())
    corrupted[-1] ^= 1
    encrypted.write_bytes(corrupted)

    decryption = run_cli(
        "--algorithm", "aes",
        "--mode", mode,
        "--decrypt",
        "--key", AES_KEY,
        "--input", encrypted,
        "--output", destination,
        "--aad", AAD,
    )

    assert decryption.returncode == 1
    assert destination.read_bytes() == b"DO NOT OVERWRITE"


@pytest.mark.parametrize(
    "algorithm",
    ["sha256", "sha3-256"],
)
def test_hash_cli_end_to_end(
    tmp_path: Path,
    algorithm,
):
    original = tmp_path / "document.bin"
    content = b"CryptoCore hashing integration test"

    original.write_bytes(content)

    result = run_cli(
        "dgst",
        "--algorithm", algorithm,
        "--input", original,
    )

    expected = hashlib.new(
        algorithm.replace("-", "_"),
        content,
    ).hexdigest()

    assert result.returncode == 0, result.stderr
    assert expected in result.stdout


def test_hmac_generate_and_verify(
    tmp_path: Path,
):
    original = tmp_path / "message.bin"
    signature = tmp_path / "message.hmac"

    original.write_bytes(
        b"CryptoCore HMAC integration test"
    )

    key = "0b" * 20

    creation = run_cli(
        "dgst",
        "--algorithm", "sha256",
        "--hmac",
        "--key", key,
        "--input", original,
        "--output", signature,
    )

    assert creation.returncode == 0, creation.stderr
    assert signature.exists()

    verification = run_cli(
        "dgst",
        "--algorithm", "sha256",
        "--hmac",
        "--key", key,
        "--input", original,
        "--verify", signature,
    )

    assert verification.returncode == 0
    assert "successful" in verification.stdout.lower()


def test_pbkdf2_cli_end_to_end(
    tmp_path: Path,
):
    output = tmp_path / "derived.key"

    result = run_cli(
        "derive",
        "--algorithm", "pbkdf2",
        "--allow-insecure-password-argv", "--show-key", "--password", "password",
        "--salt", "73616c74",
        "--iterations", "2",
        "--length", "32",
        "--output", output,
    )

    expected = hashlib.pbkdf2_hmac(
        "sha256",
        b"password",
        b"salt",
        2,
        dklen=32,
    )

    assert result.returncode == 0, result.stderr
    assert output.read_bytes() == expected
    assert result.stdout == (
        f"{expected.hex()} 73616c74\n"
    )


def test_missing_input_file(
    tmp_path: Path,
):
    result = run_cli(
        "--algorithm", "aes",
        "--mode", "ecb",
        "--encrypt",
        "--key", AES_KEY,
        "--input", tmp_path / "missing.bin",
        "--output", tmp_path / "encrypted.bin",
    )

    assert result.returncode != 0
    assert not (tmp_path / "encrypted.bin").exists()


def test_invalid_aes_key(
    tmp_path: Path,
):
    original = tmp_path / "original.bin"
    encrypted = tmp_path / "encrypted.bin"

    original.write_bytes(b"Test")

    result = run_cli(
        "--algorithm", "aes",
        "--mode", "cbc",
        "--encrypt",
        "--key", "1234",
        "--input", original,
        "--output", encrypted,
    )

    assert result.returncode != 0
    assert not encrypted.exists()