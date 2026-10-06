import hashlib
import hmac
from pathlib import Path

import pytest

from cryptocore.cli import run


def reference_hmac(
    key: bytes,
    data: bytes,
) -> str:
    return hmac.new(
        key,
        data,
        hashlib.sha256,
    ).hexdigest()


def test_hmac_stdout(
    tmp_path: Path,
    capsys,
) -> None:
    source = (
        tmp_path / "message.bin"
    )

    data = (
        b"CryptoCore Sprint 5"
    )

    key = bytes.fromhex(
        "00112233445566778899aabbccddeeff"
    )

    source.write_bytes(
        data
    )

    result = run(
        [
            "dgst",
            "--algorithm",
            "sha256",
            "--hmac",
            "--key",
            key.hex(),
            "--input",
            str(source),
        ]
    )

    assert result == 0

    captured = (
        capsys.readouterr()
    )

    expected = reference_hmac(
        key,
        data,
    )

    assert captured.out == (
        f"{expected} {source}\n"
    )


def test_hmac_requires_key(
    tmp_path: Path,
    capsys,
) -> None:
    source = (
        tmp_path / "message.bin"
    )

    source.write_bytes(
        b"test"
    )

    result = run(
        [
            "dgst",
            "--algorithm",
            "sha256",
            "--hmac",
            "--input",
            str(source),
        ]
    )

    assert result != 0

    captured = (
        capsys.readouterr()
    )

    assert (
        "--key is required"
        in captured.err
    )


def test_key_without_hmac_fails(
    tmp_path: Path,
    capsys,
) -> None:
    source = (
        tmp_path / "message.bin"
    )

    source.write_bytes(
        b"test"
    )

    result = run(
        [
            "dgst",
            "--algorithm",
            "sha256",
            "--key",
            "00112233",
            "--input",
            str(source),
        ]
    )

    assert result != 0

    captured = (
        capsys.readouterr()
    )

    assert (
        "--key requires --hmac"
        in captured.err
    )


def test_hmac_rejects_sha3(
    tmp_path: Path,
    capsys,
) -> None:
    source = (
        tmp_path / "message.bin"
    )

    source.write_bytes(
        b"test"
    )

    result = run(
        [
            "dgst",
            "--algorithm",
            "sha3-256",
            "--hmac",
            "--key",
            "00112233",
            "--input",
            str(source),
        ]
    )

    assert result != 0

    captured = (
        capsys.readouterr()
    )

    assert (
        "only sha256"
        in captured.err
    )


def test_hmac_output_file(
    tmp_path: Path,
    capsys,
) -> None:
    source = (
        tmp_path / "message.bin"
    )

    output = (
        tmp_path / "message.hmac"
    )

    data = (
        b"HMAC output test"
    )

    key = bytes.fromhex(
        "00112233445566778899aabbccddeeff"
    )

    source.write_bytes(
        data
    )

    result = run(
        [
            "dgst",
            "--algorithm",
            "sha256",
            "--hmac",
            "--key",
            key.hex(),
            "--input",
            str(source),
            "--output",
            str(output),
        ]
    )

    assert result == 0

    captured = (
        capsys.readouterr()
    )

    assert captured.out == ""

    expected = reference_hmac(
        key,
        data,
    )

    assert (
        output.read_text(
            encoding="utf-8"
        )
        == f"{expected} {source}\n"
    )


def test_hmac_verify_success(
    tmp_path: Path,
    capsys,
) -> None:
    source = (
        tmp_path / "message.bin"
    )

    expected_file = (
        tmp_path / "message.hmac"
    )

    data = (
        b"authenticated message"
    )

    key = bytes.fromhex(
        "00112233445566778899aabbccddeeff"
    )

    source.write_bytes(
        data
    )

    expected = reference_hmac(
        key,
        data,
    )

    expected_file.write_text(
        f"{expected} {source}\n",
        encoding="utf-8",
    )

    result = run(
        [
            "dgst",
            "--algorithm",
            "sha256",
            "--hmac",
            "--key",
            key.hex(),
            "--input",
            str(source),
            "--verify",
            str(expected_file),
        ]
    )

    assert result == 0

    captured = (
        capsys.readouterr()
    )

    assert captured.out == (
        "[OK] HMAC verification successful\n"
    )


def test_hmac_detects_modified_file(
    tmp_path: Path,
    capsys,
) -> None:
    source = (
        tmp_path / "message.bin"
    )

    expected_file = (
        tmp_path / "message.hmac"
    )

    key = bytes.fromhex(
        "00112233445566778899aabbccddeeff"
    )

    source.write_bytes(
        b"original content"
    )

    expected = reference_hmac(
        key,
        b"original content",
    )

    expected_file.write_text(
        f"{expected} {source}\n",
        encoding="utf-8",
    )

    source.write_bytes(
        b"modified content"
    )

    result = run(
        [
            "dgst",
            "--algorithm",
            "sha256",
            "--hmac",
            "--key",
            key.hex(),
            "--input",
            str(source),
            "--verify",
            str(expected_file),
        ]
    )

    assert result == 1

    captured = (
        capsys.readouterr()
    )

    assert captured.err == (
        "[ERROR] HMAC verification failed\n"
    )


def test_hmac_detects_wrong_key(
    tmp_path: Path,
    capsys,
) -> None:
    source = (
        tmp_path / "message.bin"
    )

    expected_file = (
        tmp_path / "message.hmac"
    )

    correct_key = bytes.fromhex(
        "00112233445566778899aabbccddeeff"
    )

    wrong_key = bytes.fromhex(
        "ffeeddccbbaa99887766554433221100"
    )

    data = (
        b"authenticated message"
    )

    source.write_bytes(
        data
    )

    expected = reference_hmac(
        correct_key,
        data,
    )

    expected_file.write_text(
        f"{expected} {source}\n",
        encoding="utf-8",
    )

    result = run(
        [
            "dgst",
            "--algorithm",
            "sha256",
            "--hmac",
            "--key",
            wrong_key.hex(),
            "--input",
            str(source),
            "--verify",
            str(expected_file),
        ]
    )

    assert result == 1

    captured = (
        capsys.readouterr()
    )

    assert (
        "HMAC verification failed"
        in captured.err
    )


@pytest.mark.parametrize(
    "key_size",
    [
        16,
        64,
        100,
    ],
)
def test_hmac_key_sizes(
    tmp_path: Path,
    capsys,
    key_size: int,
) -> None:
    source = (
        tmp_path / "message.bin"
    )

    data = (
        b"variable key length"
    )

    key = (
        b"K" * key_size
    )

    source.write_bytes(
        data
    )

    result = run(
        [
            "dgst",
            "--algorithm",
            "sha256",
            "--hmac",
            "--key",
            key.hex(),
            "--input",
            str(source),
        ]
    )

    assert result == 0

    captured = (
        capsys.readouterr()
    )

    expected = reference_hmac(
        key,
        data,
    )

    assert (
        captured.out
        == f"{expected} {source}\n"
    )


def test_hmac_empty_file(
    tmp_path: Path,
    capsys,
) -> None:
    source = (
        tmp_path / "empty.bin"
    )

    source.write_bytes(
        b""
    )

    key = (
        b"secret"
    )

    result = run(
        [
            "dgst",
            "--algorithm",
            "sha256",
            "--hmac",
            "--key",
            key.hex(),
            "--input",
            str(source),
        ]
    )

    assert result == 0

    captured = (
        capsys.readouterr()
    )

    expected = reference_hmac(
        key,
        b"",
    )

    assert (
        captured.out
        == f"{expected} {source}\n"
    )