import hashlib
from pathlib import Path

from cryptocore.cli import run


def test_dgst_sha256_stdout(
    tmp_path: Path,
    capsys,
) -> None:
    source = (
        tmp_path / "document.bin"
    )

    data = (
        b"CryptoCore Sprint 4"
    )

    source.write_bytes(
        data
    )

    result = run(
        [
            "dgst",
            "--algorithm",
            "sha256",
            "--input",
            str(source),
        ]
    )

    assert result == 0

    captured = (
        capsys.readouterr()
    )

    expected = (
        hashlib.sha256(
            data
        ).hexdigest()
    )

    assert captured.out == (
        f"{expected}  {source}\n"
    )


def test_dgst_sha3_256_stdout(
    tmp_path: Path,
    capsys,
) -> None:
    source = (
        tmp_path / "document.bin"
    )

    data = (
        b"CryptoCore SHA3-256"
    )

    source.write_bytes(
        data
    )

    result = run(
        [
            "dgst",
            "--algorithm",
            "sha3-256",
            "--input",
            str(source),
        ]
    )

    assert result == 0

    captured = (
        capsys.readouterr()
    )

    expected = (
        hashlib.sha3_256(
            data
        ).hexdigest()
    )

    assert captured.out == (
        f"{expected}  {source}\n"
    )


def test_dgst_output_file(
    tmp_path: Path,
    capsys,
) -> None:
    source = (
        tmp_path / "document.bin"
    )

    output = (
        tmp_path / "document.sha256"
    )

    data = (
        b"output file test"
    )

    source.write_bytes(
        data
    )

    result = run(
        [
            "dgst",
            "--algorithm",
            "sha256",
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

    expected = (
        hashlib.sha256(
            data
        ).hexdigest()
    )

    assert (
        output.read_text(
            encoding="utf-8"
        )
        == f"{expected}  {source}\n"
    )


def test_dgst_empty_file(
    tmp_path: Path,
    capsys,
) -> None:
    source = (
        tmp_path / "empty.bin"
    )

    source.write_bytes(
        b""
    )

    result = run(
        [
            "dgst",
            "--algorithm",
            "sha256",
            "--input",
            str(source),
        ]
    )

    assert result == 0

    captured = (
        capsys.readouterr()
    )

    assert (
        captured.out.startswith(
            "e3b0c44298fc1c149afbf4c8996fb924"
            "27ae41e4649b934ca495991b7852b855"
        )
    )


def test_dgst_invalid_algorithm(
    tmp_path: Path,
    capsys,
) -> None:
    source = (
        tmp_path / "document.bin"
    )

    source.write_bytes(
        b"test"
    )

    result = run(
        [
            "dgst",
            "--algorithm",
            "md5",
            "--input",
            str(source),
        ]
    )

    assert result != 0

    captured = (
        capsys.readouterr()
    )

    assert (
        "sha256, sha3-256"
        in captured.err
    )


def test_dgst_missing_file(
    tmp_path: Path,
    capsys,
) -> None:
    source = (
        tmp_path / "missing.bin"
    )

    result = run(
        [
            "dgst",
            "--algorithm",
            "sha256",
            "--input",
            str(source),
        ]
    )

    assert result != 0

    captured = (
        capsys.readouterr()
    )

    assert (
        "cryptocore: error:"
        in captured.err
    )


def test_dgst_rejects_encryption_arguments(
    tmp_path: Path,
    capsys,
) -> None:
    source = (
        tmp_path / "document.bin"
    )

    source.write_bytes(
        b"test"
    )

    result = run(
        [
            "dgst",
            "--algorithm",
            "sha256",
            "--input",
            str(source),
            "--mode",
            "cbc",
        ]
    )

    assert result != 0

    captured = (
        capsys.readouterr()
    )

    assert (
        "unrecognized arguments"
        in captured.err
    )

def test_hash_large_data_in_chunks(
    tmp_path: Path,
) -> None:
    source = (
        tmp_path
        / "large.bin"
    )

    block = (
        bytes(range(256))
        * 4096
    )

    with source.open(
        "wb"
    ) as file:
        for _ in range(16):
            file.write(
                block
            )

    data = (
        source.read_bytes()
    )

    from cryptocore.digest import (
        hash_file,
    )

    result = hash_file(
        str(source),
        "sha256",
    )

    expected = (
        hashlib.sha256(
            data
        ).hexdigest()
    )

    assert (
        result
        == expected
    )