from pathlib import Path

from cryptocore.cli import run


KEY = "00112233445566778899aabbccddeeff"


def build_arguments(
    operation: str,
    source: Path,
    output: Path,
    aad_file: Path,
) -> list[str]:
    return [
        "--algorithm", "aes",
        "--mode", "gcm",
        operation,
        "--key", KEY,
        "--input", str(source),
        "--output", str(output),
        "--aad-file", str(aad_file),
    ]


def test_gcm_aad_file_round_trip(tmp_path: Path):
    source = tmp_path / "plain.bin"
    encrypted = tmp_path / "encrypted.bin"
    decrypted = tmp_path / "decrypted.bin"
    aad_file = tmp_path / "metadata.bin"

    data = b"CryptoCore authenticated encryption"

    source.write_bytes(data)
    aad_file.write_bytes(bytes(range(256)) * 1024)

    assert run(
        build_arguments(
            "--encrypt",
            source,
            encrypted,
            aad_file,
        )
    ) == 0

    assert run(
        build_arguments(
            "--decrypt",
            encrypted,
            decrypted,
            aad_file,
        )
    ) == 0

    assert decrypted.read_bytes() == data


def test_gcm_modified_aad_file_rejected(tmp_path: Path):
    source = tmp_path / "plain.bin"
    encrypted = tmp_path / "encrypted.bin"
    output = tmp_path / "should_not_exist.bin"
    aad_file = tmp_path / "metadata.bin"

    source.write_bytes(b"Secret message")
    aad_file.write_bytes(b"Original metadata")

    assert run(
        build_arguments(
            "--encrypt",
            source,
            encrypted,
            aad_file,
        )
    ) == 0

    aad_file.write_bytes(b"Modified metadata")

    assert run(
        build_arguments(
            "--decrypt",
            encrypted,
            output,
            aad_file,
        )
    ) == 1

    assert not output.exists()


def test_gcm_aad_file_preserves_existing_output(tmp_path: Path):
    source = tmp_path / "plain.bin"
    encrypted = tmp_path / "encrypted.bin"
    output = tmp_path / "existing.bin"
    aad_file = tmp_path / "metadata.bin"

    source.write_bytes(b"Secret message")
    aad_file.write_bytes(b"Original metadata")
    output.write_bytes(b"KEEP THIS FILE")

    assert run(
        build_arguments(
            "--encrypt",
            source,
            encrypted,
            aad_file,
        )
    ) == 0

    aad_file.write_bytes(b"Wrong metadata")

    assert run(
        build_arguments(
            "--decrypt",
            encrypted,
            output,
            aad_file,
        )
    ) == 1

    assert output.read_bytes() == b"KEEP THIS FILE"


def test_gcm_aad_and_aad_file_conflict(tmp_path: Path):
    source = tmp_path / "plain.bin"
    encrypted = tmp_path / "encrypted.bin"
    aad_file = tmp_path / "metadata.bin"

    source.write_bytes(b"message")
    aad_file.write_bytes(b"metadata")

    arguments = build_arguments(
        "--encrypt",
        source,
        encrypted,
        aad_file,
    )

    arguments.extend(["--aad", "aabbcc"])

    assert run(arguments) == 2
    assert not encrypted.exists()