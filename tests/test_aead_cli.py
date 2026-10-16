from pathlib import Path

from Crypto.Cipher import AES

from cryptocore.cli import run


KEY = "00112233445566778899aabbccddeeff"
AAD = "aabbccddeeff"


def cli_args(mode, operation, source, output, aad=AAD):
    return [
        "--algorithm", "aes",
        "--mode", mode,
        operation,
        "--key", KEY,
        "--input", str(source),
        "--output", str(output),
        "--aad", aad,
    ]


def test_gcm_cli_round_trip(tmp_path: Path):
    source = tmp_path / "plaintext.bin"
    encrypted = tmp_path / "encrypted.bin"
    decrypted = tmp_path / "decrypted.bin"

    data = b"CryptoCore Sprint 6 GCM test"
    source.write_bytes(data)

    assert run(cli_args(
        "gcm", "--encrypt", source, encrypted
    )) == 0

    assert run(cli_args(
        "gcm", "--decrypt", encrypted, decrypted
    )) == 0

    assert decrypted.read_bytes() == data

    ciphertext = encrypted.read_bytes()
    assert len(ciphertext) == 12 + len(data) + 16


def test_gcm_cli_matches_reference(tmp_path: Path):
    source = tmp_path / "plain.bin"
    encrypted = tmp_path / "encrypted.bin"

    data = b"GCM independent verification"
    source.write_bytes(data)

    assert run(cli_args(
        "gcm", "--encrypt", source, encrypted
    )) == 0

    payload = encrypted.read_bytes()
    nonce = payload[:12]
    ciphertext = payload[12:-16]
    tag = payload[-16:]

    reference = AES.new(
        bytes.fromhex(KEY),
        AES.MODE_GCM,
        nonce=nonce,
    )
    reference.update(bytes.fromhex(AAD))

    assert reference.decrypt_and_verify(
        ciphertext, tag
    ) == data


def test_gcm_wrong_aad_creates_no_file(
    tmp_path: Path,
    capsys,
):
    source = tmp_path / "plain.bin"
    encrypted = tmp_path / "encrypted.bin"
    output = tmp_path / "should_not_exist.bin"

    source.write_bytes(b"Confidential information")

    assert run(cli_args(
        "gcm", "--encrypt", source, encrypted
    )) == 0

    result = run(cli_args(
        "gcm", "--decrypt", encrypted, output,
        aad="112233445566",
    ))

    assert result == 1
    assert not output.exists()

    captured = capsys.readouterr()

    assert "Authentication failed" in captured.err
    assert "Confidential information" not in captured.out


def test_gcm_failure_preserves_existing_file(
    tmp_path: Path,
):
    source = tmp_path / "plain.bin"
    encrypted = tmp_path / "encrypted.bin"
    output = tmp_path / "existing.bin"

    source.write_bytes(b"Important secret")
    output.write_bytes(b"DO NOT OVERWRITE")

    assert run(cli_args(
        "gcm", "--encrypt", source, encrypted
    )) == 0

    result = run(cli_args(
        "gcm", "--decrypt", encrypted, output,
        aad="001122",
    ))

    assert result == 1
    assert output.read_bytes() == b"DO NOT OVERWRITE"


def test_gcm_tampered_ciphertext(
    tmp_path: Path,
):
    source = tmp_path / "plain.bin"
    encrypted = tmp_path / "encrypted.bin"
    output = tmp_path / "decrypted.bin"

    source.write_bytes(b"Authenticated encryption")

    assert run(cli_args(
        "gcm", "--encrypt", source, encrypted
    )) == 0

    payload = bytearray(encrypted.read_bytes())
    payload[12] ^= 1
    encrypted.write_bytes(payload)

    assert run(cli_args(
        "gcm", "--decrypt", encrypted, output
    )) == 1

    assert not output.exists()


def test_gcm_tampered_tag(tmp_path: Path):
    source = tmp_path / "plain.bin"
    encrypted = tmp_path / "encrypted.bin"
    output = tmp_path / "decrypted.bin"

    source.write_bytes(b"Authenticated encryption")

    assert run(cli_args(
        "gcm", "--encrypt", source, encrypted
    )) == 0

    payload = bytearray(encrypted.read_bytes())
    payload[-1] ^= 1
    encrypted.write_bytes(payload)

    assert run(cli_args(
        "gcm", "--decrypt", encrypted, output
    )) == 1

    assert not output.exists()


def test_gcm_explicit_nonce(tmp_path: Path):
    source = tmp_path / "plain.bin"
    encrypted = tmp_path / "encrypted.bin"
    detached = tmp_path / "detached.bin"
    decrypted = tmp_path / "decrypted.bin"

    source.write_bytes(b"Explicit nonce test")

    assert run(cli_args(
        "gcm", "--encrypt", source, encrypted
    )) == 0

    payload = encrypted.read_bytes()
    nonce = payload[:12]
    detached.write_bytes(payload[12:])

    arguments = cli_args(
        "gcm", "--decrypt", detached, decrypted
    )

    arguments.extend(["--nonce", nonce.hex()])

    assert run(arguments) == 0
    assert decrypted.read_bytes() == source.read_bytes()


def test_gcm_invalid_aad(tmp_path: Path, capsys):
    source = tmp_path / "plain.bin"
    output = tmp_path / "encrypted.bin"

    source.write_bytes(b"message")

    arguments = cli_args(
        "gcm", "--encrypt", source, output,
        aad="wrongaad123",
    )

    assert run(arguments) == 2
    assert not output.exists()
    assert "hexadecimal" in capsys.readouterr().err


def test_gcm_empty_aad(tmp_path: Path):
    source = tmp_path / "plain.bin"
    encrypted = tmp_path / "encrypted.bin"
    decrypted = tmp_path / "decrypted.bin"

    source.write_bytes(b"Empty AAD test")

    assert run(cli_args(
        "gcm", "--encrypt", source, encrypted,
        aad="",
    )) == 0

    assert run(cli_args(
        "gcm", "--decrypt", encrypted, decrypted,
        aad="",
    )) == 0

    assert decrypted.read_bytes() == source.read_bytes()


def test_etm_cli_round_trip(tmp_path: Path):
    source = tmp_path / "plain.bin"
    encrypted = tmp_path / "encrypted.bin"
    decrypted = tmp_path / "decrypted.bin"

    data = b"CryptoCore Encrypt-then-MAC"
    source.write_bytes(data)

    assert run(cli_args(
        "etm", "--encrypt", source, encrypted
    )) == 0

    assert run(cli_args(
        "etm", "--decrypt", encrypted, decrypted
    )) == 0

    assert decrypted.read_bytes() == data
    assert len(encrypted.read_bytes()) == 16 + len(data) + 32


def test_etm_wrong_aad_creates_no_file(
    tmp_path: Path,
):
    source = tmp_path / "plain.bin"
    encrypted = tmp_path / "encrypted.bin"
    output = tmp_path / "should_not_exist.bin"

    source.write_bytes(b"Secret message")

    assert run(cli_args(
        "etm", "--encrypt", source, encrypted
    )) == 0

    assert run(cli_args(
        "etm", "--decrypt", encrypted, output,
        aad="112233",
    )) == 1

    assert not output.exists()


def test_etm_tampered_tag(tmp_path: Path):
    source = tmp_path / "plain.bin"
    encrypted = tmp_path / "encrypted.bin"
    output = tmp_path / "decrypted.bin"

    source.write_bytes(b"EtM authentication test")

    assert run(cli_args(
        "etm", "--encrypt", source, encrypted
    )) == 0

    payload = bytearray(encrypted.read_bytes())
    payload[-1] ^= 1
    encrypted.write_bytes(payload)

    assert run(cli_args(
        "etm", "--decrypt", encrypted, output
    )) == 1

    assert not output.exists()


def test_aad_rejected_for_legacy_mode(tmp_path: Path):
    source = tmp_path / "plain.bin"
    output = tmp_path / "encrypted.bin"

    source.write_bytes(b"message")

    assert run(cli_args(
        "cbc", "--encrypt", source, output
    )) == 2

    assert not output.exists()