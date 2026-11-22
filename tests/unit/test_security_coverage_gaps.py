import argparse
import getpass
import io
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from cryptocore import cli
from cryptocore import digest
from cryptocore.file_io import read_binary, write_binary

KEY = bytes.fromhex("d5bc5d2d327419834a52d7f9bab512ec")
KEY_HEX = KEY.hex()
IV_HEX = "000102030405060708090a0b0c0d0e0f"
NONCE_HEX = "00112233445566778899aabb"

@pytest.mark.parametrize(
    "function,value,error",
    [
        (cli.parse_key, "12", "32 hexadecimal"),
        (cli.parse_key, "z" * 32, "valid hexadecimal"),
        (cli.parse_hmac_key, "0", "even-length"),
        (cli.parse_hmac_key, "zz", "even-length"),
        (cli.parse_iv, "12", "32 hexadecimal"),
        (cli.parse_iv, "z" * 32, "valid hexadecimal"),
        (cli.parse_nonce, "12", "24 hexadecimal"),
        (cli.parse_nonce, "z" * 24, "valid hexadecimal"),
        (cli.parse_aad, "0", "even-length"),
        (cli.parse_aad, "xx", "even-length"),
        (cli.resolve_salt, "0", "even-length"),
        (cli.resolve_salt, "zz", "even-length"),
    ],
)
def test_cli_rejects_malformed_hex(function, value, error):
    with pytest.raises(cli.ArgumentError, match=error):
        function(value)

def test_cli_accepts_valid_key_material_and_aad(monkeypatch):
    assert cli.parse_key(KEY_HEX) == KEY
    assert cli.parse_hmac_key("00abff") == b"\x00\xab\xff"
    assert cli.parse_iv(IV_HEX) == bytes.fromhex(IV_HEX)
    assert cli.parse_nonce(NONCE_HEX) == bytes.fromhex(NONCE_HEX)
    assert cli.parse_aad(None) == b""
    assert cli.parse_aad("") == b""
    assert cli.parse_aad("aabb") == b"\xaa\xbb"
    assert cli.resolve_salt("73616c74") == b"salt"
    monkeypatch.setattr(
        cli,
        "generate_random_bytes",
        lambda count: b"R" * count,
    )
    assert cli.resolve_salt(None) == b"R" * 16

def _aes_arguments(**overrides):
    values = dict(
        algorithm="aes",
        mode="gcm",
        iv=None,
        nonce=None,
        encrypt=True,
        decrypt=False,
        aad=None,
        aad_file=None,
    )
    values.update(overrides)
    return argparse.Namespace(**values)

@pytest.mark.parametrize(
    "changes,fragment",
    [
        ({"algorithm": "des"}, "--algorithm"),
        ({"mode": "unknown"}, "--mode"),
        (
            {"iv": IV_HEX, "nonce": NONCE_HEX},
            "cannot be used together",
        ),
        ({"iv": IV_HEX}, "--encrypt"),
        ({"nonce": NONCE_HEX}, "--encrypt"),
        (
            {
                "mode": "ecb",
                "encrypt": False,
                "decrypt": True,
                "iv": IV_HEX,
            },
            "ECB",
        ),
        (
            {
                "mode": "ctr",
                "encrypt": False,
                "decrypt": True,
                "nonce": NONCE_HEX,
            },
            "GCM",
        ),
        (
            {
                "mode": "etm",
                "encrypt": False,
                "decrypt": True,
                "iv": IV_HEX,
            },
            "EtM",
        ),
        ({"mode": "ofb", "aad": "aa"}, "GCM and EtM"),
        (
            {"aad": "aa", "aad_file": "metadata.bin"},
            "cannot be used together",
        ),
        (
            {"mode": "cbc", "aad_file": "metadata.bin"},
            "GCM and EtM",
        ),
    ],
)
def test_cli_rejects_incompatible_aes_options(
    changes,
    fragment,
):
    with pytest.raises(cli.ArgumentError, match=fragment):
        cli.validate_arguments(
            _aes_arguments(**changes)
        )

@pytest.mark.parametrize(
    "mode",
    ["ecb", "cbc", "cfb", "ofb", "ctr", "gcm", "etm"],
)
def test_in_memory_helpers_roundtrip_all_modes(mode):
    plaintext = (
        b"Legacy CryptoCore API coverage"
        + bytes(range(31))
    )
    aad = (
        b"authenticated-metadata"
        if mode in {"gcm", "etm"}
        else b""
    )
    encrypted = cli.encrypt_data(
        plaintext,
        KEY,
        mode,
        aad,
    )
    decrypted = cli.decrypt_data(
        encrypted,
        KEY,
        mode,
        None,
        aad,
    )
    assert decrypted == plaintext

@pytest.mark.parametrize(
    "mode",
    ["cbc", "cfb", "ofb", "ctr"],
)
def test_in_memory_explicit_iv_without_iv_prefix(mode):
    plaintext = b"Explicit IV test with non-aligned length"
    encrypted = cli.encrypt_data(
        plaintext,
        KEY,
        mode,
    )
    assert cli.decrypt_data(
        encrypted[16:],
        KEY,
        mode,
        encrypted[:16].hex(),
    ) == plaintext

def test_in_memory_gcm_explicit_nonce():
    plaintext = b"GCM explicit nonce integration"
    encrypted = cli.encrypt_data(
        plaintext,
        KEY,
        "gcm",
        b"metadata",
    )
    nonce_hex = encrypted[:12].hex()

    assert cli.decrypt_data(
        encrypted[12:],
        KEY,
        "gcm",
        None,
        b"metadata",
        nonce_hex,
    ) == plaintext

    assert cli.decrypt_data(
        encrypted[12:],
        KEY,
        "gcm",
        nonce_hex,
        b"metadata",
    ) == plaintext

def test_in_memory_gcm_rejects_truncated_payload():
    with pytest.raises(cli.AuthenticationError):
        cli.decrypt_data(
            b"short",
            KEY,
            "gcm",
            None,
        )

@pytest.mark.parametrize(
    "mode",
    ["cbc", "cfb", "ofb", "ctr"],
)
def test_in_memory_rejects_missing_iv_prefix(mode):
    with pytest.raises(
        ValueError,
        match="16-byte IV",
    ):
        cli.decrypt_data(
            b"short",
            KEY,
            mode,
            None,
        )

def test_default_output_paths():
    assert cli.get_default_output(
        "example.bin",
        False,
    ) == "example.bin.enc"

    assert cli.get_default_output(
        "example.bin",
        True,
    ) == "example.bin.dec"

def test_file_io_reads_and_writes_root_and_nested_paths(
    tmp_path,
    monkeypatch,
):
    monkeypatch.chdir(tmp_path)

    write_binary("local.bin", b"hello")
    assert read_binary("local.bin") == b"hello"

    nested = Path("nested") / "deep" / "payload.bin"
    write_binary(nested, b"hello nested")
    assert read_binary(nested) == b"hello nested"

    with pytest.raises(FileNotFoundError):
        read_binary("missing.bin")

def test_password_prompt_is_not_echoed(monkeypatch):
    monkeypatch.setattr(
        getpass,
        "getpass",
        lambda prompt: "NotPrintedByCLI",
    )

    args = argparse.Namespace(
        password=None,
        password_prompt=True,
        password_env=None,
        password_file=None,
    )

    secret = cli.resolve_password(args)

    assert secret == b"NotPrintedByCLI"
    secret[:] = b"\x00" * len(secret)

def test_password_argument_is_deleted_from_namespace():
    args = argparse.Namespace(
        password="Pass123!",
        password_prompt=False,
        password_env=None,
        password_file=None,
    )

    secret = cli.resolve_password(args)

    assert args.password is None
    assert secret == b"Pass123!"

    secret[:] = b"\x00" * len(secret)

def test_password_env_missing_is_rejected(monkeypatch):
    monkeypatch.delenv(
        "CRYPTOCORE_ABSENT_SECRET",
        raising=False,
    )

    args = argparse.Namespace(
        password=None,
        password_prompt=False,
        password_env="CRYPTOCORE_ABSENT_SECRET",
        password_file=None,
    )

    with pytest.raises(
        cli.ArgumentError,
        match="not found",
    ):
        cli.resolve_password(args)

def test_password_file_size_guard(tmp_path):
    huge = tmp_path / "oversized_password"
    huge.write_bytes(b"x" * 4097)

    args = argparse.Namespace(
        password=None,
        password_prompt=False,
        password_env=None,
        password_file=str(huge),
    )

    with pytest.raises(
        cli.ArgumentError,
        match="4096",
    ):
        cli.resolve_password(args)

def _key_args(tmp_path, **overrides):
    values = dict(
        key_file=None,
        key=None,
        decrypt=False,
        encrypt=True,
        input_file=str(tmp_path / "input.bin"),
        output_file=str(tmp_path / "output.bin"),
        key_output=None,
        show_key=False,
    )
    values.update(overrides)
    return argparse.Namespace(**values)

def test_generate_key_private_sidecar_and_explicit_display(
    monkeypatch,
    tmp_path,
    capsys,
):
    monkeypatch.setattr(
        cli,
        "generate_random_bytes",
        lambda length: KEY,
    )

    args = _key_args(
        tmp_path,
        show_key=True,
    )

    assert cli.resolve_key(args) == KEY
    assert (
        tmp_path / "output.bin.key"
    ).read_bytes() == KEY

    printed = capsys.readouterr()

    assert KEY_HEX in printed.out
    assert "key saved" in printed.err.lower()

    with pytest.raises(FileExistsError):
        cli.resolve_key(args)

def test_resolve_key_file_and_missing_key(tmp_path):
    keyfile = tmp_path / "key.bin"
    keyfile.write_bytes(KEY)

    assert cli.resolve_key(
        _key_args(
            tmp_path,
            key_file=str(keyfile),
        )
    ) == KEY

    keyfile.write_bytes(b"short")

    with pytest.raises(
        cli.ArgumentError,
        match="16 raw key bytes",
    ):
        cli.resolve_key(
            _key_args(
                tmp_path,
                key_file=str(keyfile),
            )
        )

    with pytest.raises(
        cli.ArgumentError,
        match="required for decryption",
    ):
        cli.resolve_key(
            _key_args(
                tmp_path,
                key=None,
                decrypt=True,
            )
        )

def test_supplied_weak_key_warning(tmp_path, capsys):
    assert cli.resolve_key(
        _key_args(
            tmp_path,
            key="aa" * 16,
        )
    ) == b"\xaa" * 16

    assert "weak" in capsys.readouterr().err.lower()

@pytest.mark.parametrize(
    "argv,fragment",
    [
        (["derive"], "usage:"),
        (
            [
                "derive",
                "--password-file",
                "does-not-exist",
                "--iterations",
                "1",
            ],
            "--output",
        ),
        (
            [
                "derive",
                "--password-file",
                "does-not-exist",
                "--iterations",
                "0",
                "--output",
                "key.bin",
            ],
            "at least 1",
        ),
        (["dgst"], "usage:"),
        (["--algorithm", "aes"], "usage:"),
    ],
)
def test_parser_errors_return_nonzero(
    argv,
    fragment,
    capsys,
):
    assert cli.run(argv) == 2
    assert fragment in capsys.readouterr().err

def test_main_routes_sys_argv(monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        ["cryptocore", "--help"],
    )

    assert cli.main() == 0
    assert "usage:" in capsys.readouterr().out

def test_digest_rejects_conflicting_options(
    tmp_path,
    capsys,
):
    file = tmp_path / "msg"
    file.write_bytes(b"hash me")

    cases = [
        [
            "--algorithm", "sha256",
            "--input", str(file),
            "--key", "00",
        ],
        [
            "--algorithm", "sha256",
            "--input", str(file),
            "--verify", str(file),
        ],
        [
            "--algorithm", "sha256",
            "--input", str(file),
            "--hmac",
        ],
        [
            "--algorithm", "sha3-256",
            "--input", str(file),
            "--hmac",
            "--key", "00",
        ],
        [
            "--algorithm", "sha256",
            "--input", str(file),
            "--hmac",
            "--key", "00",
            "--output", str(file),
            "--verify", str(file),
        ],
    ]

    for case in cases:
        assert cli.run(
            ["dgst", *case]
        ) == 2
        assert "error:" in capsys.readouterr().err

def test_digest_stdin_for_hash_and_hmac(monkeypatch):
    monkeypatch.setattr(
        sys,
        "stdin",
        SimpleNamespace(
            buffer=io.BytesIO(b"message")
        ),
    )

    assert len(
        digest.hash_file("-", "sha256")
    ) == 64

    monkeypatch.setattr(
        sys,
        "stdin",
        SimpleNamespace(
            buffer=io.BytesIO(b"message")
        ),
    )

    assert len(
        digest.hmac_file("-", b"secret")
    ) == 64

def test_digest_verify_file_validation(tmp_path):
    digest_file = tmp_path / "bad_hmac.txt"

    for content, expected in [
        ("", "empty"),
        ("abcd", "64 hexadecimal"),
        ("z" * 64, "hexadecimal"),
    ]:
        digest_file.write_text(
            content,
            encoding="utf-8",
        )

        with pytest.raises(
            ValueError,
            match=expected,
        ):
            digest.read_expected_hmac(
                str(digest_file)
            )

def test_plain_digest_output_file(tmp_path):
    message = tmp_path / "message"
    report = tmp_path / "digest.txt"

    message.write_bytes(b"content")

    assert cli.run([
        "dgst",
        "--algorithm", "sha256",
        "--input", str(message),
        "--output", str(report),
    ]) == 0

    assert str(message) in report.read_text(
        encoding="utf-8"
    )

def test_private_key_creation_cleans_up_on_write_error(
    monkeypatch,
    tmp_path,
):
    import os

    destination = tmp_path / "incomplete.key"

    def broken_fdopen(fd, mode):
        os.close(fd)
        raise OSError(
            "injected descriptor failure"
        )

    monkeypatch.setattr(
        cli.os,
        "fdopen",
        broken_fdopen,
    )

    with pytest.raises(
        OSError,
        match="injected",
    ):
        cli._write_private_key(
            str(destination),
            KEY,
        )

    assert not destination.exists()

def test_run_reports_missing_input_and_validation(
    capsys,
    tmp_path,
):
    missing = tmp_path / "missing.bin"

    assert cli.run([
        "--algorithm", "aes",
        "--mode", "ecb",
        "--encrypt",
        "--key", KEY_HEX,
        "--input", str(missing),
    ]) == 2

    assert "input file" in capsys.readouterr().err

    missing.write_bytes(b"input")

    assert cli.run([
        "--algorithm", "aes",
        "--mode", "unsupported",
        "--encrypt",
        "--key", KEY_HEX,
        "--input", str(missing),
    ]) == 2

    assert "--mode" in capsys.readouterr().err

def test_derive_reports_write_failure_without_printing_secret(
    tmp_path,
    capsys,
):
    password_file = tmp_path / "password.bin"
    password_file.write_bytes(
        b"DontLeakMeInErrors"
    )

    output = (
        tmp_path
        / "nonexistent_parent"
        / "derived.key"
    )

    assert cli.run([
        "derive",
        "--password-file", str(password_file),
        "--salt", "73616c74",
        "--iterations", "1",
        "--length", "16",
        "--output", str(output),
    ]) == 2

    result = capsys.readouterr()

    assert "DontLeakMeInErrors" not in (
        result.out + result.err
    )
    assert not output.exists()

def test_prompt_password_end_to_end(
    monkeypatch,
    tmp_path,
    capsys,
):
    monkeypatch.setattr(
        getpass,
        "getpass",
        lambda prompt: "correct horse battery",
    )

    output = tmp_path / "derived.key"

    assert cli.run([
        "derive",
        "--password-prompt",
        "--salt", "73616c74",
        "--iterations", "1",
        "--length", "16",
        "--output", str(output),
    ]) == 0

    assert len(output.read_bytes()) == 16
    assert (
        "correct horse battery"
        not in capsys.readouterr().out
    )

def test_streaming_helpers_validate_unexpected_input(
    tmp_path,
):
    from cryptocore import streaming

    with pytest.raises(
        ValueError,
        match="unsupported",
    ):
        streaming._new_cipher(
            "missing",
            KEY,
            None,
        )

    with pytest.raises(
        ValueError,
        match="truncated",
    ):
        streaming._consume_exact(
            io.BytesIO(b"AB"),
            3,
            lambda chunk: None,
        )

def test_streaming_atomic_output_does_not_replace_on_error(
    tmp_path,
):
    from cryptocore import streaming

    destination = tmp_path / "existing.bin"
    destination.write_bytes(
        b"must survive"
    )

    with pytest.raises(
        RuntimeError,
        match="deliberate",
    ):
        with streaming._atomic_target(
            destination
        ) as target:
            target.write(
                b"new but unauthenticated"
            )
            raise RuntimeError(
                "deliberate failure"
            )

    assert destination.read_bytes() == (
        b"must survive"
    )

    assert list(
        tmp_path.glob(
            ".cryptocore-*.tmp"
        )
    ) == []

def test_streaming_aad_helpers_support_bytes_and_binary_stream():
    from cryptocore import streaming

    seen = []

    assert streaming._aad_update(
        seen.append,
        b"abc",
    ) == 3

    assert seen == [b"abc"]
    assert streaming._aad_length(
        b"abc"
    ) == 3

    stream = io.BytesIO(
        b"0123456789"
    )
    stream.seek(3)

    assert streaming._aad_length(
        stream
    ) == 10

    assert stream.tell() == 3

    seen.clear()

    assert streaming._aad_update(
        seen.append,
        stream,
    ) == 10

    assert b"".join(seen) == (
        b"0123456789"
    )