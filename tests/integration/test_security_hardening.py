"""Regression tests for security review remediations."""

import hashlib
from pathlib import Path

import pytest

from cryptocore.cli import run
from cryptocore.nonce_registry import register_nonce


KEY = "a1" * 16


def _aes(mode, operation, source, dest, *extra):
    return run([
        "--algorithm", "aes", "--mode", mode, operation,
        "--key", KEY, "--input", str(source), "--output", str(dest),
        *extra,
    ])


def test_nonce_registry_rejects_key_nonce_reuse(tmp_path):
    database = tmp_path / "nonce.db"
    register_nonce(bytes.fromhex(KEY), bytes(16), "ctr", database)
    with pytest.raises(ValueError, match="reuse detected"):
        register_nonce(bytes.fromhex(KEY), bytes(16), "gcm", database)
    register_nonce(b"\x99" * 16, bytes(16), "ctr", database)


def test_cli_nonce_registry_fails_closed(monkeypatch, tmp_path):
    monkeypatch.setenv("CRYPTOCORE_NONCE_DB", str(tmp_path / "nonces.db"))
    monkeypatch.setattr("cryptocore.streaming.generate_random_bytes", lambda size: bytes(size))
    source = tmp_path / "in.bin"
    source.write_bytes(b"identical payload")
    first = tmp_path / "one.bin"
    second = tmp_path / "two.bin"
    assert _aes("gcm", "--encrypt", source, first) == 0
    assert _aes("gcm", "--encrypt", source, second) == 2
    assert first.exists()
    assert not second.exists()


def test_argv_password_requires_explicit_opt_in(capsys):
    secret = "DoNotShowTheSecret"
    assert run(["derive", "--password", secret, "--salt", "73616c74", "--iterations", "1", "--show-key"]) == 2
    log = capsys.readouterr()
    assert secret not in log.out + log.err
    assert "--allow-insecure-password-argv" in log.err


def test_kdf_iteration_limit(capsys):
    assert run(["derive", "--password-file", "unused", "--iterations", "100001", "--output", "key.bin"]) == 2
    assert "--allow-slow-kdf" in capsys.readouterr().err
    assert run(["derive", "--password-file", "unused", "--iterations", "1000001", "--allow-slow-kdf", "--output", "key.bin"]) == 2


def test_derived_key_not_printed_by_default(tmp_path, capsys):
    password = tmp_path / "pwd.bin"
    key = tmp_path / "derived.key"
    password.write_bytes(b"password")
    assert run(["derive", "--password-file", str(password), "--salt", "73616c74", "--iterations", "1", "--output", str(key)]) == 0
    stdout = capsys.readouterr().out
    expected = hashlib.pbkdf2_hmac("sha256", b"password", b"salt", 1, 32)
    assert key.read_bytes() == expected
    assert expected.hex() not in stdout
    assert "73616c74" in stdout


def test_generated_key_never_logged_by_default(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("CRYPTOCORE_NONCE_DB", str(tmp_path / "nonces.db"))
    src = tmp_path / "in"
    out = tmp_path / "encrypted"
    src.write_bytes(b"plaintext")
    assert run(["--algorithm", "aes", "--mode", "ctr", "--encrypt", "--input", str(src), "--output", str(out)]) == 0
    captured = capsys.readouterr()
    key = (tmp_path / "encrypted.key").read_bytes()
    assert len(key) == 16
    assert key.hex() not in captured.out + captured.err
    restored = tmp_path / "restored"
    assert run(["--algorithm", "aes", "--mode", "ctr", "--decrypt", "--key-file", str(tmp_path / "encrypted.key"), "--input", str(out), "--output", str(restored)]) == 0
    assert restored.read_bytes() == b"plaintext"


def test_etm_aad_file_roundtrip(monkeypatch, tmp_path):
    monkeypatch.setenv("CRYPTOCORE_NONCE_DB", str(tmp_path / "nonces.db"))
    source = tmp_path / "plain"
    encrypted = tmp_path / "enc"
    decrypted = tmp_path / "dec"
    associated = tmp_path / "aad"
    source.write_bytes(b"EtM with streamed authenticated metadata")
    associated.write_bytes(bytes(range(256)) * 50)
    assert _aes("etm", "--encrypt", source, encrypted, "--aad-file", str(associated)) == 0
    assert _aes("etm", "--decrypt", encrypted, decrypted, "--aad-file", str(associated)) == 0
    assert decrypted.read_bytes() == source.read_bytes()
    associated.write_bytes(b"tampered")
    untouched = tmp_path / "bad_output"
    assert _aes("etm", "--decrypt", encrypted, untouched, "--aad-file", str(associated)) == 1
    assert not untouched.exists()


@pytest.mark.parametrize("mode", ["ecb", "cbc", "cfb", "ofb", "ctr", "gcm", "etm"])
def test_streamed_cli_roundtrip_across_chunks(monkeypatch, tmp_path, mode):
    monkeypatch.setenv("CRYPTOCORE_NONCE_DB", str(tmp_path / "nonces.db"))
    src = tmp_path / "plain"
    out = tmp_path / "encrypted"
    dst = tmp_path / "decrypted"
    payload = bytes(range(251)) * 523
    src.write_bytes(payload)
    assert _aes(mode, "--encrypt", src, out) == 0
    assert _aes(mode, "--decrypt", out, dst) == 0
    assert dst.read_bytes() == payload
