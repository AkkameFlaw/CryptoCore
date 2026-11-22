"""Security regressions: cross-API nonce reuse and native GCM authentication."""
from __future__ import annotations

import io
import sqlite3
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor

import pytest

from aead import EncryptThenMAC
from cryptocore import cli, streaming
from cryptocore.nonce_registry import register_nonce
from modes import AuthenticationError, GCM

KEY = bytes.fromhex("d5bc5d2d327419834a52d7f9bab512ec")
NONCE_12 = bytes.fromhex("00112233445566778899aabb")
NONCE_16 = bytes.fromhex("00112233445566778899aabbccddeeff")


def test_library_gcm_rejects_same_key_nonce_between_instances():
    first = GCM(KEY, NONCE_12).encrypt(b"first")
    assert GCM(KEY, NONCE_12).decrypt(first) == b"first"
    with pytest.raises(ValueError, match="reuse"):
        GCM(KEY, NONCE_12).encrypt(b"second")


def test_library_gcm_rejects_nonce_when_registry_unavailable(monkeypatch, tmp_path):
    monkeypatch.setenv("CRYPTOCORE_NONCE_DB", str(tmp_path / "missing" / "database.db"))
    (tmp_path / "missing").write_bytes(b"file, not a directory")
    with pytest.raises(OSError):
        GCM(KEY, NONCE_12).encrypt(b"classified")


def test_library_etm_rejects_same_nonce_between_instances():
    EncryptThenMAC(KEY).encrypt(b"first", nonce=NONCE_16)
    with pytest.raises(ValueError, match="reuse"):
        EncryptThenMAC(KEY).encrypt(b"second", nonce=NONCE_16)


def test_cli_legacy_ctr_rejects_repeated_generated_iv(monkeypatch):
    monkeypatch.setattr(cli, "generate_random_bytes", lambda length: NONCE_16)
    cli.encrypt_data(b"hello", KEY, "ctr")
    with pytest.raises(ValueError, match="reuse"):
        cli.encrypt_data(b"world", KEY, "ctr")


@pytest.mark.parametrize("mode", ["cbc", "cfb", "ofb", "ctr"])
def test_legacy_in_memory_iv_regression(monkeypatch, mode):
    monkeypatch.setattr(cli, "generate_random_bytes", lambda length: NONCE_16)
    cli.encrypt_data(b"one", KEY, mode)
    with pytest.raises(ValueError, match="reuse"):
        cli.encrypt_data(b"two", KEY, mode)


def test_cross_api_stream_and_library_gcm(monkeypatch, tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"small payload")
    monkeypatch.setattr(streaming, "generate_random_bytes", lambda n: NONCE_12)
    streaming.encrypt_file(source, tmp_path / "cipher.bin", KEY, "gcm")
    with pytest.raises(ValueError, match="reuse"):
        GCM(KEY, NONCE_12).encrypt(b"other")


def test_cross_api_stream_and_library_etm(monkeypatch, tmp_path):
    source = tmp_path / "source.bin"
    source.write_bytes(b"small payload")
    monkeypatch.setattr(streaming, "generate_random_bytes", lambda n: NONCE_16)
    streaming.encrypt_file(source, tmp_path / "cipher.bin", KEY, "etm")
    with pytest.raises(ValueError, match="reuse"):
        EncryptThenMAC(KEY).encrypt(b"other", nonce=NONCE_16)


def test_gcm_authenticates_in_memory_with_non_standard_nonce():
    nonce = bytes(range(16))
    cipher = GCM(KEY, nonce).encrypt(b"message", io.BytesIO(b"aad"))
    assert GCM(KEY, nonce).decrypt(cipher, io.BytesIO(b"aad")) == b"message"
    with pytest.raises(AuthenticationError):
        GCM(KEY, nonce).decrypt(cipher, b"bad aad")


def test_concurrent_registry_claims_only_once(tmp_path):
    registry = tmp_path / "concurrent.sqlite3"
    def attempt(_):
        try:
            register_nonce(KEY, NONCE_12, "gcm", database=registry)
            return True
        except ValueError:
            return False
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(attempt, range(12)))
    assert results.count(True) == 1
    with closing(sqlite3.connect(registry)) as connection:
        assert connection.execute("SELECT COUNT(*) FROM used_nonces").fetchone()[0] == 1


def test_gcm_runtime_does_not_expose_table_based_ghash():
    import modes.gcm as implementation
    assert not hasattr(implementation, "_GFMultiplier")
