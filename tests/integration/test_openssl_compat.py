"""Compare AES-128 classic modes with OpenSSL enc, when installed."""

import shutil
import subprocess
from pathlib import Path

import pytest

from cryptocore.modes import (
    decrypt_cbc,
    decrypt_cfb,
    decrypt_ctr,
    decrypt_ecb,
    decrypt_ofb,
    encrypt_cbc,
    encrypt_cfb,
    encrypt_ctr,
    encrypt_ecb,
    encrypt_ofb,
)


KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
IV = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
DATA = b"CryptoCore OpenSSL comparison" + bytes(range(33))


@pytest.mark.parametrize("mode", ["ecb", "cbc", "cfb", "ofb", "ctr"])
def test_classic_aes_against_openssl(mode):
    """Confirm ciphertext bytes and inverse transform against OpenSSL CLI."""
    openssl = shutil.which("openssl")
    fallback = Path(r"C:\msys64\ucrt64\bin\openssl.exe")
    if openssl is None and fallback.is_file():
        openssl = str(fallback)
    if openssl is None:
        pytest.skip("OpenSSL not found in PATH or default MSYS2 UCRT64 path")

    enc = {
        "ecb": encrypt_ecb,
        "cbc": encrypt_cbc,
        "cfb": encrypt_cfb,
        "ofb": encrypt_ofb,
        "ctr": encrypt_ctr,
    }[mode]
    dec = {
        "ecb": decrypt_ecb,
        "cbc": decrypt_cbc,
        "cfb": decrypt_cfb,
        "ofb": decrypt_ofb,
        "ctr": decrypt_ctr,
    }[mode]

    own = enc(DATA, KEY) if mode == "ecb" else enc(DATA, KEY, IV)
    command = [openssl, "enc", f"-aes-128-{mode}", "-K", KEY.hex(), "-nosalt"]
    if mode != "ecb":
        command.extend(["-iv", IV.hex()])
    if mode not in {"cbc", "ecb"}:
        command.append("-nopad")

    result = subprocess.run(
        command, input=DATA, capture_output=True, check=False
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert result.stdout == own
    inverse = dec(result.stdout, KEY) if mode == "ecb" else dec(result.stdout, KEY, IV)
    assert inverse == DATA

    result_dec = subprocess.run(
        [command[0], command[1], "-d", *command[2:]],
        input=own,
        capture_output=True,
        check=False,
    )
    assert result_dec.returncode == 0, result_dec.stderr.decode(errors="replace")
    assert result_dec.stdout == DATA
