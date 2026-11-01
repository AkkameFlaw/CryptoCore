"""Explicit opt-in AES-128 throughput benchmark; not a pytest test."""

import argparse
from time import perf_counter

from cryptocore.modes import decrypt_ctr, encrypt_ctr


def main() -> None:
    """Benchmark encrypt and decrypt on a generated test buffer."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--size-mb", type=int, default=1)
    args = parser.parse_args()
    if not 1 <= args.size_mb <= 64:
        parser.error("--size-mb must be between 1 and 64")
    data = bytes(range(256)) * (args.size_mb * 1024 * 1024 // 256)
    key = bytes.fromhex("00112233445566778899aabbccddeeff")
    iv = bytes.fromhex("00000000000000000000000000000001")
    started = perf_counter()
    ciphertext = encrypt_ctr(data, key, iv)
    enc_seconds = perf_counter() - started
    started = perf_counter()
    plaintext = decrypt_ctr(ciphertext, key, iv)
    dec_seconds = perf_counter() - started
    assert plaintext == data
    amount_mib = len(data) / (1024 * 1024)
    print(f"AES-128 CTR plaintext: {amount_mib:.0f} MiB")
    print(f"Encrypt: {enc_seconds:.6f} s, {amount_mib / max(enc_seconds, 1e-12):.2f} MiB/s")
    print(f"Decrypt: {dec_seconds:.6f} s, {amount_mib / max(dec_seconds, 1e-12):.2f} MiB/s")
    print("Round trip: True")


if __name__ == "__main__":
    main()
