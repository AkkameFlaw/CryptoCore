import argparse
from pathlib import Path
from tempfile import TemporaryDirectory
from time import perf_counter

from Crypto.Cipher import AES

from cryptocore.cli import run


CHUNK_SIZE = 1024 * 1024
KEY = "00112233445566778899aabbccddeeff"


def create_aad(path: Path, size_mb: int) -> None:
    block = bytes(range(256)) * 4096

    with path.open("wb") as file:
        for _ in range(size_mb):
            file.write(block)


def verify_reference(
    encrypted: bytes,
    aad_path: Path,
    plaintext: bytes,
) -> bool:
    nonce = encrypted[:12]
    ciphertext = encrypted[12:-16]
    tag = encrypted[-16:]

    reference = AES.new(
        bytes.fromhex(KEY),
        AES.MODE_GCM,
        nonce=nonce,
    )

    with aad_path.open("rb") as file:
        while True:
            chunk = file.read(CHUNK_SIZE)

            if not chunk:
                break

            reference.update(chunk)

    try:
        recovered = reference.decrypt_and_verify(
            ciphertext,
            tag,
        )
    except ValueError:
        return False

    return recovered == plaintext


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--size-mb",
        type=int,
        default=16,
    )

    args = parser.parse_args()

    if args.size_mb <= 0:
        parser.error("--size-mb must be positive")

    with TemporaryDirectory(
        prefix="cryptocore_aad_"
    ) as directory:
        root = Path(directory)

        aad_path = root / "large_aad.bin"
        plain_path = root / "plaintext.bin"
        encrypted_path = root / "encrypted.bin"
        decrypted_path = root / "decrypted.bin"

        plaintext = b"CryptoCore Sprint 6 large AAD test"

        plain_path.write_bytes(plaintext)

        print(f"Creating AAD: {args.size_mb} MiB")

        create_aad(aad_path, args.size_mb)

        started = perf_counter()

        encryption_result = run([
            "--algorithm", "aes",
            "--mode", "gcm",
            "--encrypt",
            "--key", KEY,
            "--input", str(plain_path),
            "--output", str(encrypted_path),
            "--aad-file", str(aad_path),
        ])

        if encryption_result != 0:
            raise RuntimeError("GCM encryption failed")

        encrypted = encrypted_path.read_bytes()

        reference_match = verify_reference(
            encrypted,
            aad_path,
            plaintext,
        )

        decryption_result = run([
            "--algorithm", "aes",
            "--mode", "gcm",
            "--decrypt",
            "--key", KEY,
            "--input", str(encrypted_path),
            "--output", str(decrypted_path),
            "--aad-file", str(aad_path),
        ])

        decrypted_match = (
            decryption_result == 0
            and decrypted_path.read_bytes() == plaintext
        )

        elapsed = perf_counter() - started

        print(f"Reference match: {reference_match}")
        print(f"Decryption match: {decrypted_match}")
        print(f"Elapsed: {elapsed:.2f} seconds")

        if not reference_match or not decrypted_match:
            raise SystemExit(1)


if __name__ == "__main__":
    main()