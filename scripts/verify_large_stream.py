"""Optional manual >1 GiB encrypted-file check; requires substantial free disk space."""

import argparse
import hashlib
import shutil
import tempfile
import tracemalloc
from pathlib import Path

from cryptocore.streaming import decrypt_file, encrypt_file


def digest(path: Path) -> str:
    """Calculate a reference SHA-256 using bounded memory (verification only)."""
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> int:
    """Create a sparse file, encrypt, decrypt, and compare streamed hashes."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--gib", type=float, default=1.05)
    parser.add_argument("--yes", action="store_true")
    args = parser.parse_args()
    if not args.yes:
        parser.error("requires --yes (this creates several GiB of temporary data)")
    size = int(args.gib * (1024 ** 3))
    if size <= 1024 ** 3:
        parser.error("size must exceed 1 GiB")
    free = shutil.disk_usage(Path.cwd()).free
    if free < 3 * size + 256 * 1024 * 1024:
        parser.error("insufficient disk space for source, ciphertext and decrypted copy")
    with tempfile.TemporaryDirectory(prefix="cryptocore-large-") as directory:
        folder = Path(directory)
        plain = folder / "plain.bin"
        encrypted = folder / "encrypted.gcm"
        decrypted = folder / "decrypted.bin"
        with plain.open("wb") as stream:
            stream.seek(size - 1)
            stream.write(b"\x7f")
        key = bytes(range(16))
        tracemalloc.start()
        encrypt_file(plain, encrypted, key, "gcm")
        decrypt_file(encrypted, decrypted, key, "gcm")
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        matched = digest(plain) == digest(decrypted)
        print(f"Size: {size} bytes")
        print(f"Peak traced Python allocations: {peak / (1024 ** 2):.2f} MiB")
        print(f"Round trip: {matched}")
        return 0 if matched else 1


if __name__ == "__main__":
    raise SystemExit(main())
