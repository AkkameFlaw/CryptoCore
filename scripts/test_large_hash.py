import argparse
import hashlib
from pathlib import Path

from cryptocore.digest import hash_file


CHUNK_SIZE = 1024 * 1024


def create_large_file(
    path: Path,
    size_gb: int,
) -> None:
    total_size = (
        size_gb
        * 1024
        * 1024
        * 1024
        + 1
    )

    block = (
        b"\x00"
        * CHUNK_SIZE
    )

    written = 0

    with path.open(
        "wb"
    ) as file:
        while (
            written
            < total_size
        ):
            size = min(
                CHUNK_SIZE,
                total_size
                - written,
            )

            file.write(
                block[:size]
            )

            written += size


def hashlib_sha256(
    path: Path,
) -> str:
    hasher = (
        hashlib.sha256()
    )

    with path.open(
        "rb"
    ) as file:
        while True:
            chunk = file.read(
                CHUNK_SIZE
            )

            if not chunk:
                break

            hasher.update(
                chunk
            )

    return (
        hasher.hexdigest()
    )


def main(
) -> None:
    parser = (
        argparse.ArgumentParser()
    )

    parser.add_argument(
        "--file",
        default="large_hash_test.bin",
    )

    parser.add_argument(
        "--size-gb",
        type=int,
        default=1,
    )

    args = (
        parser.parse_args()
    )

    path = Path(
        args.file
    )

    create_large_file(
        path,
        args.size_gb,
    )

    expected = (
        hashlib_sha256(
            path
        )
    )

    actual = hash_file(
        str(path),
        "sha256",
    )

    print(
        f"Expected: {expected}"
    )

    print(
        f"Actual:   {actual}"
    )

    print(
        f"Match:    {expected == actual}"
    )


if __name__ == "__main__":
    main()