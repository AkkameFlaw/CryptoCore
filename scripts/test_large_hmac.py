import argparse
import hashlib
import hmac
from pathlib import Path

from cryptocore.digest import hmac_file


CHUNK_SIZE = 1024 * 1024


def create_large_file(
    path: Path,
    size_mb: int,
) -> None:
    block = bytes(range(256)) * 4096

    with path.open(
        "wb"
    ) as file:
        for _ in range(
            size_mb
        ):
            file.write(
                block
            )


def reference_hmac(
    path: Path,
    key: bytes,
) -> str:
    reference = hmac.new(
        key,
        digestmod=hashlib.sha256,
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

            reference.update(
                chunk
            )

    return reference.hexdigest()


def main(
) -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--size-mb",
        type=int,
        default=16,
    )

    parser.add_argument(
        "--file",
        default="large_hmac_test.bin",
    )

    parser.add_argument(
        "--key",
        default=(
            "00112233445566778899aabbccddeeff"
        ),
    )

    args = parser.parse_args()

    if args.size_mb <= 0:
        raise ValueError(
            "--size-mb must be positive"
        )

    key = bytes.fromhex(
        args.key
    )

    path = Path(
        args.file
    )

    print(
        f"Creating {args.size_mb} MB file..."
    )

    create_large_file(
        path,
        args.size_mb,
    )

    print(
        "Calculating reference HMAC..."
    )

    expected = reference_hmac(
        path,
        key,
    )

    print(
        "Calculating CryptoCore HMAC..."
    )

    actual = hmac_file(
        str(path),
        key,
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