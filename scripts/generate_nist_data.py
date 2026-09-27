import argparse
from pathlib import Path

from cryptocore.csprng import (
    generate_random_bytes,
)


def main() -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--size-mb",
        type=int,
        default=10,
    )

    parser.add_argument(
        "--output",
        default="nist_test_data.bin",
    )

    args = parser.parse_args()

    if args.size_mb <= 0:
        raise ValueError(
            "size-mb must be positive"
        )

    total_size = (
        args.size_mb * 1_000_000
    )

    output = Path(
        args.output
    )

    chunk_size = 4096

    written = 0

    with output.open("wb") as file:
        while written < total_size:
            size = min(
                chunk_size,
                total_size - written,
            )

            file.write(
                generate_random_bytes(
                    size
                )
            )

            written += size

    print(
        f"Generated {written} bytes "
        f"in {output}"
    )


if __name__ == "__main__":
    main()