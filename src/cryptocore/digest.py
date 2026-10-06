import sys
from typing import BinaryIO

from hash import SHA256, SHA3_256


CHUNK_SIZE = 8192

HASH_ALGORITHMS = {
    "sha256": SHA256,
    "sha3-256": SHA3_256,
}


def create_hasher(
    algorithm: str,
):
    normalized = (
        algorithm.lower()
    )

    hasher_class = (
        HASH_ALGORITHMS.get(
            normalized
        )
    )

    if hasher_class is None:
        raise ValueError(
            "--algorithm must be one of: "
            "sha256, sha3-256"
        )

    return hasher_class()


def hash_stream(
    stream: BinaryIO,
    algorithm: str,
) -> str:
    hasher = create_hasher(
        algorithm
    )

    while True:
        chunk = stream.read(
            CHUNK_SIZE
        )

        if not chunk:
            break

        hasher.update(
            chunk
        )

    return hasher.hexdigest()


def hash_file(
    input_file: str,
    algorithm: str,
) -> str:
    if input_file == "-":
        return hash_stream(
            sys.stdin.buffer,
            algorithm,
        )

    with open(
        input_file,
        "rb",
    ) as file:
        return hash_stream(
            file,
            algorithm,
        )


def format_digest(
    hash_value: str,
    input_file: str,
) -> str:
    return (
        f"{hash_value}  "
        f"{input_file}"
    )


def write_digest_output(
    output_file: str,
    result: str,
) -> None:
    with open(
        output_file,
        "w",
        encoding="utf-8",
        newline="\n",
    ) as file:
        file.write(
            result
        )

        file.write(
            "\n"
        )