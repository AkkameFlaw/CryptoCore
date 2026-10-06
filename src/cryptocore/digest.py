import sys
from typing import BinaryIO

from hash import SHA256, SHA3_256
from mac import HMAC


CHUNK_SIZE = 8192

HASH_ALGORITHMS = {
    "sha256": SHA256,
    "sha3-256": SHA3_256,
}


def create_hasher(
    algorithm: str,
):
    normalized = algorithm.lower()

    hasher_class = HASH_ALGORITHMS.get(
        normalized
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


def hmac_stream(
    stream: BinaryIO,
    key: bytes,
) -> str:
    hmac = HMAC(
        key
    )

    while True:
        chunk = stream.read(
            CHUNK_SIZE
        )

        if not chunk:
            break

        hmac.update(
            chunk
        )

    return hmac.hexdigest()


def hmac_file(
    input_file: str,
    key: bytes,
) -> str:
    if input_file == "-":
        return hmac_stream(
            sys.stdin.buffer,
            key,
        )

    with open(
        input_file,
        "rb",
    ) as file:
        return hmac_stream(
            file,
            key,
        )


def format_digest(
    hash_value: str,
    input_file: str,
) -> str:
    return (
        f"{hash_value}  "
        f"{input_file}"
    )


def format_hmac(
    hmac_value: str,
    input_file: str,
) -> str:
    return (
        f"{hmac_value} "
        f"{input_file}"
    )


def read_expected_hmac(
    input_file: str,
) -> str:
    with open(
        input_file,
        "r",
        encoding="utf-8",
    ) as file:
        content = file.read()

    parts = content.split()

    if not parts:
        raise ValueError(
            "HMAC verification file is empty"
        )

    value = parts[0]

    if len(value) != 64:
        raise ValueError(
            "expected HMAC must contain "
            "64 hexadecimal characters"
        )

    try:
        raw = bytes.fromhex(
            value
        )
    except ValueError as exc:
        raise ValueError(
            "expected HMAC must be hexadecimal"
        ) from exc

    if len(raw) != 32:
        raise ValueError(
            "expected HMAC must be 32 bytes"
        )

    return value.lower()


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