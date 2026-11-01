"""Streaming file hashing and HMAC utilities used by the CLI."""

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
    """Construct the requested SHA256 or SHA3_256 incremental hasher.
    
        Args:
            algorithm: Algorithm identifier, e.g., sha256 or sha3-256.
    
        Returns:
            A value of type object; see docs/API.md.
    
        Raises:
            ValueError or OSError for invalid algorithms, malformed verification files or I/O.
    """
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
    """Hash a binary stream in bounded-size chunks and return HEX.
    
        Args:
            stream: Binary file-like object exposing read().
            algorithm: Algorithm identifier, e.g., sha256 or sha3-256.
    
        Returns:
            Text output.
    
        Raises:
            ValueError or OSError for invalid algorithms, malformed verification files or I/O.
    """
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
    """Hash the specified file or standard input (-) and return HEX.
    
        Args:
            input_file: Path to input data; digest operations support - for stdin.
            algorithm: Algorithm identifier, e.g., sha256 or sha3-256.
    
        Returns:
            Text output.
    
        Raises:
            ValueError or OSError for invalid algorithms, malformed verification files or I/O.
    """
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
    """Compute HMAC-SHA256 over a binary stream and return HEX.
    
        Args:
            stream: Binary file-like object exposing read().
            key: Secret key (16 bytes for AES-128; arbitrary bytes for HMAC).
    
        Returns:
            Text output.
    
        Raises:
            ValueError or OSError for invalid algorithms, malformed verification files or I/O.
    """
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
    """Compute HMAC-SHA256 over the file or standard input (-).
    
        Args:
            input_file: Path to input data; digest operations support - for stdin.
            key: Secret key (16 bytes for AES-128; arbitrary bytes for HMAC).
    
        Returns:
            Text output.
    
        Raises:
            ValueError or OSError for invalid algorithms, malformed verification files or I/O.
    """
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
    """Format a hash and path with two separating spaces.
    
        Args:
            hash_value: Hash string in HEX.
            input_file: Path to input data; digest operations support - for stdin.
    
        Returns:
            Text output.
    
        Raises:
            ValueError or OSError for invalid algorithms, malformed verification files or I/O.
    """
    return (
        f"{hash_value}  "
        f"{input_file}"
    )


def format_hmac(
    hmac_value: str,
    input_file: str,
) -> str:
    """Format an HMAC and path with one separating space.
    
        Args:
            hmac_value: Message authentication code in HEX.
            input_file: Path to input data; digest operations support - for stdin.
    
        Returns:
            Text output.
    
        Raises:
            ValueError or OSError for invalid algorithms, malformed verification files or I/O.
    """
    return (
        f"{hmac_value} "
        f"{input_file}"
    )


def read_expected_hmac(
    input_file: str,
) -> str:
    """Read and validate the expected 32-byte HMAC from a text file.
    
        Args:
            input_file: Path to input data; digest operations support - for stdin.
    
        Returns:
            Text output.
    
        Raises:
            ValueError or OSError for invalid algorithms, malformed verification files or I/O.
    """
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
    """Write the formatted digest or HMAC line to a UTF-8 text file.
    
        Args:
            output_file: Destination file path for the operation.
            result: Formatted text to save.
    
        Returns:
            Nothing; raises on validation failure.
    
        Raises:
            ValueError or OSError for invalid algorithms, malformed verification files or I/O.
    """
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