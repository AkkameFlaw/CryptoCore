from __future__ import annotations

import argparse
import sys

from .file_io import (
    read_binary,
    write_binary,
)

from .modes.ecb import (
    PaddingError,
    decrypt_ecb,
    encrypt_ecb,
)


class ArgumentError(ValueError):
    pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptocore",
        description=(
            "AES-128 ECB file encryption "
            "and decryption tool"
        ),
    )

    parser.add_argument(
        "--algorithm",
        required=True,
        help="Algorithm. Sprint 1 supports: aes",
    )

    parser.add_argument(
        "--mode",
        required=True,
        help="Mode. Sprint 1 supports: ecb",
    )

    operation_group = (
        parser.add_mutually_exclusive_group(
            required=True
        )
    )

    operation_group.add_argument(
        "--encrypt",
        action="store_true",
        help="Encrypt input file",
    )

    operation_group.add_argument(
        "--decrypt",
        action="store_true",
        help="Decrypt input file",
    )

    parser.add_argument(
        "--key",
        required=True,
        help=(
            "AES-128 key as "
            "32 hexadecimal characters"
        ),
    )

    parser.add_argument(
        "--input",
        required=True,
        dest="input_file",
        help="Input file",
    )

    parser.add_argument(
        "--output",
        dest="output_file",
        help="Output file",
    )

    return parser


def parse_key(key_text: str) -> bytes:
    if len(key_text) != 32:
        raise ArgumentError(
            "--key must contain exactly "
            "32 hexadecimal characters"
        )

    try:
        key = bytes.fromhex(key_text)

    except ValueError as exc:
        raise ArgumentError(
            "--key must be a valid "
            "hexadecimal string"
        ) from exc

    if len(key) != 16:
        raise ArgumentError(
            "--key must decode to "
            "exactly 16 bytes"
        )

    return key


def get_default_output(
    input_file: str,
    decrypt: bool,
) -> str:
    if decrypt:
        return f"{input_file}.dec"

    return f"{input_file}.enc"


def validate_arguments(
    args: argparse.Namespace,
) -> bytes:
    if args.algorithm.lower() != "aes":
        raise ArgumentError(
            "--algorithm must be 'aes'"
        )

    if args.mode.lower() != "ecb":
        raise ArgumentError(
            "--mode must be 'ecb'"
        )

    return parse_key(args.key)


def run(
    argv: list[str] | None = None,
) -> int:
    parser = build_parser()

    args = parser.parse_args(argv)

    try:
        key = validate_arguments(args)

        output_file = (
            args.output_file
            or get_default_output(
                args.input_file,
                args.decrypt,
            )
        )

        data = read_binary(args.input_file)

        if args.encrypt:
            result = encrypt_ecb(
                data,
                key,
            )
        else:
            result = decrypt_ecb(
                data,
                key,
            )

        write_binary(
            output_file,
            result,
        )

        return 0

    except (
        ArgumentError,
        PaddingError,
        ValueError,
        OSError,
    ) as exc:
        print(
            f"cryptocore: error: {exc}",
            file=sys.stderr,
        )

        return 2


def main() -> int:
    return run()


if __name__ == "__main__":
    raise SystemExit(main())