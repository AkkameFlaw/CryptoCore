from __future__ import annotations

import argparse
import os
import sys

from .file_io import (
    read_binary,
    write_binary,
)

from .modes import (
    PaddingError,
    decrypt_cbc,
    decrypt_cfb,
    decrypt_ctr,
    decrypt_ecb,
    decrypt_ofb,
    encrypt_cbc,
    encrypt_cfb,
    encrypt_ctr,
    encrypt_ecb,
    encrypt_ofb,
)


IV_SIZE = 16

SUPPORTED_MODES = {
    "ecb",
    "cbc",
    "cfb",
    "ofb",
    "ctr",
}


class ArgumentError(ValueError):
    pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptocore",
        description=(
            "AES-128 file encryption "
            "and decryption tool"
        ),
    )

    parser.add_argument(
        "--algorithm",
        required=True,
    )

    parser.add_argument(
        "--mode",
        required=True,
    )

    operation_group = (
        parser.add_mutually_exclusive_group(
            required=True
        )
    )

    operation_group.add_argument(
        "--encrypt",
        action="store_true",
    )

    operation_group.add_argument(
        "--decrypt",
        action="store_true",
    )

    parser.add_argument(
        "--key",
        required=True,
    )

    parser.add_argument(
        "--iv",
    )

    parser.add_argument(
        "--input",
        required=True,
        dest="input_file",
    )

    parser.add_argument(
        "--output",
        dest="output_file",
    )

    return parser


def parse_key(
    key_text: str,
) -> bytes:
    if len(key_text) != 32:
        raise ArgumentError(
            "--key must contain exactly "
            "32 hexadecimal characters"
        )

    try:
        key = bytes.fromhex(
            key_text
        )

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


def parse_iv(
    iv_text: str,
) -> bytes:
    if len(iv_text) != 32:
        raise ArgumentError(
            "--iv must contain exactly "
            "32 hexadecimal characters"
        )

    try:
        iv = bytes.fromhex(
            iv_text
        )

    except ValueError as exc:
        raise ArgumentError(
            "--iv must be a valid "
            "hexadecimal string"
        ) from exc

    if len(iv) != IV_SIZE:
        raise ArgumentError(
            "--iv must decode to "
            "exactly 16 bytes"
        )

    return iv


def get_default_output(
    input_file: str,
    decrypt: bool,
) -> str:
    if decrypt:
        return f"{input_file}.dec"

    return f"{input_file}.enc"


def validate_arguments(
    args: argparse.Namespace,
) -> tuple[bytes, str]:
    if args.algorithm.lower() != "aes":
        raise ArgumentError(
            "--algorithm must be 'aes'"
        )

    mode = args.mode.lower()

    if mode not in SUPPORTED_MODES:
        raise ArgumentError(
            "--mode must be one of: "
            "ecb, cbc, cfb, ofb, ctr"
        )

    if args.encrypt and args.iv is not None:
        raise ArgumentError(
            "--iv must not be used "
            "with --encrypt"
        )

    if mode == "ecb" and args.iv is not None:
        raise ArgumentError(
            "--iv is not used "
            "with ECB mode"
        )

    return (
        parse_key(args.key),
        mode,
    )


def encrypt_data(
    data: bytes,
    key: bytes,
    mode: str,
) -> bytes:
    if mode == "ecb":
        return encrypt_ecb(
            data,
            key,
        )

    iv = os.urandom(
        IV_SIZE
    )

    if mode == "cbc":
        ciphertext = encrypt_cbc(
            data,
            key,
            iv,
        )

    elif mode == "cfb":
        ciphertext = encrypt_cfb(
            data,
            key,
            iv,
        )

    elif mode == "ofb":
        ciphertext = encrypt_ofb(
            data,
            key,
            iv,
        )

    else:
        ciphertext = encrypt_ctr(
            data,
            key,
            iv,
        )

    return iv + ciphertext


def decrypt_data(
    data: bytes,
    key: bytes,
    mode: str,
    iv_text: str | None,
) -> bytes:
    if mode == "ecb":
        return decrypt_ecb(
            data,
            key,
        )

    if iv_text is not None:
        iv = parse_iv(
            iv_text
        )

        ciphertext = data

    else:
        if len(data) < IV_SIZE:
            raise ValueError(
                "input file is too short "
                "to contain a 16-byte IV"
            )

        iv = data[:IV_SIZE]

        ciphertext = data[
            IV_SIZE:
        ]

    if mode == "cbc":
        return decrypt_cbc(
            ciphertext,
            key,
            iv,
        )

    if mode == "cfb":
        return decrypt_cfb(
            ciphertext,
            key,
            iv,
        )

    if mode == "ofb":
        return decrypt_ofb(
            ciphertext,
            key,
            iv,
        )

    return decrypt_ctr(
        ciphertext,
        key,
        iv,
    )


def run(
    argv: list[str] | None = None,
) -> int:
    parser = build_parser()

    args = parser.parse_args(
        argv
    )

    try:
        key, mode = validate_arguments(
            args
        )

        output_file = (
            args.output_file
            or get_default_output(
                args.input_file,
                args.decrypt,
            )
        )

        data = read_binary(
            args.input_file
        )

        if args.encrypt:
            result = encrypt_data(
                data,
                key,
                mode,
            )

        else:
            result = decrypt_data(
                data,
                key,
                mode,
                args.iv,
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
    raise SystemExit(
        main()
    )