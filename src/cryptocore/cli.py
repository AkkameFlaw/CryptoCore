from __future__ import annotations

import argparse
import secrets
import sys

from .csprng import generate_random_bytes
from .digest import (
    format_digest,
    format_hmac,
    hash_file,
    hmac_file,
    read_expected_hmac,
    write_digest_output,
)
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


KEY_SIZE = 16
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
        epilog=(
            "Use 'cryptocore dgst --help' "
            "for hashing and HMAC."
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


def build_digest_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cryptocore dgst",
        description=(
            "Calculate a cryptographic "
            "message digest or HMAC"
        ),
    )

    parser.add_argument(
        "--algorithm",
        required=True,
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

    parser.add_argument(
        "--hmac",
        action="store_true",
    )

    parser.add_argument(
        "--key",
    )

    parser.add_argument(
        "--verify",
        dest="verify_file",
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

    if len(key) != KEY_SIZE:
        raise ArgumentError(
            "--key must decode to "
            "exactly 16 bytes"
        )

    return key


def parse_hmac_key(
    key_text: str,
) -> bytes:
    if len(key_text) % 2 != 0:
        raise ArgumentError(
            "--key must contain an even "
            "number of hexadecimal characters"
        )

    if any(
        character
        not in "0123456789abcdefABCDEF"
        for character in key_text
    ):
        raise ArgumentError(
            "--key must be a valid "
            "hexadecimal string"
        )

    return bytes.fromhex(
        key_text
    )


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


def is_weak_key(
    key: bytes,
) -> bool:
    if len(set(key)) == 1:
        return True

    ascending = all(
        key[index]
        == (key[0] + index) % 256
        for index in range(
            len(key)
        )
    )

    descending = all(
        key[index]
        == (key[0] - index) % 256
        for index in range(
            len(key)
        )
    )

    return (
        ascending
        or descending
    )


def resolve_key(
    args: argparse.Namespace,
) -> bytes:
    if args.key is None:
        if args.decrypt:
            raise ArgumentError(
                "--key is required "
                "for decryption"
            )

        key = generate_random_bytes(
            KEY_SIZE
        )

        print(
            "[INFO] Generated random key: "
            f"{key.hex()}"
        )

        return key

    key = parse_key(
        args.key
    )

    if is_weak_key(
        key
    ):
        print(
            "[WARNING] Provided key "
            "appears weak.",
            file=sys.stderr,
        )

    return key


def get_default_output(
    input_file: str,
    decrypt: bool,
) -> str:
    if decrypt:
        return (
            f"{input_file}.dec"
        )

    return (
        f"{input_file}.enc"
    )


def validate_arguments(
    args: argparse.Namespace,
) -> str:
    if (
        args.algorithm.lower()
        != "aes"
    ):
        raise ArgumentError(
            "--algorithm must be 'aes'"
        )

    mode = (
        args.mode.lower()
    )

    if mode not in SUPPORTED_MODES:
        raise ArgumentError(
            "--mode must be one of: "
            "ecb, cbc, cfb, ofb, ctr"
        )

    if (
        args.encrypt
        and args.iv is not None
    ):
        raise ArgumentError(
            "--iv must not be used "
            "with --encrypt"
        )

    if (
        mode == "ecb"
        and args.iv is not None
    ):
        raise ArgumentError(
            "--iv is not used "
            "with ECB mode"
        )

    return mode


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

    iv = generate_random_bytes(
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

    return (
        iv
        + ciphertext
    )


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

        iv = data[
            :IV_SIZE
        ]

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


def run_digest(
    argv: list[str],
) -> int:
    parser = build_digest_parser()

    try:
        args = parser.parse_args(
            argv
        )

    except SystemExit as exc:
        return int(
            exc.code
        )

    try:
        if args.hmac:
            if args.key is None:
                raise ArgumentError(
                    "--key is required "
                    "when --hmac is used"
                )

            if (
                args.algorithm.lower()
                != "sha256"
            ):
                raise ArgumentError(
                    "--hmac currently supports "
                    "only sha256"
                )

            if (
                args.verify_file
                and args.output_file
            ):
                raise ArgumentError(
                    "--output must not be used "
                    "with --verify"
                )

            key = parse_hmac_key(
                args.key
            )

            hmac_value = hmac_file(
                args.input_file,
                key,
            )

            if args.verify_file:
                expected = (
                    read_expected_hmac(
                        args.verify_file
                    )
                )

                if secrets.compare_digest(
                    hmac_value,
                    expected,
                ):
                    print(
                        "[OK] HMAC verification "
                        "successful"
                    )

                    return 0

                print(
                    "[ERROR] HMAC verification "
                    "failed",
                    file=sys.stderr,
                )

                return 1

            result = format_hmac(
                hmac_value,
                args.input_file,
            )

        else:
            if args.key is not None:
                raise ArgumentError(
                    "--key requires --hmac"
                )

            if args.verify_file is not None:
                raise ArgumentError(
                    "--verify requires --hmac"
                )

            hash_value = hash_file(
                args.input_file,
                args.algorithm,
            )

            result = format_digest(
                hash_value,
                args.input_file,
            )

        if args.output_file:
            write_digest_output(
                args.output_file,
                result,
            )

        else:
            print(
                result
            )

        return 0

    except (
        ArgumentError,
        ValueError,
        OSError,
    ) as exc:
        print(
            f"cryptocore: error: {exc}",
            file=sys.stderr,
        )

        return 2


def run(
    argv: list[str] | None = None,
) -> int:
    arguments = list(
        sys.argv[1:]
        if argv is None
        else argv
    )

    if (
        arguments
        and arguments[0] == "dgst"
    ):
        return run_digest(
            arguments[1:]
        )

    parser = build_parser()

    try:
        args = parser.parse_args(
            arguments
        )

    except SystemExit as exc:
        return int(
            exc.code
        )

    try:
        mode = validate_arguments(
            args
        )

        key = resolve_key(
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
        RuntimeError,
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