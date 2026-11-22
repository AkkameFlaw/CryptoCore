"""Command-line interface for AES, hashes, HMAC, PBKDF2 and authenticated modes."""

from __future__ import annotations

import argparse
import os
import secrets
import sys
from contextlib import ExitStack
from pathlib import Path
from typing import BinaryIO

from aead import EncryptThenMAC, EtMAuthenticationError
from kdf import pbkdf2_hmac_sha256
from kdf.pbkdf2 import MAX_DERIVED_KEY_LENGTH
from modes import AuthenticationError, GCM

from .csprng import generate_random_bytes
from .digest import (
    format_digest,
    format_hmac,
    hash_file,
    hmac_file,
    read_expected_hmac,
    write_digest_output,
)
from .file_io import read_binary, write_binary
from .streaming import encrypt_file, decrypt_file
from .nonce_registry import register_nonce
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
GCM_NONCE_SIZE = 12
SALT_SIZE = 16
DEFAULT_ITERATIONS = 100_000
DEFAULT_DERIVED_KEY_LENGTH = 32
MAX_SAFE_ITERATIONS = 100_000
MAX_EXPLICIT_ITERATIONS = 1_000_000

SUPPORTED_MODES = {"ecb", "cbc", "cfb", "ofb", "ctr", "gcm", "etm"}
AEAD_MODES = {"gcm", "etm"}


class ArgumentError(ValueError):
    """Command-line argument validation error.

    Notes:
        Consult docs/API.md for construction, safety, and examples.
    """
    pass


def build_parser() -> argparse.ArgumentParser:
    """Build the AES encryption/decryption command-line parser.
    
        Returns:
            A value of type argparse.ArgumentParser; see docs/API.md.
    
        Raises:
            ArgumentError, ValueError, OSError or an authentication error on invalid operations.
    """
    parser = argparse.ArgumentParser(
        prog="cryptocore",
        description="AES-128 encryption, decryption and authenticated encryption",
        epilog=(
            "Use 'cryptocore dgst --help' for hashing and HMAC, "
            "or 'cryptocore derive --help' for PBKDF2."
        ),
    )

    parser.add_argument("--algorithm", required=True)
    parser.add_argument("--mode", required=True)

    operations = parser.add_mutually_exclusive_group(required=True)
    operations.add_argument("--encrypt", action="store_true")
    operations.add_argument("--decrypt", action="store_true")

    key_sources = parser.add_mutually_exclusive_group()
    key_sources.add_argument("--key")
    key_sources.add_argument("--key-file", dest="key_file", metavar="FILE")
    parser.add_argument("--key-output", dest="key_output", metavar="FILE")
    parser.add_argument("--show-key", action="store_true", help="Explicitly allow writing a generated secret key to stdout")
    parser.add_argument("--iv")
    parser.add_argument("--nonce")
    parser.add_argument("--aad")
    parser.add_argument("--aad-file", dest="aad_file")
    parser.add_argument("--input", required=True, dest="input_file")
    parser.add_argument("--output", dest="output_file")

    return parser


def build_digest_parser() -> argparse.ArgumentParser:
    """Build the hashing and HMAC subcommand parser.
    
        Returns:
            A value of type argparse.ArgumentParser; see docs/API.md.
    
        Raises:
            ArgumentError, ValueError, OSError or an authentication error on invalid operations.
    """
    parser = argparse.ArgumentParser(
        prog="cryptocore dgst",
        description="Calculate a cryptographic message digest or HMAC",
    )

    parser.add_argument("--algorithm", required=True)
    parser.add_argument("--input", required=True, dest="input_file")
    parser.add_argument("--output", dest="output_file")
    parser.add_argument("--hmac", action="store_true")
    parser.add_argument("--key")
    parser.add_argument("--verify", dest="verify_file")

    return parser


def build_derive_parser() -> argparse.ArgumentParser:
    """Build the PBKDF2 key-derivation subcommand parser.
    
        Returns:
            A value of type argparse.ArgumentParser; see docs/API.md.
    
        Raises:
            ArgumentError, ValueError, OSError or an authentication error on invalid operations.
    """
    parser = argparse.ArgumentParser(
        prog="cryptocore derive",
        description="Derive a key using PBKDF2-HMAC-SHA256",
    )

    parser.add_argument(
        "--algorithm",
        choices=["pbkdf2"],
        default="pbkdf2",
    )

    passwords = parser.add_mutually_exclusive_group(required=True)

    passwords.add_argument("--password")
    passwords.add_argument("--password-prompt", action="store_true", help="Read a password without terminal echo")
    passwords.add_argument(
        "--password-env",
        dest="password_env",
        metavar="NAME",
    )
    passwords.add_argument(
        "--password-file",
        dest="password_file",
        metavar="FILE",
    )

    parser.add_argument("--allow-insecure-password-argv", action="store_true", help="Explicit opt-in to argv password exposure")
    parser.add_argument("--show-key", action="store_true", help="Explicitly display the derived secret key")
    parser.add_argument("--allow-slow-kdf", action="store_true", help="Allow up to 1 million PBKDF2 iterations")
    parser.add_argument("--salt")
    parser.add_argument(
        "--iterations",
        type=int,
        default=DEFAULT_ITERATIONS,
    )
    parser.add_argument(
        "--length",
        type=int,
        default=DEFAULT_DERIVED_KEY_LENGTH,
    )
    parser.add_argument("--output", dest="output_file")

    return parser


def parse_key(key_text: str) -> bytes:
    """Validate and decode a 16-byte AES key supplied as 32 HEX characters.
    
        Args:
            key_text: Secret key encoded as HEX.
    
        Returns:
            Binary result.
    
        Raises:
            ArgumentError, ValueError, OSError or an authentication error on invalid operations.
    """
    if len(key_text) != 32:
        raise ArgumentError(
            "--key must contain exactly 32 hexadecimal characters"
        )

    try:
        key = bytes.fromhex(key_text)
    except ValueError as exc:
        raise ArgumentError(
            "--key must be a valid hexadecimal string"
        ) from exc

    if len(key) != KEY_SIZE:
        raise ArgumentError(
            "--key must decode to exactly 16 bytes"
        )

    return key


def parse_hmac_key(key_text: str) -> bytes:
    """Validate and decode an arbitrary-length HEX HMAC key.
    
        Args:
            key_text: Secret key encoded as HEX.
    
        Returns:
            Binary result.
    
        Raises:
            ArgumentError, ValueError, OSError or an authentication error on invalid operations.
    """
    if len(key_text) % 2 or any(
        char not in "0123456789abcdefABCDEF"
        for char in key_text
    ):
        raise ArgumentError(
            "--key must be an even-length hexadecimal string"
        )

    return bytes.fromhex(key_text)


def parse_iv(iv_text: str) -> bytes:
    """Validate and decode an AES mode IV represented by 32 HEX characters.
    
        Args:
            iv_text: Optional IV encoded as HEX.
    
        Returns:
            Binary result.
    
        Raises:
            ArgumentError, ValueError, OSError or an authentication error on invalid operations.
    """
    if len(iv_text) != 32:
        raise ArgumentError(
            "--iv must contain exactly 32 hexadecimal characters"
        )

    try:
        iv = bytes.fromhex(iv_text)
    except ValueError as exc:
        raise ArgumentError(
            "--iv must be a valid hexadecimal string"
        ) from exc

    if len(iv) != IV_SIZE:
        raise ArgumentError(
            "--iv must decode to exactly 16 bytes"
        )

    return iv


def parse_nonce(nonce_text: str) -> bytes:
    """Validate and decode a 12-byte GCM nonce represented by 24 HEX characters.
    
        Args:
            nonce_text: Optional GCM nonce encoded as HEX.
    
        Returns:
            Binary result.
    
        Raises:
            ArgumentError, ValueError, OSError or an authentication error on invalid operations.
    """
    if len(nonce_text) != GCM_NONCE_SIZE * 2:
        raise ArgumentError(
            "GCM nonce must contain exactly 24 hexadecimal characters"
        )

    if any(
        char not in "0123456789abcdefABCDEF"
        for char in nonce_text
    ):
        raise ArgumentError(
            "GCM nonce must be a valid hexadecimal string"
        )

    return bytes.fromhex(nonce_text)


def parse_aad(aad_text: str | None) -> bytes:
    """Decode optional HEX-encoded authenticated associated data.
    
        Args:
            aad_text: Optional AAD encoded as HEX.
    
        Returns:
            Binary result.
    
        Raises:
            ArgumentError, ValueError, OSError or an authentication error on invalid operations.
    """
    if aad_text is None or aad_text == "":
        return b""

    if len(aad_text) % 2 or any(
        char not in "0123456789abcdefABCDEF"
        for char in aad_text
    ):
        raise ArgumentError(
            "--aad must be an even-length hexadecimal string"
        )

    return bytes.fromhex(aad_text)


def resolve_salt(salt_text: str | None) -> bytes:
    """Parse HEX salt or generate a fresh random 16-byte salt.
    
        Args:
            salt_text: Optional salt encoded as HEX.
    
        Returns:
            Binary result.
    
        Raises:
            ArgumentError, ValueError, OSError or an authentication error on invalid operations.
    """
    if salt_text is None:
        return generate_random_bytes(SALT_SIZE)

    if len(salt_text) % 2 or any(
        char not in "0123456789abcdefABCDEF"
        for char in salt_text
    ):
        raise ArgumentError(
            "--salt must be an even-length hexadecimal string"
        )

    return bytes.fromhex(salt_text)


def resolve_password(args: argparse.Namespace) -> bytearray:
    # Пароль не записывается в журналы и не выводится в stdout/stderr.
    """Read a PBKDF2 password into a mutable bytearray without logging its plaintext.
    
        Args:
            args: Parsed command-line options in an argparse.Namespace.
    
        Returns:
            A value of type bytearray; see docs/API.md.
    
        Raises:
            ArgumentError, ValueError, OSError or an authentication error on invalid operations.
    
        Security:
            Never log keys or passwords; see docs/SECURITY_AUDIT.md.
    """
    if args.password is not None:
        password = bytearray(args.password.encode("utf-8"))
        args.password = None
        return password

    if getattr(args, "password_prompt", False):
        import getpass
        value = getpass.getpass("CryptoCore password: ")
        password = bytearray(value.encode("utf-8"))
        del value
        return password

    if args.password_env is not None:
        value = os.environ.get(args.password_env)

        if value is None:
            raise ArgumentError(
                f"environment variable not found: {args.password_env}"
            )

        password = bytearray(value.encode("utf-8"))
        del value
        return password

    if Path(args.password_file).stat().st_size > 4096:
        raise ArgumentError("--password-file must not exceed 4096 bytes")
    password = bytearray(
        Path(args.password_file).read_bytes()
    )

    return password


def is_weak_key(key: bytes) -> bool:
    """Identify trivial repeated-byte or arithmetic-sequence AES keys.
    
        Args:
            key: Secret key (16 bytes for AES-128; arbitrary bytes for HMAC).
    
        Returns:
            Validation/condition result.
    
        Raises:
            ArgumentError, ValueError, OSError or an authentication error on invalid operations.
    """
    if len(set(key)) == 1:
        return True

    ascending = all(
        key[index] == (key[0] + index) % 256
        for index in range(len(key))
    )

    descending = all(
        key[index] == (key[0] - index) % 256
        for index in range(len(key))
    )

    return ascending or descending


def _write_private_key(path: str, key: bytes) -> None:
    """Create an exclusive 16-byte key file with restrictive permissions."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(key)
    except BaseException:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise


def resolve_key(args: argparse.Namespace) -> bytes:
    """Resolve a 16-byte AES key without exposing generated key material by default.

    A missing key on encryption creates an exclusive private sidecar key file.
    Use --key-file FILE for subsequent operations without secrets in argv.
    """
    source = getattr(args, "key_file", None)
    if source is not None:
        if Path(source).stat().st_size != KEY_SIZE:
            raise ArgumentError("--key-file must contain exactly 16 raw key bytes")
        key = Path(source).read_bytes()
        if len(key) != KEY_SIZE:
            raise ArgumentError("--key-file must contain exactly 16 raw key bytes")
        return key

    if args.key is None:
        if args.decrypt:
            raise ArgumentError("--key is required for decryption (or use --key-file)")
        key = generate_random_bytes(KEY_SIZE)
        encrypted = args.output_file or get_default_output(args.input_file, False)
        output = getattr(args, "key_output", None) or (encrypted + ".key")
        _write_private_key(output, key)
        print(f"[INFO] Generated key saved to: {output}", file=sys.stderr)
        if getattr(args, "show_key", False):
            print(f"[WARNING] Generated key (explicit output): {key.hex()}", file=sys.stdout)
        return key

    key = parse_key(args.key)
    if is_weak_key(key):
        print("[WARNING] Provided key appears weak.", file=sys.stderr)
    return key


def get_default_output(
    input_file: str,
    decrypt: bool,
) -> str:
    """Choose the default encrypted or decrypted file path.
    
        Args:
            input_file: Path to input data; digest operations support - for stdin.
            decrypt: Parameter used by this operation; see docs/API.md.
    
        Returns:
            Text output.
    
        Raises:
            ArgumentError, ValueError, OSError or an authentication error on invalid operations.
    """
    return f"{input_file}.dec" if decrypt else f"{input_file}.enc"


def validate_arguments(args: argparse.Namespace) -> str:
    """Validate compatibility of AES mode, operation and nonce/AAD options.
    
        Args:
            args: Parsed command-line options in an argparse.Namespace.
    
        Returns:
            Text output.
    
        Raises:
            ArgumentError, ValueError, OSError or an authentication error on invalid operations.
    """
    if args.algorithm.lower() != "aes":
        raise ArgumentError(
            "--algorithm must be 'aes'"
        )

    mode = args.mode.lower()

    if mode not in SUPPORTED_MODES:
        raise ArgumentError(
            "--mode must be one of: ecb, cbc, cfb, ofb, ctr, gcm, etm"
        )

    if args.iv is not None and args.nonce is not None:
        raise ArgumentError(
            "--iv and --nonce cannot be used together"
        )

    if args.encrypt and (
        args.iv is not None or args.nonce is not None
    ):
        raise ArgumentError(
            "--iv and --nonce must not be used with --encrypt"
        )

    if mode == "ecb" and args.iv is not None:
        raise ArgumentError(
            "--iv is not used with ECB mode"
        )

    if mode != "gcm" and args.nonce is not None:
        raise ArgumentError(
            "--nonce is supported only in GCM mode"
        )

    if mode == "etm" and args.iv is not None:
        raise ArgumentError(
            "--iv is not used explicitly in EtM mode"
        )

    if mode not in AEAD_MODES and args.aad is not None:
        raise ArgumentError(
            "--aad is supported only in GCM and EtM modes"
        )

    if args.aad_file is not None:
        if args.aad is not None:
            raise ArgumentError(
                "--aad and --aad-file cannot be used together"
            )

        if mode not in AEAD_MODES:
            raise ArgumentError(
                "--aad-file is supported only in GCM and EtM modes"
            )

    return mode


def encrypt_data(
    data: bytes,
    key: bytes,
    mode: str,
    aad: bytes | BinaryIO = b"",
) -> bytes:
    """Encrypt data using the selected mode and return the self-contained payload.
    
        Args:
            data: Binary input; for ciphertext, the format depends on the selected mode.
            key: Secret key (16 bytes for AES-128; arbitrary bytes for HMAC).
            mode: AES mode name: ecb, cbc, cfb, ofb, ctr, gcm or etm.
            aad: Authenticated additional bytes, or a binary stream for GCM.
    
        Returns:
            Binary result.
    
        Raises:
            ArgumentError, ValueError, OSError or an authentication error on invalid operations.
    
        Security:
            Never log keys or passwords; see docs/SECURITY_AUDIT.md.
    """
    if mode == "gcm":
        return GCM(key).encrypt(data, aad)

    if mode == "etm":
        return EncryptThenMAC(key).encrypt(data, aad)

    if mode == "ecb":
        return encrypt_ecb(data, key)

    iv = generate_random_bytes(IV_SIZE)
    register_nonce(key, iv, mode)

    if mode == "cbc":
        ciphertext = encrypt_cbc(data, key, iv)

    elif mode == "cfb":
        ciphertext = encrypt_cfb(data, key, iv)

    elif mode == "ofb":
        ciphertext = encrypt_ofb(data, key, iv)

    else:
        ciphertext = encrypt_ctr(data, key, iv)

    return iv + ciphertext


def decrypt_data(
    data: bytes,
    key: bytes,
    mode: str,
    iv_text: str | None,
    aad: bytes | BinaryIO = b"",
    nonce_text: str | None = None,
) -> bytes:
    """Decrypt payload after validation; AEAD modes authenticate before releasing plaintext.
    
        Args:
            data: Binary input; for ciphertext, the format depends on the selected mode.
            key: Secret key (16 bytes for AES-128; arbitrary bytes for HMAC).
            mode: AES mode name: ecb, cbc, cfb, ofb, ctr, gcm or etm.
            iv_text: Optional IV encoded as HEX.
            aad: Authenticated additional bytes, or a binary stream for GCM.
            nonce_text: Optional GCM nonce encoded as HEX.
    
        Returns:
            Binary result.
    
        Raises:
            ArgumentError, ValueError, OSError or an authentication error on invalid operations.
    
        Security:
            Never log keys or passwords; see docs/SECURITY_AUDIT.md.
    """
    if mode == "gcm":
        explicit_nonce = (
            nonce_text if nonce_text is not None else iv_text
        )

        if explicit_nonce is not None:
            nonce = parse_nonce(explicit_nonce)

            return GCM(key, nonce).decrypt(
                data,
                aad,
                includes_nonce=False,
            )

        if len(data) < GCM_NONCE_SIZE + GCM.tag_size:
            raise AuthenticationError(
                "Authentication failed: invalid GCM input length"
            )

        nonce = data[:GCM_NONCE_SIZE]

        return GCM(key, nonce).decrypt(data, aad)

    if mode == "etm":
        return EncryptThenMAC(key).decrypt(data, aad)

    if mode == "ecb":
        return decrypt_ecb(data, key)

    if iv_text is not None:
        iv = parse_iv(iv_text)
        ciphertext = data

    else:
        if len(data) < IV_SIZE:
            raise ValueError(
                "input file is too short to contain a 16-byte IV"
            )

        iv = data[:IV_SIZE]
        ciphertext = data[IV_SIZE:]

    if mode == "cbc":
        return decrypt_cbc(ciphertext, key, iv)

    if mode == "cfb":
        return decrypt_cfb(ciphertext, key, iv)

    if mode == "ofb":
        return decrypt_ofb(ciphertext, key, iv)

    return decrypt_ctr(ciphertext, key, iv)


def run_digest(argv: list[str]) -> int:
    """Execute the digest/HMAC CLI and return a process exit status.
    
        Args:
            argv: Argument list excluding the executable name.
    
        Returns:
            Integer result or process exit code.
    
        Raises:
            ArgumentError, ValueError, OSError or an authentication error on invalid operations.
    """
    parser = build_digest_parser()

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)

    try:
        if args.hmac:
            if args.key is None:
                raise ArgumentError(
                    "--key is required when --hmac is used"
                )

            if args.algorithm.lower() != "sha256":
                raise ArgumentError(
                    "--hmac currently supports only sha256"
                )

            if args.verify_file and args.output_file:
                raise ArgumentError(
                    "--output must not be used with --verify"
                )

            key = parse_hmac_key(args.key)
            hmac_value = hmac_file(args.input_file, key)

            if args.verify_file:
                expected = read_expected_hmac(args.verify_file)

                if secrets.compare_digest(
                    hmac_value,
                    expected,
                ):
                    print(
                        "[OK] HMAC verification successful"
                    )
                    return 0

                print(
                    "[ERROR] HMAC verification failed",
                    file=sys.stderr,
                )
                return 1

            result = format_hmac(hmac_value, args.input_file)

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
            write_digest_output(args.output_file, result)
        else:
            print(result)

        return 0

    except (ArgumentError, ValueError, OSError) as exc:
        print(
            f"cryptocore: error: {exc}",
            file=sys.stderr,
        )
        return 2


def run_derive(argv: list[str]) -> int:
    """Execute PBKDF2 CLI, emit key HEX and salt HEX, and best-effort zero mutable buffers.
    
        Args:
            argv: Argument list excluding the executable name.
    
        Returns:
            Integer result or process exit code.
    
        Raises:
            ArgumentError, ValueError, OSError or an authentication error on invalid operations.
    
        Security:
            Never log keys or passwords; see docs/SECURITY_AUDIT.md.
    """
    parser = build_derive_parser()

    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return int(exc.code)

    password = None
    key = None

    try:
        if args.iterations < 1:
            raise ArgumentError("--iterations must be at least 1")
        limit = MAX_EXPLICIT_ITERATIONS if args.allow_slow_kdf else MAX_SAFE_ITERATIONS
        if args.iterations > limit:
            raise ArgumentError(
                f"--iterations must not exceed {limit}; use --allow-slow-kdf for up to 1000000"
            )
        if args.password is not None and not args.allow_insecure_password_argv:
            raise ArgumentError(
                "--password exposes secrets in argv; use --password-env, --password-file, "
                "--password-prompt or explicitly --allow-insecure-password-argv"
            )
        if args.output_file is None and not args.show_key:
            raise ArgumentError("--output is required unless --show-key is explicitly set")

        if args.length < 1:
            raise ArgumentError(
                "--length must be positive"
            )

        if args.length > MAX_DERIVED_KEY_LENGTH:
            raise ArgumentError(
                f"--length must not exceed "
                f"{MAX_DERIVED_KEY_LENGTH} bytes"
            )

        salt = resolve_salt(args.salt)
        password = resolve_password(args)

        derived = pbkdf2_hmac_sha256(
            password,
            salt,
            args.iterations,
            args.length,
        )

        try:
            key = bytearray(derived)
        finally:
            del derived

        if args.output_file is not None:
            _write_private_key(args.output_file, key)

        if args.show_key:
            print(f"{key.hex()} {salt.hex()}")
        else:
            print(f"[INFO] Salt (HEX): {salt.hex()}")

        return 0

    except (
        ArgumentError,
        ValueError,
        OSError,
        UnicodeError,
    ) as exc:
        print(
            f"cryptocore: error: {exc}",
            file=sys.stderr,
        )
        return 2

    finally:
        if password is not None:
            password[:] = b"\x00" * len(password)

        if key is not None:
            key[:] = b"\x00" * len(key)

        del password
        del key


def run(argv: list[str] | None = None) -> int:
    """Dispatch to the selected CryptoCore CLI operation.
    
        Args:
            argv: Argument list excluding the executable name.
    
        Returns:
            Integer result or process exit code.
    
        Raises:
            ArgumentError, ValueError, OSError or an authentication error on invalid operations.
    """
    arguments = list(
        sys.argv[1:] if argv is None else argv
    )

    if arguments and arguments[0] == "dgst":
        return run_digest(arguments[1:])

    if arguments and arguments[0] == "derive":
        return run_derive(arguments[1:])

    parser = build_parser()

    try:
        args = parser.parse_args(arguments)
    except SystemExit as exc:
        return int(exc.code)

    try:
        mode = validate_arguments(args)
        if not Path(args.input_file).is_file():
            raise OSError("input file does not exist or is not a regular file")
        key = resolve_key(args)

        output_file = (
            args.output_file
            or get_default_output(
                args.input_file,
                args.decrypt,
            )
        )

        with ExitStack() as stack:
            if args.aad_file is not None:
                aad = stack.enter_context(open(args.aad_file, "rb"))
            else:
                aad = parse_aad(args.aad)
            if args.encrypt:
                encrypt_file(args.input_file, output_file, key, mode, aad)
            else:
                provided_iv = parse_iv(args.iv) if (args.iv is not None and mode not in {"gcm", "etm"}) else None
                provided_nonce = parse_nonce(args.nonce or args.iv) if mode == "gcm" and (args.nonce or args.iv) is not None else None
                decrypt_file(args.input_file, output_file, key, mode, aad, provided_iv, provided_nonce)

        if args.decrypt and mode in AEAD_MODES:
            print(
                "[SUCCESS] Decryption completed successfully"
            )

        return 0

    except (
        AuthenticationError,
        EtMAuthenticationError,
    ) as exc:
        print(
            f"[ERROR] {exc}",
            file=sys.stderr,
        )
        return 1

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
    """Console script entry point returning an integer process status.
    
        Returns:
            Integer result or process exit code.
    
        Raises:
            ArgumentError, ValueError, OSError or an authentication error on invalid operations.
    """
    return run()


if __name__ == "__main__":
    raise SystemExit(main())