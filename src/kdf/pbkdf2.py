"""Pure-Python PBKDF2-HMAC-SHA256 implemented using the local HMAC class."""

from mac import HMAC


HASH_SIZE = 32
MAX_BLOCKS = (1 << 32) - 1
MAX_DERIVED_KEY_LENGTH = 1 << 16


def _normalize_password(
    password: bytes | bytearray | str,
) -> bytes:
    """Convert str passwords to UTF-8 bytes and validate bytes-like inputs.
    
        Args:
            password: Password bytes or a UTF-8 encoded str.
    
        Returns:
            Binary result.
    
        Raises:
            TypeError or ValueError on invalid types, counts and key length.
    """
    if isinstance(password, str):
        return password.encode("utf-8")

    if isinstance(password, (bytes, bytearray, memoryview)):
        return bytes(password)

    raise TypeError("password must be bytes-like or str")


def _prf(template: HMAC, message: bytes) -> bytes:
    """Evaluate one HMAC-SHA256 PRF using an independent copy of the keyed context.
    
        Args:
            template: Parameter used by this operation; see docs/API.md.
            message: Parameter used by this operation; see docs/API.md.
    
        Returns:
            Binary result.
    
        Raises:
            TypeError or ValueError on invalid types, counts and key length.
    """
    instance = template.copy()
    instance.update(message)
    return instance.digest()


def pbkdf2_hmac_sha256(
    password: bytes | bytearray | str,
    salt: bytes,
    iterations: int,
    dklen: int,
) -> bytes:
    """Derive exactly dklen key bytes using PBKDF2-HMAC-SHA256; maximum 65536 bytes.
    
        Args:
            password: Password bytes or a UTF-8 encoded str.
            salt: Salt bytes; CLI accepts HEX and creates 16 random bytes by default.
            iterations: Positive PBKDF2 iteration count (integer).
            dklen: Requested output size in bytes (1..65536 for PBKDF2).
    
        Returns:
            Binary result.
    
        Raises:
            TypeError or ValueError on invalid types, counts and key length.
    
        Security:
            Never log keys or passwords; see docs/SECURITY_AUDIT.md.
    """
    password_bytes = _normalize_password(password)

    if not isinstance(salt, (bytes, bytearray, memoryview)):
        raise TypeError("salt must be bytes-like")

    salt_bytes = bytes(salt)

    if isinstance(iterations, bool) or not isinstance(iterations, int):
        raise TypeError("iterations must be an integer")

    if iterations < 1:
        raise ValueError("iterations must be at least 1")

    if isinstance(dklen, bool) or not isinstance(dklen, int):
        raise TypeError("dklen must be an integer")

    if dklen < 1:
        raise ValueError("dklen must be positive")

    if dklen > MAX_DERIVED_KEY_LENGTH:
        raise ValueError(
            f"dklen must not exceed {MAX_DERIVED_KEY_LENGTH} bytes"
        )

    blocks_needed = (dklen + HASH_SIZE - 1) // HASH_SIZE

    if blocks_needed > MAX_BLOCKS:
        raise ValueError("derived key length exceeds PBKDF2 limit")

    template = HMAC(password_bytes)
    derived_key = bytearray()

    for block_index in range(1, blocks_needed + 1):
        block_number = block_index.to_bytes(4, "big")

        previous = _prf(
            template,
            salt_bytes + block_number,
        )

        accumulator = bytearray(previous)

        for _ in range(1, iterations):
            previous = _prf(template, previous)

            for position, value in enumerate(previous):
                accumulator[position] ^= value

        derived_key.extend(accumulator)

    return bytes(derived_key[:dklen])