from mac import HMAC


HASH_SIZE = 32
MAX_BLOCKS = (1 << 32) - 1


def _normalize_password(
    password: bytes | str,
) -> bytes:
    if isinstance(password, str):
        return password.encode("utf-8")

    if isinstance(password, (bytes, bytearray, memoryview)):
        return bytes(password)

    raise TypeError("password must be bytes-like or str")


def _prf(template: HMAC, message: bytes) -> bytes:
    instance = template.copy()
    instance.update(message)
    return instance.digest()


def pbkdf2_hmac_sha256(
    password: bytes | str,
    salt: bytes,
    iterations: int,
    dklen: int,
) -> bytes:
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