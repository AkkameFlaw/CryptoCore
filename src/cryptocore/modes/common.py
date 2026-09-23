BLOCK_SIZE = 16


def validate_key(key: bytes) -> None:
    if len(key) != BLOCK_SIZE:
        raise ValueError(
            "AES-128 key must be exactly 16 bytes"
        )


def validate_iv(iv: bytes) -> None:
    if len(iv) != BLOCK_SIZE:
        raise ValueError(
            "IV must be exactly 16 bytes"
        )


def xor_bytes(
    left: bytes,
    right: bytes,
) -> bytes:
    return bytes(
        a ^ b
        for a, b in zip(left, right)
    )