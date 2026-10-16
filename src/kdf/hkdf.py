from mac import HMAC


HASH_SIZE = 32
MAX_BLOCKS = (1 << 32) - 1


def derive_key(
    master_key: bytes,
    context: str,
    length: int = 32,
) -> bytes:
    if not isinstance(
        master_key,
        (bytes, bytearray, memoryview),
    ):
        raise TypeError("master_key must be bytes-like")

    if not isinstance(context, str):
        raise TypeError("context must be a string")

    if not context:
        raise ValueError("context must not be empty")

    if isinstance(length, bool) or not isinstance(length, int):
        raise TypeError("length must be an integer")

    if length < 1:
        raise ValueError("length must be positive")

    blocks_needed = (length + HASH_SIZE - 1) // HASH_SIZE

    if blocks_needed > MAX_BLOCKS:
        raise ValueError("requested key length is too large")

    template = HMAC(bytes(master_key))
    context_bytes = context.encode("utf-8")
    result = bytearray()

    for counter in range(1, blocks_needed + 1):
        instance = template.copy()
        instance.update(context_bytes)
        instance.update(counter.to_bytes(4, "big"))
        result.extend(instance.digest())

    return bytes(result[:length])