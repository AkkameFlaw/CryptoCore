import os


def generate_random_bytes(
    num_bytes: int,
) -> bytes:
    if not isinstance(num_bytes, int):
        raise TypeError(
            "num_bytes must be an integer"
        )

    if num_bytes < 0:
        raise ValueError(
            "num_bytes must not be negative"
        )

    try:
        return os.urandom(num_bytes)

    except OSError as exc:
        raise RuntimeError(
            f"CSPRNG failure: {exc}"
        ) from exc