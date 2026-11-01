"""Cryptographically secure random bytes backed by the operating system."""

import os


def generate_random_bytes(
    num_bytes: int,
) -> bytes:
    """Return num_bytes of cryptographically secure OS-generated randomness.
    
        Args:
            num_bytes: Requested count of random bytes.
    
        Returns:
            Binary result.
    
        Raises:
            ValueError/TypeError on invalid input, when validated; OSError for file operations.
    """
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