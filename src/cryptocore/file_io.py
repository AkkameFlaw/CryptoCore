"""Binary file reading and writing helpers."""

from pathlib import Path


def read_binary(path: str | Path) -> bytes:

    """Read the entire file contents as bytes.
    
        Args:
            path: Parameter used by this operation; see docs/API.md.
    
        Returns:
            Binary result.
    
        Raises:
            ValueError/TypeError on invalid input, when validated; OSError for file operations.
    """
    with Path(path).open("rb") as file:
        return file.read()


def write_binary(path: str | Path, data: bytes) -> None:

    """Write bytes to a binary output file.
    
        Args:
            path: Parameter used by this operation; see docs/API.md.
            data: Binary input; for ciphertext, the format depends on the selected mode.
    
        Returns:
            Nothing; raises on validation failure.
    
        Raises:
            ValueError/TypeError on invalid input, when validated; OSError for file operations.
    """
    target = Path(path)

    if target.parent != Path("."):
        target.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

    with target.open("wb") as file:
        file.write(data)