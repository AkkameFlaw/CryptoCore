from pathlib import Path


def read_binary(path: str | Path) -> bytes:

    with Path(path).open("rb") as file:
        return file.read()


def write_binary(path: str | Path, data: bytes) -> None:

    target = Path(path)

    if target.parent != Path("."):
        target.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

    with target.open("wb") as file:
        file.write(data)