"""Public exports of the cryptocore.__main__ package."""

from .cli import main


if __name__ == "__main__":
    raise SystemExit(main())