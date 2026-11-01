"""Unified test runner for CryptoCore."""

import argparse
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]

COVERAGE_PACKAGES = (
    "cryptocore",
    "hash",
    "mac",
    "kdf",
    "modes",
    "aead",
)


def main() -> int:
    """Run the entire test suite with optional branch coverage."""
    parser = argparse.ArgumentParser(
        description="Run CryptoCore tests",
    )

    parser.add_argument(
        "--coverage",
        action="store_true",
    )

    parser.add_argument(
        "--enforce-coverage",
        action="store_true",
    )

    args, additional = parser.parse_known_args()

    command = [
        sys.executable,
        "-m",
        "pytest",
        "tests",
        "-q",
    ]

    if args.coverage or args.enforce_coverage:
        for package in COVERAGE_PACKAGES:
            command.append(f"--cov={package}")

        command.extend([
            "--cov-branch",
            "--cov-report=term-missing",
            "--cov-report=html:htmlcov",
            "--cov-report=json:coverage.json",
        ])

    if args.enforce_coverage:
        command.append("--cov-fail-under=90.01")

    command.extend(additional)

    result = subprocess.run(
        command,
        cwd=ROOT,
        check=False,
    )

    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())