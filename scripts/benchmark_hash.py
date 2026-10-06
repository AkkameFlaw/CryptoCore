import argparse
import platform
import shutil
import subprocess
from pathlib import Path
from time import perf_counter

from cryptocore.digest import hash_file


def find_program(
    names: list[str],
) -> str | None:
    for name in names:
        result = shutil.which(name)

        if result:
            return result

    return None


def find_existing(
    paths: list[str],
) -> str | None:
    for path in paths:
        if Path(path).exists():
            return path

    return None


def find_sha256sum(
) -> str | None:
    return (
        find_program(
            ["sha256sum"]
        )
        or find_existing(
            [
                r"C:\msys64\usr\bin\sha256sum.exe",
                r"C:\Program Files\Git\usr\bin\sha256sum.exe",
            ]
        )
    )


def find_sha3sum(
) -> str | None:
    return find_program(
        ["sha3sum"]
    )


def find_openssl(
) -> str | None:
    return (
        find_program(
            ["openssl"]
        )
        or find_existing(
            [
                r"C:\msys64\ucrt64\bin\openssl.exe",
                r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
            ]
        )
    )


def create_file(
    path: Path,
    size_mb: int,
) -> None:
    block = (
        bytes(range(256))
        * 4096
    )

    with path.open(
        "wb"
    ) as file:
        for _ in range(
            size_mb
        ):
            file.write(
                block
            )


def benchmark(
    function,
) -> tuple[str, float]:
    start = perf_counter()

    result = function()

    elapsed = (
        perf_counter()
        - start
    )

    return (
        result,
        elapsed,
    )


def system_sha256(
    executable: str,
    path: Path,
) -> str:
    result = subprocess.run(
        [
            executable,
            str(path),
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    return (
        result.stdout
        .strip()
        .split()[0]
    )


def system_sha3_sha3sum(
    executable: str,
    path: Path,
) -> str:
    result = subprocess.run(
        [
            executable,
            "-a",
            "256",
            str(path),
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    return (
        result.stdout
        .strip()
        .split()[0]
    )


def system_sha3_openssl(
    executable: str,
    path: Path,
) -> str:
    result = subprocess.run(
        [
            executable,
            "dgst",
            "-sha3-256",
            str(path),
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    output = (
        result.stdout.strip()
    )

    return (
        output
        .split("=")[-1]
        .strip()
    )


def main(
) -> None:
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--sizes-mb",
        type=int,
        nargs="+",
        default=[
            1,
            5,
            10,
        ],
    )

    parser.add_argument(
        "--output",
        default=(
            "docs/"
            "sprint4_performance.md"
        ),
    )

    args = parser.parse_args()

    sha256sum = (
        find_sha256sum()
    )

    sha3sum = (
        find_sha3sum()
    )

    openssl = (
        find_openssl()
    )

    if sha256sum is None:
        raise RuntimeError(
            "sha256sum was not found"
        )

    if (
        sha3sum is None
        and openssl is None
    ):
        raise RuntimeError(
            "sha3sum or OpenSSL "
            "was not found"
        )

    results = []

    for size_mb in args.sizes_mb:
        path = Path(
            f"benchmark_{size_mb}mb.bin"
        )

        create_file(
            path,
            size_mb,
        )

        try:
            crypto_hash, crypto_time = (
                benchmark(
                    lambda: hash_file(
                        str(path),
                        "sha256",
                    )
                )
            )

            system_hash, system_time = (
                benchmark(
                    lambda: system_sha256(
                        sha256sum,
                        path,
                    )
                )
            )

            results.append(
                (
                    size_mb,
                    "SHA-256",
                    crypto_time,
                    system_time,
                    crypto_time
                    / system_time,
                    crypto_hash
                    == system_hash,
                    "sha256sum",
                )
            )

            crypto_hash, crypto_time = (
                benchmark(
                    lambda: hash_file(
                        str(path),
                        "sha3-256",
                    )
                )
            )

            if sha3sum:
                system_name = (
                    "sha3sum"
                )

                system_function = (
                    lambda: (
                        system_sha3_sha3sum(
                            sha3sum,
                            path,
                        )
                    )
                )

            else:
                system_name = (
                    "OpenSSL"
                )

                system_function = (
                    lambda: (
                        system_sha3_openssl(
                            openssl,
                            path,
                        )
                    )
                )

            system_hash, system_time = (
                benchmark(
                    system_function
                )
            )

            results.append(
                (
                    size_mb,
                    "SHA3-256",
                    crypto_time,
                    system_time,
                    crypto_time
                    / system_time,
                    crypto_hash
                    == system_hash,
                    system_name,
                )
            )

        finally:
            path.unlink(
                missing_ok=True
            )

    lines = [
        "# Sprint 4 performance test",
        "",
        f"Python: {platform.python_version()}",
        "",
        f"Platform: {platform.platform()}",
        "",
        "Файлы обрабатывались потоково.",
        "",
        (
            "| Размер | Алгоритм | "
            "CryptoCore, с | "
            "Системная утилита | "
            "Система, с | "
            "Замедление | Совпадение |"
        ),
        (
            "| ---: | --- | ---: | "
            "--- | ---: | ---: | --- |"
        ),
    ]

    for (
        size_mb,
        algorithm,
        crypto_time,
        system_time,
        slowdown,
        match,
        system_name,
    ) in results:
        lines.append(
            f"| {size_mb} МБ "
            f"| {algorithm} "
            f"| {crypto_time:.6f} "
            f"| {system_name} "
            f"| {system_time:.6f} "
            f"| {slowdown:.2f}x "
            f"| {match} |"
        )

    lines.extend(
        [
            "",
            (
                "CryptoCore использует "
                "учебные реализации "
                "SHA-256 и SHA3-256 "
                "на чистом Python, "
                "поэтому ожидаемо работает "
                "медленнее оптимизированных "
                "системных реализаций."
            ),
            "",
            (
                "Во всех измерениях "
                "хеш CryptoCore также "
                "сравнивается с результатом "
                "системной утилиты."
            ),
        ]
    )

    output = Path(
        args.output
    )

    output.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output.write_text(
        "\n".join(lines) + "\n",
        encoding="utf-8",
    )

    print(
        "\n".join(lines)
    )

    print(
        f"\nSaved to: {output}"
    )


if __name__ == "__main__":
    main()