import argparse
import hashlib
import json
import platform
import sys
from pathlib import Path
from time import perf_counter

from kdf import pbkdf2_hmac_sha256


RESULTS_PATH = Path("docs/sprint7_performance.json")
REPORT_PATH = Path("docs/sprint7_performance.md")


def measure(function):
    started = perf_counter()
    result = function()
    elapsed = perf_counter() - started

    return result, elapsed


def save_results(results):
    RESULTS_PATH.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    RESULTS_PATH.write_text(
        json.dumps(
            results,
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    lines = [
        "# Sprint 7 — PBKDF2 performance",
        "",
        f"Python: {sys.version.split()[0]}",
        "",
        f"Platform: {platform.platform()}",
        "",
        "Алгоритм: PBKDF2-HMAC-SHA256",
        "",
        "Длина ключа: 32 байта",
        "",
        "| Итерации | CryptoCore, с | hashlib, с | Замедление | Совпадение |",
        "| ---: | ---: | ---: | ---: | --- |",
    ]

    for key in sorted(results, key=int):
        item = results[key]

        lines.append(
            f"| {int(key):,} "
            f"| {item['cryptocore_seconds']:.6f} "
            f"| {item['hashlib_seconds']:.6f} "
            f"| {item['slowdown']:.2f}x "
            f"| {item['match']} |"
        )

    lines.extend([
        "",
        "CryptoCore использует собственные реализации "
        "PBKDF2, HMAC-SHA256 и SHA-256.",
        "",
        "hashlib используется только для сравнения "
        "результатов и производительности.",
        "",
    ])

    REPORT_PATH.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--iterations",
        nargs="+",
        type=int,
        default=[10000],
    )

    args = parser.parse_args()

    if any(
        value < 1
        for value in args.iterations
    ):
        parser.error(
            "iterations must be positive"
        )

    password = b"CryptoCore benchmark password"

    salt = bytes.fromhex(
        "00112233445566778899aabbccddeeff"
    )

    if RESULTS_PATH.exists():
        results = json.loads(
            RESULTS_PATH.read_text(
                encoding="utf-8"
            )
        )
    else:
        results = {}

    for iterations in args.iterations:
        print(
            f"Iterations: {iterations}",
            flush=True,
        )

        actual, own_time = measure(
            lambda: pbkdf2_hmac_sha256(
                password,
                salt,
                iterations,
                32,
            )
        )

        expected, reference_time = measure(
            lambda: hashlib.pbkdf2_hmac(
                "sha256",
                password,
                salt,
                iterations,
                dklen=32,
            )
        )

        match = actual == expected

        slowdown = (
            own_time
            / max(reference_time, 1e-12)
        )

        print(
            f"CryptoCore: {own_time:.6f} s"
        )

        print(
            f"hashlib:    {reference_time:.6f} s"
        )

        print(
            f"Slowdown:   {slowdown:.2f}x"
        )

        print(
            f"Match:      {match}"
        )

        print()

        results[str(iterations)] = {
            "cryptocore_seconds": own_time,
            "hashlib_seconds": reference_time,
            "slowdown": slowdown,
            "match": match,
        }

        save_results(results)

        if not match:
            raise SystemExit(1)

        if iterations == 10000:
            print(
                "Estimated 100000 iterations: "
                f"{own_time * 10:.1f} s"
            )

            print(
                "Estimated 1000000 iterations: "
                f"{own_time * 100:.1f} s"
            )

            print()

    print(
        f"Saved to: {REPORT_PATH}"
    )


if __name__ == "__main__":
    main()