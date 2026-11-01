"""Inspect CryptoCore source files and inventory public definitions."""

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE_DIR = ROOT / "src"
OUTPUT = ROOT / "docs" / "API_INVENTORY.md"

FUNCTION_TYPES = (
    ast.FunctionDef,
    ast.AsyncFunctionDef,
)


def module_name(path: Path) -> str:
    """Convert a source file path into its Python module name."""
    parts = list(
        path.relative_to(SOURCE_DIR).with_suffix("").parts
    )

    if parts[-1] == "__init__":
        parts.pop()

    return ".".join(parts)


def signature(name: str, node) -> str:
    """Build a readable signature from a function AST node."""
    arguments = ast.unparse(node.args)

    returns = (
        ast.unparse(node.returns)
        if node.returns is not None
        else "unspecified"
    )

    return f"{name}({arguments}) -> {returns}"


def collect_definitions(path: Path) -> list[dict]:
    """Extract public functions, classes and methods from a file."""
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))

    module = module_name(path)
    results = []

    for node in tree.body:
        if isinstance(node, FUNCTION_TYPES):
            if node.name.startswith("_"):
                continue

            results.append({
                "name": f"{module}.{node.name}",
                "signature": signature(node.name, node),
                "documented": bool(ast.get_docstring(node)),
                "file": str(path.relative_to(ROOT)),
                "line": node.lineno,
            })

        elif isinstance(node, ast.ClassDef):
            if node.name.startswith("_"):
                continue

            results.append({
                "name": f"{module}.{node.name}",
                "signature": f"class {node.name}",
                "documented": bool(ast.get_docstring(node)),
                "file": str(path.relative_to(ROOT)),
                "line": node.lineno,
            })

            for method in node.body:
                if not isinstance(method, FUNCTION_TYPES):
                    continue

                if (
                    method.name.startswith("_")
                    and method.name != "__init__"
                ):
                    continue

                results.append({
                    "name": (
                        f"{module}.{node.name}.{method.name}"
                    ),
                    "signature": signature(
                        method.name,
                        method,
                    ),
                    "documented": bool(
                        ast.get_docstring(method)
                    ),
                    "file": str(path.relative_to(ROOT)),
                    "line": method.lineno,
                })

    return results


def main() -> int:
    """Create an inventory and identify missing docstrings."""
    definitions = []

    for path in sorted(SOURCE_DIR.rglob("*.py")):
        definitions.extend(collect_definitions(path))

    definitions.sort(key=lambda item: item["name"])

    missing = sum(
        not item["documented"]
        for item in definitions
    )

    lines = [
        "# CryptoCore API Inventory",
        "",
        "Generated from source files using Python AST.",
        "",
        f"Definitions found: {len(definitions)}",
        "",
        f"Missing docstrings: {missing}",
        "",
        "This inventory includes all non-private definitions.",
        "It must be reviewed before deciding which objects "
        "belong to the supported public API.",
        "",
    ]

    for item in definitions:
        status = (
            "Present"
            if item["documented"]
            else "MISSING"
        )

        lines.extend([
            f"### `{item['name']}`",
            "",
            f"Signature: `{item['signature']}`",
            "",
            f"Source: `{item['file']}:{item['line']}`",
            "",
            f"Docstring: **{status}**",
            "",
        ])

    OUTPUT.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    OUTPUT.write_text(
        "\n".join(lines),
        encoding="utf-8",
    )

    print(f"Definitions: {len(definitions)}")
    print(f"Missing docstrings: {missing}")
    print(f"Report: {OUTPUT.relative_to(ROOT)}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())