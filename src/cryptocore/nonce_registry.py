"""Atomic local registry of nonce/IV values used by the CryptoCore CLI."""

from __future__ import annotations

import hashlib
import os
from contextlib import closing
import sqlite3
from pathlib import Path


def register_nonce(key: bytes, nonce: bytes, mode: str, database: str | Path | None = None) -> None:
    """Reserve a nonce for a key before publishing a ciphertext.

    Args:
        key: Binary AES master key; never stored in the registry.
        nonce: Generated nonce or IV bytes.
        mode: Cipher mode name for diagnostic records.
        database: Override for registry path; defaults to a per-user SQLite file.

    Raises:
        ValueError: If this key and nonce pair was previously reserved.
        OSError: If the registry cannot be created or opened.

    Security:
        Uniqueness is enforced only within installations sharing this database.
        Restoring old backups, deleting the database, or using another computer
        invalidates the uniqueness guarantee. Keep the database private and do
        not reuse keys across independent installations without coordination.
    """
    if database is None:
        database = os.getenv("CRYPTOCORE_NONCE_DB")
    location = Path(database) if database else Path.home() / ".cryptocore" / "nonces.sqlite3"
    location.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name != "nt":
        os.chmod(location.parent, 0o700)
    existed = location.exists()
    try:
        with closing(sqlite3.connect(str(location), timeout=30)) as conn, conn:
            conn.execute("CREATE TABLE IF NOT EXISTS used_nonces (key_id BLOB NOT NULL, nonce BLOB NOT NULL, mode TEXT NOT NULL, PRIMARY KEY (key_id, nonce))")
            try:
                conn.execute(
                    "INSERT INTO used_nonces(key_id, nonce, mode) VALUES (?, ?, ?)",
                    (hashlib.sha256(key).digest(), nonce, mode),
                )
                conn.commit()
            except sqlite3.IntegrityError as exc:
                raise ValueError("nonce/IV reuse detected for this key; encryption refused") from exc
    except sqlite3.Error as exc:
        raise OSError("nonce registry is not available; encryption refused") from exc
    if os.name != "nt" and not existed:
        os.chmod(location, 0o600)
