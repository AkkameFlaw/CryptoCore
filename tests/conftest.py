"""Test isolation: one nonce registry per pytest test case."""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def isolated_nonce_registry(tmp_path, monkeypatch):
    monkeypatch.setenv("CRYPTOCORE_NONCE_DB", str(tmp_path / "test-nonces.sqlite3"))
