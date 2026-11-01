import runpy
import sys

import pytest


def test_module_entrypoint_help(
    monkeypatch,
    capsys,
):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "cryptocore",
            "derive",
            "--help",
        ],
    )

    with pytest.raises(SystemExit) as exc:
        runpy.run_module(
            "cryptocore",
            run_name="__main__",
        )

    assert exc.value.code == 0
    assert "usage:" in capsys.readouterr().out.lower()