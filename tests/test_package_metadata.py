from __future__ import annotations

import tomllib
from pathlib import Path

from soc_alert_deduplicator import __version__


def test_runtime_and_project_versions_match() -> None:
    project = tomllib.loads(
        (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text(
            encoding="utf-8"
        )
    )

    assert __version__ == project["project"]["version"] == "2.0.0"
