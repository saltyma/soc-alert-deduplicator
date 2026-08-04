from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from soc_alert_deduplicator.config import Settings
from soc_alert_deduplicator.io import Alert

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEMO_ALERTS = PROJECT_ROOT / "data" / "demo" / "raw_alerts.json"
EXPECTED_INCIDENTS = PROJECT_ROOT / "data" / "demo" / "expected_incidents.json"
DEFAULT_CONFIG = PROJECT_ROOT / "config.json"


@pytest.fixture
def settings() -> Settings:
    return Settings(
        group_by=("host", "user", "event_type", "process_name", "file_hash"),
        case_sensitive=False,
        missing_value="unknown",
        minimum_match_score=1.0,
    )


@pytest.fixture
def make_alert() -> Callable[..., Alert]:
    def factory(**overrides: Any) -> Alert:
        alert: Alert = {
            "alert_id": "ALERT-TEST-001",
            "timestamp": "2026-06-01T08:15:00Z",
            "source": "mock-wazuh",
            "host": "WS-001",
            "user": "analyst.lab",
            "event_type": "malware_detection",
            "process_name": "sample.exe",
            "parent_process_name": "explorer.exe",
            "command_line": "C:\\Users\\analyst.lab\\sample.exe",
            "file_hash": "a" * 64,
            "severity": "high",
            "rule_name": "Synthetic Malware Detection",
            "description": "Synthetic test alert",
        }
        alert.update(overrides)
        return alert

    return factory
