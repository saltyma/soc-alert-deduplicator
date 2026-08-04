from __future__ import annotations

import json
from pathlib import Path

from soc_alert_deduplicator.smart_pipeline import run_smart_pipeline


def test_pipeline_combines_formats_and_writes_profile_evidence(tmp_path: Path) -> None:
    json_path = tmp_path / "first.json"
    json_path.write_text(
        json.dumps(
            [
                {
                    "id": "J-1",
                    "timestamp": "2026-07-01T12:00:00Z",
                    "hostname": "ws-01",
                    "action": "login_failed",
                    "severity": "high",
                    "user": "alice",
                }
            ]
        ),
        encoding="utf-8",
    )
    csv_path = tmp_path / "second.csv"
    csv_path.write_text(
        "id,timestamp,host,event_type,severity,user\n"
        "C-1,2026-07-01T12:01:00Z,ws-01,login_failed,high,alice\n",
        encoding="utf-8",
    )
    output = tmp_path / "incidents.json"

    result = run_smart_pipeline([json_path, csv_path], output)

    assert len(result.alerts) == 2
    assert len(result.incidents) == 1
    assert output.is_file()
    profile = json.loads(result.profile_path.read_text(encoding="utf-8"))
    assert profile["engine"] == "SMART"
    assert profile["input"]["alert_count"] == 2
    assert [source["detected_format"] for source in profile["input"]["sources"]] == [
        "json",
        "csv",
    ]
    assert profile["output"]["incident_count"] == 1
    assert profile["output"]["reduction_percent"] == 50.0


def test_pipeline_accepts_optional_tuning_only_when_requested(tmp_path: Path) -> None:
    source = tmp_path / "events.log"
    source.write_text(
        "timestamp=2026-07-01T12:00:00Z host=ws-01 action=x severity=low\n",
        encoding="utf-8",
    )
    tuning = tmp_path / "smart.json"
    tuning.write_text(
        json.dumps({"threshold": 0.95, "time_window_minutes": 3}),
        encoding="utf-8",
    )

    result = run_smart_pipeline([source], tmp_path / "out.json", overrides_path=tuning)

    assert result.profile.threshold == 0.95
    assert result.profile.time_window_minutes == 3
