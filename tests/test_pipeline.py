from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from soc_alert_deduplicator.main import build_parser, main, run_pipeline

from conftest import DEFAULT_CONFIG, DEMO_ALERTS, EXPECTED_INCIDENTS, PROJECT_ROOT


def test_run_pipeline_matches_benchmark_oracle_byte_for_byte(tmp_path: Path) -> None:
    output = tmp_path / "incidents.json"

    counts = run_pipeline(DEMO_ALERTS, DEFAULT_CONFIG, output)

    assert counts == (40, 17)
    assert output.read_bytes() == EXPECTED_INCIDENTS.read_bytes()


def test_run_pipeline_changes_grouping_without_code_changes(tmp_path: Path) -> None:
    config = tmp_path / "event-only.json"
    output = tmp_path / "incidents.json"
    config.write_text(
        json.dumps(
            {
                "group_by": ["event_type"],
                "case_sensitive": False,
                "missing_value": "unknown",
                "minimum_match_score": 1.0,
            }
        ),
        encoding="utf-8",
    )

    counts = run_pipeline(DEMO_ALERTS, config, output)
    incidents = json.loads(output.read_text(encoding="utf-8"))

    assert counts == (40, 6)
    assert sum(incident["alert_count"] for incident in incidents) == 40
    assert all(
        tuple(incident["grouping_fields"]) == ("event_type",) for incident in incidents
    )


def test_main_reports_success_and_output_location(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "incidents.json"

    exit_code = main(
        [
            "--input",
            str(DEMO_ALERTS),
            "--config",
            str(DEFAULT_CONFIG),
            "--output",
            str(output),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.err == ""
    assert "Processed 40 alerts into 17 incidents." in captured.out
    assert f"Output written to {output}." in captured.out


def test_main_returns_two_and_prints_concise_domain_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "incidents.json"

    exit_code = main(
        [
            "--input",
            str(tmp_path / "missing.json"),
            "--config",
            str(DEFAULT_CONFIG),
            "--output",
            str(output),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 2
    assert captured.out == ""
    assert "error: alert file not found" in captured.err
    assert not output.exists()


def test_build_parser_applies_default_paths() -> None:
    args = build_parser().parse_args(["--input", "alerts.json"])

    assert args.input == [Path("alerts.json")]
    assert args.config is None
    assert args.output == Path("output.json")


def test_build_parser_requires_input() -> None:
    with pytest.raises(SystemExit) as exc_info:
        build_parser().parse_args([])

    assert exc_info.value.code == 2


def test_python_module_entrypoint_runs_end_to_end(tmp_path: Path) -> None:
    output = tmp_path / "incidents.json"
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(PROJECT_ROOT / "src")

    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "soc_alert_deduplicator",
            "--input",
            str(DEMO_ALERTS),
            "--config",
            str(DEFAULT_CONFIG),
            "--output",
            str(output),
        ],
        cwd=PROJECT_ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert "Processed 40 alerts into 17 incidents." in completed.stdout
    assert completed.stderr == ""
    assert output.read_bytes() == EXPECTED_INCIDENTS.read_bytes()


def test_benchmark_output_contains_every_alert_exactly_once() -> None:
    raw_alerts = json.loads(DEMO_ALERTS.read_text(encoding="utf-8"))
    incidents = json.loads(EXPECTED_INCIDENTS.read_text(encoding="utf-8"))

    input_ids = [alert["alert_id"] for alert in raw_alerts]
    grouped_ids = [
        alert_id for incident in incidents for alert_id in incident["alert_ids"]
    ]

    assert len(raw_alerts) == 40
    assert len(incidents) == 17
    assert len(grouped_ids) == len(set(grouped_ids))
    assert set(grouped_ids) == set(input_ids)
