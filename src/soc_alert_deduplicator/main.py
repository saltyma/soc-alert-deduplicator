"""Command-line orchestration for the SOC Alert Deduplicator."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from .config import load_settings
from .deduplication import group_alerts
from .errors import DeduplicatorError
from .io import load_alerts, write_incidents
from .summaries import build_incidents


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc-alert-deduplicator",
        description="Group normalized JSON security alerts into incident summaries.",
    )
    parser.add_argument(
        "--input",
        required=True,
        type=Path,
        help="path to a JSON array of alerts",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config.json"),
        help="path to grouping configuration (default: config.json)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("output.json"),
        help="path for grouped incidents (default: output.json)",
    )
    return parser


def run_pipeline(
    input_path: Path, config_path: Path, output_path: Path
) -> tuple[int, int]:
    """Run the complete v1 pipeline and return alert/incident counts."""

    settings = load_settings(config_path)
    alerts = load_alerts(input_path)
    groups = group_alerts(alerts, settings)
    incidents = build_incidents(groups, settings)
    write_incidents(
        output_path,
        incidents,
        protected_paths=(input_path, config_path),
    )
    return len(alerts), len(incidents)


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        alert_count, incident_count = run_pipeline(
            args.input,
            args.config,
            args.output,
        )
    except DeduplicatorError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"Processed {alert_count} alerts into {incident_count} incidents.")
    print(f"Output written to {args.output}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
