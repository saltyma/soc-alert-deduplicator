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
from .smart_pipeline import run_smart_pipeline


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc-alert-deduplicator",
        description=(
            "Automatically normalize security telemetry and group related alerts into "
            "explainable incidents."
        ),
    )
    parser.add_argument(
        "--input",
        required=True,
        action="append",
        type=Path,
        help="input telemetry path; repeat to combine files",
    )
    parser.add_argument(
        "--mode",
        choices=("smart", "exact"),
        help=(
            "adaptive SMART engine or legacy exact policy; defaults to SMART unless "
            "a legacy exact config is supplied"
        ),
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="optional SMART tuning file, or required exact-mode config",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("output.json"),
        help="path for grouped incidents (default: output.json)",
    )
    parser.add_argument(
        "--profile-output",
        type=Path,
        help="optional path for the inferred SMART profile sidecar",
    )
    return parser


def run_pipeline(
    input_path: Path, config_path: Path, output_path: Path
) -> tuple[int, int]:
    """Run the complete exact-policy pipeline and return alert/incident counts."""

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
        mode = args.mode
        if mode is None and args.config is not None:
            try:
                load_settings(args.config)
            except DeduplicatorError:
                mode = "smart"
            else:
                mode = "exact"
        mode = mode or "smart"
        if mode == "exact":
            if len(args.input) != 1:
                print("error: exact mode accepts exactly one --input", file=sys.stderr)
                return 2
            config_path = args.config or Path("config.json")
            alert_count, incident_count = run_pipeline(
                args.input[0],
                config_path,
                args.output,
            )
            detail = "Exact policy applied."
        else:
            result = run_smart_pipeline(
                args.input,
                args.output,
                overrides_path=args.config,
                profile_output_path=args.profile_output,
            )
            alert_count = len(result.alerts)
            incident_count = len(result.incidents)
            formats = ", ".join(
                sorted({source.detected_format for source in result.ingestion.sources})
            )
            detail = (
                f"SMART profile {result.profile.profile_id}: {formats}; "
                f"{result.profile.time_window_minutes}-minute window.\n"
                f"Profile written to {result.profile_path}."
            )
    except DeduplicatorError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"Processed {alert_count} alerts into {incident_count} incidents.")
    print(f"Output written to {args.output}.")
    print(detail)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
