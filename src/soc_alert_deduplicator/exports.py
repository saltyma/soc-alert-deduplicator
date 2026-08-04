"""Additional incident export formats."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

from .errors import IncidentOutputError
from .io import Incident

CSV_FIELDS = (
    "incident_id",
    "severity",
    "alert_count",
    "host",
    "user",
    "event_type",
    "process_name",
    "file_hash",
    "first_seen",
    "last_seen",
    "alert_ids",
    "grouping_fields",
    "summary",
)


def _safe_csv_value(value: Any) -> Any:
    if isinstance(value, str) and value.lstrip().startswith(("=", "+", "-", "@")):
        return f"'{value}"
    return value


def _csv_row(incident: Incident) -> dict[str, Any]:
    row = {field: incident.get(field, "") for field in CSV_FIELDS}
    row["alert_ids"] = ";".join(str(value) for value in incident["alert_ids"])
    row["grouping_fields"] = json.dumps(
        incident["grouping_fields"], ensure_ascii=False, sort_keys=True
    )
    return {field: _safe_csv_value(value) for field, value in row.items()}


def write_incidents_csv(
    path: Path,
    incidents: list[Incident],
    *,
    protected_paths: tuple[Path, ...] = (),
) -> None:
    """Write a stable UTF-8 CSV export atomically."""

    resolved_output = path.resolve(strict=False)
    if any(
        resolved_output == protected.resolve(strict=False)
        for protected in protected_paths
    ):
        raise IncidentOutputError(
            f"CSV output cannot overwrite a protected file: {path}"
        )

    parent = path.parent
    if not parent.exists():
        raise IncidentOutputError(f"CSV output directory does not exist: {parent}")
    if not parent.is_dir():
        raise IncidentOutputError(f"CSV output parent is not a directory: {parent}")
    if path.exists() and path.is_dir():
        raise IncidentOutputError(f"CSV output path is a directory: {path}")

    temporary_path: Path | None = None
    try:
        with NamedTemporaryFile(
            mode="w",
            encoding="utf-8-sig",
            newline="",
            dir=parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS)
            writer.writeheader()
            writer.writerows(_csv_row(incident) for incident in incidents)
        temporary_path.replace(path)
    except (OSError, TypeError, ValueError, KeyError) as exc:
        raise IncidentOutputError(f"cannot write CSV output {path}: {exc}") from exc
    finally:
        if temporary_path is not None and temporary_path.exists():
            try:
                temporary_path.unlink()
            except OSError:
                pass
