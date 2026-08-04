"""Safe JSON input validation and atomic output writing."""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

from .errors import AlertInputError, IncidentOutputError

Alert = dict[str, Any]
Incident = dict[str, Any]

REQUIRED_ALERT_FIELDS = (
    "alert_id",
    "timestamp",
    "source",
    "host",
    "event_type",
    "severity",
)
OPTIONAL_TEXT_FIELDS = frozenset(
    {
        "user",
        "process_name",
        "parent_process_name",
        "command_line",
        "file_hash",
        "rule_name",
        "description",
    }
)
SEVERITIES = frozenset({"informational", "low", "medium", "high", "critical"})
_SHA256_PATTERN = re.compile(r"^[0-9a-fA-F]{64}$")


class _DuplicateJsonKey(ValueError):
    pass


def _reject_duplicate_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey(key)
        result[key] = value
    return result


def parse_timestamp(value: str, *, alert_id: str) -> datetime:
    """Parse an ISO 8601 timestamp and require an explicit timezone."""

    normalized = f"{value[:-1]}+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise AlertInputError(
            f"alert {alert_id} has an invalid ISO 8601 timestamp: {value!r}"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise AlertInputError(
            f"alert {alert_id} timestamp must include a timezone: {value!r}"
        )
    return parsed


def _required_text(alert: Alert, field: str, *, index: int) -> str:
    value = alert.get(field)
    if not isinstance(value, str) or not value.strip():
        alert_id = alert.get("alert_id", "<unknown>")
        raise AlertInputError(
            f"alert at index {index} ({alert_id}) requires a nonempty string "
            f"for {field}"
        )
    return value


def _validate_alert(alert: Alert, *, index: int) -> None:
    missing = [field for field in REQUIRED_ALERT_FIELDS if field not in alert]
    if missing:
        alert_id = alert.get("alert_id", "<unknown>")
        raise AlertInputError(
            f"alert at index {index} ({alert_id}) is missing required field(s): "
            f"{', '.join(missing)}"
        )

    for field in REQUIRED_ALERT_FIELDS:
        _required_text(alert, field, index=index)

    alert_id = alert["alert_id"]
    parse_timestamp(alert["timestamp"], alert_id=alert_id)

    severity = alert["severity"]
    if severity not in SEVERITIES:
        allowed = ", ".join(sorted(SEVERITIES))
        raise AlertInputError(
            f"alert {alert_id} has unsupported severity {severity!r}; "
            f"expected one of: {allowed}"
        )

    for field in OPTIONAL_TEXT_FIELDS:
        if (
            field in alert
            and alert[field] is not None
            and not isinstance(alert[field], str)
        ):
            raise AlertInputError(
                f"alert {alert_id} field {field} must be a string or null"
            )

    file_hash = alert.get("file_hash")
    if isinstance(file_hash, str) and file_hash.strip():
        if not _SHA256_PATTERN.fullmatch(file_hash.strip()):
            raise AlertInputError(
                f"alert {alert_id} file_hash must be a 64-character hexadecimal "
                "SHA-256 value"
            )


def load_alerts(path: Path) -> list[Alert]:
    """Read and validate a UTF-8 JSON array of alerts."""

    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError as exc:
        raise AlertInputError(f"alert file not found: {path}") from exc
    except UnicodeDecodeError as exc:
        raise AlertInputError(f"alert file is not valid UTF-8: {path}") from exc
    except OSError as exc:
        raise AlertInputError(f"cannot read alert file {path}: {exc}") from exc

    try:
        payload = json.loads(text, object_pairs_hook=_reject_duplicate_json_keys)
    except _DuplicateJsonKey as exc:
        raise AlertInputError(f"duplicate JSON object key in {path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise AlertInputError(
            f"invalid JSON in {path} at line {exc.lineno}, column {exc.colno}: "
            f"{exc.msg}"
        ) from exc

    if not isinstance(payload, list):
        raise AlertInputError(
            f"alert input must be a JSON array, got {type(payload).__name__}"
        )

    alerts: list[Alert] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(payload):
        if not isinstance(item, dict):
            raise AlertInputError(
                f"alert at index {index} must be a JSON object, "
                f"got {type(item).__name__}"
            )

        alert = dict(item)
        _validate_alert(alert, index=index)
        alert_id = alert["alert_id"]
        if alert_id in seen_ids:
            raise AlertInputError(f"duplicate alert_id: {alert_id}")
        seen_ids.add(alert_id)
        alerts.append(alert)

    return alerts


def write_incidents(
    path: Path,
    incidents: list[Incident],
    *,
    protected_paths: tuple[Path, ...] = (),
) -> None:
    """Atomically write incidents without overwriting an input/config file."""

    resolved_output = path.resolve(strict=False)
    for protected in protected_paths:
        if resolved_output == protected.resolve(strict=False):
            raise IncidentOutputError(
                f"output path cannot overwrite an input file: {path}"
            )

    parent = path.parent
    if not parent.exists():
        raise IncidentOutputError(f"output directory does not exist: {parent}")
    if not parent.is_dir():
        raise IncidentOutputError(f"output parent is not a directory: {parent}")
    if path.exists() and path.is_dir():
        raise IncidentOutputError(f"output path is a directory: {path}")

    temporary_path: Path | None = None
    try:
        with NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary_path = Path(handle.name)
            json.dump(
                incidents,
                handle,
                ensure_ascii=False,
                allow_nan=False,
                indent=2,
            )
            handle.write("\n")
        temporary_path.replace(path)
    except (OSError, TypeError, ValueError) as exc:
        raise IncidentOutputError(
            f"cannot write incident output {path}: {exc}"
        ) from exc
    finally:
        if temporary_path is not None and temporary_path.exists():
            try:
                temporary_path.unlink()
            except OSError:
                pass
