"""Automatic ingestion and schema mapping for common security telemetry formats."""

from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import json
import re
import sys
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path, PureWindowsPath
from typing import Any, Iterable, Sequence

from .errors import AlertInputError, DeduplicatorError, RawImportError
from .io import (
    Alert,
    REQUIRED_ALERT_FIELDS,
    SEVERITIES,
    parse_timestamp,
    validate_alerts,
    write_json_document,
)
from .raw_import import parse_crowdstrike_json, parse_windows_event_xml

MAX_EXPANDED_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 128
WINDOWS_EVENT_MARKER = "http://schemas.microsoft.com/win/2004/08/events/event"

_RFC5424 = re.compile(
    r"^<(?P<priority>\d{1,3})>(?P<version>\d{1,3})\s+"
    r"(?P<timestamp>\S+)\s+(?P<host>\S+)\s+(?P<app>\S+)\s+"
    r"(?P<procid>\S+)\s+(?P<msgid>\S+)\s+(?P<body>.*)$"
)
_BSD_SYSLOG = re.compile(
    r"^(?:<(?P<priority>\d{1,3})>)?"
    r"(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<app>[\w.\\/-]+)(?:\[(?P<pid>\d+)\])?:\s*"
    r"(?P<body>.*)$"
)
_KEY_VALUE = re.compile(
    r"(?P<key>[A-Za-z_][\w.:-]*)=(?P<value>\"(?:\\.|[^\"])*\"|'(?:\\.|[^'])*'|\S+)"
)
_ISO_TIMESTAMP = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
)
_SHA256 = re.compile(r"(?i)(?:sha256[=: ]*)?\b([0-9a-f]{64})\b")
_NON_KEY = re.compile(r"[^a-z0-9]+")
_EVENT_TOKEN = re.compile(r"[^a-z0-9]+")

FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "alert_id": (
        "alert_id",
        "alertid",
        "id",
        "uuid",
        "event_uid",
        "eventuuid",
        "event_record_id",
        "eventrecordid",
        "record_id",
        "recordid",
        "_id",
    ),
    "timestamp": (
        "timestamp",
        "@timestamp",
        "event_time",
        "eventtime",
        "datetime",
        "date_time",
        "time",
        "created_at",
        "creationtime",
        "utc_time",
        "utctime",
        "timegenerated",
        "systemtime",
        "devicereceipttime",
        "rt",
    ),
    "source": (
        "source",
        "sourcetype",
        "log_source",
        "logsource",
        "product",
        "device_product",
        "deviceproduct",
        "vendor",
        "device_vendor",
        "observer_type",
        "dataset",
    ),
    "host": (
        "host",
        "hostname",
        "computer",
        "computername",
        "devicehostname",
        "dhost",
        "destinationhost",
        "agent_name",
        "agentname",
        "device_name",
        "devicename",
        "aid",
        "src",
        "sourcehost",
    ),
    "event_type": (
        "event_type",
        "eventtype",
        "event_name",
        "eventname",
        "event_action",
        "eventaction",
        "action",
        "signature",
        "signatureid",
        "name",
        "msgid",
        "eventid",
        "rule_name",
        "rulename",
        "category",
        "cat",
    ),
    "severity": (
        "severity",
        "sev",
        "level",
        "priority",
        "risk",
        "risk_score",
        "threatlevel",
        "rule_level",
    ),
    "user": (
        "user",
        "username",
        "user_name",
        "usrname",
        "account",
        "accountname",
        "subjectusername",
        "targetusername",
        "sourceuser",
        "user_sid",
        "usersid",
    ),
    "process_name": (
        "process_name",
        "processname",
        "process",
        "image",
        "imagefilename",
        "sourceimage",
        "newprocessname",
        "executable",
        "exe",
    ),
    "target_process_name": (
        "target_process_name",
        "targetprocessname",
        "targetimage",
        "targetimagefilename",
        "destinationprocessname",
    ),
    "parent_process_name": (
        "parent_process_name",
        "parentprocessname",
        "parentimage",
        "parentbasefilename",
        "parent_image_file_name",
    ),
    "command_line": (
        "command_line",
        "commandline",
        "processcommandline",
        "cmdline",
        "cmd",
    ),
    "file_hash": (
        "file_hash",
        "filehash",
        "sha256",
        "sha256hashdata",
        "hash",
        "hashes",
    ),
    "rule_name": (
        "rule_name",
        "rulename",
        "rule_description",
        "ruledescription",
        "signature",
        "detection_name",
        "detectionname",
    ),
    "description": (
        "description",
        "message",
        "msg",
        "reason",
        "details",
        "summary",
        "event_original",
        "raw",
    ),
}
NORMALIZED_ALIASES = {
    field: tuple(_NON_KEY.sub("", alias.casefold()) for alias in aliases)
    for field, aliases in FIELD_ALIASES.items()
}


@dataclass(frozen=True, slots=True)
class SourceReport:
    """Ingestion evidence for one source file or archive member."""

    path: str
    detected_format: str
    record_count: int
    mapped_fields: tuple[str, ...]
    warnings: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class IngestionResult:
    """Normalized alerts and transparent auto-detection evidence."""

    alerts: list[Alert]
    sources: tuple[SourceReport, ...]

    @property
    def warnings(self) -> tuple[str, ...]:
        return tuple(warning for source in self.sources for warning in source.warnings)


class _DuplicateKey(ValueError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(key)
        result[key] = value
    return result


def _key(value: str) -> str:
    return _NON_KEY.sub("", value.casefold())


def _text(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    result = str(value).strip()
    return result if result and result != "-" else None


def _flatten(value: object, prefix: str = "") -> dict[str, object]:
    flattened: dict[str, object] = {}
    if isinstance(value, dict):
        for raw_key, child in value.items():
            name = str(raw_key)
            path = f"{prefix}.{name}" if prefix else name
            if isinstance(child, dict):
                flattened.update(_flatten(child, path))
            elif (
                isinstance(child, list)
                and child
                and all(isinstance(item, dict) for item in child)
            ):
                flattened[path] = child
            else:
                flattened[path] = child
    else:
        flattened[prefix or "value"] = value
    return flattened


def _field_index(flattened: dict[str, object]) -> dict[str, object]:
    indexed: dict[str, object] = {}
    for name, value in flattened.items():
        if _text(value) is None:
            continue
        parts = name.split(".")
        for start in range(len(parts)):
            indexed.setdefault(_key(".".join(parts[start:])), value)
    return indexed


def _lookup(indexed: dict[str, object], field: str) -> object | None:
    for alias in NORMALIZED_ALIASES[field]:
        if alias in indexed:
            return indexed[alias]
    return None


def _basename(value: object) -> str | None:
    result = _text(value)
    if result is None:
        return None
    return PureWindowsPath(result).name or result


def _event_slug(value: object) -> str:
    text = (_text(value) or "generic_event").casefold()
    slug = _EVENT_TOKEN.sub("_", text).strip("_")
    return slug[:120] or "generic_event"


def _normalize_severity(value: object, *, syslog_priority: bool = False) -> str:
    text = (_text(value) or "").casefold()
    named = {
        "emergency": "critical",
        "alert": "critical",
        "fatal": "critical",
        "critical": "critical",
        "crit": "critical",
        "error": "high",
        "err": "high",
        "high": "high",
        "warning": "medium",
        "warn": "medium",
        "medium": "medium",
        "notice": "low",
        "low": "low",
        "info": "informational",
        "informational": "informational",
        "debug": "informational",
    }
    if text in SEVERITIES:
        return text
    if text in named:
        return named[text]
    try:
        number = float(text)
    except ValueError:
        return "informational"
    if syslog_priority:
        number = int(number) % 8
        return (
            "critical"
            if number <= 2
            else "high"
            if number == 3
            else "medium"
            if number == 4
            else "low"
            if number == 5
            else "informational"
        )
    return (
        "critical"
        if number >= 9
        else "high"
        if number >= 6
        else "medium"
        if number >= 3
        else "low"
        if number > 0
        else "informational"
    )


def _normalize_timestamp(
    value: object,
    *,
    fallback: datetime,
    warnings: list[str],
) -> str:
    text = _text(value)
    if text is None:
        warnings.append("missing timestamps were derived from source file metadata")
        return fallback.isoformat(timespec="microseconds").replace("+00:00", "Z")
    if re.fullmatch(r"\d{10,19}", text):
        number = int(text)
        divisor = 1
        if len(text) >= 19:
            divisor = 1_000_000_000
        elif len(text) >= 16:
            divisor = 1_000_000
        elif len(text) >= 13:
            divisor = 1_000
        try:
            parsed = datetime.fromtimestamp(number / divisor, tz=timezone.utc)
        except (OSError, OverflowError, ValueError):
            parsed = fallback
            warnings.append("invalid numeric timestamps used source file metadata")
        return parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")

    normalized = text.replace(" ", "T", 1) if "T" not in text and " " in text else text
    if normalized.endswith("Z"):
        candidate = normalized
    elif re.search(r"[+-]\d{2}:?\d{2}$", normalized):
        candidate = normalized
    else:
        candidate = f"{normalized}Z"
        warnings.append("timezone-free timestamps were interpreted as UTC")
    try:
        parsed = parse_timestamp(candidate, alert_id="auto-import")
    except AlertInputError:
        for pattern in ("%b %d %H:%M:%S", "%b  %d %H:%M:%S"):
            try:
                partial = datetime.strptime(text, pattern)
            except ValueError:
                continue
            parsed = partial.replace(year=fallback.year, tzinfo=timezone.utc)
            warnings.append("year-free syslog timestamps used the source file year")
            break
        else:
            warnings.append("unrecognized timestamps used source file metadata")
            parsed = fallback
    return parsed.isoformat(timespec="microseconds").replace("+00:00", "Z")


def _record_id(origin: str, index: int, record: object) -> str:
    canonical = json.dumps(record, ensure_ascii=False, sort_keys=True, default=str)
    digest = hashlib.sha256(f"{origin}\n{index}\n{canonical}".encode()).hexdigest()[:20]
    return f"AUTO-{digest.upper()}"


def _extract_hash(value: object) -> str | None:
    text = _text(value)
    if text is None:
        return None
    match = _SHA256.search(text)
    if match and match.group(1) != "0" * 64:
        return match.group(1).casefold()
    return None


def _record_to_alert(
    record: dict[str, object],
    *,
    origin: str,
    index: int,
    detected_format: str,
    fallback_time: datetime,
    warnings: list[str],
) -> Alert:
    flattened = _flatten(record)
    indexed = _field_index(flattened)
    provided_id = _text(_lookup(indexed, "alert_id"))
    source = _text(_lookup(indexed, "source")) or detected_format
    host = _text(_lookup(indexed, "host")) or "unknown-endpoint"
    description = _text(_lookup(indexed, "description"))
    event_value = _lookup(indexed, "event_type") or description or "generic_event"
    timestamp = _normalize_timestamp(
        _lookup(indexed, "timestamp"),
        fallback=fallback_time + timedelta(microseconds=index),
        warnings=warnings,
    )
    severity_value = _lookup(indexed, "severity")
    syslog_priority = "syslog_priority" in flattened
    if syslog_priority:
        severity_value = flattened["syslog_priority"]

    alert: Alert = {
        "alert_id": provided_id or _record_id(origin, index, record),
        "timestamp": timestamp,
        "source": source,
        "host": host,
        "event_type": _event_slug(event_value),
        "severity": _normalize_severity(
            severity_value, syslog_priority=syslog_priority
        ),
        "user": _text(_lookup(indexed, "user")),
        "process_name": _basename(_lookup(indexed, "process_name")),
        "target_process_name": _basename(_lookup(indexed, "target_process_name")),
        "parent_process_name": _basename(_lookup(indexed, "parent_process_name")),
        "command_line": _text(_lookup(indexed, "command_line")),
        "file_hash": _extract_hash(_lookup(indexed, "file_hash")),
        "rule_name": _text(_lookup(indexed, "rule_name")),
        "description": description or f"Imported {detected_format} record.",
        "detected_format": detected_format,
        "source_record": f"{origin}:{index}",
    }
    return alert


def _nested_records(payload: object) -> list[dict[str, object]]:
    if isinstance(payload, list):
        return [dict(item) for item in payload if isinstance(item, dict)]
    if not isinstance(payload, dict):
        return []
    for key in ("alerts", "events", "results", "items", "records"):
        candidate = payload.get(key)
        if isinstance(candidate, list):
            return [dict(item) for item in candidate if isinstance(item, dict)]
    data = payload.get("data")
    if isinstance(data, list):
        return [dict(item) for item in data if isinstance(item, dict)]
    hits = payload.get("hits")
    if isinstance(hits, dict) and isinstance(hits.get("hits"), list):
        return [dict(item) for item in hits["hits"] if isinstance(item, dict)]
    return [dict(payload)]


def _parse_json(text: str) -> tuple[list[dict[str, object]], str]:
    try:
        payload = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except _DuplicateKey as exc:
        raise RawImportError(f"duplicate JSON key: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise RawImportError(
            f"invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc
    records = _nested_records(payload)
    if not records:
        raise RawImportError("JSON input contains no object records")
    return records, "json"


def _parse_json_lines(text: str) -> tuple[list[dict[str, object]], str]:
    records: list[dict[str, object]] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            payload = json.loads(line, object_pairs_hook=_reject_duplicate_keys)
        except (_DuplicateKey, json.JSONDecodeError) as exc:
            raise RawImportError(
                f"invalid JSON Lines record at line {line_number}: {exc}"
            ) from exc
        if not isinstance(payload, dict):
            raise RawImportError(f"JSON Lines record {line_number} is not an object")
        records.append(dict(payload))
    if not records:
        raise RawImportError("JSON Lines input contains no records")
    return records, "json-lines"


def _parse_delimited(text: str, *, suffix: str) -> tuple[list[dict[str, object]], str]:
    sample = text[:8192]
    delimiter = "\t" if suffix in {".tsv", ".tab"} else None
    if delimiter is None:
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
            delimiter = dialect.delimiter
        except csv.Error:
            delimiter = ","
    reader = csv.DictReader(io.StringIO(text), delimiter=delimiter)
    if not reader.fieldnames or len(reader.fieldnames) < 2:
        raise RawImportError(
            "delimited input requires a header with at least two fields"
        )
    records = [dict(row) for row in reader]
    if not records:
        raise RawImportError("delimited input contains no data rows")
    label = "tsv" if delimiter == "\t" else "csv"
    return records, label


def _split_unescaped_pipes(value: str, *, maxsplit: int) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for character in value:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            current.append(character)
            escaped = True
        elif character == "|" and len(parts) < maxsplit:
            parts.append("".join(current))
            current.clear()
        else:
            current.append(character)
    parts.append("".join(current))
    return parts


def _extension_pairs(value: str, *, delimiter: str | None = None) -> dict[str, object]:
    if delimiter:
        pairs: dict[str, object] = {}
        for item in value.split(delimiter):
            key, separator, raw_value = item.partition("=")
            if separator and key.strip():
                pairs[key.strip()] = raw_value.strip()
        return pairs
    pairs = {}
    matches = list(_KEY_VALUE.finditer(value))
    for position, match in enumerate(matches):
        start = match.start("value")
        end = (
            matches[position + 1].start() if position + 1 < len(matches) else len(value)
        )
        raw_value = value[start:end].strip()
        if (
            len(raw_value) >= 2
            and raw_value[0] == raw_value[-1]
            and raw_value[0] in "\"'"
        ):
            raw_value = raw_value[1:-1]
        pairs[match.group("key")] = raw_value
    return pairs


def _parse_cef_line(line: str) -> dict[str, object]:
    marker = line.find("CEF:")
    if marker < 0:
        raise RawImportError("CEF marker not found")
    prefix = line[:marker].strip()
    parts = _split_unescaped_pipes(line[marker:], maxsplit=7)
    if len(parts) != 8:
        raise RawImportError("CEF header requires seven pipe-delimited fields")
    version, vendor, product, product_version, signature, name, severity, extension = (
        parts
    )
    record: dict[str, object] = {
        "source": f"{vendor}/{product}",
        "device_vendor": vendor,
        "device_product": product,
        "device_version": product_version,
        "signature": signature,
        "event_name": name,
        "severity": severity,
        "cef_version": version.removeprefix("CEF:"),
    }
    record.update(_extension_pairs(extension))
    if prefix:
        record["syslog_prefix"] = prefix
        match = _ISO_TIMESTAMP.search(prefix)
        if match and "timestamp" not in record:
            record["timestamp"] = match.group(0)
    return record


def _parse_leef_line(line: str) -> dict[str, object]:
    marker = line.find("LEEF:")
    if marker < 0:
        raise RawImportError("LEEF marker not found")
    prefix = line[:marker].strip()
    parts = line[marker:].split("|", 6)
    if len(parts) < 6:
        raise RawImportError("LEEF header is incomplete")
    version, vendor, product, product_version, event_id = parts[:5]
    delimiter = "\t"
    attributes = parts[5]
    if len(parts) == 7:
        delimiter_spec = parts[5]
        attributes = parts[6]
        if delimiter_spec:
            if delimiter_spec.casefold().startswith(("x", "0x")):
                try:
                    delimiter = chr(
                        int(delimiter_spec.removeprefix("0x").removeprefix("x"), 16)
                    )
                except ValueError:
                    delimiter = "\t"
            else:
                delimiter = delimiter_spec[0]
    record: dict[str, object] = {
        "source": f"{vendor}/{product}",
        "device_vendor": vendor,
        "device_product": product,
        "device_version": product_version,
        "eventid": event_id,
        "leef_version": version.removeprefix("LEEF:"),
    }
    record.update(_extension_pairs(attributes, delimiter=delimiter))
    if prefix:
        record["syslog_prefix"] = prefix
    return record


def _parse_syslog_line(line: str) -> dict[str, object]:
    match = _RFC5424.match(line)
    if match:
        fields = match.groupdict()
        body = fields["body"]
        return {
            "timestamp": fields["timestamp"],
            "host": fields["host"],
            "source": fields["app"],
            "msgid": fields["msgid"],
            "description": body,
            "syslog_priority": fields["priority"],
            **_extension_pairs(body),
        }
    match = _BSD_SYSLOG.match(line)
    if match:
        fields = match.groupdict()
        return {
            "timestamp": fields["timestamp"],
            "host": fields["host"],
            "source": fields["app"],
            "description": fields["body"],
            "syslog_priority": fields.get("priority") or "6",
            **_extension_pairs(fields["body"]),
        }
    raise RawImportError("syslog header not recognized")


def _line_records(text: str) -> tuple[list[dict[str, object]], str]:
    records: list[dict[str, object]] = []
    formats: set[str] = set()
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if "CEF:" in stripped:
            records.append(_parse_cef_line(stripped))
            formats.add("cef")
        elif "LEEF:" in stripped:
            records.append(_parse_leef_line(stripped))
            formats.add("leef")
        elif _RFC5424.match(stripped) or _BSD_SYSLOG.match(stripped):
            records.append(_parse_syslog_line(stripped))
            formats.add("syslog")
        else:
            pairs = _extension_pairs(stripped)
            if len(pairs) >= 2:
                pairs.setdefault("description", stripped)
                records.append(pairs)
                formats.add("key-value")
            else:
                timestamp = _ISO_TIMESTAMP.search(stripped)
                records.append(
                    {
                        "timestamp": timestamp.group(0) if timestamp else None,
                        "event_name": "plain_text_event",
                        "description": stripped,
                    }
                )
                formats.add("plain-text")
    if not records:
        raise RawImportError("text input contains no records")
    label = next(iter(formats)) if len(formats) == 1 else "mixed-text"
    return records, label


def _windows_xml_records(text: str) -> list[tuple[int, str]]:
    records: list[tuple[int, str]] = []
    parts: list[str] = []
    start = 0
    for line_number, line in enumerate(text.splitlines(keepends=True), start=1):
        if not parts and "<Event" in line:
            start = line_number
        if parts or "<Event" in line:
            parts.append(line)
        if parts and "</Event>" in line:
            records.append((start, "".join(parts).strip()))
            parts.clear()
    if parts:
        raise RawImportError(f"unterminated Windows Event XML at line {start}")
    return records


def _xml_to_record(element: ET.Element) -> dict[str, object]:
    record: dict[str, object] = {}
    for node in element.iter():
        if node is element:
            continue
        name = node.tag.rsplit("}", 1)[-1]
        text = (node.text or "").strip()
        if text and name not in record:
            record[name] = text
        for attribute, value in node.attrib.items():
            record[f"{name}_{attribute}"] = value
    return record


def _parse_xml(text: str) -> tuple[list[dict[str, object]], str]:
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise RawImportError(f"invalid XML: {exc}") from exc
    children = list(root)
    child_tags = {child.tag for child in children}
    children_look_like_records = bool(children) and (
        (len(children) > 1 and len(child_tags) == 1)
        or all(list(child) for child in children)
    )
    candidates = children if children_look_like_records else [root]
    records = [_xml_to_record(candidate) for candidate in candidates]
    records = [record for record in records if record]
    if not records:
        raise RawImportError("XML input contains no scalar event data")
    return records, "xml"


def _looks_delimited(text: str) -> bool:
    lines = [line for line in text.splitlines() if line.strip()][:4]
    if len(lines) < 2:
        return False
    for delimiter in (",", "\t", ";"):
        counts = [line.count(delimiter) for line in lines]
        if counts[0] >= 1 and len(set(counts)) == 1:
            return True
    return False


def _records_from_text(
    text: str, *, suffix: str
) -> tuple[list[dict[str, object]], str]:
    stripped = text.lstrip("\ufeff\r\n\t ")
    if not stripped:
        raise RawImportError("input file is empty")
    if suffix in {".jsonl", ".ndjson"}:
        return _parse_json_lines(stripped)
    if stripped.startswith("["):
        return _parse_json(stripped)
    if stripped.startswith("{"):
        try:
            return _parse_json(stripped)
        except RawImportError:
            return _parse_json_lines(stripped)
    if suffix in {".csv", ".tsv", ".tab"} or _looks_delimited(stripped):
        return _parse_delimited(stripped, suffix=suffix)
    if re.match(r"^<[A-Za-z_:]", stripped):
        return _parse_xml(stripped)
    return _line_records(stripped)


def _mapped_fields(alerts: Iterable[Alert]) -> tuple[str, ...]:
    available: set[str] = set()
    for alert in alerts:
        for field, value in alert.items():
            if field in REQUIRED_ALERT_FIELDS or _text(value) is not None:
                available.add(field)
    return tuple(sorted(available))


def _normalize_records(
    records: Sequence[dict[str, object]],
    *,
    origin: str,
    detected_format: str,
    fallback_time: datetime,
) -> tuple[list[Alert], tuple[str, ...]]:
    alerts: list[Alert] = []
    warnings: list[str] = []
    for index, record in enumerate(records, start=1):
        if detected_format == "json-lines" and record.get("event_simpleName"):
            raw = json.dumps(record, ensure_ascii=False)
            try:
                alert = parse_crowdstrike_json(
                    raw, origin=Path(origin), line_number=index
                )
                alert["detected_format"] = "crowdstrike-json-lines"
                alert["source_record"] = f"{origin}:{index}"
                alerts.append(alert)
                continue
            except RawImportError:
                pass
        alerts.append(
            _record_to_alert(
                record,
                origin=origin,
                index=index,
                detected_format=detected_format,
                fallback_time=fallback_time,
                warnings=warnings,
            )
        )
    return alerts, tuple(dict.fromkeys(warnings))


def _decode_bytes(data: bytes, *, origin: str) -> str:
    def readable(text: str) -> bool:
        if not text:
            return True
        controls = sum(
            ord(character) < 32 and character not in "\r\n\t" for character in text
        )
        return controls / len(text) < 0.02

    sample = data[:4096]
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            decoded = data.decode("utf-16")
        except UnicodeDecodeError as exc:
            raise RawImportError(
                f"binary or unsupported text encoding: {origin}"
            ) from exc
        if readable(decoded):
            return decoded
    if b"\x00" in sample:
        even = sample[0::2]
        odd = sample[1::2]
        even_ratio = even.count(0) / max(len(even), 1)
        odd_ratio = odd.count(0) / max(len(odd), 1)
        if max(even_ratio, odd_ratio) >= 0.3:
            encoding = "utf-16-be" if even_ratio > odd_ratio else "utf-16-le"
            try:
                decoded = data.decode(encoding)
            except UnicodeDecodeError:
                decoded = ""
            if readable(decoded):
                return decoded
        raise RawImportError(f"binary or unsupported text encoding: {origin}")
    for encoding in ("utf-8-sig", "utf-8", "cp1252"):
        try:
            decoded = data.decode(encoding)
        except UnicodeDecodeError:
            continue
        if readable(decoded):
            return decoded
    raise RawImportError(f"unsupported text encoding: {origin}")


def _ingest_text(
    text: str,
    *,
    origin: str,
    suffix: str,
    fallback_time: datetime,
) -> tuple[list[Alert], SourceReport]:
    if WINDOWS_EVENT_MARKER in text and "<Event" in text:
        alerts = [
            parse_windows_event_xml(record, origin=Path(origin), line_number=line)
            for line, record in _windows_xml_records(text)
        ]
        for index, alert in enumerate(alerts, start=1):
            alert["detected_format"] = "windows-event-xml"
            alert["source_record"] = f"{origin}:{index}"
        report = SourceReport(
            path=origin,
            detected_format="windows-event-xml",
            record_count=len(alerts),
            mapped_fields=_mapped_fields(alerts),
            warnings=(),
        )
        return alerts, report

    records, detected_format = _records_from_text(text, suffix=suffix)
    alerts, warnings = _normalize_records(
        records,
        origin=origin,
        detected_format=detected_format,
        fallback_time=fallback_time,
    )
    return alerts, SourceReport(
        path=origin,
        detected_format=detected_format,
        record_count=len(alerts),
        mapped_fields=_mapped_fields(alerts),
        warnings=warnings,
    )


def _read_limited(handle: Any, *, origin: str) -> bytes:
    data = handle.read(MAX_EXPANDED_BYTES + 1)
    if len(data) > MAX_EXPANDED_BYTES:
        raise RawImportError(f"expanded input exceeds 256 MiB safety limit: {origin}")
    return data


def _ingest_path(path: Path) -> tuple[list[Alert], list[SourceReport]]:
    try:
        stat = path.stat()
    except FileNotFoundError as exc:
        raise RawImportError(f"input file not found: {path}") from exc
    except OSError as exc:
        raise RawImportError(f"cannot inspect input file {path}: {exc}") from exc
    if not path.is_file():
        raise RawImportError(f"input path is not a file: {path}")
    fallback_time = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
    suffix = path.suffix.casefold()

    if suffix == ".zip":
        alerts: list[Alert] = []
        reports: list[SourceReport] = []
        try:
            with zipfile.ZipFile(path) as archive:
                members = [
                    member for member in archive.infolist() if not member.is_dir()
                ]
                if len(members) > MAX_ARCHIVE_MEMBERS:
                    raise RawImportError("ZIP archive exceeds 128-member safety limit")
                if sum(member.file_size for member in members) > MAX_EXPANDED_BYTES:
                    raise RawImportError(
                        "ZIP archive exceeds 256 MiB expanded safety limit"
                    )
                for member in members:
                    if member.flag_bits & 0x1:
                        raise RawImportError("encrypted ZIP members are not supported")
                    member_origin = f"{path}!{member.filename}"
                    with archive.open(member) as handle:
                        text = _decode_bytes(
                            _read_limited(handle, origin=member_origin),
                            origin=member_origin,
                        )
                    member_alerts, report = _ingest_text(
                        text,
                        origin=member_origin,
                        suffix=Path(member.filename).suffix.casefold(),
                        fallback_time=fallback_time,
                    )
                    alerts.extend(member_alerts)
                    reports.append(report)
        except zipfile.BadZipFile as exc:
            raise RawImportError(f"invalid ZIP archive: {path}") from exc
        return alerts, reports

    try:
        if suffix == ".gz":
            with gzip.open(path, "rb") as handle:
                data = _read_limited(handle, origin=str(path))
            inner_suffix = Path(path.stem).suffix.casefold()
        else:
            with path.open("rb") as handle:
                data = _read_limited(handle, origin=str(path))
            inner_suffix = suffix
    except (OSError, EOFError) as exc:
        raise RawImportError(f"cannot read input file {path}: {exc}") from exc
    text = _decode_bytes(data, origin=str(path))
    alerts, report = _ingest_text(
        text,
        origin=str(path),
        suffix=inner_suffix,
        fallback_time=fallback_time,
    )
    return alerts, [report]


def load_any_alerts(paths: Sequence[Path]) -> IngestionResult:
    """Detect, parse, and normalize one or more local telemetry files."""

    if not paths:
        raise RawImportError("at least one input file is required")
    alerts: list[Alert] = []
    reports: list[SourceReport] = []
    seen_ids: set[str] = set()
    for path in paths:
        source_alerts, source_reports = _ingest_path(path)
        for alert in source_alerts:
            alert_id = str(alert["alert_id"])
            if alert_id in seen_ids:
                suffix = hashlib.sha256(
                    str(alert.get("source_record", alert_id)).encode()
                ).hexdigest()[:10]
                alert["alert_id"] = f"{alert_id}-{suffix}"
            seen_ids.add(str(alert["alert_id"]))
            alerts.append(alert)
        reports.extend(source_reports)
    if not alerts:
        raise RawImportError("input contains no importable telemetry records")
    return IngestionResult(alerts=alerts, sources=tuple(reports))


def run_normalize(input_paths: Sequence[Path], output_path: Path) -> IngestionResult:
    """Auto-detect input files and write a validated normalized alert array."""

    ingestion = load_any_alerts(input_paths)
    result = IngestionResult(
        alerts=validate_alerts(ingestion.alerts), sources=ingestion.sources
    )
    write_json_document(output_path, result.alerts, protected_paths=tuple(input_paths))
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="soc-alert-normalize",
        description="Auto-detect and normalize common security telemetry formats.",
    )
    parser.add_argument(
        "--input",
        required=True,
        action="append",
        type=Path,
        help="input path; repeat to combine files",
    )
    parser.add_argument("--output", required=True, type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        result = run_normalize(args.input, args.output)
    except DeduplicatorError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    formats = ", ".join(sorted({source.detected_format for source in result.sources}))
    print(f"Normalized {len(result.alerts)} records from: {formats}.")
    print(f"Output written to {args.output}.")
    if result.warnings:
        print(f"Warnings: {len(result.warnings)}; inspect the output before analysis.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
