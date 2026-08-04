"""End-to-end orchestration for automatic V2 ingestion and deduplication."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from .io import Alert, Incident, validate_alerts, write_incidents, write_json_document
from .smart_deduplication import build_smart_incidents, cluster_alerts
from .smart_profile import (
    SmartOverrides,
    SmartProfile,
    infer_smart_profile,
    load_smart_overrides,
)
from .universal_import import IngestionResult, load_any_alerts


@dataclass(frozen=True, slots=True)
class SmartPipelineResult:
    alerts: list[Alert]
    incidents: list[Incident]
    profile: SmartProfile
    ingestion: IngestionResult
    profile_path: Path


def _profile_document(result: SmartPipelineResult) -> dict[str, Any]:
    return {
        **result.profile.to_dict(),
        "input": {
            "alert_count": len(result.alerts),
            "sources": [
                {
                    "path": source.path,
                    "detected_format": source.detected_format,
                    "record_count": source.record_count,
                    "mapped_fields": list(source.mapped_fields),
                    "warnings": list(source.warnings),
                }
                for source in result.ingestion.sources
            ],
        },
        "output": {
            "incident_count": len(result.incidents),
            "reduction_percent": round(
                (1 - len(result.incidents) / len(result.alerts)) * 100, 2
            ),
        },
    }


def run_smart_pipeline(
    input_paths: Sequence[Path],
    output_path: Path,
    *,
    overrides_path: Path | None = None,
    profile_output_path: Path | None = None,
) -> SmartPipelineResult:
    """Auto-detect, normalize, profile, deduplicate, and write one alert batch."""

    ingestion = load_any_alerts(input_paths)
    alerts = validate_alerts(ingestion.alerts)
    overrides = (
        load_smart_overrides(overrides_path)
        if overrides_path is not None
        else SmartOverrides()
    )
    profile = infer_smart_profile(alerts, overrides)
    incidents = build_smart_incidents(cluster_alerts(alerts, profile), profile)
    protected = tuple(input_paths) + (
        (overrides_path,) if overrides_path is not None else ()
    )
    profile_path = profile_output_path or output_path.with_suffix(".profile.json")
    write_incidents(output_path, incidents, protected_paths=protected)
    result = SmartPipelineResult(
        alerts=alerts,
        incidents=incidents,
        profile=profile,
        ingestion=ingestion,
        profile_path=profile_path,
    )
    write_json_document(
        profile_path,
        _profile_document(result),
        protected_paths=protected + (output_path,),
    )
    return result
