from __future__ import annotations

from pathlib import Path

import pytest

from soc_alert_deduplicator.config import load_settings
from soc_alert_deduplicator.deduplication import group_alerts
from soc_alert_deduplicator.raw_import import import_raw_files
from soc_alert_deduplicator.summaries import build_incidents

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DATASET_ROOT = PROJECT_ROOT / "data" / "external" / "splunk_attack_data" / "T1003.001"
RAW_FILES = [
    DATASET_ROOT / "raw" / "windows-sysmon_creddump.log",
    DATASET_ROOT / "raw" / "procdump_windows-security.log",
    DATASET_ROOT / "raw" / "crowdstrike_falcon.log",
    DATASET_ROOT / "raw" / "createdump_windows-sysmon.log",
    DATASET_ROOT / "raw" / "windows-sysmon.log",
]


@pytest.mark.integration
@pytest.mark.skipif(
    not all(path.is_file() for path in RAW_FILES),
    reason="optional real-data bundle has not been downloaded",
)
def test_complete_pinned_real_dataset_preserves_every_alert_reference() -> None:
    alerts = import_raw_files(RAW_FILES)
    settings = load_settings(PROJECT_ROOT / "config.real-data.json")
    incidents = build_incidents(group_alerts(alerts, settings), settings)

    input_ids = [alert["alert_id"] for alert in alerts]
    grouped_ids = [
        alert_id for incident in incidents for alert_id in incident["alert_ids"]
    ]

    assert len(alerts) == 8050
    assert len(set(input_ids)) == 8050
    assert len(incidents) == 498
    assert len(grouped_ids) == 8050
    assert len(set(grouped_ids)) == 8050
    assert set(grouped_ids) == set(input_ids)
    assert max(incident["alert_count"] for incident in incidents) == 3545
