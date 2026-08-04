from __future__ import annotations

from typing import Any

from soc_alert_deduplicator.smart_deduplication import (
    build_smart_incidents,
    cluster_alerts,
    compare_alerts,
)
from soc_alert_deduplicator.smart_profile import SmartOverrides, infer_smart_profile


def profile_for(alerts: list[dict[str, Any]]):
    return infer_smart_profile(
        alerts,
        SmartOverrides(threshold=0.72, time_window_minutes=10),
    )


def test_random_command_ids_are_normalized_as_duplicate_evidence(
    make_alert: Any,
) -> None:
    first = make_alert(
        alert_id="A-1",
        file_hash=None,
        command_line="tool.exe --job 123 --id 11111111-1111-1111-1111-111111111111",
    )
    second = make_alert(
        alert_id="A-2",
        timestamp="2026-06-01T08:16:00Z",
        file_hash=None,
        command_line="tool.exe --job 999 --id 22222222-2222-2222-2222-222222222222",
    )
    profile = profile_for([first, second])

    match = compare_alerts(first, second, profile)
    clusters = cluster_alerts([first, second], profile)

    assert match.score >= profile.threshold
    assert len(clusters) == 1
    assert build_smart_incidents(clusters, profile)[0]["alert_count"] == 2


def test_different_process_identities_never_chain_through_missing_data(
    make_alert: Any,
) -> None:
    missing = make_alert(alert_id="A-0", process_name=None, file_hash=None)
    cmd = make_alert(
        alert_id="A-1",
        timestamp="2026-06-01T08:16:00Z",
        process_name="cmd.exe",
        file_hash=None,
    )
    powershell = make_alert(
        alert_id="A-2",
        timestamp="2026-06-01T08:17:00Z",
        process_name="powershell.exe",
        file_hash=None,
    )
    profile = profile_for([missing, cmd, powershell])

    clusters = cluster_alerts([missing, cmd, powershell], profile)

    assert len(clusters) == 2
    identities = [
        {str(alert.get("process_name")) for alert in cluster.alerts}
        for cluster in clusters
    ]
    assert not any({"cmd.exe", "powershell.exe"} <= values for values in identities)


def test_host_hash_and_target_process_conflicts_are_hard_boundaries(
    make_alert: Any,
) -> None:
    first = make_alert(alert_id="A-1", target_process_name="lsass.exe")
    other_host = make_alert(alert_id="A-2", host="WS-002")
    other_hash = make_alert(alert_id="A-3", file_hash="b" * 64)
    other_target = make_alert(alert_id="A-4", target_process_name="winlogon.exe")
    profile = profile_for([first, other_host, other_hash, other_target])

    assert compare_alerts(first, other_host, profile).conflicts == ("host",)
    assert compare_alerts(first, other_hash, profile).conflicts == ("file_hash",)
    assert (
        "target_process_name" in compare_alerts(first, other_target, profile).conflicts
    )


def test_time_window_and_maximum_cluster_span_split_long_streams(
    make_alert: Any,
) -> None:
    alerts = [
        make_alert(alert_id=f"A-{minute}", timestamp=f"2026-06-01T08:{minute:02d}:00Z")
        for minute in (0, 9, 18, 27, 36)
    ]
    profile = profile_for(alerts)

    clusters = cluster_alerts(alerts, profile)

    assert [len(cluster.alerts) for cluster in clusters] == [4, 1]


def test_incident_exposes_explainable_match_metadata(make_alert: Any) -> None:
    alerts = [
        make_alert(alert_id="A-1"),
        make_alert(alert_id="A-2", timestamp="2026-06-01T08:16:00Z"),
    ]
    profile = profile_for(alerts)

    incident = build_smart_incidents(cluster_alerts(alerts, profile), profile)[0]

    assert incident["deduplication"]["engine"] == "SMART"
    assert incident["deduplication"]["profile_id"] == profile.profile_id
    assert incident["deduplication"]["confidence"] > 0.9
    assert "host" in incident["deduplication"]["evidence_fields"]
    assert incident["alert_ids"] == ["A-1", "A-2"]
