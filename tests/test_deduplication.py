from __future__ import annotations

from collections.abc import Callable

import pytest

from soc_alert_deduplicator.config import Settings
from soc_alert_deduplicator.deduplication import group_alerts
from soc_alert_deduplicator.io import Alert


def test_equivalent_alerts_form_one_group_after_normalization(
    settings: Settings,
    make_alert: Callable[..., Alert],
) -> None:
    first = make_alert(alert_id="A-1")
    second = make_alert(
        alert_id="A-2",
        host=" ws-001 ",
        user="ANALYST.LAB",
        event_type="MALWARE_DETECTION",
        process_name=" SAMPLE.EXE ",
        file_hash=("A" * 64),
    )

    groups = group_alerts([first, second], settings)

    assert len(groups) == 1
    assert [alert["alert_id"] for alert in groups[0][1]] == ["A-1", "A-2"]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("host", "WS-002"),
        ("user", "other.lab"),
        ("event_type", "process_creation"),
        ("process_name", "other.exe"),
        ("file_hash", "b" * 64),
    ],
)
def test_each_configured_field_can_separate_groups(
    settings: Settings,
    make_alert: Callable[..., Alert],
    field: str,
    value: str,
) -> None:
    first = make_alert(alert_id="A-1")
    second = make_alert(alert_id="A-2", **{field: value})

    groups = group_alerts([first, second], settings)

    assert len(groups) == 2


def test_missing_optional_values_share_the_unknown_group(
    settings: Settings,
    make_alert: Callable[..., Alert],
) -> None:
    first = make_alert(alert_id="A-1", user=None, process_name=None, file_hash=None)
    second = make_alert(alert_id="A-2", user=" ", process_name="", file_hash=" ")
    third = make_alert(alert_id="A-3")
    del third["user"]
    del third["process_name"]
    del third["file_hash"]

    groups = group_alerts([first, second, third], settings)

    assert len(groups) == 1
    assert groups[0][0] == (
        "ws-001",
        "unknown",
        "malware_detection",
        "unknown",
        "unknown",
    )


def test_group_order_follows_first_appearance(
    settings: Settings,
    make_alert: Callable[..., Alert],
) -> None:
    second_group = make_alert(alert_id="A-2", host="WS-002")
    first_group = make_alert(alert_id="A-1", host="WS-001")
    first_group_repeat = make_alert(alert_id="A-3", host="ws-001")

    groups = group_alerts(
        [second_group, first_group, first_group_repeat],
        settings,
    )

    assert [key[0] for key, _ in groups] == ["ws-002", "ws-001"]
    assert [len(alerts) for _, alerts in groups] == [1, 2]


def test_empty_input_produces_no_groups(settings: Settings) -> None:
    assert group_alerts([], settings) == []
