"""Native Qt visualizations and focused incident investigation UI."""

from __future__ import annotations

import json
from typing import Any

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QPersistentModelIndex,
    QPointF,
    QRectF,
    Qt,
)
from PySide6.QtGui import QColor, QFont, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTabWidget,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from .insights import (
    TimelineBucket,
    build_narrative,
    format_duration,
    format_timestamp,
    humanize_event,
    incident_duration,
)
from .io import Alert, Incident

SEVERITY_COLORS = {
    "Critical": "#FF5D73",
    "High": "#FF8A4C",
    "Medium": "#F5C451",
    "Low": "#62C6FF",
    "Informational": "#8A93A7",
    "Unknown": "#697386",
}


class HorizontalBarChart(QWidget):
    """A compact accessible bar chart for dashboard summaries."""

    def __init__(self, title: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.title = title
        self._data: list[tuple[str, int, str]] = []
        self.setMinimumSize(190, 108)
        self.setAccessibleName(f"{title} chart")
        self.setToolTip(f"{title}. Values are labelled directly on every bar.")

    @property
    def data_points(self) -> list[tuple[str, int, str]]:
        return list(self._data)

    def set_data(self, values: list[tuple[str, int, str]]) -> None:
        self._data = [(str(label), int(value), color) for label, value, color in values]
        description = ", ".join(f"{label}: {value}" for label, value, _ in self._data)
        self.setAccessibleDescription(description or "No data in the current view")
        self.update()

    def paintEvent(self, event: Any) -> None:  # noqa: N802
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        painter.setPen(QColor("#E8ECF4"))
        title_font = QFont(self.font())
        title_font.setBold(True)
        painter.setFont(title_font)
        painter.drawText(QRectF(4, 3, self.width() - 8, 22), self.title)
        if not self._data:
            painter.setPen(QColor("#697386"))
            painter.drawText(
                QRectF(4, 36, self.width() - 8, self.height() - 40),
                Qt.AlignmentFlag.AlignCenter,
                "No matching incidents",
            )
            return

        maximum = max(value for _, value, _ in self._data) or 1
        top = 32.0
        available = max(18.0, self.height() - top - 6)
        row_height = available / len(self._data)
        label_width = min(94.0, max(58.0, self.width() * 0.34))
        bar_left = label_width + 7
        bar_width = max(28.0, self.width() - bar_left - 30)
        for index, (label, value, color) in enumerate(self._data):
            y = top + index * row_height
            painter.setFont(self.font())
            painter.setPen(QColor("#AEB7C7"))
            painter.drawText(
                QRectF(4, y, label_width - 2, row_height),
                Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft,
                label,
            )
            track = QRectF(
                bar_left, y + row_height * 0.28, bar_width, row_height * 0.42
            )
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor("#202838"))
            painter.drawRoundedRect(track, 4, 4)
            fill = QRectF(track)
            fill.setWidth(max(4.0, track.width() * value / maximum))
            painter.setBrush(QColor(color))
            painter.drawRoundedRect(fill, 4, 4)
            painter.setPen(QColor("#E8ECF4"))
            painter.drawText(
                QRectF(bar_left + bar_width + 6, y, 24, row_height),
                Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignRight,
                str(value),
            )


class TimelineChart(QWidget):
    """A labelled activity histogram with no external chart dependency."""

    def __init__(
        self, title: str = "Alert activity", parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self.title = title
        self._buckets: list[TimelineBucket] = []
        self.setMinimumSize(260, 112)
        self.setAccessibleName(f"{title} timeline")
        self.setToolTip(
            "Alert counts over time. The tallest bucket marks peak activity."
        )

    @property
    def buckets(self) -> list[TimelineBucket]:
        return list(self._buckets)

    def set_buckets(self, buckets: list[TimelineBucket]) -> None:
        self._buckets = list(buckets)
        description = ", ".join(
            f"{bucket.label}: {bucket.count}" for bucket in self._buckets
        )
        self.setAccessibleDescription(description or "No timed alerts in this view")
        self.update()

    def paintEvent(self, event: Any) -> None:  # noqa: N802
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        title_font = QFont(self.font())
        title_font.setBold(True)
        painter.setFont(title_font)
        painter.setPen(QColor("#E8ECF4"))
        painter.drawText(QRectF(4, 3, self.width() - 8, 22), self.title)
        if not self._buckets:
            painter.setPen(QColor("#697386"))
            painter.drawText(
                QRectF(4, 36, self.width() - 8, self.height() - 40),
                Qt.AlignmentFlag.AlignCenter,
                "No timed alerts",
            )
            return

        plot = QRectF(10, 34, max(20, self.width() - 20), max(28, self.height() - 61))
        painter.setPen(QPen(QColor("#283143"), 1))
        for level in (0.25, 0.5, 0.75, 1.0):
            y = plot.bottom() - plot.height() * level
            painter.drawLine(QPointF(plot.left(), y), QPointF(plot.right(), y))

        maximum = max(bucket.count for bucket in self._buckets) or 1
        slot = plot.width() / len(self._buckets)
        bar_width = max(3.0, slot * 0.68)
        for index, bucket in enumerate(self._buckets):
            height = plot.height() * bucket.count / maximum
            rect = QRectF(
                plot.left() + index * slot + (slot - bar_width) / 2,
                plot.bottom() - height,
                bar_width,
                height,
            )
            painter.setPen(Qt.PenStyle.NoPen)
            painter.setBrush(QColor("#52D6B8" if bucket.count < maximum else "#76E5CB"))
            painter.drawRoundedRect(rect, 3, 3)
        painter.setPen(QColor("#7F899C"))
        painter.setFont(self.font())
        painter.drawText(
            QRectF(plot.left(), plot.bottom() + 5, plot.width() / 2, 18),
            Qt.AlignmentFlag.AlignLeft,
            self._buckets[0].label,
        )
        painter.drawText(
            QRectF(plot.center().x(), plot.bottom() + 5, plot.width() / 2, 18),
            Qt.AlignmentFlag.AlignRight,
            self._buckets[-1].label,
        )


class RelationshipDiagram(QWidget):
    """Visualize process-to-target activity for the selected incident."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._incident: Incident = {}
        self.setMinimumHeight(180)
        self.setAccessibleName("Incident relationship diagram")

    def set_incident(self, incident: Incident) -> None:
        self._incident = dict(incident)
        process = str(incident.get("process_name") or "Source activity")
        target = str(
            incident.get("target_process_name") or incident.get("host") or "Target"
        )
        event = humanize_event(incident.get("event_type"))
        self.setAccessibleDescription(f"{process} to {target} through {event}")
        self.update()

    @staticmethod
    def _node(
        painter: QPainter, rect: QRectF, heading: str, value: str, accent: str
    ) -> None:
        painter.setPen(QPen(QColor(accent), 1.2))
        painter.setBrush(QColor("#111A24"))
        painter.drawRoundedRect(rect, 11, 11)
        painter.setPen(QColor("#8792A7"))
        small = QFont(painter.font())
        small.setPointSizeF(max(7.5, small.pointSizeF() - 1))
        small.setBold(True)
        painter.setFont(small)
        painter.drawText(
            rect.adjusted(12, 10, -12, -rect.height() / 2),
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
            heading.upper(),
        )
        value_font = QFont(painter.font())
        value_font.setPointSizeF(value_font.pointSizeF() + 1)
        painter.setFont(value_font)
        painter.setPen(QColor("#F1F4F9"))
        painter.drawText(
            rect.adjusted(12, rect.height() / 2 - 5, -12, -7),
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
            value,
        )

    def paintEvent(self, event: Any) -> None:  # noqa: N802
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        process = str(self._incident.get("process_name") or "Source activity")
        target = str(
            self._incident.get("target_process_name")
            or self._incident.get("host")
            or "Affected asset"
        )
        activity = humanize_event(self._incident.get("event_type"))
        host = str(self._incident.get("host") or "Unknown host")
        count = int(self._incident.get("alert_count", 1) or 1)
        painter.setPen(QColor("#8792A7"))
        painter.drawText(QRectF(8, 4, self.width() - 16, 22), f"Observed on {host}")
        painter.setPen(QColor("#DCE2EC"))
        painter.drawText(
            QRectF(8, 27, self.width() - 16, 24),
            Qt.AlignmentFlag.AlignCenter,
            activity,
        )

        margin = 10.0
        gap = min(118.0, max(80.0, self.width() * 0.20))
        node_width = max(105.0, (self.width() - gap - margin * 2) / 2)
        node_height = 76.0
        y = 70.0
        left = QRectF(margin, y, node_width, node_height)
        right = QRectF(self.width() - margin - node_width, y, node_width, node_height)
        self._node(painter, left, "Initiating process", process, "#52D6B8")
        self._node(painter, right, "Target", target, "#FF8A4C")

        start = QPointF(left.right() + 7, left.center().y())
        end = QPointF(right.left() - 8, right.center().y())
        painter.setPen(QPen(QColor("#566177"), 2))
        painter.drawLine(start, end)
        arrow = QPainterPath()
        arrow.moveTo(end)
        arrow.lineTo(end.x() - 8, end.y() - 5)
        arrow.lineTo(end.x() - 8, end.y() + 5)
        arrow.closeSubpath()
        painter.fillPath(arrow, QColor("#566177"))
        painter.setPen(QColor("#DCE2EC"))
        label = f"{count} alert{'s' if count != 1 else ''}"
        painter.drawText(
            QRectF(left.right(), y - 3, max(1, right.left() - left.right()), 34),
            Qt.AlignmentFlag.AlignCenter,
            label,
        )


class GroupingDiagram(QWidget):
    """Explain how source alerts became one incident."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._incident: Incident = {}
        self.setMinimumHeight(180)
        self.setAccessibleName("Alert grouping decision diagram")

    def set_incident(self, incident: Incident) -> None:
        self._incident = dict(incident)
        count = int(incident.get("alert_count", 1) or 1)
        confidence = float((incident.get("deduplication") or {}).get("confidence", 1.0))
        self.setAccessibleDescription(
            f"{count} source alerts matched on shared evidence to form one incident "
            f"at {confidence:.0%} grouping confidence"
        )
        self.update()

    def paintEvent(self, event: Any) -> None:  # noqa: N802
        del event
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        width = self.width()
        count = int(self._incident.get("alert_count", 1) or 1)
        details = self._incident.get("deduplication") or {}
        confidence = float(details.get("confidence", 1.0))
        fields = (
            details.get("evidence_fields")
            or self._incident.get("grouping_fields")
            or []
        )
        evidence = ", ".join(str(item).replace("_", " ") for item in list(fields)[:4])
        boxes = (
            ("SOURCE ALERTS", f"{count} records", "#62C6FF"),
            ("EVIDENCE MATCH", evidence or "Shared context", "#F5C451"),
            ("INCIDENT", f"1 case · {confidence:.0%}", "#52D6B8"),
        )
        margin, gap = 8.0, 28.0
        box_width = max(70.0, (width - margin * 2 - gap * 2) / 3)
        y, height = 52.0, 82.0
        for index, (heading, value, color) in enumerate(boxes):
            rect = QRectF(margin + index * (box_width + gap), y, box_width, height)
            painter.setPen(QPen(QColor(color), 1.1))
            painter.setBrush(QColor("#111A24"))
            painter.drawRoundedRect(rect, 10, 10)
            painter.setPen(QColor("#8792A7"))
            painter.drawText(
                rect.adjusted(8, 9, -8, -45),
                Qt.AlignmentFlag.AlignCenter,
                heading,
            )
            painter.setPen(QColor("#F1F4F9"))
            painter.drawText(
                rect.adjusted(8, 35, -8, -8),
                Qt.AlignmentFlag.AlignCenter | Qt.TextFlag.TextWordWrap,
                value,
            )
            if index < 2:
                start = QPointF(rect.right() + 4, rect.center().y())
                end = QPointF(rect.right() + gap - 5, rect.center().y())
                painter.setPen(QPen(QColor("#566177"), 2))
                painter.drawLine(start, end)
                painter.drawLine(end, QPointF(end.x() - 6, end.y() - 4))
                painter.drawLine(end, QPointF(end.x() - 6, end.y() + 4))


class AlertTableModel(QAbstractTableModel):
    """Efficient source-alert table for the investigation dialog."""

    COLUMNS = (
        ("Time", "timestamp"),
        ("Severity", "severity"),
        ("Source", "source"),
        ("Event", "event_type"),
        ("Process", "process_name"),
        ("Target", "target_process_name"),
        ("User", "user"),
    )

    def __init__(self, alerts: list[Alert], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._alerts = list(alerts)

    def alert_at(self, row: int) -> Alert:
        return self._alerts[row]

    def rowCount(
        self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()
    ) -> int:
        return 0 if parent.isValid() else len(self._alerts)

    def columnCount(
        self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()
    ) -> int:
        return 0 if parent.isValid() else len(self.COLUMNS)

    def headerData(
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> Any:
        if (
            role == Qt.ItemDataRole.DisplayRole
            and orientation == Qt.Orientation.Horizontal
        ):
            return self.COLUMNS[section][0]
        return None

    def data(
        self,
        index: QModelIndex | QPersistentModelIndex,
        role: int = Qt.ItemDataRole.DisplayRole,
    ) -> Any:
        if not index.isValid():
            return None
        alert = self._alerts[index.row()]
        key = self.COLUMNS[index.column()][1]
        value = alert.get(key)
        if role == Qt.ItemDataRole.DisplayRole:
            if key == "timestamp":
                return format_timestamp(value)
            if key == "event_type":
                return humanize_event(value)
            return str(value or "—")
        if role == Qt.ItemDataRole.UserRole:
            return alert
        if role == Qt.ItemDataRole.ForegroundRole and key == "severity":
            return QColor(SEVERITY_COLORS.get(str(value).title(), "#E8ECF4"))
        return None


def _section(title: str, body: str) -> QFrame:
    card = QFrame()
    card.setProperty("card", True)
    layout = QVBoxLayout(card)
    layout.setContentsMargins(16, 14, 16, 14)
    layout.setSpacing(7)
    heading = QLabel(title)
    heading.setObjectName("sectionTitle")
    text = QLabel(body)
    text.setWordWrap(True)
    text.setProperty("muted", True)
    text.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    layout.addWidget(heading)
    layout.addWidget(text)
    return card


class IncidentDetailDialog(QDialog):
    """A resizable, progressive-disclosure incident investigation view."""

    def __init__(
        self, incident: Incident, alerts: list[Alert], parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self.incident = dict(incident)
        self.alerts = list(alerts)
        self.narrative = build_narrative(self.incident)
        self.setWindowTitle(f"{self.narrative.title} · Incident investigation")
        self.setMinimumSize(760, 560)
        self.setModal(False)
        self.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
        self.setAccessibleName("Incident investigation")
        screen = QApplication.primaryScreen()
        if screen:
            available = screen.availableGeometry()
            self.resize(
                min(1100, int(available.width() * 0.86)),
                min(780, int(available.height() * 0.86)),
            )
        else:
            self.resize(1000, 720)

        root = QVBoxLayout(self)
        root.setContentsMargins(18, 18, 18, 16)
        root.setSpacing(12)
        root.addWidget(self._build_header())

        self.tabs = QTabWidget()
        self.tabs.setAccessibleName("Investigation sections")
        self.tabs.addTab(self._build_overview(), "Overview")
        self.tabs.addTab(self._build_timeline(), "Timeline")
        self.tabs.addTab(self._build_grouping(), "Why grouped")
        self.tabs.addTab(
            self._build_source_alerts(), f"Source alerts ({len(self.alerts):,})"
        )
        root.addWidget(self.tabs, 1)

        buttons = QHBoxLayout()
        buttons.addStretch(1)
        self.copy_button = QPushButton("Copy incident brief")
        self.copy_button.setAccessibleName("Copy incident brief to clipboard")
        self.copy_button.clicked.connect(self.copy_incident_brief)
        close_button = QPushButton("Close")
        close_button.setObjectName("primaryButton")
        close_button.clicked.connect(self.close)
        buttons.addWidget(self.copy_button)
        buttons.addWidget(close_button)
        root.addLayout(buttons)

    def _build_header(self) -> QWidget:
        frame = QFrame()
        frame.setProperty("card", True)
        layout = QVBoxLayout(frame)
        layout.setContentsMargins(18, 15, 18, 15)
        layout.setSpacing(6)
        eyebrow = QLabel("INCIDENT INVESTIGATION")
        eyebrow.setObjectName("eyebrow")
        title = QLabel(self.narrative.title)
        title.setObjectName("title")
        title.setWordWrap(True)
        metadata = QLabel(
            f"{self.incident.get('incident_id', 'Incident')}   ·   "
            f"{str(self.incident.get('severity', 'unknown')).title()} severity   ·   "
            f"{int(self.incident.get('alert_count', 1) or 1):,} source alerts   ·   "
            f"{float((self.incident.get('deduplication') or {}).get('confidence', 1.0)):.0%} grouping confidence"
        )
        metadata.setProperty("muted", True)
        layout.addWidget(eyebrow)
        layout.addWidget(title)
        layout.addWidget(metadata)
        return frame

    @staticmethod
    def _scroll(content: QWidget) -> QScrollArea:
        scroll = QScrollArea()
        scroll.setObjectName("investigationScroll")
        scroll.setStyleSheet(
            "QScrollArea, QScrollArea > QWidget > QWidget {"
            "background: transparent; border: none; }"
        )
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setWidget(content)
        return scroll

    def _build_overview(self) -> QWidget:
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(7, 12, 7, 12)
        layout.setSpacing(10)
        layout.addWidget(_section("What happened", self.narrative.story))
        layout.addWidget(
            _section("Why it deserves attention", self.narrative.why_it_matters)
        )

        diagram_card = QFrame()
        diagram_card.setProperty("card", True)
        diagram_layout = QVBoxLayout(diagram_card)
        diagram_layout.setContentsMargins(14, 12, 14, 10)
        heading = QLabel("Activity relationship")
        heading.setObjectName("sectionTitle")
        self.relationship_diagram = RelationshipDiagram()
        self.relationship_diagram.set_incident(self.incident)
        diagram_layout.addWidget(heading)
        diagram_layout.addWidget(self.relationship_diagram)
        layout.addWidget(diagram_card)

        facts = QFrame()
        facts.setProperty("card", True)
        facts_layout = QGridLayout(facts)
        facts_layout.setContentsMargins(16, 14, 16, 14)
        fact_values = (
            ("First observed", format_timestamp(self.incident.get("first_seen"))),
            ("Last observed", format_timestamp(self.incident.get("last_seen"))),
            ("Duration", format_duration(incident_duration(self.incident))),
            ("Host", str(self.incident.get("host") or "Unknown")),
            ("User", str(self.incident.get("user") or "Not reported")),
            (
                "Source formats",
                ", ".join(self.incident.get("source_formats") or ["Normalized alerts"]),
            ),
        )
        for index, (label, value) in enumerate(fact_values):
            cell = QVBoxLayout()
            heading = QLabel(label.upper())
            heading.setObjectName("fieldLabel")
            rendered = QLabel(value)
            rendered.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse
            )
            rendered.setWordWrap(True)
            cell.addWidget(heading)
            cell.addWidget(rendered)
            facts_layout.addLayout(cell, index // 2, index % 2)
        layout.addWidget(facts)

        actions = "\n".join(
            f"{index}. {action}"
            for index, action in enumerate(self.narrative.recommended_checks, start=1)
        )
        layout.addWidget(_section("Recommended checks", actions))
        layout.addStretch(1)
        return self._scroll(content)

    def _build_timeline(self) -> QWidget:
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(7, 12, 7, 12)
        layout.setSpacing(10)
        timeline_card = QFrame()
        timeline_card.setProperty("card", True)
        timeline_layout = QVBoxLayout(timeline_card)
        timeline_layout.setContentsMargins(14, 12, 14, 12)
        from .insights import timeline_buckets

        self.timeline_chart = TimelineChart("Source alert activity")
        self.timeline_chart.set_buckets(timeline_buckets(self.alerts))
        timeline_layout.addWidget(self.timeline_chart)
        timeline_layout.addWidget(
            QLabel(
                f"From {format_timestamp(self.incident.get('first_seen'))} to "
                f"{format_timestamp(self.incident.get('last_seen'))} · "
                f"{format_duration(incident_duration(self.incident))}"
            )
        )
        layout.addWidget(timeline_card)

        self.timeline_table = QTableView()
        self.timeline_table.setModel(AlertTableModel(self.alerts, self.timeline_table))
        self.timeline_table.setAlternatingRowColors(True)
        self.timeline_table.setSelectionBehavior(
            QTableView.SelectionBehavior.SelectRows
        )
        self.timeline_table.setSortingEnabled(False)
        self.timeline_table.verticalHeader().setVisible(False)
        header = self.timeline_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        for column in range(4, 7):
            self.timeline_table.hideColumn(column)
        layout.addWidget(self.timeline_table, 1)
        return content

    def _build_grouping(self) -> QWidget:
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(7, 12, 7, 12)
        layout.setSpacing(10)
        diagram_card = QFrame()
        diagram_card.setProperty("card", True)
        diagram_layout = QVBoxLayout(diagram_card)
        diagram_layout.setContentsMargins(14, 12, 14, 10)
        title = QLabel("From many alerts to one investigation")
        title.setObjectName("sectionTitle")
        self.grouping_diagram = GroupingDiagram()
        self.grouping_diagram.set_incident(self.incident)
        diagram_layout.addWidget(title)
        diagram_layout.addWidget(self.grouping_diagram)
        layout.addWidget(diagram_card)
        layout.addWidget(
            _section("Why these alerts belong together", self.narrative.why_grouped)
        )

        details = self.incident.get("deduplication") or {}
        evidence = (
            details.get("evidence_fields") or self.incident.get("grouping_fields") or []
        )
        fields = (
            ", ".join(str(field).replace("_", " ") for field in evidence)
            or "Available context"
        )
        technical = (
            f"Evidence used: {fields}\n"
            f"Match strategy: {str(details.get('match_type', 'exact')).replace('_', ' ').title()}\n"
            f"Activity window: {details.get('time_window_minutes', 'Not limited')} minutes\n"
            f"Profile: {details.get('profile_id', 'Exact grouping')}"
        )
        layout.addWidget(_section("Decision details", technical))
        layout.addWidget(
            _section(
                "How to read the confidence score",
                "Grouping confidence answers: ‘How strongly does the available evidence say "
                "these records describe the same activity?’ It does not measure threat severity "
                "and it does not replace analyst validation.",
            )
        )
        layout.addStretch(1)
        return self._scroll(content)

    def _build_source_alerts(self) -> QWidget:
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(7, 12, 7, 12)
        layout.setSpacing(8)
        helper = QLabel(
            "Select a row to inspect the original normalized record and its retained provenance."
        )
        helper.setProperty("muted", True)
        layout.addWidget(helper)

        splitter = QSplitter(Qt.Orientation.Vertical)
        self.alert_model = AlertTableModel(self.alerts)
        self.alert_table = QTableView()
        self.alert_table.setModel(self.alert_model)
        self.alert_table.setAlternatingRowColors(True)
        self.alert_table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.alert_table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self.alert_table.verticalHeader().setVisible(False)
        header = self.alert_table.horizontalHeader()
        for column in range(self.alert_model.columnCount()):
            header.setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        splitter.addWidget(self.alert_table)

        detail_card = QFrame()
        detail_card.setProperty("card", True)
        detail_layout = QVBoxLayout(detail_card)
        detail_layout.setContentsMargins(14, 12, 14, 12)
        detail_title = QLabel("Source alert details")
        detail_title.setObjectName("sectionTitle")
        self.alert_detail = QPlainTextEdit()
        self.alert_detail.setReadOnly(True)
        self.alert_detail.setAccessibleName("Selected source alert details")
        detail_layout.addWidget(detail_title)
        detail_layout.addWidget(self.alert_detail)
        splitter.addWidget(detail_card)
        splitter.setSizes([330, 220])
        layout.addWidget(splitter, 1)

        selection = self.alert_table.selectionModel()
        if selection:
            selection.currentChanged.connect(self._source_alert_changed)
        if self.alerts:
            self.alert_table.selectRow(0)
            self._show_alert(self.alerts[0])
        else:
            self.alert_detail.setPlainText("No source alert records were available.")
        return content

    def _source_alert_changed(
        self, current: QModelIndex, previous: QModelIndex
    ) -> None:
        del previous
        if current.isValid():
            self._show_alert(self.alert_model.alert_at(current.row()))

    def _show_alert(self, alert: Alert) -> None:
        preferred = (
            "alert_id",
            "timestamp",
            "severity",
            "source",
            "host",
            "user",
            "event_type",
            "process_name",
            "parent_process_name",
            "target_process_name",
            "command_line",
            "file_hash",
            "rule_name",
            "description",
            "detected_format",
            "source_record",
        )
        ordered = {key: alert[key] for key in preferred if key in alert}
        ordered.update(
            {key: value for key, value in alert.items() if key not in ordered}
        )
        self.alert_detail.setPlainText(
            json.dumps(ordered, indent=2, ensure_ascii=False, default=str)
        )

    def incident_brief(self) -> str:
        checks = "\n".join(f"- {item}" for item in self.narrative.recommended_checks)
        return (
            f"{self.incident.get('incident_id', 'Incident')} — {self.narrative.title}\n\n"
            f"What happened\n{self.narrative.story}\n\n"
            f"Why it matters\n{self.narrative.why_it_matters}\n\n"
            f"Why grouped\n{self.narrative.why_grouped}\n\n"
            f"Recommended checks\n{checks}"
        )

    def copy_incident_brief(self) -> None:
        QApplication.clipboard().setText(self.incident_brief())
        self.copy_button.setText("Copied")
