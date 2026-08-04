"""Dark desktop dashboard for local alert deduplication."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any, cast

from PySide6.QtCore import (
    QAbstractTableModel,
    QModelIndex,
    QPersistentModelIndex,
    QSortFilterProxyModel,
    Qt,
    QUrl,
)
from PySide6.QtGui import (
    QColor,
    QDesktopServices,
    QFont,
    QFontDatabase,
    QIcon,
    QKeySequence,
    QShortcut,
)
from PySide6.QtWidgets import (
    QApplication,
    QComboBox,
    QFileDialog,
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableView,
    QVBoxLayout,
    QWidget,
)

from .config import Settings, load_settings
from .deduplication import group_alerts
from .errors import DeduplicatorError
from .exports import write_incidents_csv
from .io import Alert, Incident, load_alerts, write_incidents
from .summaries import SEVERITY_RANK, build_incidents

APP_NAME = "SOC Alert Deduplicator"
SEVERITY_COLORS = {
    "informational": "#8A93A7",
    "low": "#62C6FF",
    "medium": "#F5C451",
    "high": "#FF8A4C",
    "critical": "#FF5D73",
}

DARK_STYLESHEET = """
* {
    font-family: "Segoe UI";
    font-size: 13px;
    color: #E8ECF4;
}
QMainWindow, QWidget#appRoot {
    background: #090C12;
}
QFrame#header, QFrame#sidebar, QFrame#tableCard, QFrame#detailCard,
QFrame[card="true"] {
    background: #111620;
    border: 1px solid #222A38;
    border-radius: 14px;
}
QFrame#header {
    background: #0E131C;
}
QLabel#brandMark {
    background: #173630;
    border: 1px solid #2A6A5D;
    border-radius: 12px;
    padding: 8px;
}
QLabel#eyebrow {
    color: #52D6B8;
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1px;
}
QLabel#title {
    color: #F7F9FC;
    font-size: 24px;
    font-weight: 700;
}
QLabel#subtitle, QLabel[muted="true"] {
    color: #8993A6;
}
QLabel#sectionTitle {
    color: #F1F4F9;
    font-size: 15px;
    font-weight: 650;
}
QLabel#statusPill {
    color: #63E6C6;
    background: #102C27;
    border: 1px solid #215A4F;
    border-radius: 12px;
    padding: 6px 11px;
    font-size: 11px;
    font-weight: 650;
}
QLabel#fieldLabel {
    color: #98A2B5;
    font-size: 11px;
    font-weight: 600;
}
QLabel#chip {
    color: #B9F5E6;
    background: #142B29;
    border: 1px solid #24524C;
    border-radius: 8px;
    padding: 5px 8px;
    font-family: "Consolas";
    font-size: 10px;
}
QLineEdit, QComboBox, QPlainTextEdit {
    background: #0B0F17;
    border: 1px solid #293243;
    border-radius: 9px;
    padding: 9px 10px;
    selection-background-color: #2D806F;
}
QLineEdit:focus, QComboBox:focus, QPlainTextEdit:focus {
    border: 1px solid #52D6B8;
}
QLineEdit:read-only {
    color: #AAB3C2;
}
QComboBox::drop-down {
    border: none;
    width: 24px;
}
QComboBox QAbstractItemView {
    background: #121824;
    border: 1px solid #2B3547;
    selection-background-color: #1D4A42;
    outline: 0;
}
QPushButton {
    background: #181F2C;
    border: 1px solid #303A4D;
    border-radius: 9px;
    padding: 9px 13px;
    font-weight: 600;
}
QPushButton:hover {
    background: #202A39;
    border-color: #46536A;
}
QPushButton:pressed {
    background: #111722;
}
QPushButton#primaryButton {
    color: #07110F;
    background: #58D7B9;
    border-color: #58D7B9;
    padding: 11px 14px;
    font-weight: 750;
}
QPushButton#primaryButton:hover {
    background: #76E5CB;
    border-color: #76E5CB;
}
QPushButton#pathButton {
    min-width: 34px;
    max-width: 34px;
    padding: 8px 0;
}
QPushButton:disabled {
    color: #596273;
    background: #121721;
    border-color: #242B38;
}
QTableView {
    background: #0E131C;
    alternate-background-color: #101722;
    border: none;
    border-radius: 10px;
    gridline-color: #202838;
    outline: 0;
    selection-background-color: #173A35;
    selection-color: #F5F8FB;
}
QHeaderView::section {
    color: #8792A7;
    background: #111824;
    border: none;
    border-bottom: 1px solid #283143;
    padding: 10px 8px;
    font-size: 10px;
    font-weight: 700;
}
QScrollBar:vertical {
    background: transparent;
    width: 10px;
    margin: 2px;
}
QScrollBar::handle:vertical {
    background: #303A4D;
    border-radius: 4px;
    min-height: 28px;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}
QSplitter::handle {
    background: transparent;
    width: 8px;
    height: 8px;
}
QLabel#metricLabel {
    color: #8994A8;
    font-size: 10px;
    font-weight: 700;
}
QLabel#metricValue {
    color: #F6F8FB;
    font-size: 25px;
    font-weight: 750;
}
QLabel#metricNote {
    color: #5FD9BD;
    font-size: 10px;
}
QLabel#detailSummary {
    color: #EDF1F7;
    font-size: 14px;
    font-weight: 600;
}
QLabel#detailValue {
    color: #C8D0DE;
    font-family: "Consolas";
    font-size: 11px;
}
QLabel#emptyState {
    color: #697386;
    font-size: 13px;
    padding: 24px;
}
"""


def noise_reduction_percent(alert_count: int, incident_count: int) -> float:
    """Return the percentage of queue items removed by grouping."""

    if alert_count <= 0:
        return 0.0
    return max(0.0, (1 - incident_count / alert_count) * 100)


def highest_severity(incidents: list[Incident]) -> str:
    """Return the highest incident severity or a neutral placeholder."""

    if not incidents:
        return "none"
    return max(
        (str(incident["severity"]) for incident in incidents),
        key=SEVERITY_RANK.__getitem__,
    )


def discover_project_root(start: Path | None = None) -> Path | None:
    """Find a source checkout containing the demo and default configuration."""

    candidates = (
        [start]
        if start is not None
        else [Path.cwd(), Path(__file__).resolve().parents[2]]
    )
    for candidate in candidates:
        resolved = candidate.resolve()
        if (resolved / "config.json").is_file() and (
            resolved / "data" / "demo" / "raw_alerts.json"
        ).is_file():
            return resolved
    return None


class IncidentTableModel(QAbstractTableModel):
    """Read-only model for incident summaries."""

    COLUMNS = (
        ("Incident", "incident_id"),
        ("Severity", "severity"),
        ("Alerts", "alert_count"),
        ("Host", "host"),
        ("User", "user"),
        ("Event", "event_type"),
        ("First seen", "first_seen"),
        ("Last seen", "last_seen"),
    )

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._incidents: list[Incident] = []

    def set_incidents(self, incidents: list[Incident]) -> None:
        self.beginResetModel()
        self._incidents = list(incidents)
        self.endResetModel()

    def incident_at(self, row: int) -> Incident:
        return self._incidents[row]

    def rowCount(
        self, parent: QModelIndex | QPersistentModelIndex = QModelIndex()
    ) -> int:
        return 0 if parent.isValid() else len(self._incidents)

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
        incident = self._incidents[index.row()]
        key = self.COLUMNS[index.column()][1]
        value = incident[key]

        if role == Qt.ItemDataRole.DisplayRole:
            if key == "event_type":
                return str(value).replace("_", " ")
            return str(value)
        if role == Qt.ItemDataRole.UserRole:
            return incident
        if role == Qt.ItemDataRole.ForegroundRole and key == "severity":
            return QColor(SEVERITY_COLORS.get(str(value), "#E8ECF4"))
        if role == Qt.ItemDataRole.FontRole and key in {"incident_id", "severity"}:
            font = QFont()
            font.setBold(True)
            return font
        if role == Qt.ItemDataRole.TextAlignmentRole and key == "alert_count":
            return Qt.AlignmentFlag.AlignCenter
        return None


class IncidentFilterProxy(QSortFilterProxyModel):
    """Search and severity filtering for the incident queue."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._query = ""
        self._severity = "all"
        self.setDynamicSortFilter(True)

    def set_query(self, query: str) -> None:
        self._query = query.strip().casefold()
        self.beginFilterChange()
        self.endFilterChange(QSortFilterProxyModel.Direction.Rows)

    def set_severity(self, severity: str) -> None:
        self._severity = severity.casefold()
        self.beginFilterChange()
        self.endFilterChange(QSortFilterProxyModel.Direction.Rows)

    def filterAcceptsRow(
        self,
        source_row: int,
        source_parent: QModelIndex | QPersistentModelIndex,
    ) -> bool:
        model = self.sourceModel()
        if not isinstance(model, IncidentTableModel):
            return False
        incident = model.incident_at(source_row)
        if self._severity != "all" and incident["severity"] != self._severity:
            return False
        if not self._query:
            return True
        searchable = " ".join(
            str(incident.get(field, ""))
            for field in (
                "incident_id",
                "severity",
                "host",
                "user",
                "event_type",
                "process_name",
                "summary",
            )
        ).casefold()
        return self._query in searchable


class MetricCard(QFrame):
    def __init__(self, label: str, accent: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setProperty("card", True)
        self.setMinimumHeight(104)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 13)
        layout.setSpacing(3)

        title = QLabel(label.upper())
        title.setObjectName("metricLabel")
        self.value = QLabel("—")
        self.value.setObjectName("metricValue")
        self.note = QLabel("Awaiting analysis")
        self.note.setObjectName("metricNote")
        self.note.setStyleSheet(f"color: {accent};")

        layout.addWidget(title)
        layout.addWidget(self.value)
        layout.addWidget(self.note)

    def update_value(self, value: str, note: str) -> None:
        self.value.setText(value)
        self.note.setText(note)


class MainWindow(QMainWindow):
    """Primary desktop workflow for analysts."""

    def __init__(self, project_root: Path | None = None) -> None:
        super().__init__()
        self.project_root = project_root or discover_project_root()
        self.alerts: list[Alert] = []
        self.incidents: list[Incident] = []
        self.settings: Settings | None = None
        self.last_error = ""

        self.setWindowTitle(f"{APP_NAME} — Incident Clarity Console")
        self.setMinimumSize(1180, 720)
        self.resize(1440, 900)
        self.setAcceptDrops(True)

        icon_path = Path(__file__).with_name("assets") / "shield.svg"
        if icon_path.is_file():
            self.setWindowIcon(QIcon(str(icon_path)))

        self.model = IncidentTableModel(self)
        self.proxy = IncidentFilterProxy(self)
        self.proxy.setSourceModel(self.model)
        self._build_ui(icon_path)
        self._connect_actions()
        self._set_default_paths()

    def _build_ui(self, icon_path: Path) -> None:
        root = QWidget()
        root.setObjectName("appRoot")
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(18, 18, 18, 18)
        root_layout.setSpacing(14)
        root_layout.addWidget(self._build_header(icon_path))

        body = QSplitter(Qt.Orientation.Horizontal)
        body.setChildrenCollapsible(False)
        body.addWidget(self._build_sidebar())
        body.addWidget(self._build_dashboard())
        body.setSizes([310, 1080])
        root_layout.addWidget(body, 1)
        self.setCentralWidget(root)

    def _build_header(self, icon_path: Path) -> QFrame:
        header = QFrame()
        header.setObjectName("header")
        layout = QHBoxLayout(header)
        layout.setContentsMargins(18, 14, 18, 14)
        layout.setSpacing(14)

        mark = QLabel()
        mark.setObjectName("brandMark")
        mark.setFixedSize(50, 50)
        if icon_path.is_file():
            mark.setPixmap(QIcon(str(icon_path)).pixmap(30, 30))
            mark.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(mark)

        title_box = QVBoxLayout()
        title_box.setSpacing(1)
        eyebrow = QLabel("SECURITY OPERATIONS  /  LOCAL ANALYSIS")
        eyebrow.setObjectName("eyebrow")
        title = QLabel("Incident Clarity Console")
        title.setObjectName("title")
        subtitle = QLabel(
            "Collapse repetitive alerts into deterministic, explainable incidents."
        )
        subtitle.setObjectName("subtitle")
        title_box.addWidget(eyebrow)
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        layout.addLayout(title_box)
        layout.addStretch()

        self.status_pill = QLabel("●  READY  ·  OFFLINE")
        self.status_pill.setObjectName("statusPill")
        layout.addWidget(self.status_pill)
        return header

    def _build_sidebar(self) -> QFrame:
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setMinimumWidth(290)
        sidebar.setMaximumWidth(340)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(18, 18, 18, 18)
        layout.setSpacing(12)

        title = QLabel("Run configuration")
        title.setObjectName("sectionTitle")
        description = QLabel(
            "Choose local JSON and policy files. Processing never leaves this machine."
        )
        description.setProperty("muted", True)
        description.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(description)
        layout.addSpacing(5)

        self.input_path, self.input_button = self._path_field(
            layout, "ALERT INPUT", "Select a JSON alert array"
        )
        self.config_path, self.config_button = self._path_field(
            layout, "GROUPING POLICY", "Select config.json"
        )
        self.output_path, self.output_button = self._path_field(
            layout, "JSON OUTPUT", "Choose output.json"
        )

        chip_label = QLabel("ACTIVE GROUPING FIELDS")
        chip_label.setObjectName("fieldLabel")
        layout.addWidget(chip_label)
        self.chip_container = QWidget()
        self.chip_layout = QGridLayout(self.chip_container)
        self.chip_layout.setContentsMargins(0, 0, 0, 0)
        self.chip_layout.setSpacing(6)
        layout.addWidget(self.chip_container)
        self._show_group_fields(
            ("host", "user", "event_type", "process_name", "file_hash")
        )

        layout.addStretch()
        self.demo_button = QPushButton("Load verified demo")
        self.analyze_button = QPushButton("Analyze alerts  →")
        self.analyze_button.setObjectName("primaryButton")
        self.run_note = QLabel("Ctrl+R to run  ·  Drop a JSON file anywhere")
        self.run_note.setProperty("muted", True)
        self.run_note.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.demo_button)
        layout.addWidget(self.analyze_button)
        layout.addWidget(self.run_note)
        return sidebar

    def _path_field(
        self, layout: QVBoxLayout, label: str, placeholder: str
    ) -> tuple[QLineEdit, QPushButton]:
        title = QLabel(label)
        title.setObjectName("fieldLabel")
        layout.addWidget(title)
        row = QHBoxLayout()
        row.setSpacing(6)
        edit = QLineEdit()
        edit.setPlaceholderText(placeholder)
        button = QPushButton("…")
        button.setObjectName("pathButton")
        row.addWidget(edit, 1)
        row.addWidget(button)
        layout.addLayout(row)
        return edit, button

    def _build_dashboard(self) -> QWidget:
        dashboard = QWidget()
        layout = QVBoxLayout(dashboard)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        metrics = QHBoxLayout()
        metrics.setSpacing(10)
        self.alert_metric = MetricCard("Raw alerts", "#62C6FF")
        self.incident_metric = MetricCard("Incidents", "#B393FF")
        self.reduction_metric = MetricCard("Noise reduced", "#58D7B9")
        self.severity_metric = MetricCard("Highest severity", "#FF8A4C")
        for card in (
            self.alert_metric,
            self.incident_metric,
            self.reduction_metric,
            self.severity_metric,
        ):
            metrics.addWidget(card)
        layout.addLayout(metrics)

        content = QSplitter(Qt.Orientation.Vertical)
        content.setChildrenCollapsible(False)
        content.addWidget(self._build_table_card())
        content.addWidget(self._build_detail_card())
        content.setSizes([460, 230])
        layout.addWidget(content, 1)
        return dashboard

    def _build_table_card(self) -> QFrame:
        card = QFrame()
        card.setObjectName("tableCard")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        toolbar = QHBoxLayout()
        title_box = QVBoxLayout()
        title_box.setSpacing(1)
        title = QLabel("Incident queue")
        title.setObjectName("sectionTitle")
        self.queue_note = QLabel("Run an analysis to populate the queue")
        self.queue_note.setProperty("muted", True)
        title_box.addWidget(title)
        title_box.addWidget(self.queue_note)
        toolbar.addLayout(title_box)
        toolbar.addStretch()

        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("Search incidents…")
        self.search_box.setClearButtonEnabled(True)
        self.search_box.setMaximumWidth(250)
        self.severity_filter = QComboBox()
        self.severity_filter.addItem("All severities", "all")
        self.severity_filter.setMinimumWidth(145)
        self.csv_button = QPushButton("Export CSV")
        self.csv_button.setEnabled(False)
        toolbar.addWidget(self.search_box)
        toolbar.addWidget(self.severity_filter)
        toolbar.addWidget(self.csv_button)
        layout.addLayout(toolbar)

        self.table = QTableView()
        self.table.setModel(self.proxy)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableView.SelectionMode.SingleSelection)
        self.table.setSortingEnabled(True)
        self.table.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(39)
        header = self.table.horizontalHeader()
        header.setStretchLastSection(False)
        for column in range(len(IncidentTableModel.COLUMNS)):
            mode = (
                QHeaderView.ResizeMode.Stretch
                if column in {3, 4, 5}
                else QHeaderView.ResizeMode.ResizeToContents
            )
            header.setSectionResizeMode(column, mode)
        layout.addWidget(self.table, 1)
        return card

    def _build_detail_card(self) -> QFrame:
        card = QFrame()
        card.setObjectName("detailCard")
        layout = QVBoxLayout(card)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(9)

        top = QHBoxLayout()
        title = QLabel("Incident evidence")
        title.setObjectName("sectionTitle")
        self.detail_id = QLabel("NO SELECTION")
        self.detail_id.setObjectName("eyebrow")
        top.addWidget(title)
        top.addWidget(self.detail_id)
        top.addStretch()
        self.open_button = QPushButton("Open JSON")
        self.open_button.setEnabled(False)
        self.copy_button = QPushButton("Copy summary")
        self.copy_button.setEnabled(False)
        top.addWidget(self.copy_button)
        top.addWidget(self.open_button)
        layout.addLayout(top)

        self.empty_detail = QLabel(
            "Select an incident to inspect its summary, normalized context, and source alert IDs."
        )
        self.empty_detail.setObjectName("emptyState")
        self.empty_detail.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.empty_detail, 1)

        self.detail_content = QWidget()
        detail_layout = QGridLayout(self.detail_content)
        detail_layout.setContentsMargins(0, 0, 0, 0)
        detail_layout.setHorizontalSpacing(24)
        detail_layout.setVerticalSpacing(7)
        self.detail_summary = QLabel()
        self.detail_summary.setObjectName("detailSummary")
        self.detail_summary.setWordWrap(True)
        detail_layout.addWidget(self.detail_summary, 0, 0, 1, 4)
        self.detail_values: dict[str, QLabel] = {}
        for column, (label, key) in enumerate(
            (("HOST", "host"), ("USER", "user"), ("PROCESS", "process_name"))
        ):
            box = QVBoxLayout()
            heading = QLabel(label)
            heading.setObjectName("fieldLabel")
            value = QLabel("—")
            value.setObjectName("detailValue")
            value.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            box.addWidget(heading)
            box.addWidget(value)
            detail_layout.addLayout(box, 1, column)
            self.detail_values[key] = value
        ids_box = QVBoxLayout()
        ids_title = QLabel("SOURCE ALERTS")
        ids_title.setObjectName("fieldLabel")
        self.alert_ids = QPlainTextEdit()
        self.alert_ids.setReadOnly(True)
        self.alert_ids.setMaximumHeight(64)
        ids_box.addWidget(ids_title)
        ids_box.addWidget(self.alert_ids)
        detail_layout.addLayout(ids_box, 1, 3)
        self.detail_content.setVisible(False)
        layout.addWidget(self.detail_content, 1)
        return card

    def _connect_actions(self) -> None:
        self.input_button.clicked.connect(self._choose_input)
        self.config_button.clicked.connect(self._choose_config)
        self.output_button.clicked.connect(self._choose_output)
        self.demo_button.clicked.connect(self.load_demo)
        self.analyze_button.clicked.connect(self.analyze)
        self.search_box.textChanged.connect(self.proxy.set_query)
        self.severity_filter.currentIndexChanged.connect(self._severity_changed)
        self.csv_button.clicked.connect(self._choose_csv_export)
        self.open_button.clicked.connect(self._open_output)
        self.copy_button.clicked.connect(self._copy_summary)
        self.table.selectionModel().currentChanged.connect(self._selection_changed)

        QShortcut(QKeySequence.StandardKey.Open, self, self._choose_input)
        QShortcut(QKeySequence("Ctrl+R"), self, lambda: self.analyze())

    def _set_default_paths(self) -> None:
        if self.project_root is None:
            return
        self.input_path.setText("data/demo/raw_alerts.json")
        self.config_path.setText("config.json")
        self.output_path.setText("output.json")

    def _resolved_path(self, value: str) -> Path:
        path = Path(value.strip())
        if path.is_absolute():
            return path
        return (self.project_root or Path.cwd()) / path

    def _show_group_fields(self, fields: Sequence[str]) -> None:
        while self.chip_layout.count():
            item = self.chip_layout.takeAt(0)
            if item is None:
                continue
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        for index, field in enumerate(fields):
            chip = QLabel(field)
            chip.setObjectName("chip")
            chip.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.chip_layout.addWidget(chip, index // 2, index % 2)

    def _choose_input(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select alert input", self.input_path.text(), "JSON files (*.json)"
        )
        if path:
            self.input_path.setText(path)

    def _choose_config(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Select grouping configuration",
            self.config_path.text(),
            "JSON files (*.json)",
        )
        if path:
            self.config_path.setText(path)

    def _choose_output(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Choose JSON output", self.output_path.text(), "JSON files (*.json)"
        )
        if path:
            self.output_path.setText(path)

    def load_demo(self) -> bool:
        if self.project_root is None:
            self._report_error("Demo files are unavailable outside a source checkout.")
            return False
        self._set_default_paths()
        return self.analyze()

    def analyze(self, *, show_dialog: bool = True) -> bool:
        input_path = self._resolved_path(self.input_path.text())
        config_path = self._resolved_path(self.config_path.text())
        output_path = self._resolved_path(self.output_path.text())
        self.status_pill.setText("●  ANALYZING")
        self.analyze_button.setEnabled(False)
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            settings = load_settings(config_path)
            alerts = load_alerts(input_path)
            incidents = build_incidents(group_alerts(alerts, settings), settings)
            write_incidents(
                output_path,
                incidents,
                protected_paths=(input_path, config_path),
            )
        except DeduplicatorError as exc:
            self._report_error(str(exc), show_dialog=show_dialog)
            return False
        finally:
            QApplication.restoreOverrideCursor()
            self.analyze_button.setEnabled(True)

        self.alerts = alerts
        self.incidents = incidents
        self.settings = settings
        self.last_error = ""
        self.model.set_incidents(incidents)
        self._show_group_fields(settings.group_by)
        self._update_metrics()
        self._refresh_severity_filter()
        self.csv_button.setEnabled(bool(incidents))
        self.open_button.setEnabled(True)
        self.queue_note.setText(
            f"{len(incidents)} deterministic groups  ·  {len(alerts)} alerts preserved"
        )
        self.status_pill.setText("●  COMPLETE  ·  OFFLINE")
        if incidents:
            self.table.selectRow(0)
        return True

    def _report_error(self, message: str, *, show_dialog: bool = True) -> None:
        self.last_error = message
        self.status_pill.setText("●  ACTION REQUIRED")
        if show_dialog:
            QMessageBox.critical(self, "Analysis could not complete", message)

    def _update_metrics(self) -> None:
        alert_count = len(self.alerts)
        incident_count = len(self.incidents)
        reduction = noise_reduction_percent(alert_count, incident_count)
        top_severity = highest_severity(self.incidents)
        duplicates = alert_count - incident_count
        self.alert_metric.update_value(str(alert_count), "validated records")
        self.incident_metric.update_value(str(incident_count), "triage-ready groups")
        self.reduction_metric.update_value(
            f"{reduction:.1f}%", f"{duplicates} rows removed"
        )
        self.severity_metric.update_value(
            top_severity.upper(), "highest queue priority"
        )
        color = SEVERITY_COLORS.get(top_severity, "#8A93A7")
        self.severity_metric.note.setStyleSheet(f"color: {color};")

    def _refresh_severity_filter(self) -> None:
        severities = sorted(
            {str(incident["severity"]) for incident in self.incidents},
            key=SEVERITY_RANK.__getitem__,
            reverse=True,
        )
        self.severity_filter.blockSignals(True)
        self.severity_filter.clear()
        self.severity_filter.addItem("All severities", "all")
        for severity in severities:
            self.severity_filter.addItem(severity.title(), severity)
        self.severity_filter.blockSignals(False)
        self.proxy.set_severity("all")

    def _severity_changed(self) -> None:
        severity = self.severity_filter.currentData() or "all"
        self.proxy.set_severity(str(severity))

    def _selection_changed(self, current: QModelIndex, previous: QModelIndex) -> None:
        del previous
        if not current.isValid():
            return
        source = self.proxy.mapToSource(current)
        incident = self.model.incident_at(source.row())
        self._show_incident(incident)

    def _show_incident(self, incident: Incident) -> None:
        self.empty_detail.setVisible(False)
        self.detail_content.setVisible(True)
        self.detail_id.setText(
            f"{incident['incident_id']}  ·  {str(incident['severity']).upper()}"
        )
        self.detail_id.setStyleSheet(
            f"color: {SEVERITY_COLORS.get(str(incident['severity']), '#52D6B8')};"
        )
        self.detail_summary.setText(str(incident["summary"]))
        for key, label in self.detail_values.items():
            label.setText(str(incident[key]))
        self.alert_ids.setPlainText(
            "  ·  ".join(str(value) for value in incident["alert_ids"])
        )
        self.copy_button.setEnabled(True)

    def _choose_csv_export(self) -> None:
        default = self._resolved_path(self.output_path.text()).with_suffix(".csv")
        path, _ = QFileDialog.getSaveFileName(
            self, "Export incidents as CSV", str(default), "CSV files (*.csv)"
        )
        if path:
            self.export_csv(Path(path))

    def export_csv(self, path: Path, *, show_dialog: bool = True) -> bool:
        if not self.incidents:
            self._report_error(
                "Run an analysis before exporting CSV.", show_dialog=show_dialog
            )
            return False
        try:
            write_incidents_csv(
                path,
                self.incidents,
                protected_paths=(
                    self._resolved_path(self.input_path.text()),
                    self._resolved_path(self.config_path.text()),
                    self._resolved_path(self.output_path.text()),
                ),
            )
        except DeduplicatorError as exc:
            self._report_error(str(exc), show_dialog=show_dialog)
            return False
        self.status_pill.setText("●  CSV EXPORTED  ·  OFFLINE")
        return True

    def _open_output(self) -> None:
        output = self._resolved_path(self.output_path.text())
        if output.is_file():
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(output)))

    def _copy_summary(self) -> None:
        QApplication.clipboard().setText(self.detail_summary.text())
        self.status_pill.setText("●  SUMMARY COPIED")

    def dragEnterEvent(self, event: Any) -> None:
        urls = event.mimeData().urls() if event.mimeData().hasUrls() else []
        if any(Path(url.toLocalFile()).suffix.casefold() == ".json" for url in urls):
            event.acceptProposedAction()

    def dropEvent(self, event: Any) -> None:
        for url in event.mimeData().urls():
            path = Path(url.toLocalFile())
            if path.suffix.casefold() == ".json":
                self.input_path.setText(str(path))
                event.acceptProposedAction()
                break


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=f"Launch the {APP_NAME} desktop UI.")
    parser.add_argument("--input", type=Path, help="preselect an alert JSON file")
    parser.add_argument("--config", type=Path, help="preselect a config JSON file")
    parser.add_argument("--output", type=Path, help="preselect a JSON output path")
    parser.add_argument("--demo", action="store_true", help="load and process the demo")
    parser.add_argument(
        "--screenshot", type=Path, help="save the rendered window as PNG"
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    app = cast(QApplication | None, QApplication.instance())
    owns_app = app is None
    if app is None:
        app = QApplication([APP_NAME])
    if sys.platform == "win32":
        for filename in ("segoeui.ttf", "segoeuib.ttf", "consola.ttf"):
            font_path = Path("C:/Windows/Fonts") / filename
            if font_path.is_file():
                QFontDatabase.addApplicationFont(str(font_path))
    app.setApplicationName(APP_NAME)
    app.setOrganizationName("SOC Portfolio Lab")
    app.setStyle("Fusion")
    app.setFont(QFont("Segoe UI", 10))
    app.setStyleSheet(DARK_STYLESHEET)

    window = MainWindow()
    if args.demo:
        window._set_default_paths()
    if args.input:
        window.input_path.setText(str(args.input))
    if args.config:
        window.config_path.setText(str(args.config))
    if args.output:
        window.output_path.setText(str(args.output))
    if args.demo:
        window.analyze()

    window.show()
    app.processEvents()
    if args.screenshot:
        args.screenshot.parent.mkdir(parents=True, exist_ok=True)
        if not window.grab().save(str(args.screenshot), "PNG"):
            print(
                f"error: could not save screenshot to {args.screenshot}",
                file=sys.stderr,
            )
            return 2
        window.close()
        return 0
    return app.exec() if owns_app else 0


if __name__ == "__main__":
    raise SystemExit(main())
