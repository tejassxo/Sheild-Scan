"""Security Findings Workspace for ShieldScan.
Evidence-grounded vulnerability intelligence and risk classification.
"""

from __future__ import annotations
from typing import List, Optional
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget,
    QTableWidgetItem, QHeaderView, QPushButton, QButtonGroup
)
from src.models.assessment import ScanResult
from src.models.finding import Finding, FindingSeverity
from src.ui.components.search_bar import SearchBar
from src.ui.components.detail_drawer import DetailDrawer
from src.ui.tokens import (
    C_TEXT_PRIMARY, C_TEXT_SECONDARY, C_TEXT_MUTED, C_ACCENT,
    C_POSITIVE, C_WARNING, C_BORDER
)


class FindingsView(QWidget):
    """Security Findings & Evidence Workspace."""

    def __init__(self, parent: QWidget = None):
        super().__init__(parent)
        self._current_scan: Optional[ScanResult] = None
        self._all_findings: List[Finding] = []
        self._active_severity: Optional[str] = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(18)

        # Header
        self._title = QLabel("Findings & Security Intelligence")
        self._title.setObjectName("view_title")
        self._subtitle = QLabel("Auditable security observations categorized by severity with verified evidence.")
        self._subtitle.setObjectName("view_subtitle")
        layout.addWidget(self._title)
        layout.addWidget(self._subtitle)

        # Filter Bar (Severity Buttons + Search)
        filter_row = QHBoxLayout()
        filter_row.setSpacing(8)

        self._btn_group = QButtonGroup(self)
        self._btn_all = QPushButton("All")
        self._btn_high = QPushButton("High")
        self._btn_med = QPushButton("Medium")
        self._btn_low = QPushButton("Low")
        self._btn_info = QPushButton("Informational")

        buttons = [
            (self._btn_all, None),
            (self._btn_high, "HIGH"),
            (self._btn_med, "MEDIUM"),
            (self._btn_low, "LOW"),
            (self._btn_info, "INFORMATIONAL"),
        ]

        for btn, sev in buttons:
            btn.setCheckable(True)
            btn.setFixedHeight(34)
            self._btn_group.addButton(btn)
            btn.clicked.connect(lambda checked, s=sev: self._set_severity_filter(s))
            filter_row.addWidget(btn)

        self._btn_all.setChecked(True)
        filter_row.addSpacing(12)

        self._search = SearchBar("Search findings by ID, title, host, or CVE…")
        self._search.text_changed.connect(self._apply_filters)
        filter_row.addWidget(self._search, stretch=1)

        layout.addLayout(filter_row)

        # Findings Table
        self._table = QTableWidget(0, 6)
        self._table.setHorizontalHeaderLabels(["Severity", "ID", "Title", "Target", "Category", "Confidence"])
        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.Stretch)
        hdr.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        hdr.setHighlightSections(False)
        self._table.verticalHeader().setVisible(False)
        self._table.verticalHeader().setDefaultSectionSize(34)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setSelectionMode(QTableWidget.SingleSelection)
        self._table.setAlternatingRowColors(True)
        self._table.cellDoubleClicked.connect(self._on_finding_double_clicked)
        layout.addWidget(self._table, stretch=1)

    def load_scan(self, scan_result: ScanResult):
        self._current_scan = scan_result
        self._all_findings = scan_result.all_findings
        self._apply_filters()

    def _set_severity_filter(self, sev: Optional[str]):
        self._active_severity = sev
        self._apply_filters()

    def _apply_filters(self):
        query = self._search.text().strip().lower()
        filtered = []

        for f in self._all_findings:
            if self._active_severity and f.severity.value != self._active_severity:
                continue
            if query:
                cves = " ".join(f.cve_references).lower()
                matches = (
                    query in f.id.lower() or
                    query in f.title.lower() or
                    query in f.host.lower() or
                    query in f.category.value.lower() or
                    query in f.description.lower() or
                    query in cves
                )
                if not matches:
                    continue
            filtered.append(f)

        self._populate_table(filtered)

    def _populate_table(self, findings_list: List[Finding]):
        self._table.setRowCount(0)
        for f in findings_list:
            row = self._table.rowCount()
            self._table.insertRow(row)

            # Severity Pill Text
            item_sev = QTableWidgetItem(f.severity.value)
            if f.severity == FindingSeverity.HIGH:
                item_sev.setForeground(Qt.red)
            elif f.severity == FindingSeverity.MEDIUM:
                item_sev.setForeground(Qt.darkYellow)
            elif f.severity == FindingSeverity.INFORMATIONAL:
                item_sev.setForeground(Qt.darkGreen)

            item_id = QTableWidgetItem(f.id)
            item_title = QTableWidgetItem(f.title)
            target_str = f"{f.host}:{f.port}" if f.port else f.host
            item_target = QTableWidgetItem(target_str)
            cat_str = f.category.value.replace("_", " ").title()
            item_cat = QTableWidgetItem(cat_str)
            item_conf = QTableWidgetItem(f.confidence.value)

            item_sev.setToolTip(f"Severity: {f.severity.value}")
            item_id.setToolTip(f"Finding ID: {f.id}")
            item_title.setToolTip(f"{f.title}\n\nDescription:\n{f.description}\n\nRemediation:\n{f.recommendation}")
            item_target.setToolTip(f"Target: {target_str}")
            item_cat.setToolTip(f"Category: {cat_str}")
            item_conf.setToolTip(f"Confidence: {f.confidence.value}")

            self._table.setItem(row, 0, item_sev)
            self._table.setItem(row, 1, item_id)
            self._table.setItem(row, 2, item_title)
            self._table.setItem(row, 3, item_target)
            self._table.setItem(row, 4, item_cat)
            self._table.setItem(row, 5, item_conf)



    def _on_finding_double_clicked(self, row: int, col: int):
        query = self._search.text().strip().lower()
        active = [
            f for f in self._all_findings
            if (not self._active_severity or f.severity.value == self._active_severity)
            and (not query or query in f.id.lower() or query in f.title.lower() or query in f.host.lower())
        ]
        if row < len(active):
            f = active[row]
            drawer = DetailDrawer(f"Finding — {f.title}", self)
            drawer.add_meta_row("Finding ID", f.id)
            drawer.add_meta_row("Severity", f.severity.value, is_accent=(f.severity == FindingSeverity.HIGH))
            drawer.add_meta_row("Target", f"{f.host}:{f.port if f.port else 'Host'}")
            drawer.add_meta_row("Category", f.category.value)
            drawer.add_meta_row("Confidence", f.confidence.value)
            if f.cve_references:
                drawer.add_meta_row("CVE Advisories", ", ".join(f.cve_references))

            ev_txt = f"Description:\n{f.description}\n\n"
            if f.evidence:
                ev_txt += f"Observation: {f.evidence.observation}\n"
                if f.evidence.raw_data:
                    ev_txt += f"Raw Evidence: {f.evidence.raw_data}\n\n"
            ev_txt += f"Impact:\n{f.impact or 'Exposure may lead to information disclosure.'}\n\n"
            ev_txt += f"Actionable Remediation:\n{f.recommendation or 'Audit access controls and firewall policy.'}"
            drawer.set_evidence_text(ev_txt)
            drawer.exec_()
