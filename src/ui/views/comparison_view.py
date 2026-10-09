"""Historical Assessment Comparison View for ShieldScan.
Transforms network scanning into an ongoing network drift and change-observation system.
"""

from __future__ import annotations
from typing import List, Optional
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QComboBox,
    QPushButton, QFrame, QGridLayout, QTableWidget, QTableWidgetItem,
    QHeaderView
)
from src.models.assessment import ScanResult
from src.models.comparison import ScanComparison
from src.analysis.change_detector import compare_assessments
from src.storage.scan_store import ScanStore
from src.ui.components.metric_card import MetricCard
from src.ui.tokens import (
    C_TEXT_PRIMARY, C_TEXT_SECONDARY, C_TEXT_MUTED, C_ACCENT,
    C_POSITIVE, C_WARNING, C_BORDER
)


class ComparisonView(QWidget):
    """Historical Scan Comparison workspace."""

    def __init__(self, store: ScanStore, parent: QWidget = None):
        super().__init__(parent)
        self._store = store
        self._all_scans: List[ScanResult] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(16)

        # Header
        self._title = QLabel("Historical Scan Comparison")
        self._title.setObjectName("view_title")
        self._subtitle = QLabel("Diff any two network assessments to identify host expansion, port drift, and resolved risks.")
        self._subtitle.setObjectName("view_subtitle")
        layout.addWidget(self._title)
        layout.addWidget(self._subtitle)

        # Scan Selection Bar
        sel_card = QFrame()
        sel_card.setObjectName("card")
        sel_lo = QHBoxLayout(sel_card)
        sel_lo.setContentsMargins(16, 14, 16, 14)
        sel_lo.setSpacing(14)

        sel_lo.addWidget(QLabel("Baseline Scan:"))
        self._combo_baseline = QComboBox()
        sel_lo.addWidget(self._combo_baseline, stretch=1)

        sel_lo.addWidget(QLabel("Current Assessment:"))
        self._combo_current = QComboBox()
        sel_lo.addWidget(self._combo_current, stretch=1)

        self._btn_compare = QPushButton("Compare Scans →")
        self._btn_compare.setObjectName("btn_primary")
        self._btn_compare.clicked.connect(self._run_comparison)
        sel_lo.addWidget(self._btn_compare)

        layout.addWidget(sel_card)

        # Delta Metric Cards
        delta_grid = QGridLayout()
        delta_grid.setSpacing(12)

        self._m_hosts_delta = MetricCard("Net Host Change", "0", "0 new / 0 removed")
        self._m_ports_delta = MetricCard("New Open Ports", "0", "0 closed")
        self._m_svc_delta = MetricCard("Service Version Shifts", "0", "Updated banners")
        self._m_find_delta = MetricCard("New Findings", "0", "0 resolved", is_accent=True)

        delta_grid.addWidget(self._m_hosts_delta, 0, 0)
        delta_grid.addWidget(self._m_ports_delta, 0, 1)
        delta_grid.addWidget(self._m_svc_delta, 0, 2)
        delta_grid.addWidget(self._m_find_delta, 0, 3)
        layout.addLayout(delta_grid)

        # Detailed Delta Table
        lbl_tbl = QLabel("DETAILED NETWORK DRIFT LOG")
        lbl_tbl.setStyleSheet(f"font-size: 10px; font-weight: 700; color: {C_TEXT_MUTED}; letter-spacing: 0.8px;")
        layout.addWidget(lbl_tbl)

        self._table = QTableWidget(0, 4)
        self._table.setHorizontalHeaderLabels(["Change Category", "Target / Host", "Observed Difference", "Status"])
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self._table, stretch=1)

    def refresh_scans(self):
        """Reloads scan list from storage."""
        self._all_scans = self._store.list_all()
        self._combo_baseline.clear()
        self._combo_current.clear()

        for s in self._all_scans:
            label = f"{s.target} ({s.profile_name}) — {s.started_at[:19].replace('T', ' ')}"
            self._combo_baseline.addItem(label, s.id)
            self._combo_current.addItem(label, s.id)

        # By default, select second as baseline and first as current if available
        if len(self._all_scans) >= 2:
            self._combo_current.setCurrentIndex(0)
            self._combo_baseline.setCurrentIndex(1)
            self._run_comparison()

    def _run_comparison(self):
        if len(self._all_scans) < 2:
            return

        base_id = self._combo_baseline.currentData()
        curr_id = self._combo_current.currentData()

        if base_id == curr_id:
            return

        base_scan = self._store.get_by_id(base_id)
        curr_scan = self._store.get_by_id(curr_id)

        if not base_scan or not curr_scan:
            return

        comp = compare_assessments(base_scan, curr_scan)

        # Update Metrics
        sm = comp.summary_metrics
        self._m_hosts_delta.set_value(f"{sm['net_hosts']:+d}")
        self._m_hosts_delta.set_context(f"+{sm['new_hosts_count']} new / -{sm['removed_hosts_count']} removed")

        self._m_ports_delta.set_value(f"+{sm['new_open_ports_count']}")
        self._m_ports_delta.set_context(f"-{sm['closed_ports_count']} closed")

        self._m_svc_delta.set_value(str(sm['service_changes_count']))
        self._m_svc_delta.set_context("Version or daemon change")

        self._m_find_delta.set_value(f"+{sm['new_findings_count']}")
        self._m_find_delta.set_context(f"-{sm['resolved_findings_count']} resolved")

        # Populate Delta Table
        self._table.setRowCount(0)

        # New Hosts
        for nh in comp.new_hosts:
            r = self._table.rowCount()
            self._table.insertRow(r)
            self._table.setItem(r, 0, QTableWidgetItem("HOST ADDED"))
            self._table.setItem(r, 1, QTableWidgetItem(nh))
            self._table.setItem(r, 2, QTableWidgetItem("Host newly discovered active in network scope"))
            it_st = QTableWidgetItem("+ NEW")
            it_st.setForeground(Qt.darkGreen)
            self._table.setItem(r, 3, it_st)

        # Removed Hosts
        for rh in comp.removed_hosts:
            r = self._table.rowCount()
            self._table.insertRow(r)
            self._table.setItem(r, 0, QTableWidgetItem("HOST REMOVED"))
            self._table.setItem(r, 1, QTableWidgetItem(rh))
            self._table.setItem(r, 2, QTableWidgetItem("Host no longer responsive to discovery probes"))
            it_st = QTableWidgetItem("- REMOVED")
            it_st.setForeground(Qt.red)
            self._table.setItem(r, 3, it_st)

        # New Open Ports
        for np in comp.new_open_ports:
            r = self._table.rowCount()
            self._table.insertRow(r)
            self._table.setItem(r, 0, QTableWidgetItem("PORT OPENED"))
            self._table.setItem(r, 1, QTableWidgetItem(f"{np.host}:{np.port}/{np.protocol}"))
            self._table.setItem(r, 2, QTableWidgetItem(f"Port now listening ({np.service})"))
            it_st = QTableWidgetItem("+ OPEN")
            it_st.setForeground(Qt.darkGreen)
            self._table.setItem(r, 3, it_st)

        # Closed Ports
        for cp in comp.closed_ports:
            r = self._table.rowCount()
            self._table.insertRow(r)
            self._table.setItem(r, 0, QTableWidgetItem("PORT CLOSED"))
            self._table.setItem(r, 1, QTableWidgetItem(f"{cp.host}:{cp.port}/{cp.protocol}"))
            self._table.setItem(r, 2, QTableWidgetItem(f"Previously listening port now closed"))
            it_st = QTableWidgetItem("- CLOSED")
            it_st.setForeground(Qt.darkGray)
            self._table.setItem(r, 3, it_st)

        # Service Changes
        for sc in comp.service_changes:
            r = self._table.rowCount()
            self._table.insertRow(r)
            self._table.setItem(r, 0, QTableWidgetItem("SERVICE CHANGED"))
            self._table.setItem(r, 1, QTableWidgetItem(f"{sc.host}:{sc.port}"))
            self._table.setItem(r, 2, QTableWidgetItem(f"Migrated from '{sc.old_service}' to '{sc.new_service}'"))
            it_st = QTableWidgetItem("MODIFIED")
            it_st.setForeground(Qt.darkYellow)
            self._table.setItem(r, 3, it_st)

        # New Findings
        for nf in comp.new_findings:
            r = self._table.rowCount()
            self._table.insertRow(r)
            self._table.setItem(r, 0, QTableWidgetItem(f"FINDING ({nf.severity})"))
            self._table.setItem(r, 1, QTableWidgetItem(nf.host))
            self._table.setItem(r, 2, QTableWidgetItem(f"[{nf.finding_id}] {nf.title}"))
            it_st = QTableWidgetItem("+ NEW RISK")
            it_st.setForeground(Qt.red)
            self._table.setItem(r, 3, it_st)

        # Resolved Findings
        for rf in comp.resolved_findings:
            r = self._table.rowCount()
            self._table.insertRow(r)
            self._table.setItem(r, 0, QTableWidgetItem(f"FINDING RESOLVED ({rf.severity})"))
            self._table.setItem(r, 1, QTableWidgetItem(rf.host))
            self._table.setItem(r, 2, QTableWidgetItem(f"[{rf.finding_id}] {rf.title}"))
            it_st = QTableWidgetItem("✓ RESOLVED")
            it_st.setForeground(Qt.darkGreen)
            self._table.setItem(r, 3, it_st)
