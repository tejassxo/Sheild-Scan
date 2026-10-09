"""Main Application Window for ShieldScan.
Assembles the Apple-inspired left sidebar, unified navigation, and stacked workspaces.
"""

from __future__ import annotations
from typing import Dict, Optional
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QFrame, QLabel, QPushButton, QStackedWidget,
    QStatusBar, QApplication
)
from src.models.assessment import ScanResult
from src.storage.scan_store import ScanStore
from src.ui.styles import SHIELDSCAN_QSS
from src.ui.tokens import (
    C_CANVAS, C_SURFACE_PRIMARY, C_TEXT_PRIMARY, C_TEXT_SECONDARY,
    C_TEXT_MUTED, C_ACCENT, C_BORDER, C_POSITIVE
)
from src.ui.views.overview_view import OverviewView
from src.ui.views.scan_view import ScanView
from src.ui.views.hosts_view import HostsView
from src.ui.views.services_view import ServicesView
from src.ui.views.findings_view import FindingsView
from src.ui.views.comparison_view import ComparisonView
from src.ui.views.reports_view import ReportsView
from src.ui.views.settings_view import SettingsView


class MainWindow(QMainWindow):
    """ShieldScan Primary Application Window."""

    def __init__(self, store: Optional[ScanStore] = None):
        super().__init__()
        self.setWindowTitle("ShieldScan — Network Visibility & Security Assessment")
        self.setMinimumSize(1024, 660)
        self.resize(1280, 800)
        self.setStyleSheet(SHIELDSCAN_QSS)


        self._store = store or ScanStore()
        self._current_scan: Optional[ScanResult] = None
        self._nav_buttons: Dict[str, QPushButton] = {}

        # Root central container
        central = QWidget()
        central.setObjectName("central_root")
        self.setCentralWidget(central)

        root_layout = QHBoxLayout(central)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # ── Left Navigation Sidebar ──────────────────────────────────────────
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(235)
        sb_layout = QVBoxLayout(sidebar)
        sb_layout.setContentsMargins(0, 22, 0, 18)
        sb_layout.setSpacing(4)

        # Brand / Identity
        brand_frame = QFrame()
        bf_layout = QVBoxLayout(brand_frame)
        bf_layout.setContentsMargins(20, 0, 20, 14)
        bf_layout.setSpacing(3)

        lbl_logo = QLabel("SHIELDSCAN")
        lbl_logo.setObjectName("sidebar_logo")
        lbl_sub = QLabel("NETWORK INTELLIGENCE")
        lbl_sub.setObjectName("sidebar_sub")
        bf_layout.addWidget(lbl_logo)
        bf_layout.addWidget(lbl_sub)
        sb_layout.addWidget(brand_frame)

        # Categorized Navigation Items
        nav_sections = [
            ("WORKSPACE", [
                ("overview", "Overview"),
                ("scans", "Assessments"),
            ]),
            ("INTELLIGENCE", [
                ("hosts", "Host Explorer"),
                ("services", "Service Inventory"),
                ("findings", "Findings Engine"),
            ]),
            ("DELIVERABLES & SYSTEM", [
                ("compare", "Historical Compare"),
                ("reports", "Report Center"),
                ("settings", "Settings"),
            ]),
        ]

        for section_title, items in nav_sections:
            lbl_sec = QLabel(section_title)
            lbl_sec.setObjectName("sidebar_section_hdr")
            sb_layout.addWidget(lbl_sec)

            for key, label in items:
                btn = QPushButton(label)
                btn.setObjectName("nav_btn")
                btn.setCheckable(True)
                btn.clicked.connect(lambda checked, k=key: self._switch_view(k))
                sb_layout.addWidget(btn)
                self._nav_buttons[key] = btn

        sb_layout.addStretch()

        # Engine Telemetry Footer Box
        footer_card = QFrame()
        footer_card.setObjectName("card_secondary")
        footer_card.setStyleSheet("margin: 0 14px; padding: 6px;")
        fc_lo = QVBoxLayout(footer_card)
        fc_lo.setContentsMargins(10, 8, 10, 8)
        fc_lo.setSpacing(2)

        lbl_fc_title = QLabel("ENGINE CORE v5.0")
        lbl_fc_title.setStyleSheet(f"font-size: 9.5px; font-weight: 700; color: {C_TEXT_MUTED}; letter-spacing: 0.8px;")
        lbl_fc_desc = QLabel("● Live Engine Ready\n● Non-Destructive Safe")
        lbl_fc_desc.setStyleSheet(f"font-size: 10px; color: {C_POSITIVE}; font-weight: 600; line-height: 1.3;")
        fc_lo.addWidget(lbl_fc_title)
        fc_lo.addWidget(lbl_fc_desc)
        sb_layout.addWidget(footer_card)

        root_layout.addWidget(sidebar)

        # ── Right Stacked View Area ──────────────────────────────────────────
        self._stack = QStackedWidget()
        self._view_map: Dict[str, QWidget] = {}

        # 1. Overview
        self._v_overview = OverviewView()
        self._v_overview.nav_requested.connect(self._switch_view)
        self._add_view("overview", self._v_overview)

        # 2. Scans
        self._v_scans = ScanView()
        self._v_scans.scan_completed.connect(self._on_scan_completed)
        self._add_view("scans", self._v_scans)

        # 3. Hosts
        self._v_hosts = HostsView()
        self._add_view("hosts", self._v_hosts)

        # 4. Services
        self._v_services = ServicesView()
        self._add_view("services", self._v_services)

        # 5. Findings
        self._v_findings = FindingsView()
        self._add_view("findings", self._v_findings)

        # 6. Compare
        self._v_compare = ComparisonView(self._store)
        self._add_view("compare", self._v_compare)

        # 7. Reports
        self._v_reports = ReportsView()
        self._add_view("reports", self._v_reports)

        # 8. Settings
        self._v_settings = SettingsView()
        self._add_view("settings", self._v_settings)

        root_layout.addWidget(self._stack, stretch=1)

        # ── Status Bar ───────────────────────────────────────────────────────
        sb = QStatusBar()
        sb.showMessage("Ready · ShieldScan Enterprise Core")
        self.setStatusBar(sb)

        # Select initial view
        self._switch_view("overview")

        # Load latest historical scan if exists
        latest = self._store.get_latest()
        if latest:
            self._propagate_scan(latest)

    def _add_view(self, key: str, widget: QWidget):
        self._stack.addWidget(widget)
        self._view_map[key] = widget

    def _switch_view(self, key: str):
        if key in self._view_map:
            widget = self._view_map[key]
            self._stack.setCurrentWidget(widget)
            for k, btn in self._nav_buttons.items():
                btn.setChecked(k == key)
            if key == "compare":
                self._v_compare.refresh_scans()

    def _on_scan_completed(self, scan_result: ScanResult):
        # 1. Save scan to historical store
        self._store.save(scan_result)
        # 2. Propagate to all views
        self._propagate_scan(scan_result)
        # 3. Status bar notification
        self.statusBar().showMessage(
            f"Assessment completed: {scan_result.target} — {scan_result.stats.open_ports} open ports, "
            f"{scan_result.stats.total_findings} findings saved."
        )

    def _propagate_scan(self, scan_result: ScanResult):
        self._current_scan = scan_result
        self._v_overview.load_scan(scan_result)
        self._v_hosts.load_scan(scan_result)
        self._v_services.load_scan(scan_result)
        self._v_findings.load_scan(scan_result)
        self._v_reports.load_scan(scan_result)
        self._v_compare.refresh_scans()
