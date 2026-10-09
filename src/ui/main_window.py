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
    C_TEXT_MUTED, C_ACCENT, C_BORDER
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
        self.setMinimumSize(1240, 780)
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
        sidebar.setFixedWidth(220)
        sb_layout = QVBoxLayout(sidebar)
        sb_layout.setContentsMargins(0, 20, 0, 20)
        sb_layout.setSpacing(6)

        # Brand / Identity
        brand_frame = QFrame()
        bf_layout = QVBoxLayout(brand_frame)
        bf_layout.setContentsMargins(18, 0, 18, 16)
        bf_layout.setSpacing(2)

        lbl_logo = QLabel("SHIELDSCAN")
        lbl_logo.setObjectName("sidebar_logo")
        lbl_sub = QLabel("NETWORK INTELLIGENCE")
        lbl_sub.setObjectName("sidebar_sub")
        bf_layout.addWidget(lbl_logo)
        bf_layout.addWidget(lbl_sub)
        sb_layout.addWidget(brand_frame)

        # Navigation Items (Section 13)
        nav_items = [
            ("overview", "Overview"),
            ("scans", "Assessments"),
            ("hosts", "Hosts"),
            ("services", "Services"),
            ("findings", "Findings"),
            ("compare", "Compare"),
            ("reports", "Reports"),
            ("settings", "Settings"),
        ]

        for key, label in nav_items:
            btn = QPushButton(label)
            btn.setObjectName("nav_btn")
            btn.setCheckable(True)
            btn.clicked.connect(lambda checked, k=key: self._switch_view(k))
            sb_layout.addWidget(btn)
            self._nav_buttons[key] = btn

        sb_layout.addStretch()

        # Footer project label
        lbl_footer = QLabel("ShieldScan v5.0\nDefensive Architecture")
        lbl_footer.setStyleSheet(f"font-size: 10px; color: {C_TEXT_MUTED}; padding: 0 18px;")
        sb_layout.addWidget(lbl_footer)

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
