"""Network Overview Dashboard View for ShieldScan.
Clean Apple-level information hierarchy presenting network visibility metrics without visual noise.
"""

from __future__ import annotations
from typing import Callable, Optional
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QPushButton, QScrollArea, QGridLayout
)
from src.models.assessment import ScanResult
from src.ui.components.metric_card import MetricCard
from src.ui.tokens import (
    C_TEXT_PRIMARY, C_TEXT_SECONDARY, C_TEXT_MUTED, C_ACCENT,
    C_POSITIVE, C_WARNING, C_BORDER
)


class OverviewView(QWidget):
    """Network Overview Dashboard View."""
    nav_requested = pyqtSignal(str)  # "scans", "hosts", "services", "findings", "reports"

    def __init__(self, parent: QWidget = None):
        super().__init__(parent)
        self._current_scan: Optional[ScanResult] = None

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        content = QWidget()
        self._root_layout = QVBoxLayout(content)
        self._root_layout.setContentsMargins(28, 24, 28, 24)
        self._root_layout.setSpacing(20)

        # ── Header ──────────────────────────────────────────────────────────
        hdr_layout = QHBoxLayout()
        v_title = QVBoxLayout()
        self._title = QLabel("Network Overview")
        self._title.setObjectName("view_title")
        self._subtitle = QLabel("Understand your network attack surface and active services.")
        self._subtitle.setObjectName("view_subtitle")
        v_title.addWidget(self._title)
        v_title.addWidget(self._subtitle)
        hdr_layout.addLayout(v_title)

        hdr_layout.addStretch()

        self._btn_new_scan = QPushButton("Start New Assessment →")
        self._btn_new_scan.setObjectName("btn_primary")
        self._btn_new_scan.clicked.connect(lambda: self.nav_requested.emit("scans"))
        hdr_layout.addWidget(self._btn_new_scan)
        self._root_layout.addLayout(hdr_layout)

        # ── Primary Metrics Row ──────────────────────────────────────────────
        metrics_grid = QGridLayout()
        metrics_grid.setSpacing(14)

        self._m_hosts = MetricCard("Hosts Discovered", "0", "0 reachable")
        self._m_ports = MetricCard("Open Ports", "0", "0 total probed")
        self._m_services = MetricCard("Identified Services", "0", "Banner verified")
        self._m_findings = MetricCard("Security Findings", "0", "0 critical/high", is_accent=True)

        metrics_grid.addWidget(self._m_hosts, 0, 0)
        metrics_grid.addWidget(self._m_ports, 0, 1)
        metrics_grid.addWidget(self._m_services, 0, 2)
        metrics_grid.addWidget(self._m_findings, 0, 3)
        self._root_layout.addLayout(metrics_grid)

        # Make metrics clickable for deep navigation (Section 12)
        self._m_hosts.mousePressEvent = lambda e: self.nav_requested.emit("hosts")
        self._m_ports.mousePressEvent = lambda e: self.nav_requested.emit("services")
        self._m_services.mousePressEvent = lambda e: self.nav_requested.emit("services")
        self._m_findings.mousePressEvent = lambda e: self.nav_requested.emit("findings")

        # ── Recent Assessment Details Card ───────────────────────────────────
        self._card_recent = QFrame()
        self._card_recent.setObjectName("card")
        c_layout = QVBoxLayout(self._card_recent)
        c_layout.setContentsMargins(20, 18, 20, 18)
        c_layout.setSpacing(12)

        lbl_rec_title = QLabel("RECENT ASSESSMENT INTELLIGENCE")
        lbl_rec_title.setStyleSheet(f"font-size: 10px; font-weight: 700; color: {C_TEXT_MUTED}; letter-spacing: 0.8px;")
        c_layout.addWidget(lbl_rec_title)

        self._lbl_target_info = QLabel("No active or historical scans loaded. Initiate a scan to view network intelligence.")
        self._lbl_target_info.setStyleSheet("font-size: 13px; font-weight: 600;")
        c_layout.addWidget(self._lbl_target_info)

        self._lbl_time_info = QLabel("—")
        self._lbl_time_info.setStyleSheet(f"font-size: 11px; color: {C_TEXT_SECONDARY};")
        c_layout.addWidget(self._lbl_time_info)

        # Severity Pills Bar
        self._pills_layout = QHBoxLayout()
        self._pills_layout.setSpacing(12)

        self._lbl_sev_high = QLabel("High Risk: 0")
        self._lbl_sev_high.setStyleSheet(f"font-size: 11px; font-weight: 700; color: {C_ACCENT};")
        self._lbl_sev_med = QLabel("Medium: 0")
        self._lbl_sev_med.setStyleSheet(f"font-size: 11px; font-weight: 600; color: {C_WARNING};")
        self._lbl_sev_low = QLabel("Low: 0")
        self._lbl_sev_low.setStyleSheet(f"font-size: 11px; color: {C_TEXT_SECONDARY};")
        self._lbl_sev_info = QLabel("Informational: 0")
        self._lbl_sev_info.setStyleSheet(f"font-size: 11px; font-weight: 600; color: {C_POSITIVE};")

        self._pills_layout.addWidget(self._lbl_sev_high)
        self._pills_layout.addWidget(self._lbl_sev_med)
        self._pills_layout.addWidget(self._lbl_sev_low)
        self._pills_layout.addWidget(self._lbl_sev_info)
        self._pills_layout.addStretch()

        c_layout.addLayout(self._pills_layout)
        self._root_layout.addWidget(self._card_recent)

        # ── Quick Navigation Workspace Cards ─────────────────────────────────
        lbl_nav_sec = QLabel("WORKSPACES & WORKFLOWS")
        lbl_nav_sec.setStyleSheet(f"font-size: 10px; font-weight: 700; color: {C_TEXT_MUTED}; letter-spacing: 0.8px;")
        self._root_layout.addWidget(lbl_nav_sec)

        nav_grid = QGridLayout()
        nav_grid.setSpacing(14)

        ws_items = [
            ("Host Explorer", "Inspect discovered hosts, latency, and open ports.", "hosts"),
            ("Service Inventory", "Audit identified protocols, products, and banners.", "services"),
            ("Findings Engine", "Review evidence-backed security findings and remediation.", "findings"),
            ("Historical Comparison", "Diff assessments across time to track network drift.", "compare"),
            ("Report Center", "Generate one-click Word reports and college presentations.", "reports"),
        ]

        for idx, (w_title, w_desc, w_target) in enumerate(ws_items):
            card_ws = QFrame()
            card_ws.setObjectName("card")
            card_ws.setCursor(Qt.PointingHandCursor)
            wlo = QVBoxLayout(card_ws)
            wlo.setContentsMargins(16, 14, 16, 14)
            wlo.setSpacing(4)
            
            lt = QLabel(w_title)
            lt.setStyleSheet("font-size: 13px; font-weight: 700;")
            ld = QLabel(w_desc)
            ld.setStyleSheet(f"font-size: 11px; color: {C_TEXT_SECONDARY};")
            wlo.addWidget(lt)
            wlo.addWidget(ld)
            
            target_key = w_target
            card_ws.mousePressEvent = lambda e, t=target_key: self.nav_requested.emit(t)
            
            row = idx // 2
            col = idx % 2
            nav_grid.addWidget(card_ws, row, col)

        self._root_layout.addLayout(nav_grid)
        self._root_layout.addStretch()

        scroll.setWidget(content)
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(scroll)

    def load_scan(self, scan_result: ScanResult):
        """Updates dashboard with latest scan results."""
        self._current_scan = scan_result
        st = scan_result.stats

        self._m_hosts.set_value(str(st.reachable_hosts))
        self._m_hosts.set_context(f"{st.total_hosts} scope targets")

        self._m_ports.set_value(str(st.open_ports))
        self._m_ports.set_context(f"{st.total_ports_tested:,} total probed")

        self._m_services.set_value(str(st.services_identified))
        self._m_services.set_context("Banner & TLS verified")

        self._m_findings.set_value(str(st.total_findings))
        self._m_findings.set_context(f"High: {st.findings_by_severity.get('HIGH',0)} | Med: {st.findings_by_severity.get('MEDIUM',0)}")

        self._lbl_target_info.setText(
            f"Target: {scan_result.target}  ·  Profile: {scan_result.profile_name}  ·  Duration: {scan_result.duration_seconds:.2f}s"
        )
        self._lbl_time_info.setText(
            f"Concluded at {scan_result.started_at[:19].replace('T', ' ')}  ·  Scan ID: {scan_result.id}"
        )

        h_count = st.findings_by_severity.get("HIGH", 0)
        m_count = st.findings_by_severity.get("MEDIUM", 0)
        l_count = st.findings_by_severity.get("LOW", 0)
        i_count = st.findings_by_severity.get("INFORMATIONAL", 0)

        self._lbl_sev_high.setText(f"High Risk: {h_count}")
        self._lbl_sev_med.setText(f"Medium: {m_count}")
        self._lbl_sev_low.setText(f"Low: {l_count}")
        self._lbl_sev_info.setText(f"Informational: {i_count}")
