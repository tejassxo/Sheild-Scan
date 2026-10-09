"""Network Overview Dashboard View for ShieldScan.
Clean Apple-level information hierarchy presenting network visibility metrics without visual noise.
"""

from __future__ import annotations
from typing import Callable, Optional
from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QPushButton, QScrollArea, QGridLayout, QProgressBar
)
from src.models.assessment import ScanResult
from src.ui.components.metric_card import MetricCard
from src.ui.tokens import (
    C_TEXT_PRIMARY, C_TEXT_SECONDARY, C_TEXT_MUTED, C_ACCENT,
    C_POSITIVE, C_WARNING, C_BORDER, C_SURFACE_SECONDARY
)


class OverviewView(QWidget):
    """Network Overview Dashboard View."""
    nav_requested = pyqtSignal(str)  # "scans", "hosts", "services", "findings", "reports", "compare"

    def __init__(self, parent: QWidget = None):
        super().__init__(parent)
        self._current_scan: Optional[ScanResult] = None

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        content = QWidget()
        self._root_layout = QVBoxLayout(content)
        self._root_layout.setContentsMargins(32, 28, 32, 28)
        self._root_layout.setSpacing(22)

        # ── Header ──────────────────────────────────────────────────────────
        hdr_layout = QHBoxLayout()
        v_title = QVBoxLayout()
        v_title.setSpacing(4)
        self._title = QLabel("Network Overview")
        self._title.setObjectName("view_title")
        self._subtitle = QLabel("Real-time visibility, asset attack surface, and verified security intelligence.")
        self._subtitle.setObjectName("view_subtitle")
        v_title.addWidget(self._title)
        v_title.addWidget(self._subtitle)
        hdr_layout.addLayout(v_title)

        hdr_layout.addStretch()

        self._btn_reports = QPushButton("Report Center 📄")
        self._btn_reports.setFixedHeight(36)
        self._btn_reports.clicked.connect(lambda: self.nav_requested.emit("reports"))
        hdr_layout.addWidget(self._btn_reports)

        self._btn_new_scan = QPushButton("Start New Assessment →")
        self._btn_new_scan.setObjectName("btn_primary")
        self._btn_new_scan.setFixedHeight(36)
        self._btn_new_scan.clicked.connect(lambda: self.nav_requested.emit("scans"))
        hdr_layout.addWidget(self._btn_new_scan)
        self._root_layout.addLayout(hdr_layout)

        # ── Primary Metrics Row ──────────────────────────────────────────────
        metrics_grid = QGridLayout()
        metrics_grid.setSpacing(16)

        self._m_hosts = MetricCard("Hosts Discovered", "0", "0 reachable scope targets")
        self._m_ports = MetricCard("Open Ports", "0", "0 total probed listeners")
        self._m_services = MetricCard("Identified Services", "0", "Banner & TLS verified")
        self._m_findings = MetricCard("Security Findings", "0", "0 critical/high findings", is_accent=True)

        metrics_grid.addWidget(self._m_hosts, 0, 0)
        metrics_grid.addWidget(self._m_ports, 0, 1)
        metrics_grid.addWidget(self._m_services, 0, 2)
        metrics_grid.addWidget(self._m_findings, 0, 3)
        self._root_layout.addLayout(metrics_grid)

        # Deep navigation on metric click
        self._m_hosts.setCursor(Qt.PointingHandCursor)
        self._m_ports.setCursor(Qt.PointingHandCursor)
        self._m_services.setCursor(Qt.PointingHandCursor)
        self._m_findings.setCursor(Qt.PointingHandCursor)
        self._m_hosts.mousePressEvent = lambda e: self.nav_requested.emit("hosts")
        self._m_ports.mousePressEvent = lambda e: self.nav_requested.emit("services")
        self._m_services.mousePressEvent = lambda e: self.nav_requested.emit("services")
        self._m_findings.mousePressEvent = lambda e: self.nav_requested.emit("findings")

        # ── Middle Row: Dual Analytics Cards (Intelligence & Posture) ─────────
        mid_layout = QHBoxLayout()
        mid_layout.setSpacing(16)

        # 1. Left Card: Assessment Intelligence & Severity Profile
        self._card_recent = QFrame()
        self._card_recent.setObjectName("card")
        c_layout = QVBoxLayout(self._card_recent)
        c_layout.setContentsMargins(22, 18, 22, 18)
        c_layout.setSpacing(10)

        lbl_rec_title = QLabel("ACTIVE ASSESSMENT INTELLIGENCE")
        lbl_rec_title.setStyleSheet(f"font-size: 10.5px; font-weight: 700; color: {C_TEXT_MUTED}; letter-spacing: 0.8px;")
        c_layout.addWidget(lbl_rec_title)

        self._lbl_target_info = QLabel("No active or historical scans loaded. Initiate an assessment to view intelligence.")
        self._lbl_target_info.setStyleSheet("font-size: 13.5px; font-weight: 600; line-height: 1.3;")
        self._lbl_target_info.setWordWrap(True)
        c_layout.addWidget(self._lbl_target_info)

        self._lbl_time_info = QLabel("—")
        self._lbl_time_info.setStyleSheet(f"font-size: 11.5px; color: {C_TEXT_SECONDARY};")
        c_layout.addWidget(self._lbl_time_info)

        # Severity Distribution Bar
        self._sev_bar = QProgressBar()
        self._sev_bar.setRange(0, 100)
        self._sev_bar.setValue(0)
        self._sev_bar.setTextVisible(False)
        self._sev_bar.setFixedHeight(10)
        self._sev_bar.setStyleSheet(f"""
            QProgressBar {{
                background-color: {C_SURFACE_SECONDARY};
                border: 1px solid {C_BORDER};
                border-radius: 5px;
            }}
            QProgressBar::chunk {{
                background-color: {C_ACCENT};
                border-radius: 4px;
            }}
        """)
        c_layout.addWidget(self._sev_bar)

        # Severity Pills Layout
        self._pills_layout = QHBoxLayout()
        self._pills_layout.setSpacing(14)

        self._lbl_sev_high = QLabel("High Risk: 0")
        self._lbl_sev_high.setStyleSheet(f"font-size: 12px; font-weight: 700; color: {C_ACCENT};")
        self._lbl_sev_med = QLabel("Medium: 0")
        self._lbl_sev_med.setStyleSheet(f"font-size: 12px; font-weight: 600; color: {C_WARNING};")
        self._lbl_sev_low = QLabel("Low: 0")
        self._lbl_sev_low.setStyleSheet(f"font-size: 12px; color: {C_TEXT_SECONDARY};")
        self._lbl_sev_info = QLabel("Informational: 0")
        self._lbl_sev_info.setStyleSheet(f"font-size: 12px; font-weight: 600; color: {C_POSITIVE};")

        self._pills_layout.addWidget(self._lbl_sev_high)
        self._pills_layout.addWidget(self._lbl_sev_med)
        self._pills_layout.addWidget(self._lbl_sev_low)
        self._pills_layout.addWidget(self._lbl_sev_info)
        self._pills_layout.addStretch()
        c_layout.addLayout(self._pills_layout)

        mid_layout.addWidget(self._card_recent, stretch=3)

        # 2. Right Card: Security Posture Summary
        self._card_posture = QFrame()
        self._card_posture.setObjectName("card")
        posture_layout = QVBoxLayout(self._card_posture)
        posture_layout.setContentsMargins(22, 18, 22, 18)
        posture_layout.setSpacing(8)

        lbl_posture_title = QLabel("SECURITY POSTURE SUMMARY")
        lbl_posture_title.setStyleSheet(f"font-size: 10.5px; font-weight: 700; color: {C_TEXT_MUTED}; letter-spacing: 0.8px;")
        posture_layout.addWidget(lbl_posture_title)

        self._lbl_posture_host = QLabel("• Host Reachability: 100% responsive")
        self._lbl_posture_host.setStyleSheet(f"font-size: 12px; color: {C_TEXT_PRIMARY}; font-weight: 500;")
        posture_layout.addWidget(self._lbl_posture_host)

        self._lbl_posture_density = QLabel("• Port Surface Density: —")
        self._lbl_posture_density.setStyleSheet(f"font-size: 12px; color: {C_TEXT_PRIMARY}; font-weight: 500;")
        posture_layout.addWidget(self._lbl_posture_density)

        self._lbl_posture_svc = QLabel("• Verified Service Fingerprints: —")
        self._lbl_posture_svc.setStyleSheet(f"font-size: 12px; color: {C_TEXT_PRIMARY}; font-weight: 500;")
        posture_layout.addWidget(self._lbl_posture_svc)

        self._lbl_posture_status = QLabel("• Audit State: Ready for assessment")
        self._lbl_posture_status.setStyleSheet(f"font-size: 12px; color: {C_POSITIVE}; font-weight: 600;")
        posture_layout.addWidget(self._lbl_posture_status)

        mid_layout.addWidget(self._card_posture, stretch=2)
        self._root_layout.addLayout(mid_layout)

        # ── Quick Navigation Workspace Cards ─────────────────────────────────
        lbl_nav_sec = QLabel("WORKSPACES & WORKFLOWS")
        lbl_nav_sec.setStyleSheet(f"font-size: 10.5px; font-weight: 700; color: {C_TEXT_MUTED}; letter-spacing: 0.8px;")
        self._root_layout.addWidget(lbl_nav_sec)

        nav_grid = QGridLayout()
        nav_grid.setSpacing(16)

        ws_items = [
            ("Host Explorer", "Inspect discovered hosts, latency telemetry, and individual port listeners.", "hosts", "🖥"),
            ("Service Inventory", "Audit identified network protocols, daemon products, and verified banners.", "services", "⚡"),
            ("Findings Engine", "Review evidence-backed security observations, CVEs, and remediation steps.", "findings", "🛡"),
            ("Historical Comparison", "Diff assessments across time to track host expansion and port drift.", "compare", "⚖"),
            ("Report & Slide Center", "Generate one-click Word assessment reports (.docx) and college slides (.pptx).", "reports", "📄"),
            ("Assessment Controller", "Configure asynchronous port enumeration with full 65K range & multi-vector probes.", "scans", "🎯"),
        ]

        for idx, (w_title, w_desc, w_target, w_icon) in enumerate(ws_items):
            card_ws = QFrame()
            card_ws.setObjectName("card_clickable")
            card_ws.setCursor(Qt.PointingHandCursor)
            card_ws.setMinimumHeight(92)
            wlo = QVBoxLayout(card_ws)
            wlo.setContentsMargins(18, 16, 18, 16)
            wlo.setSpacing(4)

            h_row = QHBoxLayout()
            lt = QLabel(f"{w_icon}  {w_title}")
            lt.setStyleSheet("font-size: 13.5px; font-weight: 700; color: #1D1D1F;")
            h_row.addWidget(lt)
            h_row.addStretch()
            arr = QLabel("→")
            arr.setStyleSheet(f"font-size: 14px; font-weight: 700; color: {C_TEXT_MUTED};")
            h_row.addWidget(arr)
            wlo.addLayout(h_row)

            ld = QLabel(w_desc)
            ld.setStyleSheet(f"font-size: 11.5px; color: {C_TEXT_SECONDARY}; line-height: 1.2;")
            ld.setWordWrap(True)
            wlo.addWidget(ld)

            target_key = w_target
            card_ws.mousePressEvent = lambda e, t=target_key: self.nav_requested.emit(t)

            row = idx // 3
            col = idx % 3
            nav_grid.addWidget(card_ws, row, col)

        self._root_layout.addLayout(nav_grid)

        scroll.setWidget(content)
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(scroll)

    def load_scan(self, scan_result: ScanResult):
        """Updates dashboard with latest scan results."""
        self._current_scan = scan_result
        st = scan_result.stats

        self._m_hosts.set_value(str(st.reachable_hosts))
        self._m_hosts.set_context(f"{st.total_hosts} scope targets reachable")

        self._m_ports.set_value(str(st.open_ports))
        self._m_ports.set_context(f"{st.total_ports_tested:,} total probed listeners")

        self._m_services.set_value(str(st.services_identified))
        self._m_services.set_context("Banner & TLS verified")

        h_count = st.findings_by_severity.get("HIGH", 0)
        m_count = st.findings_by_severity.get("MEDIUM", 0)
        l_count = st.findings_by_severity.get("LOW", 0)
        i_count = st.findings_by_severity.get("INFORMATIONAL", 0)

        self._m_findings.set_value(str(st.total_findings))
        self._m_findings.set_context(f"High: {h_count} · Med: {m_count} · Low: {l_count}")

        self._lbl_target_info.setText(
            f"Target: {scan_result.target}   ·   Profile: {scan_result.profile_name}   ·   Duration: {scan_result.duration_seconds:.2f}s"
        )
        self._lbl_time_info.setText(
            f"Concluded at {scan_result.started_at[:19].replace('T', ' ')}   ·   Scan ID: {scan_result.id}"
        )

        self._lbl_sev_high.setText(f"High Risk: {h_count}")
        self._lbl_sev_med.setText(f"Medium: {m_count}")
        self._lbl_sev_low.setText(f"Low: {l_count}")
        self._lbl_sev_info.setText(f"Informational: {i_count}")

        total_findings = st.total_findings
        if total_findings > 0:
            high_pct = int((h_count / total_findings) * 100)
            self._sev_bar.setValue(max(high_pct, 15 if h_count > 0 else 0))
        else:
            self._sev_bar.setValue(0)

        # Update Security Posture
        reach_pct = int((st.reachable_hosts / max(st.total_hosts, 1)) * 100)
        self._lbl_posture_host.setText(f"• Host Reachability: {reach_pct}% ({st.reachable_hosts}/{st.total_hosts} scope targets)")
        
        avg_ports = (st.open_ports / max(st.reachable_hosts, 1)) if st.reachable_hosts else 0
        self._lbl_posture_density.setText(f"• Port Surface Density: {avg_ports:.1f} open ports / host average")
        
        svc_ratio = (st.services_identified / max(st.open_ports, 1)) * 100 if st.open_ports else 0
        self._lbl_posture_svc.setText(f"• Verified Services: {st.services_identified} fingerprints ({svc_ratio:.0f}% coverage)")
        
        if h_count > 0:
            self._lbl_posture_status.setText(f"• Audit State: ⚠️ {h_count} High-risk exposures require remediation")
            self._lbl_posture_status.setStyleSheet(f"font-size: 12px; color: {C_ACCENT}; font-weight: 700;")
        else:
            self._lbl_posture_status.setText("• Audit State: ✓ No critical vulnerabilities detected")
            self._lbl_posture_status.setStyleSheet(f"font-size: 12px; color: {C_POSITIVE}; font-weight: 600;")
