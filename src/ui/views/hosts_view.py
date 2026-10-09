"""Host Explorer Workspace for ShieldScan.
Clean host inventory with master-detail progressive disclosure of ports, services, and evidence.
"""

from __future__ import annotations
from typing import Optional
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QSplitter,
    QListWidget, QListWidgetItem, QTableWidget, QTableWidgetItem,
    QHeaderView, QFrame, QPushButton
)
from src.models.assessment import ScanResult
from src.models.host import HostRecord
from src.ui.components.badges import StatusBadge
from src.ui.components.detail_drawer import DetailDrawer
from src.ui.tokens import (
    C_TEXT_PRIMARY, C_TEXT_SECONDARY, C_TEXT_MUTED, C_ACCENT,
    C_POSITIVE, C_BORDER, FONT_FAMILY_PRIMARY, FONT_FAMILY_MONO
)



class HostsView(QWidget):
    """Host Explorer workspace."""

    def __init__(self, parent: QWidget = None):
        super().__init__(parent)
        self._current_scan: Optional[ScanResult] = None
        self._selected_host: Optional[HostRecord] = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(18)

        # Header
        self._title = QLabel("Host Explorer")
        self._title.setObjectName("view_title")
        self._subtitle = QLabel("Drill down into individual host systems, verified listeners, and forensic evidence.")
        self._subtitle.setObjectName("view_subtitle")
        layout.addWidget(self._title)
        layout.addWidget(self._subtitle)

        # Splitter (Left: Host List, Right: Host Details)
        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.setHandleWidth(2)

        # Left Panel (Host List)
        left_panel = QFrame()
        left_panel.setObjectName("card")
        left_panel.setMinimumWidth(240)
        l_lo = QVBoxLayout(left_panel)
        l_lo.setContentsMargins(14, 14, 14, 14)
        l_lo.setSpacing(8)

        lbl_hl = QLabel("DISCOVERED HOSTS")
        lbl_hl.setStyleSheet(f"font-size: 10px; font-weight: 700; color: {C_TEXT_MUTED}; letter-spacing: 0.8px;")
        l_lo.addWidget(lbl_hl)

        self._host_list = QListWidget()
        self._host_list.setStyleSheet(f"font-family: {FONT_FAMILY_PRIMARY}; font-size: 12px; font-weight: 500; border: none;")
        self._host_list.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._host_list.currentItemChanged.connect(self._on_host_selected)
        l_lo.addWidget(self._host_list)


        splitter.addWidget(left_panel)

        # Right Panel (Host Details)
        right_panel = QFrame()
        right_panel.setObjectName("card")
        right_panel.setMinimumWidth(440)
        r_lo = QVBoxLayout(right_panel)
        r_lo.setContentsMargins(20, 18, 20, 18)
        r_lo.setSpacing(12)

        # Host Identity Banner
        self._lbl_host_ip = QLabel("Select a host system")
        self._lbl_host_ip.setStyleSheet("font-size: 18px; font-weight: 700;")
        self._lbl_host_meta = QLabel("—")
        self._lbl_host_meta.setStyleSheet(f"font-size: 12px; color: {C_TEXT_SECONDARY};")
        r_lo.addWidget(self._lbl_host_ip)
        r_lo.addWidget(self._lbl_host_meta)

        # Discovered Ports Table
        lbl_pt = QLabel("OPEN PORTS & SERVICES")
        lbl_pt.setStyleSheet(f"font-size: 10px; font-weight: 700; color: {C_TEXT_MUTED}; letter-spacing: 0.8px;")
        r_lo.addWidget(lbl_pt)

        self._ports_table = QTableWidget(0, 5)
        self._ports_table.setHorizontalHeaderLabels(["Port", "State", "Service", "Product / Version", "Evidence"])
        p_hdr = self._ports_table.horizontalHeader()
        p_hdr.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        p_hdr.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        p_hdr.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        p_hdr.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        p_hdr.setSectionResizeMode(4, QHeaderView.Stretch)
        p_hdr.setHighlightSections(False)
        self._ports_table.verticalHeader().setDefaultSectionSize(32)
        self._ports_table.setMinimumHeight(180)
        self._ports_table.cellDoubleClicked.connect(self._on_port_double_clicked)
        r_lo.addWidget(self._ports_table, stretch=3)

        # Findings Summary for Host
        lbl_ft = QLabel("SECURITY FINDINGS FOR THIS HOST")
        lbl_ft.setStyleSheet(f"font-size: 10px; font-weight: 700; color: {C_TEXT_MUTED}; letter-spacing: 0.8px;")
        r_lo.addWidget(lbl_ft)

        self._findings_table = QTableWidget(0, 4)
        self._findings_table.setHorizontalHeaderLabels(["Severity", "ID", "Title", "Port"])
        f_hdr = self._findings_table.horizontalHeader()
        f_hdr.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        f_hdr.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        f_hdr.setSectionResizeMode(2, QHeaderView.Stretch)
        f_hdr.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        f_hdr.setHighlightSections(False)
        self._findings_table.verticalHeader().setVisible(False)
        self._findings_table.verticalHeader().setDefaultSectionSize(32)
        self._findings_table.setSelectionBehavior(QTableWidget.SelectRows)
        self._findings_table.setSelectionMode(QTableWidget.SingleSelection)
        self._findings_table.setAlternatingRowColors(True)
        self._findings_table.setMinimumHeight(150)
        r_lo.addWidget(self._findings_table, stretch=2)

        splitter.addWidget(right_panel)
        splitter.setSizes([280, 780])
        layout.addWidget(splitter, stretch=1)

    def load_scan(self, scan_result: ScanResult):
        self._current_scan = scan_result
        self._host_list.clear()
        self._ports_table.setRowCount(0)
        self._findings_table.setRowCount(0)

        for ip, host in scan_result.hosts.items():
            label = f"{ip}"
            if host.hostname:
                label += f" ({host.hostname})"
            item = QListWidgetItem(label)
            item.setData(Qt.UserRole, ip)
            item.setToolTip(f"{ip} - {host.status.value} ({len(host.open_ports)} ports)")
            self._host_list.addItem(item)

        if self._host_list.count() > 0:
            self._host_list.setCurrentRow(0)

    def _on_host_selected(self, current: Optional[QListWidgetItem], previous=None):
        if not current or not self._current_scan:
            return
        ip = current.data(Qt.UserRole)
        host = self._current_scan.hosts.get(ip)
        if not host:
            return

        self._selected_host = host
        h_name = f" · {host.hostname}" if host.hostname else ""
        self._lbl_host_ip.setText(f"{host.ip}{h_name}")
        self._lbl_host_meta.setText(
            f"Status: {host.status.value}  ·  Latency: {host.latency_ms:.1f}ms  ·  "
            f"{len(host.open_ports)} Open Ports  ·  {len(host.findings)} Findings"
        )

        # Populate Ports
        self._ports_table.setRowCount(0)
        for p in host.open_ports:
            row = self._ports_table.rowCount()
            self._ports_table.insertRow(row)

            it_port = QTableWidgetItem(f"{p.port}/{p.protocol.value}")
            it_state = QTableWidgetItem(p.state.value)
            svc_name = p.service.name if p.service else "Unknown"
            it_svc = QTableWidgetItem(svc_name)
            prod_ver = f"{p.service.product} {p.service.version}".strip() if p.service else "—"
            it_prod = QTableWidgetItem(prod_ver or "—")
            ev_str = p.evidence.observation if p.evidence else "TCP Connection"
            it_ev = QTableWidgetItem(ev_str)

            # Tooltips to guarantee full visibility
            it_port.setToolTip(f"Port {p.port}/{p.protocol.value}")
            it_state.setToolTip(f"State: {p.state.value}")
            it_svc.setToolTip(f"Service: {svc_name}")
            it_prod.setToolTip(f"Product & Version: {prod_ver or '—'}")
            it_ev.setToolTip(ev_str)

            self._ports_table.setItem(row, 0, it_port)
            self._ports_table.setItem(row, 1, it_state)
            self._ports_table.setItem(row, 2, it_svc)
            self._ports_table.setItem(row, 3, it_prod)
            self._ports_table.setItem(row, 4, it_ev)

        # Populate Findings
        self._findings_table.setRowCount(0)
        for f in host.findings:
            row = self._findings_table.rowCount()
            self._findings_table.insertRow(row)

            it_sev = QTableWidgetItem(f.severity.value)
            if f.severity.value == "HIGH":
                it_sev.setForeground(Qt.red)
            elif f.severity.value == "MEDIUM":
                it_sev.setForeground(Qt.darkYellow)
            elif f.severity.value == "INFORMATIONAL":
                it_sev.setForeground(Qt.darkGreen)

            it_id = QTableWidgetItem(f.id)
            it_title = QTableWidgetItem(f.title)
            it_port = QTableWidgetItem(str(f.port) if f.port else "Host")

            it_sev.setToolTip(f"Severity: {f.severity.value}")
            it_id.setToolTip(f"Finding ID: {f.id}")
            it_title.setToolTip(f"{f.title}\n{f.description}")
            it_port.setToolTip(f"Target Port: {f.port if f.port else 'Host-wide'}")

            self._findings_table.setItem(row, 0, it_sev)
            self._findings_table.setItem(row, 1, it_id)
            self._findings_table.setItem(row, 2, it_title)
            self._findings_table.setItem(row, 3, it_port)


    def _on_port_double_clicked(self, row: int, col: int):
        if not self._selected_host:
            return
        ports = self._selected_host.open_ports
        if row < len(ports):
            p = ports[row]
            drawer = DetailDrawer(f"Port {p.port}/{p.protocol.value} Details", self)
            drawer.add_meta_row("Host", self._selected_host.ip)
            drawer.add_meta_row("Port", str(p.port))
            drawer.add_meta_row("State", p.state.value)
            if p.service:
                drawer.add_meta_row("Service", p.service.name)
                drawer.add_meta_row("Product", p.service.product or "—")
                drawer.add_meta_row("Version", p.service.version or "—")
                drawer.add_meta_row("Confidence", p.service.confidence.value)
            ev = p.evidence or (p.service.evidence if p.service else None)
            ev_txt = ev.observation if ev else "Standard TCP connection."
            if ev and ev.raw_data:
                ev_txt += f"\n\n--- RAW EVIDENCE ---\n{ev.raw_data}"
            drawer.set_evidence_text(ev_txt)
            drawer.exec_()
