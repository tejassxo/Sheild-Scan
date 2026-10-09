"""Scan Orchestration & Live Monitoring View for ShieldScan.
Features full 65K port range, multi-technique scans (TCP, UDP, SYN, Xmas, FIN, Null),
interactive pause/resume, and silky-smooth non-blocking 60 FPS UI performance.
"""

from __future__ import annotations
import asyncio
import time
from typing import Optional
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QComboBox, QPushButton, QFrame, QProgressBar, QSpinBox,
    QCheckBox, QTableWidget, QTableWidgetItem, QHeaderView,
    QMessageBox
)
from src.models.assessment import ScanResult
from src.models.scan_profile import (
    BUILTIN_PROFILES, ScanProfile, ScanTechnique, parse_port_range
)
from src.models.port import PortRecord, PortState
from src.scanner.controller import ScanController
from src.ui.components.detail_drawer import DetailDrawer
from src.ui.tokens import (
    C_TEXT_PRIMARY, C_TEXT_SECONDARY, C_TEXT_MUTED, C_ACCENT,
    C_POSITIVE, C_WARNING, C_BORDER, FONT_FAMILY_MONO
)


class ScanThread(QThread):
    """Background worker thread running ScanController asynchronous loop."""
    sig_status = pyqtSignal(str)
    sig_progress = pyqtSignal(int, int, float, float)
    sig_port = pyqtSignal(str, object)
    sig_finished = pyqtSignal(object)
    sig_error = pyqtSignal(str)

    def __init__(self, controller: ScanController, parent=None):
        super().__init__(parent)
        self.controller = controller

    def run(self):
        policy = getattr(asyncio, "WindowsSelectorEventLoopPolicy", None)
        if policy:
            asyncio.set_event_loop_policy(policy())
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            self.controller.on_status = self.sig_status.emit
            self.controller.on_progress = self.sig_progress.emit
            self.controller.on_port_result = self.sig_port.emit
            self.controller.on_error = self.sig_error.emit
            result = loop.run_until_complete(self.controller.run())
            self.sig_finished.emit(result)
        finally:
            loop.close()


class ScanView(QWidget):
    """New Scan configuration and Live Operational scanning view."""
    scan_completed = pyqtSignal(object)  # Emits ScanResult

    def __init__(self, parent: QWidget = None):
        super().__init__(parent)
        self._thread: Optional[ScanThread] = None
        self._controller: Optional[ScanController] = None
        self._t_start: float = 0.0
        self._discovered_open_ports: list[tuple[str, PortRecord]] = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(16)

        # ── Title ────────────────────────────────────────────────────────────
        self._title = QLabel("Network Assessment Controller")
        self._title.setObjectName("view_title")
        self._subtitle = QLabel("Full 65,535 port enumeration, Nmap-grade techniques (TCP/UDP/SYN/Xmas), and live evidence telemetry.")
        self._subtitle.setObjectName("view_subtitle")
        layout.addWidget(self._title)
        layout.addWidget(self._subtitle)

        # ── Configuration Card (Progressive Disclosure) ──────────────────────
        self._card_config = QFrame()
        self._card_config.setObjectName("card")
        cfg_lo = QVBoxLayout(self._card_config)
        cfg_lo.setContentsMargins(20, 16, 20, 16)
        cfg_lo.setSpacing(12)

        # Row 1: Target Scope and Scan Technique
        r1 = QHBoxLayout()
        r1.setSpacing(14)

        # Target input
        v_tgt = QVBoxLayout()
        lbl_target = QLabel("TARGET SCOPE (IP, Hostname, CIDR Subnet, or Range)")
        lbl_target.setStyleSheet(f"font-size: 10px; font-weight: 700; color: {C_TEXT_MUTED}; letter-spacing: 0.8px;")
        v_tgt.addWidget(lbl_target)
        self._inp_target = QLineEdit()
        self._inp_target.setPlaceholderText("e.g. 127.0.0.1, 192.168.1.0/28, scanme.nmap.org")
        self._inp_target.setText("127.0.0.1")
        v_tgt.addWidget(self._inp_target)
        r1.addLayout(v_tgt, stretch=3)

        # Scan Technique (Nmap Options)
        v_tech = QVBoxLayout()
        lbl_tech = QLabel("SCAN TECHNIQUE / PROTOCOL")
        lbl_tech.setStyleSheet(f"font-size: 10px; font-weight: 700; color: {C_TEXT_MUTED}; letter-spacing: 0.8px;")
        v_tech.addWidget(lbl_tech)
        self._combo_technique = QComboBox()
        for t in ScanTechnique:
            self._combo_technique.addItem(t.value, t.name)
        v_tech.addWidget(self._combo_technique)
        r1.addLayout(v_tech, stretch=2)

        cfg_lo.addLayout(r1)

        # Row 2: Profile Selection
        v_prof = QVBoxLayout()
        lbl_prof = QLabel("SCAN PROFILE & PORT SCOPE")
        lbl_prof.setStyleSheet(f"font-size: 10px; font-weight: 700; color: {C_TEXT_MUTED}; letter-spacing: 0.8px;")
        v_prof.addWidget(lbl_prof)

        self._combo_profile = QComboBox()
        for p in BUILTIN_PROFILES:
            self._combo_profile.addItem(f"{p.name} — {p.scope_desc}", p.id)
        self._combo_profile.addItem("Custom Port Range (User Defined)", "custom")
        self._combo_profile.currentIndexChanged.connect(self._on_profile_changed)
        v_prof.addWidget(self._combo_profile)

        self._lbl_prof_desc = QLabel(BUILTIN_PROFILES[0].description)
        self._lbl_prof_desc.setStyleSheet(f"font-size: 11px; color: {C_TEXT_SECONDARY};")
        v_prof.addWidget(self._lbl_prof_desc)
        cfg_lo.addLayout(v_prof)

        # Row 3: Custom Port Input (visible when Custom is selected or in Advanced)
        self._row_custom_ports = QHBoxLayout()
        self._lbl_cust_port = QLabel("Custom Ports (e.g. 1-65535, 80,443,8000-8080):")
        self._inp_custom_ports = QLineEdit("1-65535")
        self._row_custom_ports.addWidget(self._lbl_cust_port)
        self._row_custom_ports.addWidget(self._inp_custom_ports, stretch=1)
        self._frame_custom = QFrame()
        self._frame_custom.setLayout(self._row_custom_ports)
        self._frame_custom.setVisible(False)
        cfg_lo.addWidget(self._frame_custom)

        # Collapsible Advanced Settings (Section 16)
        self._btn_toggle_adv = QPushButton("Show Advanced Configuration ▼")
        self._btn_toggle_adv.setStyleSheet("text-align: left; border: none; font-size: 11px; font-weight: 600; color: #1D1D1F; padding: 4px 0;")
        self._btn_toggle_adv.clicked.connect(self._toggle_advanced)
        cfg_lo.addWidget(self._btn_toggle_adv)

        self._adv_frame = QFrame()
        self._adv_frame.setVisible(False)
        adv_lo = QVBoxLayout(self._adv_frame)
        adv_lo.setContentsMargins(0, 4, 0, 4)
        adv_lo.setSpacing(8)

        adv_row = QHBoxLayout()
        adv_row.addWidget(QLabel("Concurrency (workers):"))
        self._spin_workers = QSpinBox()
        self._spin_workers.setRange(20, 1500)
        self._spin_workers.setValue(800)
        adv_row.addWidget(self._spin_workers)

        adv_row.addWidget(QLabel("Probe Timeout (s):"))
        self._spin_timeout = QLineEdit("0.18")
        self._spin_timeout.setFixedWidth(60)
        adv_row.addWidget(self._spin_timeout)
        adv_row.addStretch()
        adv_lo.addLayout(adv_row)

        self._chk_discovery = QCheckBox("Enable Multi-Vector Host Discovery (ICMP + TCP ping before ports)")
        self._chk_discovery.setChecked(True)
        adv_lo.addWidget(self._chk_discovery)

        self._chk_deep_svc = QCheckBox("Enable Deep Protocol Service Fingerprinting (Banners, TLS, products on open ports)")
        self._chk_deep_svc.setChecked(True)
        adv_lo.addWidget(self._chk_deep_svc)

        cfg_lo.addWidget(self._adv_frame)

        # Action Buttons (Start, Pause, Stop, Clear)
        btn_lo = QHBoxLayout()
        btn_lo.setSpacing(10)

        self._btn_launch = QPushButton("Start Assessment →")
        self._btn_launch.setObjectName("btn_primary")
        self._btn_launch.setFixedHeight(34)
        self._btn_launch.clicked.connect(self.start_scan)
        btn_lo.addWidget(self._btn_launch)

        self._btn_pause = QPushButton("⏸  Pause")
        self._btn_pause.setFixedHeight(34)
        self._btn_pause.setEnabled(False)
        self._btn_pause.clicked.connect(self.toggle_pause)
        btn_lo.addWidget(self._btn_pause)

        self._btn_stop = QPushButton("Stop Scan")
        self._btn_stop.setObjectName("btn_stop")
        self._btn_stop.setFixedHeight(34)
        self._btn_stop.setEnabled(False)
        self._btn_stop.clicked.connect(self.stop_scan)
        btn_lo.addWidget(self._btn_stop)

        self._btn_clear = QPushButton("Clear")
        self._btn_clear.setFixedHeight(34)
        self._btn_clear.clicked.connect(self.clear_results)
        btn_lo.addWidget(self._btn_clear)

        btn_lo.addStretch()
        cfg_lo.addLayout(btn_lo)
        layout.addWidget(self._card_config)

        # ── Operational Live Status (Calm, High-FPS, Precise) ────────────────
        self._card_live = QFrame()
        self._card_live.setObjectName("card")
        live_lo = QVBoxLayout(self._card_live)
        live_lo.setContentsMargins(20, 16, 20, 16)
        live_lo.setSpacing(10)

        live_hdr = QHBoxLayout()
        self._lbl_live_state = QLabel("OPERATIONAL STATUS: IDLE")
        self._lbl_live_state.setStyleSheet(f"font-size: 11px; font-weight: 700; color: {C_TEXT_MUTED}; letter-spacing: 0.8px;")
        live_hdr.addWidget(self._lbl_live_state)
        live_hdr.addStretch()

        self._lbl_live_speed = QLabel("Speed: —")
        self._lbl_live_speed.setStyleSheet(f"font-family: {FONT_FAMILY_MONO}; font-size: 11px; color: {C_TEXT_SECONDARY}; margin-right: 14px;")
        live_hdr.addWidget(self._lbl_live_speed)

        self._lbl_live_elapsed = QLabel("Elapsed: 00:00")
        self._lbl_live_elapsed.setStyleSheet(f"font-family: {FONT_FAMILY_MONO}; font-size: 11px; font-weight: 600;")
        live_hdr.addWidget(self._lbl_live_elapsed)
        live_lo.addLayout(live_hdr)

        self._progress_bar = QProgressBar()
        self._progress_bar.setValue(0)
        self._progress_bar.setFormat("Ready")
        live_lo.addWidget(self._progress_bar)

        self._lbl_activity = QLabel("Ready to initiate assessment.")
        self._lbl_activity.setStyleSheet(f"font-size: 12px; color: {C_TEXT_SECONDARY};")
        live_lo.addWidget(self._lbl_activity)

        # Live Verified Open Ports Table (Streams only open ports for maximum UI smoothness)
        lbl_tbl = QLabel("OPEN PORTS VERIFIED (Double-click any entry for raw evidence trace)")
        lbl_tbl.setStyleSheet(f"font-size: 10px; font-weight: 700; color: {C_TEXT_MUTED}; letter-spacing: 0.8px;")
        live_lo.addWidget(lbl_tbl)

        self._table_live = QTableWidget(0, 5)
        self._table_live.setHorizontalHeaderLabels(["Host", "Port / Protocol", "State", "Service / Product", "Latency"])
        self._table_live.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._table_live.cellDoubleClicked.connect(self._on_row_double_clicked)
        self._table_live.setMinimumHeight(200)
        live_lo.addWidget(self._table_live)

        layout.addWidget(self._card_live, stretch=1)

        # Timer for elapsed time
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick_timer)

    def _on_profile_changed(self, idx: int):
        if idx < len(BUILTIN_PROFILES):
            p = BUILTIN_PROFILES[idx]
            self._lbl_prof_desc.setText(f"{p.description} ({len(p.ports):,} ports · {p.depth_desc})")
            self._spin_workers.setValue(p.concurrency)
            self._spin_timeout.setText(str(p.timeout))
            self._frame_custom.setVisible(False)
            # Match technique if UDP profile
            if p.id == "udp_services":
                self._combo_technique.setCurrentIndex(2)  # UDP Sweep
            elif self._combo_technique.currentIndex() == 2:
                self._combo_technique.setCurrentIndex(0)  # TCP Connect
        else:
            # Custom selected
            self._lbl_prof_desc.setText("Custom user-specified ports and ranges.")
            self._frame_custom.setVisible(True)

    def _toggle_advanced(self):
        vis = not self._adv_frame.isVisible()
        self._adv_frame.setVisible(vis)
        self._btn_toggle_adv.setText("Hide Advanced Configuration ▲" if vis else "Show Advanced Configuration ▼")

    def _tick_timer(self):
        if self._t_start > 0 and self._controller and not self._controller.is_paused:
            el = time.perf_counter() - self._t_start
            m, s = divmod(int(el), 60)
            self._lbl_live_elapsed.setText(f"Elapsed: {m:02d}:{s:02d}")

    def start_scan(self):
        tgt = self._inp_target.text().strip()
        if not tgt:
            QMessageBox.warning(self, "Missing Target", "Please specify a target IP, hostname, CIDR, or range.")
            return

        p_idx = self._combo_profile.currentIndex()
        if p_idx < len(BUILTIN_PROFILES):
            base_p = BUILTIN_PROFILES[p_idx]
            ports = base_p.ports
            p_name = base_p.name
            p_id = base_p.id
        else:
            custom_str = self._inp_custom_ports.text().strip()
            ports = parse_port_range(custom_str)
            if not ports:
                QMessageBox.warning(self, "Invalid Ports", "Please enter valid ports (e.g., 1-65535 or 80,443).")
                return
            p_name = f"Custom ({len(ports):,} ports)"
            p_id = "custom"

        # Selected technique
        tech_idx = self._combo_technique.currentIndex()
        technique = list(ScanTechnique)[tech_idx]

        try:
            timeout_val = float(self._spin_timeout.text().strip())
        except ValueError:
            timeout_val = 0.20

        profile = ScanProfile(
            id=p_id,
            name=p_name,
            description=f"Scanning {len(ports):,} ports using {technique.value}",
            scope_desc=f"{len(ports):,} ports via {technique.value}",
            depth_desc="Deep service analysis on open ports",
            resource_desc="Async parallel workers",
            ports=ports,
            technique=technique,
            timeout=timeout_val,
            concurrency=self._spin_workers.value(),
            discover_hosts=self._chk_discovery.isChecked(),
            deep_service_detection=self._chk_deep_svc.isChecked(),
        )

        self._controller = ScanController(target_spec=tgt, profile=profile)
        self._thread = ScanThread(self._controller, self)
        self._thread.sig_status.connect(self._on_status)
        self._thread.sig_progress.connect(self._on_progress)
        self._thread.sig_port.connect(self._on_port)
        self._thread.sig_finished.connect(self._on_finished)
        self._thread.sig_error.connect(self._on_error)

        self._t_start = time.perf_counter()
        self._timer.start(500)
        self._discovered_open_ports.clear()

        # UI state transitions
        self._btn_launch.setEnabled(False)
        self._btn_pause.setEnabled(True)
        self._btn_pause.setText("⏸  Pause")
        self._btn_stop.setEnabled(True)
        self._inp_target.setEnabled(False)
        self._combo_profile.setEnabled(False)
        self._combo_technique.setEnabled(False)
        self._table_live.setRowCount(0)
        self._lbl_live_state.setText("OPERATIONAL STATUS: SCANNING")
        self._lbl_live_state.setStyleSheet(f"font-size: 11px; font-weight: 700; color: {C_ACCENT}; letter-spacing: 0.8px;")

        self._thread.start()

    def toggle_pause(self):
        if not self._controller:
            return
        if self._controller.is_paused:
            self._controller.resume()
            self._btn_pause.setText("⏸  Pause")
            self._lbl_live_state.setText("OPERATIONAL STATUS: SCANNING")
            self._lbl_live_state.setStyleSheet(f"font-size: 11px; font-weight: 700; color: {C_ACCENT}; letter-spacing: 0.8px;")
        else:
            self._controller.pause()
            self._btn_pause.setText("▶  Resume")
            self._lbl_live_state.setText("OPERATIONAL STATUS: PAUSED")
            self._lbl_live_state.setStyleSheet(f"font-size: 11px; font-weight: 700; color: {C_WARNING}; letter-spacing: 0.8px;")

    def stop_scan(self):
        if self._controller:
            self._controller.stop()
            self._btn_stop.setEnabled(False)
            self._btn_pause.setEnabled(False)
            self._lbl_activity.setText("Stopping active workers safely…")

    def clear_results(self):
        self._table_live.setRowCount(0)
        self._discovered_open_ports.clear()
        self._progress_bar.setValue(0)
        self._progress_bar.setFormat("Ready")
        self._lbl_live_speed.setText("Speed: —")
        self._lbl_live_elapsed.setText("Elapsed: 00:00")
        self._lbl_live_state.setText("OPERATIONAL STATUS: IDLE")
        self._lbl_live_state.setStyleSheet(f"font-size: 11px; font-weight: 700; color: {C_TEXT_MUTED}; letter-spacing: 0.8px;")
        self._lbl_activity.setText("Ready to initiate assessment.")

    def _on_status(self, msg: str):
        self._lbl_activity.setText(msg)

    def _on_progress(self, done: int, total: int, pct: float, speed: float):
        self._progress_bar.setValue(int(pct))
        self._progress_bar.setFormat(f"{done:,} / {total:,} ports ({pct:.1f}%)")
        if speed > 0:
            self._lbl_live_speed.setText(f"Speed: {speed:,.0f} ports/s")

    def _on_port(self, host_ip: str, p_rec: PortRecord):
        if p_rec.state == PortState.OPEN:
            self._discovered_open_ports.append((host_ip, p_rec))
            row = self._table_live.rowCount()
            self._table_live.insertRow(row)

            svc_name = p_rec.service.name if p_rec.service else "—"
            if p_rec.service and p_rec.service.product:
                svc_name += f" ({p_rec.service.product})"

            self._table_live.setItem(row, 0, QTableWidgetItem(host_ip))
            self._table_live.setItem(row, 1, QTableWidgetItem(f"{p_rec.port}/{p_rec.protocol.value}"))

            st_item = QTableWidgetItem(p_rec.state.value)
            st_item.setForeground(Qt.darkGreen)
            self._table_live.setItem(row, 2, st_item)

            self._table_live.setItem(row, 3, QTableWidgetItem(svc_name))
            self._table_live.setItem(row, 4, QTableWidgetItem(f"{p_rec.latency_ms:.1f} ms"))
            self._table_live.scrollToBottom()

    def _on_finished(self, scan_result: ScanResult):
        self._timer.stop()
        self._btn_launch.setEnabled(True)
        self._btn_pause.setEnabled(False)
        self._btn_pause.setText("⏸  Pause")
        self._btn_stop.setEnabled(False)
        self._inp_target.setEnabled(True)
        self._combo_profile.setEnabled(True)
        self._combo_technique.setEnabled(True)
        self._progress_bar.setValue(100)
        self._progress_bar.setFormat(f"Complete · {scan_result.stats.total_ports_tested:,} ports · {scan_result.duration_seconds:.2f}s")
        self._lbl_live_state.setText(f"OPERATIONAL STATUS: {scan_result.status}")
        self._lbl_live_state.setStyleSheet(f"font-size: 11px; font-weight: 700; color: {C_POSITIVE}; letter-spacing: 0.8px;")
        self.scan_completed.emit(scan_result)

    def _on_error(self, err: str):
        self._timer.stop()
        self._btn_launch.setEnabled(True)
        self._btn_pause.setEnabled(False)
        self._btn_stop.setEnabled(False)
        self._inp_target.setEnabled(True)
        self._combo_profile.setEnabled(True)
        self._combo_technique.setEnabled(True)
        self._lbl_live_state.setText("OPERATIONAL STATUS: ERROR")
        self._lbl_activity.setText(f"Error: {err}")

    def _on_row_double_clicked(self, row: int, col: int):
        if row < len(self._discovered_open_ports):
            host_ip, p = self._discovered_open_ports[row]
            drawer = DetailDrawer(f"Port {p.port}/{p.protocol.value} Details — {host_ip}", self)
            drawer.add_meta_row("Host", host_ip)
            drawer.add_meta_row("Port / Protocol", f"{p.port}/{p.protocol.value}")
            drawer.add_meta_row("State", p.state.value)
            if p.service:
                drawer.add_meta_row("Service", p.service.name)
                drawer.add_meta_row("Product", p.service.product or "—")
                drawer.add_meta_row("Version", p.service.version or "—")
                drawer.add_meta_row("Confidence", p.service.confidence.value)
            ev = p.evidence or (p.service.evidence if p.service else None)
            ev_txt = ev.observation if ev else "Connection verified."
            if ev and ev.raw_data:
                ev_txt += f"\n\n--- RAW EVIDENCE ---\n{ev.raw_data}"
            drawer.set_evidence_text(ev_txt)
            drawer.exec_()
