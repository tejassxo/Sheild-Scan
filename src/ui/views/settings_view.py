"""Preferences & System Settings View for ShieldScan.
"""

from __future__ import annotations
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QFrame, QSpinBox,
    QLineEdit, QCheckBox, QPushButton, QHBoxLayout, QMessageBox,
    QScrollArea, QGridLayout
)
from src.ui.tokens import (
    C_TEXT_PRIMARY, C_TEXT_SECONDARY, C_TEXT_MUTED, C_ACCENT,
    C_POSITIVE, C_BORDER, C_SURFACE_SECONDARY
)


class SettingsView(QWidget):
    """Preferences and scan tuning configuration view."""

    def __init__(self, parent: QWidget = None):
        super().__init__(parent)

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(22)

        # Header
        self._title = QLabel("System Settings & Engine Defaults")
        self._title.setObjectName("view_title")
        self._subtitle = QLabel("Configure network socket timeouts, concurrency boundaries, and defensive guardrails.")
        self._subtitle.setObjectName("view_subtitle")
        layout.addWidget(self._title)
        layout.addWidget(self._subtitle)

        # Settings Grid (2 Column Cards)
        grid = QGridLayout()
        grid.setSpacing(18)

        # 1. Performance & Sockets Card
        card_perf = QFrame()
        card_perf.setObjectName("card")
        p_lo = QVBoxLayout(card_perf)
        p_lo.setContentsMargins(22, 18, 22, 18)
        p_lo.setSpacing(12)

        lbl_p_title = QLabel("ENGINE PERFORMANCE & CONCURRENCY")
        lbl_p_title.setStyleSheet(f"font-size: 10.5px; font-weight: 700; color: {C_TEXT_MUTED}; letter-spacing: 0.8px;")
        p_lo.addWidget(lbl_p_title)

        r1 = QHBoxLayout()
        r1.addWidget(QLabel("Default Concurrency Worker Limit:"))
        self._workers = QSpinBox()
        self._workers.setRange(20, 1500)
        self._workers.setValue(800)
        self._workers.setFixedWidth(100)
        r1.addWidget(self._workers)
        p_lo.addLayout(r1)

        r2 = QHBoxLayout()
        r2.addWidget(QLabel("Default Probe Socket Timeout (s):"))
        self._timeout = QLineEdit("0.18")
        self._timeout.setFixedWidth(100)
        r2.addWidget(self._timeout)
        p_lo.addLayout(r2)

        r3 = QHBoxLayout()
        r3.addWidget(QLabel("Multi-Vector Discovery Retry Count:"))
        self._retries = QSpinBox()
        self._retries.setRange(1, 5)
        self._retries.setValue(2)
        self._retries.setFixedWidth(100)
        r3.addWidget(self._retries)
        p_lo.addLayout(r3)

        grid.addWidget(card_perf, 0, 0)

        # 2. Defensive Guardrails Card
        card_guard = QFrame()
        card_guard.setObjectName("card")
        g_lo = QVBoxLayout(card_guard)
        g_lo.setContentsMargins(22, 18, 22, 18)
        g_lo.setSpacing(12)

        lbl_g_title = QLabel("DEFENSIVE AUDITING GUARDRAILS")
        lbl_g_title.setStyleSheet(f"font-size: 10.5px; font-weight: 700; color: {C_TEXT_MUTED}; letter-spacing: 0.8px;")
        g_lo.addWidget(lbl_g_title)

        self._chk_safe = QCheckBox("Enforce Safe Guardrails (Cap target scope expansion to 256 hosts)")
        self._chk_safe.setChecked(True)
        g_lo.addWidget(self._chk_safe)

        self._chk_non_destructive = QCheckBox("Enforce Non-Destructive Probes (No aggressive exploitation attempts)")
        self._chk_non_destructive.setChecked(True)
        g_lo.addWidget(self._chk_non_destructive)

        self._chk_evidence_audit = QCheckBox("Capture Raw Network Telemetry for Evidentiary Defense Auditing")
        self._chk_evidence_audit.setChecked(True)
        g_lo.addWidget(self._chk_evidence_audit)

        grid.addWidget(card_guard, 0, 1)

        layout.addLayout(grid)

        # About & Engineering Specifications Card
        about_card = QFrame()
        about_card.setObjectName("card")
        a_lo = QVBoxLayout(about_card)
        a_lo.setContentsMargins(22, 18, 22, 18)
        a_lo.setSpacing(10)

        lbl_ab = QLabel("ABOUT SHIELDSCAN DEFENSIVE ARCHITECTURE")
        lbl_ab.setStyleSheet(f"font-size: 10.5px; font-weight: 700; color: {C_TEXT_MUTED}; letter-spacing: 0.8px;")
        a_lo.addWidget(lbl_ab)

        lbl_info = QLabel(
            "<b>ShieldScan</b> is a high-performance network visibility and security assessment platform developed for "
            "rigorous academic and enterprise network evaluation. It incorporates non-blocking asynchronous I/O with "
            "configurable concurrency up to 1,500 workers, multi-vector host discovery (ICMP, TCP Ping), full 65,535 port "
            "enumeration across multiple probing techniques (TCP Connect, UDP Sweep, SYN/Stealth, Xmas, FIN, Null), "
            "deep service fingerprinting with TLS cipher extraction, auditable evidence capture, historical drift tracking, "
            "and automated Word (.docx) & PowerPoint (.pptx) report generation."
        )
        lbl_info.setWordWrap(True)
        lbl_info.setStyleSheet(f"font-size: 12.5px; color: {C_TEXT_PRIMARY}; line-height: 1.4;")
        a_lo.addWidget(lbl_info)

        lbl_spec = QLabel(
            "• Core Framework: Python 3.10+ / PyQt5 Responsive Engine\n"
            "• Network Stack: Asynchronous Socket Engine + Scapy Layer 3/4 Handshakes\n"
            "• Storage Architecture: Canonical JSON Data Store with UUID Tracking\n"
            "• Deliverables Engine: Python-docx & Python-pptx Native Generators"
        )
        lbl_spec.setStyleSheet(f"font-size: 11.5px; color: {C_TEXT_SECONDARY}; line-height: 1.4; padding-top: 6px;")
        a_lo.addWidget(lbl_spec)

        layout.addWidget(about_card)

        scroll.setWidget(content)
        root_lo = QVBoxLayout(self)
        root_lo.setContentsMargins(0, 0, 0, 0)
        root_lo.addWidget(scroll)
