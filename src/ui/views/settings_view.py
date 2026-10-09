"""Preferences & System Settings View for ShieldScan.
"""

from __future__ import annotations
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QFrame, QSpinBox,
    QLineEdit, QCheckBox, QPushButton, QHBoxLayout, QMessageBox
)
from src.ui.tokens import (
    C_TEXT_PRIMARY, C_TEXT_SECONDARY, C_TEXT_MUTED, C_ACCENT,
    C_BORDER
)


class SettingsView(QWidget):
    """Preferences and scan tuning configuration view."""

    def __init__(self, parent: QWidget = None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(20)

        # Header
        self._title = QLabel("System Settings & Engine Defaults")
        self._title.setObjectName("view_title")
        self._subtitle = QLabel("Configure network socket timeouts, concurrency boundaries, and defensive guardrails.")
        self._subtitle.setObjectName("view_subtitle")
        layout.addWidget(self._title)
        layout.addWidget(self._subtitle)

        # Settings Card
        card = QFrame()
        card.setObjectName("card")
        c_lo = QVBoxLayout(card)
        c_lo.setContentsMargins(20, 18, 20, 18)
        c_lo.setSpacing(14)

        # Concurrency
        r1 = QHBoxLayout()
        r1.addWidget(QLabel("Default Concurrency Worker Limit:"))
        self._workers = QSpinBox()
        self._workers.setRange(20, 1000)
        self._workers.setValue(250)
        r1.addWidget(self._workers)
        r1.addStretch()
        c_lo.addLayout(r1)

        # Socket Timeout
        r2 = QHBoxLayout()
        r2.addWidget(QLabel("Default Probe Socket Timeout (seconds):"))
        self._timeout = QLineEdit("0.35")
        self._timeout.setFixedWidth(80)
        r2.addWidget(self._timeout)
        r2.addStretch()
        c_lo.addLayout(r2)

        # Safety Checkbox
        self._chk_safe = QCheckBox("Enforce Safe Guardrails (Cap target expansion to 256 hosts, non-destructive)")
        self._chk_safe.setChecked(True)
        c_lo.addWidget(self._chk_safe)

        layout.addWidget(card)

        # About Card
        about_card = QFrame()
        about_card.setObjectName("card")
        a_lo = QVBoxLayout(about_card)
        a_lo.setContentsMargins(20, 18, 20, 18)
        a_lo.setSpacing(8)

        lbl_ab = QLabel("ABOUT SHIELDSCAN ENTERPRISE CORE")
        lbl_ab.setStyleSheet(f"font-size: 10px; font-weight: 700; color: {C_TEXT_MUTED}; letter-spacing: 0.8px;")
        a_lo.addWidget(lbl_ab)

        lbl_info = QLabel(
            "<b>ShieldScan</b> is a modern network visibility and security assessment platform developed for academic "
            "Computer Networks defense. It provides non-destructive multi-vector discovery, asynchronous port enumeration, "
            "deep service fingerprinting, evidence traceability, historical change detection, and automated report generation."
        )
        lbl_info.setWordWrap(True)
        lbl_info.setStyleSheet(f"font-size: 11.5px; color: {C_TEXT_PRIMARY};")
        a_lo.addWidget(lbl_info)

        layout.addWidget(about_card)
        layout.addStretch()
