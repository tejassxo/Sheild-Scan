"""Evidence & Item Detail Modal Drawer for ShieldScan.
Reveals deep technical evidence, raw traces, and remediation without cluttering primary views.
"""

from __future__ import annotations
from typing import Optional
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit,
    QPushButton, QFrame, QWidget, QApplication
)
from src.ui.tokens import (
    C_CANVAS, C_SURFACE_PRIMARY, C_SURFACE_SECONDARY, C_TEXT_PRIMARY,
    C_TEXT_SECONDARY, C_TEXT_MUTED, C_BORDER, C_ACCENT, C_POSITIVE,
    FONT_FAMILY_MONO
)


class DetailDrawer(QDialog):
    """Clean detail inspection dialog for ports, services, or findings."""

    def __init__(self, title: str, parent: QWidget = None):
        super().__init__(parent)
        self.setWindowTitle(f"ShieldScan Details — {title}")
        self.setMinimumSize(560, 480)
        self.setStyleSheet(f"background-color: {C_CANVAS}; color: {C_TEXT_PRIMARY};")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(14)

        # Header Title
        self._lbl_title = QLabel(title)
        self._lbl_title.setStyleSheet("font-size: 16px; font-weight: 700;")
        layout.addWidget(self._lbl_title)

        # Meta Card
        self._meta_card = QFrame()
        self._meta_card.setObjectName("card")
        self._meta_layout = QVBoxLayout(self._meta_card)
        self._meta_layout.setContentsMargins(14, 12, 14, 12)
        self._meta_layout.setSpacing(6)
        layout.addWidget(self._meta_card)

        # Evidence Header
        lbl_ev = QLabel("OBSERVED EVIDENCE & TRACE")
        lbl_ev.setStyleSheet(f"font-size: 10px; font-weight: 700; color: {C_TEXT_MUTED}; letter-spacing: 0.8px;")
        layout.addWidget(lbl_ev)

        # Evidence Text Area (Monospace)
        self._txt_evidence = QTextEdit()
        self._txt_evidence.setReadOnly(True)
        self._txt_evidence.setStyleSheet(
            f"font-family: {FONT_FAMILY_MONO}; font-size: 11px; background-color: {C_SURFACE_PRIMARY}; "
            f"border: 1px solid {C_BORDER}; border-radius: 6px; padding: 10px;"
        )
        layout.addWidget(self._txt_evidence, stretch=1)

        # Bottom Button Bar
        btn_bar = QHBoxLayout()
        btn_bar.addStretch()

        self._btn_copy = QPushButton("Copy Trace")
        self._btn_copy.clicked.connect(self._copy_trace)
        btn_bar.addWidget(self._btn_copy)

        self._btn_close = QPushButton("Done")
        self._btn_close.setObjectName("btn_primary")
        self._btn_close.clicked.connect(self.accept)
        btn_bar.addWidget(self._btn_close)

        layout.addLayout(btn_bar)

    def add_meta_row(self, label: str, value: str, is_accent: bool = False):
        lbl = QLabel(f"<b>{label}:</b>  {value}")
        color = C_ACCENT if is_accent else C_TEXT_PRIMARY
        lbl.setStyleSheet(f"font-size: 11.5px; color: {color};")
        self._meta_layout.addWidget(lbl)

    def set_evidence_text(self, text: str):
        self._txt_evidence.setPlainText(text)

    def _copy_trace(self):
        cb = QApplication.clipboard()
        cb.setText(self._txt_evidence.toPlainText())
        self._btn_copy.setText("Copied!")
