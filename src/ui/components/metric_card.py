"""Metric Card Component for ShieldScan.
Spacious, typography-driven metric card with clear hierarchy.
"""

from __future__ import annotations
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QFrame, QLabel, QVBoxLayout, QWidget
from src.ui.tokens import C_TEXT_PRIMARY, C_TEXT_SECONDARY, C_TEXT_MUTED, C_ACCENT


class MetricCard(QFrame):
    """Clean metric card showing primary value, label, and secondary context."""

    def __init__(self, label: str, value: str = "0", context: str = "", parent: QWidget = None, is_accent: bool = False):
        super().__init__(parent)
        self.setObjectName("card")
        self.setMinimumHeight(104)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(4)

        self._lbl_label = QLabel(label.upper())
        self._lbl_label.setStyleSheet(f"font-size: 10.5px; font-weight: 700; color: {C_TEXT_MUTED}; letter-spacing: 0.8px;")
        layout.addWidget(self._lbl_label)

        self._lbl_value = QLabel(value)
        val_color = C_ACCENT if is_accent else C_TEXT_PRIMARY
        self._lbl_value.setStyleSheet(f"font-size: 32px; font-weight: 700; color: {val_color}; line-height: 1.1;")
        layout.addWidget(self._lbl_value)

        if context:
            self._lbl_ctx = QLabel(context)
            self._lbl_ctx.setStyleSheet(f"font-size: 11px; font-weight: 500; color: {C_TEXT_SECONDARY};")
            layout.addWidget(self._lbl_ctx)
        else:
            self._lbl_ctx = None

    def set_value(self, value: str):
        self._lbl_value.setText(value)

    def set_context(self, context: str):
        if self._lbl_ctx:
            self._lbl_ctx.setText(context)
        else:
            self._lbl_ctx = QLabel(context)
            self._lbl_ctx.setStyleSheet(f"font-size: 11px; font-weight: 500; color: {C_TEXT_SECONDARY};")
            self.layout().addWidget(self._lbl_ctx)
