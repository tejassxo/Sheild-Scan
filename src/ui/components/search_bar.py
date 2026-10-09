"""Global & Table Search Bar for ShieldScan.
"""

from __future__ import annotations
from PyQt5.QtCore import pyqtSignal
from PyQt5.QtWidgets import QHBoxLayout, QLineEdit, QPushButton, QWidget
from src.ui.tokens import C_BORDER, C_SURFACE_PRIMARY, C_TEXT_MUTED


class SearchBar(QWidget):
    """Clean filter field with quick clear button."""
    text_changed = pyqtSignal(str)

    def __init__(self, placeholder: str = "Search hosts, ports, services, findings…", parent: QWidget = None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        self._input = QLineEdit()
        self._input.setPlaceholderText(placeholder)
        self._input.textChanged.connect(self.text_changed.emit)
        layout.addWidget(self._input)

        self._btn_clear = QPushButton("✕")
        self._btn_clear.setFixedWidth(26)
        self._btn_clear.setFixedHeight(28)
        self._btn_clear.setToolTip("Clear search")
        self._btn_clear.setStyleSheet(f"color: {C_TEXT_MUTED}; font-size: 11px; padding: 0;")
        self._btn_clear.clicked.connect(self._input.clear)
        layout.addWidget(self._btn_clear)

    def text(self) -> str:
        return self._input.text()

    def set_text(self, text: str):
        self._input.setText(text)
