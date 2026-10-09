"""Status and Severity Badges for ShieldScan.
Restrained semantic pill indicators adhering to the color lock.
"""

from __future__ import annotations
from PyQt5.QtWidgets import QLabel, QWidget
from src.ui.tokens import (
    C_POSITIVE, C_POSITIVE_LIGHT, C_WARNING, C_WARNING_LIGHT,
    C_CRITICAL, C_ACCENT_LIGHT, C_TEXT_SECONDARY, C_SURFACE_SECONDARY
)


class StatusBadge(QLabel):
    """Pill indicator for port/host state (OPEN, CLOSED, FILTERED)."""

    def __init__(self, state: str, parent: QWidget = None):
        super().__init__(state.upper(), parent)
        st = state.upper()
        if st in ("OPEN", "REACHABLE"):
            fg, bg = C_POSITIVE, C_POSITIVE_LIGHT
        elif st in ("FILTERED", "UNCERTAIN"):
            fg, bg = C_WARNING, C_WARNING_LIGHT
        else:
            fg, bg = C_TEXT_SECONDARY, C_SURFACE_SECONDARY

        self.setStyleSheet(
            f"color: {fg}; background-color: {bg}; font-size: 9px; font-weight: 700; "
            f"padding: 2px 7px; border-radius: 4px; border: 1px solid {fg}40;"
        )


class SeverityBadge(QLabel):
    """Pill indicator for finding severity (HIGH, MEDIUM, LOW, INFORMATIONAL)."""

    def __init__(self, severity: str, parent: QWidget = None):
        super().__init__(severity.upper(), parent)
        s = severity.upper()
        if s == "HIGH":
            fg, bg = C_CRITICAL, C_ACCENT_LIGHT
        elif s == "MEDIUM":
            fg, bg = C_WARNING, C_WARNING_LIGHT
        elif s == "INFORMATIONAL":
            fg, bg = C_POSITIVE, C_POSITIVE_LIGHT
        else:
            fg, bg = C_TEXT_SECONDARY, C_SURFACE_SECONDARY

        self.setStyleSheet(
            f"color: {fg}; background-color: {bg}; font-size: 9px; font-weight: 700; "
            f"padding: 2px 7px; border-radius: 4px; border: 1px solid {fg}40;"
        )
