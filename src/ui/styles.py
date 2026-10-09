"""QSS Stylesheet for ShieldScan.
Clean Apple-inspired light engineering aesthetic with high contrast and zero gradients.
"""

from __future__ import annotations
from src.ui.tokens import (
    C_CANVAS, C_SURFACE_PRIMARY, C_SURFACE_SECONDARY, C_SURFACE_TERTIARY,
    C_TEXT_PRIMARY, C_TEXT_SECONDARY, C_TEXT_MUTED, C_BORDER, C_BORDER_LIGHT,
    C_ACCENT, C_ACCENT_HOVER, C_ACCENT_LIGHT, C_POSITIVE, C_WARNING,
    FONT_FAMILY_PRIMARY, FONT_FAMILY_MONO
)

SHIELDSCAN_QSS = f"""
* {{
    font-family: {FONT_FAMILY_PRIMARY};
    outline: none;
}}

QMainWindow, QWidget#central_root {{
    background-color: {C_CANVAS};
    color: {C_TEXT_PRIMARY};
}}

QWidget {{
    background-color: transparent;
    color: {C_TEXT_PRIMARY};
}}

/* Sidebar */
QFrame#sidebar {{
    background-color: {C_SURFACE_PRIMARY};
    border-right: 1px solid {C_BORDER};
}}

QLabel#sidebar_logo {{
    font-size: 15px;
    font-weight: 700;
    color: {C_ACCENT};
    letter-spacing: 1.5px;
}}

QLabel#sidebar_sub {{
    font-size: 9px;
    font-weight: 600;
    color: {C_TEXT_MUTED};
    letter-spacing: 1px;
}}

QPushButton#nav_btn {{
    text-align: left;
    padding: 8px 12px;
    font-size: 12px;
    font-weight: 600;
    color: {C_TEXT_SECONDARY};
    border: none;
    border-radius: 6px;
    margin: 2px 8px;
}}

QPushButton#nav_btn:hover {{
    background-color: {C_SURFACE_SECONDARY};
    color: {C_TEXT_PRIMARY};
}}

QPushButton#nav_btn:checked, QPushButton#nav_btn[active="true"] {{
    background-color: {C_SURFACE_SECONDARY};
    color: {C_ACCENT};
    font-weight: 700;
}}

/* Surface Cards */
QFrame#card {{
    background-color: {C_SURFACE_PRIMARY};
    border: 1px solid {C_BORDER};
    border-radius: 8px;
}}

QFrame#card_secondary {{
    background-color: {C_SURFACE_SECONDARY};
    border: 1px solid {C_BORDER_LIGHT};
    border-radius: 6px;
}}

/* Typography */
QLabel#view_title {{
    font-size: 20px;
    font-weight: 700;
    color: {C_TEXT_PRIMARY};
}}

QLabel#view_subtitle {{
    font-size: 12px;
    color: {C_TEXT_SECONDARY};
}}

QLabel#section_heading {{
    font-size: 13px;
    font-weight: 700;
    color: {C_TEXT_PRIMARY};
    letter-spacing: 0.5px;
}}

QLabel#mono_text {{
    font-family: {FONT_FAMILY_MONO};
    font-size: 11px;
}}

/* Form Controls */
QLineEdit, QComboBox, QSpinBox {{
    background-color: {C_SURFACE_PRIMARY};
    border: 1px solid {C_BORDER};
    border-radius: 6px;
    padding: 7px 11px;
    font-size: 12px;
    color: {C_TEXT_PRIMARY};
    selection-background-color: {C_ACCENT_LIGHT};
    selection-color: {C_ACCENT};
}}

QLineEdit:focus, QComboBox:focus, QSpinBox:focus {{
    border: 1.5px solid {C_ACCENT};
    background-color: {C_SURFACE_PRIMARY};
}}

QComboBox::drop-down {{
    border: none;
    padding-right: 8px;
}}

QComboBox QAbstractItemView {{
    background-color: {C_SURFACE_PRIMARY};
    border: 1px solid {C_BORDER};
    selection-background-color: {C_SURFACE_SECONDARY};
    selection-color: {C_ACCENT};
    padding: 4px;
}}

/* Buttons */
QPushButton {{
    border-radius: 6px;
    padding: 7px 14px;
    font-size: 11px;
    font-weight: 600;
    border: 1px solid {C_BORDER};
    background-color: {C_SURFACE_PRIMARY};
    color: {C_TEXT_PRIMARY};
}}

QPushButton:hover {{
    background-color: {C_SURFACE_SECONDARY};
    border-color: {C_BORDER};
}}

QPushButton:pressed {{
    background-color: {C_SURFACE_TERTIARY};
}}

QPushButton#btn_primary {{
    background-color: {C_ACCENT};
    color: #FFFFFF;
    border: 1px solid {C_ACCENT};
    font-weight: 700;
    font-size: 12px;
}}

QPushButton#btn_primary:hover {{
    background-color: {C_ACCENT_HOVER};
    border-color: {C_ACCENT_HOVER};
}}

QPushButton#btn_primary:disabled {{
    background-color: {C_BORDER};
    border-color: {C_BORDER};
    color: {C_TEXT_MUTED};
}}

QPushButton#btn_stop {{
    background-color: #FFFFFF;
    color: {C_ACCENT};
    border: 1px solid {C_ACCENT};
}}

QPushButton#btn_stop:hover {{
    background-color: {C_ACCENT_LIGHT};
}}

/* Table Views */
QTableView {{
    background-color: {C_SURFACE_PRIMARY};
    alternate-background-color: {C_CANVAS};
    border: 1px solid {C_BORDER};
    border-radius: 8px;
    gridline-color: {C_BORDER_LIGHT};
    font-family: {FONT_FAMILY_MONO};
    font-size: 11px;
    color: {C_TEXT_PRIMARY};
    selection-background-color: {C_SURFACE_SECONDARY};
    selection-color: {C_ACCENT};
}}

QTableView::item {{
    padding: 6px 10px;
    border-bottom: 1px solid {C_BORDER_LIGHT};
}}

QTableView::item:selected {{
    background-color: {C_SURFACE_SECONDARY};
    color: {C_ACCENT};
    font-weight: 600;
}}

QHeaderView::section {{
    background-color: {C_SURFACE_SECONDARY};
    color: {C_TEXT_SECONDARY};
    font-weight: 700;
    font-size: 10px;
    letter-spacing: 0.5px;
    padding: 7px 10px;
    border: none;
    border-right: 1px solid {C_BORDER_LIGHT};
    border-bottom: 1px solid {C_BORDER};
}}

/* Scrollbars */
QScrollBar:vertical {{
    background-color: transparent;
    width: 7px;
    margin: 0px;
}}

QScrollBar::handle:vertical {{
    background-color: {C_BORDER};
    border-radius: 3px;
    min-height: 25px;
}}

QScrollBar::handle:vertical:hover {{
    background-color: {C_TEXT_MUTED};
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}

/* Progress Bar */
QProgressBar {{
    background-color: {C_SURFACE_SECONDARY};
    border: 1px solid {C_BORDER};
    border-radius: 4px;
    text-align: center;
    color: {C_TEXT_SECONDARY};
    font-size: 10px;
    font-weight: 600;
    height: 16px;
}}

QProgressBar::chunk {{
    background-color: {C_ACCENT};
    border-radius: 3px;
}}

/* Tabs */
QTabWidget::pane {{
    border: 1px solid {C_BORDER};
    border-radius: 6px;
    background-color: {C_SURFACE_PRIMARY};
    top: -1px;
}}

QTabBar::tab {{
    background-color: transparent;
    color: {C_TEXT_MUTED};
    padding: 8px 16px;
    font-weight: 600;
    font-size: 11px;
    border-bottom: 2px solid transparent;
}}

QTabBar::tab:selected {{
    color: {C_ACCENT};
    border-bottom: 2px solid {C_ACCENT};
}}

QTabBar::tab:hover:!selected {{
    color: {C_TEXT_PRIMARY};
}}

QStatusBar {{
    background-color: {C_SURFACE_PRIMARY};
    color: {C_TEXT_SECONDARY};
    font-size: 11px;
    border-top: 1px solid {C_BORDER};
    padding: 4px 12px;
}}
"""
