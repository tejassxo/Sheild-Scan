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
    font-size: 16px;
    font-weight: 800;
    color: {C_ACCENT};
    letter-spacing: 1.8px;
}}

QLabel#sidebar_sub {{
    font-size: 9.5px;
    font-weight: 700;
    color: {C_TEXT_MUTED};
    letter-spacing: 1.2px;
}}

QLabel#sidebar_section_hdr {{
    font-size: 9.5px;
    font-weight: 800;
    color: {C_TEXT_MUTED};
    letter-spacing: 1px;
    padding: 10px 18px 4px 18px;
}}

QPushButton#nav_btn {{
    text-align: left;
    padding: 9px 14px;
    font-size: 12.5px;
    font-weight: 600;
    color: {C_TEXT_SECONDARY};
    border: none;
    border-radius: 7px;
    margin: 2px 10px;
}}

QPushButton#nav_btn:hover {{
    background-color: {C_SURFACE_SECONDARY};
    color: {C_TEXT_PRIMARY};
}}

QPushButton#nav_btn:checked, QPushButton#nav_btn[active="true"] {{
    background-color: {C_SURFACE_SECONDARY};
    color: {C_ACCENT};
    font-weight: 700;
    border-left: 3px solid {C_ACCENT};
}}

/* Surface Cards */
QFrame#card {{
    background-color: {C_SURFACE_PRIMARY};
    border: 1px solid {C_BORDER};
    border-radius: 8px;
}}

QFrame#card_clickable {{
    background-color: {C_SURFACE_PRIMARY};
    border: 1px solid {C_BORDER};
    border-radius: 8px;
}}

QFrame#card_clickable:hover {{
    border-color: #B42318;
    background-color: #FFFFFF;
}}

QFrame#card_secondary {{
    background-color: {C_SURFACE_SECONDARY};
    border: 1px solid {C_BORDER_LIGHT};
    border-radius: 6px;
}}

/* Typography */
QLabel#view_title {{
    font-size: 22px;
    font-weight: 700;
    color: {C_TEXT_PRIMARY};
}}

QLabel#view_subtitle {{
    font-size: 12.5px;
    color: {C_TEXT_SECONDARY};
}}

QLabel#section_heading {{
    font-size: 13.5px;
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

/* Splitters */
QSplitter::handle {{
    background-color: {C_BORDER_LIGHT};
}}

QSplitter::handle:horizontal {{
    width: 1px;
}}

QSplitter::handle:vertical {{
    height: 1px;
}}

/* List Widgets */
QListWidget {{
    background-color: transparent;
    border: none;
    outline: none;
}}

QListWidget::item {{
    padding: 8px 12px;
    border-radius: 6px;
    margin-bottom: 2px;
    color: {C_TEXT_PRIMARY};
}}

QListWidget::item:hover {{
    background-color: {C_SURFACE_SECONDARY};
}}

QListWidget::item:selected {{
    background-color: {C_SURFACE_SECONDARY};
    color: {C_ACCENT};
    font-weight: 700;
}}

/* Table Views */
QTableView, QTableWidget {{
    background-color: {C_SURFACE_PRIMARY};
    alternate-background-color: #FAFAF8;
    border: 1px solid {C_BORDER};
    border-radius: 8px;
    gridline-color: transparent;
    font-family: {FONT_FAMILY_PRIMARY};
    font-size: 12px;
    color: {C_TEXT_PRIMARY};
    selection-background-color: {C_SURFACE_SECONDARY};
    selection-color: {C_ACCENT};
    outline: none;
}}


QTableView::item, QTableWidget::item {{
    padding: 7px 10px;
    border-bottom: 1px solid {C_BORDER_LIGHT};
}}

QTableView::item:selected, QTableWidget::item:selected {{
    background-color: {C_SURFACE_SECONDARY};
    color: {C_ACCENT};
    font-weight: 600;
}}

QHeaderView {{
    background-color: transparent;
    border: none;
}}

QHeaderView::section {{
    background-color: {C_SURFACE_SECONDARY};
    color: {C_TEXT_SECONDARY};
    font-weight: 700;
    font-size: 10px;
    letter-spacing: 0.6px;
    padding: 8px 10px;
    border: none;
    border-right: 1px solid {C_BORDER_LIGHT};
    border-bottom: 1px solid {C_BORDER};
    text-align: left;
}}

/* Scrollbars */
QScrollBar:vertical {{
    background-color: transparent;
    width: 6px;
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

QScrollBar:horizontal {{
    background-color: transparent;
    height: 6px;
    margin: 0px;
}}

QScrollBar::handle:horizontal {{
    background-color: {C_BORDER};
    border-radius: 3px;
    min-width: 25px;
}}

QScrollBar::handle:horizontal:hover {{
    background-color: {C_TEXT_MUTED};
}}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {{
    width: 0px;
}}

QScrollArea {{
    background-color: transparent;
    border: none;
}}

/* Tooltips */
QToolTip {{
    background-color: {C_TEXT_PRIMARY};
    color: #FFFFFF;
    border: 1px solid #333336;
    border-radius: 4px;
    padding: 5px 9px;
    font-size: 11px;
    font-family: {FONT_FAMILY_PRIMARY};
}}

/* Progress Bar */
QProgressBar {{
    background-color: {C_SURFACE_SECONDARY};
    border: 1px solid {C_BORDER};
    border-radius: 5px;
    text-align: center;
    color: {C_TEXT_PRIMARY};
    font-size: 11px;
    font-weight: 700;
    min-height: 22px;
    max-height: 22px;
}}

QProgressBar::chunk {{
    background-color: {C_ACCENT};
    border-radius: 4px;
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

