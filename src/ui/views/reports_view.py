"""Report Center View for ShieldScan.
One-click generation of professional Word (.docx) reports, college presentations (.pptx), and data exports.
"""

from __future__ import annotations
import os
import subprocess
from pathlib import Path
from typing import Optional
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QMessageBox, QGridLayout
)
from src.models.assessment import ScanResult
from src.reporting.docx_report import generate_docx_report
from src.reporting.exporter import export_json, export_csv_bundle
from src.presentation.pptx_deck import generate_presentation
from src.ui.tokens import (
    C_TEXT_PRIMARY, C_TEXT_SECONDARY, C_TEXT_MUTED, C_ACCENT,
    C_POSITIVE, C_BORDER
)

REPORTS_DIR = Path("C:/Users/tejas/.gemini/antigravity-ide/scratch/ShieldScan/reports/generated")
PRESENTATIONS_DIR = Path("C:/Users/tejas/.gemini/antigravity-ide/scratch/ShieldScan/presentations/generated")
EXPORTS_DIR = Path("C:/Users/tejas/.gemini/antigravity-ide/scratch/ShieldScan/exports")


class ReportsView(QWidget):
    """Report Center Workspace."""

    def __init__(self, parent: QWidget = None):
        super().__init__(parent)
        self._current_scan: Optional[ScanResult] = None

        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(20)

        # Header
        self._title = QLabel("Report & Presentation Center")
        self._title.setObjectName("view_title")
        self._subtitle = QLabel("Generate executive-ready Word assessment reports, college slide decks, and structured exports.")
        self._subtitle.setObjectName("view_subtitle")
        layout.addWidget(self._title)
        layout.addWidget(self._subtitle)

        # Selected Scan Context Card
        self._ctx_card = QFrame()
        self._ctx_card.setObjectName("card")
        ctx_lo = QVBoxLayout(self._ctx_card)
        ctx_lo.setContentsMargins(20, 16, 20, 16)
        ctx_lo.setSpacing(6)

        lbl_cx_title = QLabel("ACTIVE ASSESSMENT CONTEXT")
        lbl_cx_title.setStyleSheet(f"font-size: 10px; font-weight: 700; color: {C_TEXT_MUTED}; letter-spacing: 0.8px;")
        ctx_lo.addWidget(lbl_cx_title)

        self._lbl_scan_info = QLabel("No active scan selected. Run an assessment or select from history.")
        self._lbl_scan_info.setStyleSheet("font-size: 13px; font-weight: 600;")
        ctx_lo.addWidget(self._lbl_scan_info)

        layout.addWidget(self._ctx_card)

        # Action Cards Grid
        grid = QGridLayout()
        grid.setSpacing(16)

        # 1. Word Report Card
        card_docx = QFrame()
        card_docx.setObjectName("card")
        d_lo = QVBoxLayout(card_docx)
        d_lo.setContentsMargins(18, 16, 18, 16)
        d_lo.setSpacing(8)

        ld_title = QLabel("Executive Word Report (.docx)")
        ld_title.setStyleSheet("font-size: 14px; font-weight: 700;")
        ld_desc = QLabel("Generates a formal, engineering-grade Word assessment containing executive summary, methodology, host inventories, evidence logs, and recommendations.")
        ld_desc.setStyleSheet(f"font-size: 11px; color: {C_TEXT_SECONDARY};")
        ld_desc.setWordWrap(True)
        
        self._btn_gen_docx = QPushButton("Generate Assessment Report (.docx)")
        self._btn_gen_docx.setObjectName("btn_primary")
        self._btn_gen_docx.clicked.connect(self._generate_docx)

        d_lo.addWidget(ld_title)
        d_lo.addWidget(ld_desc)
        d_lo.addStretch()
        d_lo.addWidget(self._btn_gen_docx)
        grid.addWidget(card_docx, 0, 0)

        # 2. PowerPoint Slide Deck Card
        card_pptx = QFrame()
        card_pptx.setObjectName("card")
        p_lo = QVBoxLayout(card_pptx)
        p_lo.setContentsMargins(18, 16, 18, 16)
        p_lo.setSpacing(8)

        lp_title = QLabel("College Presentation Deck (.pptx)")
        lp_title.setStyleSheet("font-size: 14px; font-weight: 700;")
        lp_desc = QLabel("Generates a 7-slide academic presentation with system objectives, product architecture diagrams, real scan metrics, and project differentiation.")
        lp_desc.setStyleSheet(f"font-size: 11px; color: {C_TEXT_SECONDARY};")
        lp_desc.setWordWrap(True)

        self._btn_gen_pptx = QPushButton("Generate College Slides (.pptx)")
        self._btn_gen_pptx.clicked.connect(self._generate_pptx)

        p_lo.addWidget(lp_title)
        p_lo.addWidget(lp_desc)
        p_lo.addStretch()
        p_lo.addWidget(self._btn_gen_pptx)
        grid.addWidget(card_pptx, 0, 1)

        # 3. Structured JSON Export Card
        card_json = QFrame()
        card_json.setObjectName("card")
        j_lo = QVBoxLayout(card_json)
        j_lo.setContentsMargins(18, 16, 18, 16)
        j_lo.setSpacing(8)

        lj_title = QLabel("Structured JSON Export (.json)")
        lj_title.setStyleSheet("font-size: 14px; font-weight: 700;")
        lj_desc = QLabel("Exports the canonical single-source-of-truth assessment result with complete nested host records, raw evidence traces, and metadata.")
        lj_desc.setStyleSheet(f"font-size: 11px; color: {C_TEXT_SECONDARY};")
        lj_desc.setWordWrap(True)

        self._btn_gen_json = QPushButton("Export JSON Model")
        self._btn_gen_json.clicked.connect(self._export_json)

        j_lo.addWidget(lj_title)
        j_lo.addWidget(lj_desc)
        j_lo.addStretch()
        j_lo.addWidget(self._btn_gen_json)
        grid.addWidget(card_json, 1, 0)

        # 4. Tabular CSV Bundle Card
        card_csv = QFrame()
        card_csv.setObjectName("card")
        c_lo = QVBoxLayout(card_csv)
        c_lo.setContentsMargins(18, 16, 18, 16)
        c_lo.setSpacing(8)

        lc_title = QLabel("Tabular CSV Bundle (.csv)")
        lc_title.setStyleSheet("font-size: 14px; font-weight: 700;")
        lc_desc = QLabel("Generates discrete CSV files for Hosts, Ports/Services, and Findings suitable for spreadsheet review or SIEM ingestion.")
        lc_desc.setStyleSheet(f"font-size: 11px; color: {C_TEXT_SECONDARY};")
        lc_desc.setWordWrap(True)

        self._btn_gen_csv = QPushButton("Export CSV Suite")
        self._btn_gen_csv.clicked.connect(self._export_csv)

        c_lo.addWidget(lc_title)
        c_lo.addWidget(lc_desc)
        c_lo.addStretch()
        c_lo.addWidget(self._btn_gen_csv)
        grid.addWidget(card_csv, 1, 1)

        layout.addLayout(grid)

        # Output Log / Status
        self._lbl_status = QLabel("Ready to generate deliverables.")
        self._lbl_status.setStyleSheet(f"font-size: 11px; color: {C_TEXT_SECONDARY};")
        layout.addWidget(self._lbl_status)

        layout.addStretch()

    def load_scan(self, scan_result: ScanResult):
        self._current_scan = scan_result
        self._lbl_scan_info.setText(
            f"Target: {scan_result.target}  ·  Profile: {scan_result.profile_name}  ·  "
            f"{scan_result.stats.reachable_hosts} alive hosts, {scan_result.stats.open_ports} open ports, {scan_result.stats.total_findings} findings."
        )

    def _generate_docx(self):
        if not self._current_scan:
            QMessageBox.warning(self, "No Scan Active", "Please run or select an assessment first.")
            return

        out_path = REPORTS_DIR / f"ShieldScan_Assessment_{self._current_scan.id}.docx"
        try:
            generate_docx_report(self._current_scan, out_path)
            self._lbl_status.setText(f"✓ Word report generated: {out_path}")
            QMessageBox.information(self, "Report Generated", f"Executive assessment successfully generated:\n{out_path}")
        except Exception as e:
            QMessageBox.critical(self, "Generation Error", f"Failed to generate Word report:\n{e}")

    def _generate_pptx(self):
        if not self._current_scan:
            QMessageBox.warning(self, "No Scan Active", "Please run or select an assessment first.")
            return

        out_path = PRESENTATIONS_DIR / f"ShieldScan_Presentation_{self._current_scan.id}.pptx"
        try:
            generate_presentation(self._current_scan, out_path)
            self._lbl_status.setText(f"✓ PowerPoint presentation generated: {out_path}")
            QMessageBox.information(self, "Presentation Generated", f"Academic slide deck successfully generated:\n{out_path}")
        except Exception as e:
            QMessageBox.critical(self, "Generation Error", f"Failed to generate presentation:\n{e}")

    def _export_json(self):
        if not self._current_scan:
            QMessageBox.warning(self, "No Scan Active", "Please run or select an assessment first.")
            return

        out_path = EXPORTS_DIR / "json" / f"shieldscan_{self._current_scan.id}.json"
        try:
            export_json(self._current_scan, out_path)
            self._lbl_status.setText(f"✓ JSON model exported: {out_path}")
            QMessageBox.information(self, "JSON Exported", f"Canonical model exported to:\n{out_path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export JSON:\n{e}")

    def _export_csv(self):
        if not self._current_scan:
            QMessageBox.warning(self, "No Scan Active", "Please run or select an assessment first.")
            return

        out_dir = EXPORTS_DIR / "csv"
        try:
            paths = export_csv_bundle(self._current_scan, out_dir)
            self._lbl_status.setText(f"✓ CSV bundle exported to: {out_dir}")
            QMessageBox.information(self, "CSV Suite Exported", f"CSV files generated in:\n{out_dir}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export CSVs:\n{e}")
