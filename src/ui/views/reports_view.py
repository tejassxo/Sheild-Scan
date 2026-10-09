"""Report Center View for ShieldScan.
One-click generation of professional Word (.docx) reports, college presentations (.pptx), and direct folder access.
"""

from __future__ import annotations
import os
import sys
import subprocess
from pathlib import Path
from typing import Optional
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFrame, QMessageBox, QGridLayout, QScrollArea
)
from src.models.assessment import ScanResult
from src.reporting.docx_report import generate_docx_report
from src.reporting.exporter import export_json, export_csv_bundle
from src.presentation.pptx_deck import generate_presentation
from src.ui.tokens import (
    C_TEXT_PRIMARY, C_TEXT_SECONDARY, C_TEXT_MUTED, C_ACCENT,
    C_POSITIVE, C_BORDER, C_SURFACE_SECONDARY
)

BASE_DIR = Path(__file__).resolve().parents[3]
REPORTS_DIR = BASE_DIR / "reports"
PRESENTATIONS_DIR = BASE_DIR / "presentations"
EXPORTS_DIR = BASE_DIR / "exports"


def open_path_in_os(path: Path):
    """Opens a file or directory in the operating system's default viewer."""
    try:
        path = path.resolve()
        if sys.platform == "win32":
            os.startfile(str(path))
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])
        else:
            subprocess.Popen(["xdg-open", str(path)])
    except Exception as e:
        pass


class ReportsView(QWidget):
    """Report & Presentation Center Workspace."""

    def __init__(self, parent: QWidget = None):
        super().__init__(parent)
        self._current_scan: Optional[ScanResult] = None

        # Ensure directories exist
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        PRESENTATIONS_DIR.mkdir(parents=True, exist_ok=True)
        EXPORTS_DIR.mkdir(parents=True, exist_ok=True)

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(22)

        # Header
        self._title = QLabel("Report & Presentation Center")
        self._title.setObjectName("view_title")
        self._subtitle = QLabel("Generate executive Word assessment reports, college presentation decks, and structured exports.")
        self._subtitle.setObjectName("view_subtitle")
        layout.addWidget(self._title)
        layout.addWidget(self._subtitle)

        # Selected Scan Context Card
        self._ctx_card = QFrame()
        self._ctx_card.setObjectName("card")
        ctx_lo = QVBoxLayout(self._ctx_card)
        ctx_lo.setContentsMargins(22, 18, 22, 18)
        ctx_lo.setSpacing(6)

        lbl_cx_title = QLabel("ACTIVE ASSESSMENT CONTEXT FOR GENERATION")
        lbl_cx_title.setStyleSheet(f"font-size: 10.5px; font-weight: 700; color: {C_TEXT_MUTED}; letter-spacing: 0.8px;")
        ctx_lo.addWidget(lbl_cx_title)

        self._lbl_scan_info = QLabel("No active scan selected. Run an assessment or select from history.")
        self._lbl_scan_info.setStyleSheet("font-size: 13.5px; font-weight: 600; color: #1D1D1F;")
        ctx_lo.addWidget(self._lbl_scan_info)

        layout.addWidget(self._ctx_card)

        # Action Deliverables Grid
        grid = QGridLayout()
        grid.setSpacing(18)

        # 1. Word Report Card
        card_docx = QFrame()
        card_docx.setObjectName("card")
        card_docx.setMinimumHeight(150)
        d_lo = QVBoxLayout(card_docx)
        d_lo.setContentsMargins(22, 18, 22, 18)
        d_lo.setSpacing(10)

        ld_hdr = QHBoxLayout()
        ld_title = QLabel("📄  Executive Word Report (.docx)")
        ld_title.setStyleSheet("font-size: 15px; font-weight: 700;")
        ld_tag = QLabel("DEFENSE DOCUMENT")
        ld_tag.setStyleSheet(f"font-size: 9.5px; font-weight: 700; color: {C_ACCENT}; padding: 2px 6px; background: #FDF2F2; border-radius: 4px;")
        ld_hdr.addWidget(ld_title)
        ld_hdr.addStretch()
        ld_hdr.addWidget(ld_tag)
        d_lo.addLayout(ld_hdr)

        ld_desc = QLabel("Generates a formal, engineering-grade Word assessment containing executive summary, methodology, host inventories, evidence logs, and recommendations.")
        ld_desc.setStyleSheet(f"font-size: 12px; color: {C_TEXT_SECONDARY}; line-height: 1.3;")
        ld_desc.setWordWrap(True)
        d_lo.addWidget(ld_desc)
        d_lo.addStretch()

        d_btns = QHBoxLayout()
        self._btn_gen_docx = QPushButton("Generate Report (.docx)")
        self._btn_gen_docx.setObjectName("btn_primary")
        self._btn_gen_docx.setFixedHeight(34)
        self._btn_gen_docx.clicked.connect(self._generate_docx)
        d_btns.addWidget(self._btn_gen_docx, stretch=2)

        self._btn_open_docx_folder = QPushButton("Open Folder 📁")
        self._btn_open_docx_folder.setFixedHeight(34)
        self._btn_open_docx_folder.clicked.connect(lambda: open_path_in_os(REPORTS_DIR))
        d_btns.addWidget(self._btn_open_docx_folder, stretch=1)
        d_lo.addLayout(d_btns)

        grid.addWidget(card_docx, 0, 0)

        # 2. PowerPoint Slide Deck Card
        card_pptx = QFrame()
        card_pptx.setObjectName("card")
        card_pptx.setMinimumHeight(150)
        p_lo = QVBoxLayout(card_pptx)
        p_lo.setContentsMargins(22, 18, 22, 18)
        p_lo.setSpacing(10)

        lp_hdr = QHBoxLayout()
        lp_title = QLabel("📊  College Presentation Deck (.pptx)")
        lp_title.setStyleSheet("font-size: 15px; font-weight: 700;")
        lp_tag = QLabel("ACADEMIC SLIDES")
        lp_tag.setStyleSheet(f"font-size: 9.5px; font-weight: 700; color: {C_POSITIVE}; padding: 2px 6px; background: #F0F7F3; border-radius: 4px;")
        lp_hdr.addWidget(lp_title)
        lp_hdr.addStretch()
        lp_hdr.addWidget(lp_tag)
        p_lo.addLayout(lp_hdr)

        lp_desc = QLabel("Generates a 7-slide academic presentation with system objectives, product architecture diagrams, real scan metrics, and project differentiation.")
        lp_desc.setStyleSheet(f"font-size: 12px; color: {C_TEXT_SECONDARY}; line-height: 1.3;")
        lp_desc.setWordWrap(True)
        p_lo.addWidget(lp_desc)
        p_lo.addStretch()

        p_btns = QHBoxLayout()
        self._btn_gen_pptx = QPushButton("Generate Slides (.pptx)")
        self._btn_gen_pptx.setObjectName("btn_primary")
        self._btn_gen_pptx.setFixedHeight(34)
        self._btn_gen_pptx.clicked.connect(self._generate_pptx)
        p_btns.addWidget(self._btn_gen_pptx, stretch=2)

        self._btn_open_pptx_folder = QPushButton("Open Folder 📁")
        self._btn_open_pptx_folder.setFixedHeight(34)
        self._btn_open_pptx_folder.clicked.connect(lambda: open_path_in_os(PRESENTATIONS_DIR))
        p_btns.addWidget(self._btn_open_pptx_folder, stretch=1)
        p_lo.addLayout(p_btns)

        grid.addWidget(card_pptx, 0, 1)

        # 3. Structured JSON Export Card
        card_json = QFrame()
        card_json.setObjectName("card")
        card_json.setMinimumHeight(150)
        j_lo = QVBoxLayout(card_json)
        j_lo.setContentsMargins(22, 18, 22, 18)
        j_lo.setSpacing(10)

        lj_hdr = QHBoxLayout()
        lj_title = QLabel("{ }  Structured JSON Model (.json)")
        lj_title.setStyleSheet("font-size: 15px; font-weight: 700;")
        lj_hdr.addWidget(lj_title)
        j_lo.addLayout(lj_hdr)

        lj_desc = QLabel("Exports the canonical single-source-of-truth assessment result with complete nested host records, raw evidence traces, and metadata.")
        lj_desc.setStyleSheet(f"font-size: 12px; color: {C_TEXT_SECONDARY}; line-height: 1.3;")
        lj_desc.setWordWrap(True)
        j_lo.addWidget(lj_desc)
        j_lo.addStretch()

        j_btns = QHBoxLayout()
        self._btn_gen_json = QPushButton("Export JSON Model")
        self._btn_gen_json.setFixedHeight(34)
        self._btn_gen_json.clicked.connect(self._export_json)
        j_btns.addWidget(self._btn_gen_json, stretch=2)

        self._btn_open_json_folder = QPushButton("Open Folder 📁")
        self._btn_open_json_folder.setFixedHeight(34)
        self._btn_open_json_folder.clicked.connect(lambda: open_path_in_os(EXPORTS_DIR / "json"))
        j_btns.addWidget(self._btn_open_json_folder, stretch=1)
        j_lo.addLayout(j_btns)

        grid.addWidget(card_json, 1, 0)

        # 4. Tabular CSV Bundle Card
        card_csv = QFrame()
        card_csv.setObjectName("card")
        card_csv.setMinimumHeight(150)
        c_lo = QVBoxLayout(card_csv)
        c_lo.setContentsMargins(22, 18, 22, 18)
        c_lo.setSpacing(10)

        lc_hdr = QHBoxLayout()
        lc_title = QLabel("📊  Tabular CSV Bundle (.csv)")
        lc_title.setStyleSheet("font-size: 15px; font-weight: 700;")
        lc_hdr.addWidget(lc_title)
        c_lo.addLayout(lc_hdr)

        lc_desc = QLabel("Generates discrete CSV files for Hosts, Ports/Services, and Findings suitable for spreadsheet review or external SIEM ingestion.")
        lc_desc.setStyleSheet(f"font-size: 12px; color: {C_TEXT_SECONDARY}; line-height: 1.3;")
        lc_desc.setWordWrap(True)
        c_lo.addWidget(lc_desc)
        c_lo.addStretch()

        c_btns = QHBoxLayout()
        self._btn_gen_csv = QPushButton("Export CSV Suite")
        self._btn_gen_csv.setFixedHeight(34)
        self._btn_gen_csv.clicked.connect(self._export_csv)
        c_btns.addWidget(self._btn_gen_csv, stretch=2)

        self._btn_open_csv_folder = QPushButton("Open Folder 📁")
        self._btn_open_csv_folder.setFixedHeight(34)
        self._btn_open_csv_folder.clicked.connect(lambda: open_path_in_os(EXPORTS_DIR / "csv"))
        c_btns.addWidget(self._btn_open_csv_folder, stretch=1)
        c_lo.addLayout(c_btns)

        grid.addWidget(card_csv, 1, 1)

        layout.addLayout(grid)

        # Direct File Directory Quick Access Card
        card_access = QFrame()
        card_access.setObjectName("card")
        acc_lo = QVBoxLayout(card_access)
        acc_lo.setContentsMargins(22, 18, 22, 18)
        acc_lo.setSpacing(10)

        lbl_acc_title = QLabel("LOCAL DELIVERABLE DIRECTORIES")
        lbl_acc_title.setStyleSheet(f"font-size: 10.5px; font-weight: 700; color: {C_TEXT_MUTED}; letter-spacing: 0.8px;")
        acc_lo.addWidget(lbl_acc_title)

        lbl_acc_sub = QLabel(
            "All generated presentations and Word reports are saved directly to your local project folders "
            "for immediate offline editing in Microsoft PowerPoint and Word:"
        )
        lbl_acc_sub.setStyleSheet(f"font-size: 12px; color: {C_TEXT_PRIMARY};")
        acc_lo.addWidget(lbl_acc_sub)

        dir_btns = QHBoxLayout()
        dir_btns.setSpacing(12)

        btn_d1 = QPushButton("📂  Presentations Folder (PPTX)")
        btn_d1.setFixedHeight(36)
        btn_d1.clicked.connect(lambda: open_path_in_os(PRESENTATIONS_DIR))
        dir_btns.addWidget(btn_d1)

        btn_d2 = QPushButton("📂  Reports Folder (DOCX)")
        btn_d2.setFixedHeight(36)
        btn_d2.clicked.connect(lambda: open_path_in_os(REPORTS_DIR))
        dir_btns.addWidget(btn_d2)

        btn_d3 = QPushButton("📂  Exports Folder (JSON & CSV)")
        btn_d3.setFixedHeight(36)
        btn_d3.clicked.connect(lambda: open_path_in_os(EXPORTS_DIR))
        dir_btns.addWidget(btn_d3)

        acc_lo.addLayout(dir_btns)
        layout.addWidget(card_access)

        # Output Log / Status
        self._lbl_status = QLabel("Ready to generate deliverables.")
        self._lbl_status.setStyleSheet(f"font-size: 12px; font-weight: 600; color: {C_TEXT_SECONDARY};")
        layout.addWidget(self._lbl_status)

        scroll.setWidget(content)
        root_lo = QVBoxLayout(self)
        root_lo.setContentsMargins(0, 0, 0, 0)
        root_lo.addWidget(scroll)

    def load_scan(self, scan_result: ScanResult):
        self._current_scan = scan_result
        self._lbl_scan_info.setText(
            f"Target: {scan_result.target}   ·   Profile: {scan_result.profile_name}   ·   "
            f"{scan_result.stats.reachable_hosts} alive hosts, {scan_result.stats.open_ports} open ports, {scan_result.stats.total_findings} findings."
        )

    def _generate_docx(self):
        if not self._current_scan:
            QMessageBox.warning(self, "No Scan Active", "Please run or select an assessment first.")
            return

        out_path = REPORTS_DIR / f"ShieldScan_Assessment_{self._current_scan.id}.docx"
        try:
            generate_docx_report(self._current_scan, out_path)
            self._lbl_status.setText(f"✓ Word report generated: {out_path.name}")
            msg = QMessageBox(self)
            msg.setWindowTitle("Report Generated")
            msg.setText(f"Executive assessment report generated successfully:\n\n{out_path}")
            btn_open = msg.addButton("Open Document", QMessageBox.ActionRole)
            msg.addButton("OK", QMessageBox.AcceptRole)
            msg.exec_()
            if msg.clickedButton() == btn_open:
                open_path_in_os(out_path)
        except Exception as e:
            QMessageBox.critical(self, "Generation Error", f"Failed to generate Word report:\n{e}")

    def _generate_pptx(self):
        if not self._current_scan:
            QMessageBox.warning(self, "No Scan Active", "Please run or select an assessment first.")
            return

        out_path = PRESENTATIONS_DIR / f"ShieldScan_Presentation_{self._current_scan.id}.pptx"
        try:
            generate_presentation(self._current_scan, out_path)
            self._lbl_status.setText(f"✓ PowerPoint presentation generated: {out_path.name}")
            msg = QMessageBox(self)
            msg.setWindowTitle("Presentation Generated")
            msg.setText(f"Academic presentation deck generated successfully:\n\n{out_path}")
            btn_open = msg.addButton("Open Slide Deck", QMessageBox.ActionRole)
            msg.addButton("OK", QMessageBox.AcceptRole)
            msg.exec_()
            if msg.clickedButton() == btn_open:
                open_path_in_os(out_path)
        except Exception as e:
            QMessageBox.critical(self, "Generation Error", f"Failed to generate presentation:\n{e}")

    def _export_json(self):
        if not self._current_scan:
            QMessageBox.warning(self, "No Scan Active", "Please run or select an assessment first.")
            return

        out_dir = EXPORTS_DIR / "json"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_path = out_dir / f"shieldscan_{self._current_scan.id}.json"
        try:
            export_json(self._current_scan, out_path)
            self._lbl_status.setText(f"✓ JSON model exported: {out_path.name}")
            QMessageBox.information(self, "JSON Exported", f"Canonical JSON model exported to:\n{out_path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export JSON:\n{e}")

    def _export_csv(self):
        if not self._current_scan:
            QMessageBox.warning(self, "No Scan Active", "Please run or select an assessment first.")
            return

        out_dir = EXPORTS_DIR / "csv"
        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            paths = export_csv_bundle(self._current_scan, out_dir)
            self._lbl_status.setText(f"✓ CSV bundle exported to: {out_dir}")
            QMessageBox.information(self, "CSV Suite Exported", f"CSV files generated in:\n{out_dir}")
        except Exception as e:
            QMessageBox.critical(self, "Export Error", f"Failed to export CSVs:\n{e}")
