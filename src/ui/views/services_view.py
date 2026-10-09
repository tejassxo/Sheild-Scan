"""Services Inventory View for ShieldScan.
Clean searchable and filterable table of all detected network services across assessed hosts.
"""

from __future__ import annotations
from typing import Optional
from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTableWidget,
    QTableWidgetItem, QHeaderView, QFrame
)
from src.models.assessment import ScanResult
from src.ui.components.search_bar import SearchBar
from src.ui.components.detail_drawer import DetailDrawer
from src.ui.tokens import (
    C_TEXT_PRIMARY, C_TEXT_SECONDARY, C_TEXT_MUTED, C_ACCENT,
    FONT_FAMILY_MONO
)


class ServicesView(QWidget):
    """Network Service Inventory View."""

    def __init__(self, parent: QWidget = None):
        super().__init__(parent)
        self._current_scan: Optional[ScanResult] = None
        self._all_services = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(32, 28, 32, 28)
        layout.setSpacing(18)

        # Header
        self._title = QLabel("Service Inventory")
        self._title.setObjectName("view_title")
        self._subtitle = QLabel("Auditable registry of all listening network services, banners, and detected products.")
        self._subtitle.setObjectName("view_subtitle")
        layout.addWidget(self._title)
        layout.addWidget(self._subtitle)

        # Search Bar
        self._search = SearchBar("Filter by service, product, version, host, or port…")
        self._search.text_changed.connect(self._filter_table)
        layout.addWidget(self._search)

        # Services Table
        self._table = QTableWidget(0, 6)
        self._table.setHorizontalHeaderLabels(["Host", "Port / Proto", "Service", "Product", "Version", "Confidence"])
        hdr = self._table.horizontalHeader()
        hdr.setSectionResizeMode(0, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(3, QHeaderView.Stretch)
        hdr.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        hdr.setSectionResizeMode(5, QHeaderView.ResizeToContents)
        hdr.setHighlightSections(False)
        self._table.verticalHeader().setVisible(False)
        self._table.verticalHeader().setDefaultSectionSize(34)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setSelectionMode(QTableWidget.SingleSelection)
        self._table.setAlternatingRowColors(True)
        self._table.cellDoubleClicked.connect(self._on_service_double_clicked)
        layout.addWidget(self._table, stretch=1)

    def load_scan(self, scan_result: ScanResult):
        self._current_scan = scan_result
        self._all_services = scan_result.all_services
        self._populate_table(self._all_services)

    def _populate_table(self, services_list):
        self._table.setRowCount(0)
        for s in services_list:
            row = self._table.rowCount()
            self._table.insertRow(row)

            it_host = QTableWidgetItem(s["host"])
            it_port = QTableWidgetItem(f"{s['port']}/{s['protocol']}")
            it_name = QTableWidgetItem(s["name"])
            prod_str = s["product"] or "—"
            it_prod = QTableWidgetItem(prod_str)
            ver_str = s["version"] or "—"
            it_ver = QTableWidgetItem(ver_str)
            it_conf = QTableWidgetItem(s["confidence"])

            it_host.setToolTip(f"Host: {s['host']}")
            it_port.setToolTip(f"Port: {s['port']}/{s['protocol']}")
            it_name.setToolTip(f"Service: {s['name']}")
            it_prod.setToolTip(f"Product: {prod_str}\nBanner: {s.get('banner', '')}")
            it_ver.setToolTip(f"Version: {ver_str}")
            it_conf.setToolTip(f"Identification Confidence: {s['confidence']}")

            self._table.setItem(row, 0, it_host)
            self._table.setItem(row, 1, it_port)
            self._table.setItem(row, 2, it_name)
            self._table.setItem(row, 3, it_prod)
            self._table.setItem(row, 4, it_ver)
            self._table.setItem(row, 5, it_conf)


    def _filter_table(self, query: str):
        q = query.strip().lower()
        if not q:
            self._populate_table(self._all_services)
            return

        filtered = [
            s for s in self._all_services
            if q in s["host"].lower()
            or q in str(s["port"])
            or q in s["name"].lower()
            or q in s["product"].lower()
            or q in s["version"].lower()
            or q in s["banner"].lower()
        ]
        self._populate_table(filtered)

    def _on_service_double_clicked(self, row: int, col: int):
        q = self._search.text().strip().lower()
        active_list = [
            s for s in self._all_services
            if not q or (
                q in s["host"].lower() or q in str(s["port"]) or q in s["name"].lower()
                or q in s["product"].lower() or q in s["version"].lower() or q in s["banner"].lower()
            )
        ]
        if row < len(active_list):
            s = active_list[row]
            drawer = DetailDrawer(f"Service Details — {s['name']} on {s['host']}:{s['port']}", self)
            drawer.add_meta_row("Host", s["host"])
            drawer.add_meta_row("Port / Proto", f"{s['port']}/{s['protocol']}")
            drawer.add_meta_row("Service Name", s["name"])
            drawer.add_meta_row("Product", s["product"] or "—")
            drawer.add_meta_row("Version", s["version"] or "—")
            drawer.add_meta_row("Confidence", s["confidence"])
            drawer.add_meta_row("Latency", f"{s['latency_ms']:.2f} ms")
            drawer.set_evidence_text(f"Raw Banner Observation:\n{s['banner'] or 'Standard handshake confirmed connection.'}")
            drawer.exec_()
