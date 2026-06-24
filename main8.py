"""
ShieldScan Professional  v4.1  — Refined Network Auditor
=========================================================
- Fixed Top 1000 port list logic
- Fixed label text blending with transparent backgrounds
- Strict domain validation (auto-removes http/https)
- Silent 5k port recheck completely hidden from UI math
- Removed Interface dropdown
- Fixed stylesheet override blocking green text for open ports
"""

from __future__ import annotations

import asyncio
import os
import platform
import random
import socket
import sys
import threading
import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

# ── Scapy (optional) ──────────────────────────────────────────────────────
try:
    os.environ.setdefault("SCAPY_OUTPUT_LOCK", "1")
    from scapy.all import (
        IP, TCP, UDP, ICMP, ARP, Ether,
        sr1, srp, send, conf as scapy_conf, get_if_list,
    )
    scapy_conf.verb = 0
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

# ── PyQt5 ─────────────────────────────────────────────────────────────────
from PyQt5.QtCore import (
    QAbstractTableModel, QModelIndex, QSortFilterProxyModel,
    Qt, QThread, QTimer, pyqtSignal, QRect, QSize, QEvent, QCoreApplication,
)
from PyQt5.QtGui import (
    QBrush, QColor, QFont, QPalette, QPainter, QLinearGradient,
    QPixmap, QIcon, QFontMetrics,
)
from PyQt5.QtWidgets import (
    QAbstractItemView, QApplication, QComboBox, QFileDialog,
    QFrame, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow,
    QMessageBox, QProgressBar, QPushButton, QSizePolicy,
    QStatusBar, QTabWidget, QTableView, QVBoxLayout, QWidget,
    QSpinBox, QCheckBox, QDialog, QScrollArea, QSplashScreen,
)

# ═════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ═════════════════════════════════════════════════════════════════════════════

APP_NAME    = "ShieldScan Professional"
APP_VERSION = "4.1"

ASYNC_SEM_LIMIT   = 800
ASYNC_BATCH       = 400
SCAPY_BATCH       = 256
SCAPY_WORKERS_DEF = 300
SCAPY_WORKERS_MIN = 40
THROTTLE_TRIGGER  = 50
EMIT_INTERVAL_MS  = 50
BANNER_TIMEOUT    = 0.20

FULL_SCAN_THRESHOLD = 65000
RECHECK_TIMEOUT     = 0.20
RECHECK_PORTS_IMPORTANT = sorted(set(
    list(range(1, 5001)) +
    [p for p in list(range(1, 1001)) if p > 5000]
))

# ── Premium Color Palette ─────────────────────────────────────────────────
C_PRIMARY       = "#0F1419"
C_SECONDARY     = "#1A1F2E"
C_TERTIARY      = "#252D3D"
C_ACCENT        = "#00D97E"
C_ACCENT_HOVER  = "#00F59F"
C_ACCENT_DIM    = "#00A856"
C_DANGER        = "#FF5555"
C_WARNING       = "#FFD700"
C_INFO          = "#4A9EFF"
C_TEXT_PRIMARY  = "#F0F0F5"
C_TEXT_SECONDARY= "#A0A0B0"
C_TEXT_MUTED    = "#6A6A7A"
C_BORDER        = "#35404F"
C_BORDER_LIGHT  = "#45505F"

# ═════════════════════════════════════════════════════════════════════════════
# PORT LISTS & CONFIGS
# ═════════════════════════════════════════════════════════════════════════════

TOP_100 = [
    21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,
    5900,8080,20,69,79,81,88,102,119,123,137,138,161,179,194,389,427,444,
    465,500,514,515,540,548,554,587,631,636,646,873,990,992,994,1080,1194,
    1433,1521,2000,2049,2082,2083,2086,2087,2095,2096,2181,2222,2375,2376,
    3000,3001,3128,3268,3269,4444,4848,5000,5432,5555,5672,5985,5986,6379,
    6443,7001,7070,7443,8000,8008,8009,8443,8888,9090,9200,9443,10000,
    27017,27018,28017,50000
]

# Fixed Top 1000 logic
TOP_1000 = sorted(set(TOP_100 + list(range(1, 1001))))

SERVICE_MAP = {
    20:"FTP-Data",21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
    67:"DHCP",69:"TFTP",79:"Finger",80:"HTTP",88:"Kerberos",110:"POP3",
    111:"RPC",119:"NNTP",123:"NTP",135:"MSRPC",137:"NetBIOS-NS",
    138:"NetBIOS-DG",139:"NetBIOS",143:"IMAP",161:"SNMP",179:"BGP",
    194:"IRC",389:"LDAP",443:"HTTPS",445:"SMB",465:"SMTPS",514:"Syslog",
    515:"LPD",548:"AFP",554:"RTSP",587:"SMTP-Sub",631:"IPP",636:"LDAPS",
    873:"Rsync",993:"IMAPS",995:"POP3S",1080:"SOCKS",1194:"OpenVPN",
    1433:"MSSQL",1521:"Oracle",1701:"L2TP",1723:"PPTP",1900:"UPnP",
    2049:"NFS",2082:"cPanel",2083:"cPanel-SSL",2181:"Zookeeper",
    2222:"SSH-Alt",2375:"Docker",2376:"Docker-SSL",3000:"Node.js",
    3001:"Node.js",3128:"Squid",3306:"MySQL",3389:"RDP",4444:"Meterpreter",
    4500:"IPSec-NAT",4848:"GlassFish",5000:"UPnP/Flask",5353:"mDNS",
    5432:"PostgreSQL",5555:"ADB",5672:"AMQP",5900:"VNC",5985:"WinRM-HTTP",
    5986:"WinRM-HTTPS",6379:"Redis",6443:"Kubernetes",7001:"WebLogic",
    8080:"HTTP-Alt",8443:"HTTPS-Alt",8888:"Jupyter",9090:"Prometheus",
    9200:"Elasticsearch",9443:"VMware",10000:"Webmin",17185:"VxWorks-WDBRPC",
    27017:"MongoDB",27018:"MongoDB",28017:"MongoDB-Web",50000:"SAP",
}

BANNER_PROBES = {
    80:  b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    443: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8080:b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8443:b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8888:b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    21:  b"", 22: b"", 25: b"", 110: b"", 143: b"", 3306: b"",
}

UDP_PAYLOADS = {
    53:   b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
    123:  b"\x1b" + b"\x00" * 47,
    161:  b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
    1900: b"M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n",
    5353: b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05local\x00\x00\xff\x00\x01",
}

# ═════════════════════════════════════════════════════════════════════════════
# ENUMS & DATA CLASSES
# ═════════════════════════════════════════════════════════════════════════════

class PortStatus(Enum):
    OPEN     = "OPEN"
    CLOSED   = "CLOSED"
    FILTERED = "FILTERED"

class ScanType(Enum):
    TCP_CONNECT = "TCP Connect"
    STEALTH_SYN = "Stealth SYN"
    UDP_SWEEP   = "UDP Sweep"
    XMAS_SCAN   = "Xmas Scan"

@dataclass
class ScanResult:
    port:     int
    status:   PortStatus
    service:  str
    banner:   str
    latency:  float

@dataclass
class ScanProfile:
    label:   str
    ports:   List[int]
    timeout: float

PROFILES = [
    ScanProfile("Flash — Top 100", TOP_100, 0.20),
    ScanProfile("Quick — Top 1000", TOP_1000, 0.30),
    ScanProfile("Full — 1–65535", list(range(1, 65536)), 0.40),
]

# ═════════════════════════════════════════════════════════════════════════════
# PREMIUM STYLESHEET
# ═════════════════════════════════════════════════════════════════════════════

PREMIUM_STYLESHEET = f"""
/* ─────────────────────────────────────────────────────────────────────── */
/* Global                                                                  */
/* ─────────────────────────────────────────────────────────────────────── */
* {{
    font-family: 'Segoe UI', 'SF Pro Display', system-ui, sans-serif;
    outline: none;
}}
QMainWindow, QWidget {{
    background-color: {C_PRIMARY};
    color: {C_TEXT_PRIMARY};
}}

/* ─────────────────────────────────────────────────────────────────────── */
/* Panels & Frames                                                         */
/* ─────────────────────────────────────────────────────────────────────── */
QFrame#sidebar {{
    background-color: {C_SECONDARY};
    border: 1px solid {C_BORDER};
    border-radius: 12px;
    padding: 0px;
}}
QFrame#metrics_panel {{
    background-color: {C_SECONDARY};
    border: 1px solid {C_BORDER};
    border-radius: 10px;
}}
QFrame#metric_card {{
    background-color: {C_TERTIARY};
    border: 1px solid {C_BORDER_LIGHT};
    border-radius: 8px;
}}

/* ─────────────────────────────────────────────────────────────────────── */
/* Labels & Typography                                                     */
/* ─────────────────────────────────────────────────────────────────────── */
QLabel#app_title {{
    color: {C_ACCENT};
    font-size: 18px;
    font-weight: 700;
    letter-spacing: 1.5px;
    background: transparent;
}}
QLabel#app_subtitle {{
    color: {C_TEXT_SECONDARY};
    font-size: 10px;
    letter-spacing: 2px;
    font-weight: 500;
    background: transparent;
}}
QLabel#section_label {{
    color: {C_TEXT_MUTED};
    font-size: 10px;
    font-weight: 700;
    letter-spacing: 1.2px;
    text-transform: uppercase;
    background: transparent;
}}
QLabel#status_label {{
    color: {C_TEXT_SECONDARY};
    font-size: 11px;
    font-family: 'Cascadia Code', 'Consolas', monospace;
    background: transparent;
}}

/* ─────────────────────────────────────────────────────────────────────── */
/* Input Fields                                                            */
/* ─────────────────────────────────────────────────────────────────────── */
QLineEdit, QComboBox {{
    background-color: {C_PRIMARY};
    border: 1px solid {C_BORDER_LIGHT};
    border-radius: 6px;
    padding: 8px 12px;
    color: {C_TEXT_PRIMARY};
    font-size: 12px;
    selection-background-color: {C_ACCENT_DIM};
}}
QLineEdit:focus, QComboBox:focus {{
    border: 2px solid {C_ACCENT};
    background-color: {C_SECONDARY};
}}
QComboBox::drop-down {{
    border: none;
    padding-right: 8px;
}}
QComboBox QAbstractItemView {{
    background-color: {C_SECONDARY};
    border: 1px solid {C_BORDER};
    selection-background-color: {C_ACCENT_DIM};
    color: {C_TEXT_PRIMARY};
    padding: 2px;
}}

/* ─────────────────────────────────────────────────────────────────────── */
/* Buttons                                                                 */
/* ─────────────────────────────────────────────────────────────────────── */
QPushButton {{
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: 600;
    font-size: 11px;
    border: 1px solid transparent;
    color: {C_TEXT_PRIMARY};
}}
QPushButton#btn_launch {{
    background-color: {C_ACCENT};
    color: {C_PRIMARY};
    letter-spacing: 0.5px;
    font-weight: 700;
}}
QPushButton#btn_launch:hover {{
    background-color: {C_ACCENT_HOVER};
}}
QPushButton#btn_launch:pressed {{
    background-color: {C_ACCENT_DIM};
}}
QPushButton#btn_launch:disabled {{
    background-color: {C_BORDER};
    color: {C_TEXT_MUTED};
}}

QPushButton#btn_pause {{
    background-color: transparent;
    color: {C_WARNING};
    border: 1px solid {C_WARNING};
}}
QPushButton#btn_pause:hover {{
    background-color: rgba(255, 215, 0, 0.1);
}}
QPushButton#btn_pause:disabled {{
    color: {C_TEXT_MUTED};
    border-color: {C_BORDER};
}}

QPushButton#btn_stop {{
    background-color: transparent;
    color: {C_DANGER};
    border: 1px solid {C_DANGER};
}}
QPushButton#btn_stop:hover {{
    background-color: rgba(255, 85, 85, 0.1);
}}
QPushButton#btn_stop:disabled {{
    color: {C_TEXT_MUTED};
    border-color: {C_BORDER};
}}

QPushButton#btn_clear, QPushButton#btn_export, QPushButton#btn_load_more {{
    background-color: transparent;
    color: {C_TEXT_SECONDARY};
    border: 1px solid {C_BORDER};
}}
QPushButton#btn_clear:hover, QPushButton#btn_export:hover, QPushButton#btn_load_more:hover {{
    color: {C_TEXT_PRIMARY};
    border-color: {C_ACCENT};
    background-color: rgba(0, 217, 126, 0.05);
}}

/* ─────────────────────────────────────────────────────────────────────── */
/* Tabs                                                                    */
/* ─────────────────────────────────────────────────────────────────────── */
QTabWidget::pane {{
    border: 1px solid {C_BORDER};
    border-radius: 8px;
    background-color: transparent;
    top: -1px;
}}
QTabBar::tab {{
    background-color: transparent;
    color: {C_TEXT_SECONDARY};
    padding: 8px 20px;
    font-weight: 600;
    font-size: 11px;
    letter-spacing: 0.5px;
    border: 1px solid transparent;
    border-bottom: 2px solid transparent;
    margin-right: 2px;
}}
QTabBar::tab:selected {{
    color: {C_ACCENT};
    border-bottom: 2px solid {C_ACCENT};
}}
QTabBar::tab:hover:!selected {{
    color: {C_TEXT_PRIMARY};
    background-color: rgba(255, 255, 255, 0.02);
}}

/* ─────────────────────────────────────────────────────────────────────── */
/* Tables                                                                  */
/* ─────────────────────────────────────────────────────────────────────── */
QTableView {{
    background-color: {C_SECONDARY};
    alternate-background-color: {C_TERTIARY};
    border: 1px solid {C_BORDER};
    border-radius: 8px;
    gridline-color: transparent;
    selection-background-color: rgba(0, 217, 126, 0.15);
    selection-color: {C_ACCENT};
    font-family: 'Cascadia Code', 'Consolas', monospace;
    font-size: 11px;
    color: {C_TEXT_PRIMARY};
}}
QTableView::item {{
    padding: 5px 8px;
    border-bottom: 1px solid rgba(53, 64, 79, 0.3);
    /* Removed text color override so ForegroundRole controls Green open ports */
}}
QTableView::item:selected {{
    background-color: rgba(0, 217, 126, 0.15);
    color: {C_ACCENT};
}}
QHeaderView::section {{
    background-color: {C_PRIMARY};
    color: {C_TEXT_SECONDARY};
    font-weight: 700;
    font-size: 10px;
    letter-spacing: 0.5px;
    padding: 8px 8px;
    border: none;
    border-right: 1px solid {C_BORDER};
    border-bottom: 2px solid {C_ACCENT_DIM};
}}

/* ─────────────────────────────────────────────────────────────────────── */
/* Scrollbar                                                               */
/* ─────────────────────────────────────────────────────────────────────── */
QScrollBar:vertical {{
    background-color: transparent;
    width: 8px;
    margin: 0px;
}}
QScrollBar::handle:vertical {{
    background-color: {C_BORDER_LIGHT};
    border-radius: 4px;
    min-height: 20px;
}}
QScrollBar::handle:vertical:hover {{
    background-color: {C_TEXT_MUTED};
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}

/* ─────────────────────────────────────────────────────────────────────── */
/* Progress Bar                                                            */
/* ─────────────────────────────────────────────────────────────────────── */
QProgressBar {{
    background-color: {C_PRIMARY};
    border: 1px solid {C_BORDER};
    border-radius: 4px;
    text-align: center;
    color: {C_TEXT_MUTED};
    font-size: 10px;
    height: 16px;
    font-family: 'Cascadia Code', monospace;
}}
QProgressBar::chunk {{
    background-color: qlineargradient(
        x1:0, y1:0, x2:1, y2:0,
        stop:0 {C_ACCENT_DIM},
        stop:1 {C_ACCENT}
    );
    border-radius: 3px;
}}

/* ─────────────────────────────────────────────────────────────────────── */
/* Status Bar                                                              */
/* ─────────────────────────────────────────────────────────────────────── */
QStatusBar {{
    background-color: {C_PRIMARY};
    color: {C_TEXT_SECONDARY};
    font-size: 10px;
    border-top: 1px solid {C_BORDER};
    padding: 3px 8px;
}}

/* ─────────────────────────────────────────────────────────────────────── */
/* Tooltip                                                                 */
/* ─────────────────────────────────────────────────────────────────────── */
QToolTip {{
    background-color: {C_SECONDARY};
    color: {C_TEXT_PRIMARY};
    border: 1px solid {C_BORDER};
    border-radius: 5px;
    padding: 6px 10px;
    font-size: 11px;
}}
"""

# ═════════════════════════════════════════════════════════════════════════════
# ADAPTIVE THROTTLE
# ═════════════════════════════════════════════════════════════════════════════

class AdaptiveThrottle:
    def __init__(self, initial: int = SCAPY_WORKERS_DEF, minimum: int = SCAPY_WORKERS_MIN, trigger: int = THROTTLE_TRIGGER):
        self._workers          = initial
        self._minimum          = minimum
        self._trigger          = trigger
        self._consecutive      = 0
        self._total_reductions = 0
        self._lock             = threading.Lock()

    def record(self, is_timeout: bool) -> bool:
        with self._lock:
            if is_timeout:
                self._consecutive += 1
                if self._consecutive >= self._trigger and self._workers > self._minimum:
                    self._workers = max(self._minimum, self._workers // 2)
                    self._consecutive = 0
                    self._total_reductions += 1
                    return True
            else:
                self._consecutive = 0
        return False

    @property
    def workers(self) -> int:
        with self._lock:
            return self._workers

    @property
    def reductions(self) -> int:
        with self._lock:
            return self._total_reductions

# ═════════════════════════════════════════════════════════════════════════════
# ASYNC & SCAPY ENGINES
# ═════════════════════════════════════════════════════════════════════════════

async def _grab_banner(host: str, port: int) -> str:
    probe = BANNER_PROBES.get(port)
    if probe is None: return ""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=BANNER_TIMEOUT)
        try:
            if probe:
                writer.write(probe)
                await writer.drain()
            raw = await asyncio.wait_for(reader.read(256), timeout=BANNER_TIMEOUT)
            text = raw.decode("utf-8", errors="replace").strip()
            return " │ ".join(ln.strip() for ln in text.splitlines() if ln.strip())[:120]
        finally:
            writer.close()
            try: await asyncio.wait_for(writer.wait_closed(), timeout=0.1)
            except Exception: pass
    except Exception:
        return ""

async def _async_probe(host: str, port: int, timeout: float, sem: asyncio.Semaphore) -> ScanResult:
    async with sem:
        t0 = time.perf_counter()
        status: PortStatus
        banner = ""
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            status = PortStatus.OPEN
            writer.close()
            try: await asyncio.wait_for(writer.wait_closed(), timeout=0.1)
            except Exception: pass
            banner = await _grab_banner(host, port)
        except asyncio.TimeoutError:
            status = PortStatus.FILTERED
        except ConnectionRefusedError:
            status = PortStatus.CLOSED
        except OSError:
            status = PortStatus.FILTERED

        return ScanResult(port, status, SERVICE_MAP.get(port, ""), banner, round((time.perf_counter() - t0) * 1000.0, 2))

async def run_async_engine(
    host: str, ports: List[int], timeout: float,
    on_result: Callable[[ScanResult], None],
    on_progress: Callable[[int, int], None],
    stop_event: asyncio.Event,
    pause_fn: Callable[[], bool],
) -> None:
    sem = asyncio.Semaphore(ASYNC_SEM_LIMIT)
    total = len(ports)
    done = 0

    for start in range(0, total, ASYNC_BATCH):
        if stop_event.is_set(): break
        while pause_fn():
            await asyncio.sleep(0.05)
            if stop_event.is_set(): return

        batch = ports[start : start + ASYNC_BATCH]
        tasks = [asyncio.create_task(_async_probe(host, p, timeout, sem)) for p in batch]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            if isinstance(r, ScanResult):
                on_result(r)
        done += len(batch)
        on_progress(done, total)
        await asyncio.sleep(0.005)

    on_progress(total, total)

def _scapy_syn_probe(host: str, port: int, timeout: float, throttle: AdaptiveThrottle, iface: str) -> ScanResult:
    t0 = time.perf_counter()
    try:
        pkt = IP(dst=host) / TCP(sport=random.randint(1024, 65000), dport=port, flags="S", seq=random.randint(0, 0xFFFFFFFF))
        resp = sr1(pkt, timeout=timeout, verbose=0, iface=iface or None)
        lat = round((time.perf_counter() - t0) * 1000.0, 2)

        if resp is None:
            throttle.record(is_timeout=True)
            return ScanResult(port, PortStatus.FILTERED, SERVICE_MAP.get(port,""), "", lat)

        throttle.record(is_timeout=False)
        if resp.haslayer(TCP):
            flags = resp[TCP].flags
            if flags & 0x12 == 0x12:
                send(IP(dst=host)/TCP(sport=resp[TCP].dport, dport=port, flags="R", seq=resp[TCP].ack), verbose=0, iface=iface or None)
                return ScanResult(port, PortStatus.OPEN, SERVICE_MAP.get(port,""), "", lat)
            if flags & 0x04:
                return ScanResult(port, PortStatus.CLOSED, SERVICE_MAP.get(port,""), "", lat)
        if resp.haslayer(ICMP) and resp[ICMP].type == 3 and resp[ICMP].code in (1, 2, 3, 9, 10, 13):
            return ScanResult(port, PortStatus.FILTERED, SERVICE_MAP.get(port,""), "", lat)
    except Exception:
        lat = round((time.perf_counter() - t0) * 1000.0, 2)
    return ScanResult(port, PortStatus.FILTERED, SERVICE_MAP.get(port,""), "", lat)

def _scapy_xmas_probe(host: str, port: int, timeout: float, throttle: AdaptiveThrottle, iface: str) -> ScanResult:
    t0 = time.perf_counter()
    try:
        pkt = IP(dst=host) / TCP(sport=random.randint(1024, 65000), dport=port, flags="FPU")
        resp = sr1(pkt, timeout=timeout, verbose=0, iface=iface or None)
        lat = round((time.perf_counter() - t0) * 1000.0, 2)

        if resp is None:
            throttle.record(is_timeout=True)
            return ScanResult(port, PortStatus.OPEN, SERVICE_MAP.get(port,""), "Xmas: no RST", lat)

        throttle.record(is_timeout=False)
        if resp.haslayer(TCP) and resp[TCP].flags & 0x04:
            return ScanResult(port, PortStatus.CLOSED, SERVICE_MAP.get(port,""), "", lat)
        if resp.haslayer(ICMP) and resp[ICMP].type == 3:
            return ScanResult(port, PortStatus.FILTERED, SERVICE_MAP.get(port,""), "", lat)
    except Exception:
        lat = round((time.perf_counter() - t0) * 1000.0, 2)
    return ScanResult(port, PortStatus.FILTERED, SERVICE_MAP.get(port,""), "", lat)

def _scapy_udp_probe(host: str, port: int, timeout: float, throttle: AdaptiveThrottle, iface: str) -> ScanResult:
    t0 = time.perf_counter()
    try:
        payload = UDP_PAYLOADS.get(port, b"\x00")
        pkt = IP(dst=host) / UDP(dport=port) / payload
        resp = sr1(pkt, timeout=timeout, verbose=0, iface=iface or None)
        lat = round((time.perf_counter() - t0) * 1000.0, 2)

        if resp is None:
            throttle.record(is_timeout=True)
            return ScanResult(port, PortStatus.OPEN, SERVICE_MAP.get(port,""), "UDP: open|filtered", lat)

        throttle.record(is_timeout=False)
        if resp.haslayer(UDP):
            return ScanResult(port, PortStatus.OPEN, SERVICE_MAP.get(port,""), "", lat)
        if resp.haslayer(ICMP) and resp[ICMP].type == 3:
            if resp[ICMP].code == 3: return ScanResult(port, PortStatus.CLOSED, SERVICE_MAP.get(port,""), "", lat)
            return ScanResult(port, PortStatus.FILTERED, SERVICE_MAP.get(port,""), "", lat)
    except Exception:
        lat = round((time.perf_counter() - t0) * 1000.0, 2)
    return ScanResult(port, PortStatus.FILTERED, SERVICE_MAP.get(port,""), "", lat)

def run_scapy_engine(
    host: str, ports: List[int], timeout: float, scan_type: ScanType,
    iface: str, throttle: AdaptiveThrottle,
    on_result: Callable[[ScanResult], None],
    on_progress: Callable[[int, int], None],
    on_throttle: Callable[[int], None],
    stop_event: threading.Event,
    pause_fn: Callable[[], bool],
) -> None:
    _PROBE = {
        ScanType.STEALTH_SYN: _scapy_syn_probe,
        ScanType.XMAS_SCAN:   _scapy_xmas_probe,
        ScanType.UDP_SWEEP:   _scapy_udp_probe,
    }[scan_type]
    total = len(ports)
    done = 0

    for start in range(0, total, SCAPY_BATCH):
        if stop_event.is_set(): break
        while pause_fn():
            time.sleep(0.05)
            if stop_event.is_set(): return

        batch = ports[start : start + SCAPY_BATCH]
        with ThreadPoolExecutor(max_workers=throttle.workers) as pool:
            fmap = {pool.submit(_PROBE, host, p, timeout, throttle, iface): p for p in batch}
            for fut in as_completed(fmap):
                if stop_event.is_set():
                    pool.shutdown(wait=False, cancel_futures=True)
                    break
                try:
                    result = fut.result()
                    on_result(result)
                    if throttle.record(result.status == PortStatus.FILTERED):
                        on_throttle(throttle.workers)
                except Exception: pass
        done += len(batch)
        on_progress(done, total)
    on_progress(total, total)

# ═════════════════════════════════════════════════════════════════════════════
# TABLE MODELS
# ═════════════════════════════════════════════════════════════════════════════

_COLS = ["Port", "Status", "Service", "Latency ms", "Banner"]
_C_PORT=0; _C_STAT=1; _C_SVC=2; _C_LAT=3; _C_BAN=4

_COLOR_OPEN = {
    "fg": QColor(C_ACCENT),
    "bg": QColor(0, 217, 126, 20),
}
_COLOR_FILTERED = {
    "fg": QColor(C_WARNING),
    "bg": QColor(255, 215, 0, 15),
}
_COLOR_CLOSED = {
    "fg": QColor(C_TEXT_SECONDARY),
    "bg": None,
}

class PortTableModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._rows: List[ScanResult] = []
        self._mono = QFont("Cascadia Code,Consolas,monospace", 10)
        self._bold = QFont("Cascadia Code,Consolas,monospace", 10)
        self._bold.setBold(True)

    def rowCount(self, parent=QModelIndex()) -> int: 
        return len(self._rows)
    
    def columnCount(self, parent=QModelIndex()) -> int: 
        return len(_COLS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return _COLS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole) -> Any:
        if not index.isValid(): 
            return None
        r, col = self._rows[index.row()], index.column()
        
        if role == Qt.DisplayRole:
            if col == _C_PORT: return str(r.port)
            if col == _C_STAT: return r.status.value
            if col == _C_SVC:  return r.service or "—"
            if col == _C_LAT:  return f"{r.latency:.1f}"
            if col == _C_BAN:  return r.banner or "—"
        
        if role == Qt.ForegroundRole:
            color_map = {
                PortStatus.OPEN:     _COLOR_OPEN["fg"],
                PortStatus.FILTERED: _COLOR_FILTERED["fg"],
                PortStatus.CLOSED:   _COLOR_CLOSED["fg"],
            }
            return QBrush(color_map.get(r.status, QColor(C_TEXT_SECONDARY)))
        
        if role == Qt.BackgroundRole:
            color_map = {
                PortStatus.OPEN:     _COLOR_OPEN["bg"],
                PortStatus.FILTERED: _COLOR_FILTERED["bg"],
                PortStatus.CLOSED:   _COLOR_CLOSED["bg"],
            }
            bg = color_map.get(r.status)
            if bg: return QBrush(bg)
            return QBrush(QColor(C_TERTIARY if index.row() % 2 == 0 else C_SECONDARY))
        
        if role == Qt.TextAlignmentRole:
            return Qt.AlignVCenter | (Qt.AlignRight if col in (_C_PORT, _C_LAT) else Qt.AlignLeft)
        
        if role == Qt.FontRole:
            return self._bold if (col == _C_STAT and r.status == PortStatus.OPEN) else self._mono
        
        if role == Qt.ToolTipRole and col == _C_BAN and r.banner:
            return r.banner
        
        return None

    def append_batch(self, batch: List[ScanResult]) -> None:
        if not batch: 
            return
        self.beginInsertRows(QModelIndex(), len(self._rows), len(self._rows) + len(batch) - 1)
        self._rows.extend(batch)
        self.endInsertRows()

    def update_result(self, r: ScanResult) -> None:
        for i, row in enumerate(self._rows):
            if row.port == r.port:
                self._rows[i] = r
                tl = self.index(i, 0)
                br = self.index(i, len(_COLS) - 1)
                self.dataChanged.emit(tl, br, [Qt.DisplayRole, Qt.ForegroundRole, Qt.BackgroundRole, Qt.FontRole])
                return

    def clear(self) -> None:
        self.beginResetModel()
        self._rows.clear()
        self.endResetModel()

    def all_results(self) -> List[ScanResult]: 
        return list(self._rows)

    def stats(self) -> Tuple[int, int, int]:
        o = f = c = 0
        for r in self._rows:
            if   r.status is PortStatus.OPEN:     o += 1
            elif r.status is PortStatus.FILTERED: f += 1
            else:                                 c += 1
        return o, f, c

    def results_by_status(self, status: PortStatus) -> List[ScanResult]:
        return [r for r in self._rows if r.status == status]

# ═════════════════════════════════════════════════════════════════════════════
# SCAN WORKER (WITH SILENT 5K RECHECK HIDDEN FROM UI)
# ═════════════════════════════════════════════════════════════════════════════

class ScanWorker(QThread):
    sig_progress      = pyqtSignal(int, int)
    sig_throttle      = pyqtSignal(int)
    sig_finished      = pyqtSignal(float)
    sig_error         = pyqtSignal(str)
    sig_status        = pyqtSignal(str)
    sig_result_update = pyqtSignal(object)

    def __init__(self, host: str, profile: ScanProfile, scan_type: ScanType, iface: str, parent=None):
        super().__init__(parent)
        self._host        = host
        self._profile     = profile
        self._scan_type   = scan_type
        self._iface       = iface
        self.throttle     = AdaptiveThrottle()
        self._buffer: Deque[ScanResult]        = deque()
        self._update_buffer: Deque[ScanResult] = deque()
        self._all_results: Dict[int, ScanResult] = {}
        self._lock              = threading.Lock()
        self._paused            = False
        self._stop_event_th     = threading.Event()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._async_stop: Optional[asyncio.Event]       = None
        self._is_full_scan      = len(profile.ports) >= FULL_SCAN_THRESHOLD

    def stop(self) -> None:
        self._paused = False
        self._stop_event_th.set()
        if self._async_stop and self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._async_stop.set)

    def pause(self)  -> None: self._paused = True
    def resume(self) -> None: self._paused = False

    def drain_results(self) -> List[ScanResult]:
        with self._lock:
            items = list(self._buffer)
            self._buffer.clear()
        return items

    def drain_updates(self) -> List[ScanResult]:
        with self._lock:
            items = list(self._update_buffer)
            self._update_buffer.clear()
        return items

    def run(self) -> None:
        t_start = time.perf_counter()
        try:
            if self._scan_type == ScanType.TCP_CONNECT:
                self._run_async(t_start)
            else:
                self._run_scapy(t_start)
        except Exception as exc:
            self.sig_error.emit(f"{type(exc).__name__}: {exc}")

    def _run_async(self, t_start: float) -> None:
        policy = getattr(asyncio, "WindowsSelectorEventLoopPolicy", None)
        if policy: asyncio.set_event_loop_policy(policy())
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        try:
            loop.run_until_complete(self._async_main(t_start))
        finally:
            loop.close()
            self._loop = None

    async def _async_main(self, t_start: float) -> None:
        self._async_stop = asyncio.Event()
        try:
            info = await asyncio.get_event_loop().getaddrinfo(
                self._host, None, type=socket.SOCK_STREAM
            )
            resolved = info[0][4][0]
        except Exception:
            resolved = self._host

        total_ports = len(self._profile.ports)
        
        def progress_wrapper_main(done: int, total: int):
            if self._is_full_scan:
                mapped_done = int(done * 0.8)
            else:
                mapped_done = done
            self.sig_progress.emit(mapped_done, total_ports)
        
        await run_async_engine(
            host       = resolved,
            ports      = self._profile.ports,
            timeout    = self._profile.timeout,
            on_result  = self._push_result,
            on_progress= progress_wrapper_main,
            stop_event = self._async_stop,
            pause_fn   = lambda: self._paused,
        )

        if self._is_full_scan and not self._async_stop.is_set():
            await self._async_recheck(resolved)

        self.sig_finished.emit(time.perf_counter() - t_start)

    async def _async_recheck(self, host: str) -> None:
        candidates = [
            p for p in RECHECK_PORTS_IMPORTANT
            if self._all_results.get(p) is not None
            and self._all_results[p].status == PortStatus.FILTERED
        ]
        
        total_ports = len(self._profile.ports)
        if not candidates:
            self.sig_progress.emit(total_ports, total_ports)
            return

        sem = asyncio.Semaphore(ASYNC_SEM_LIMIT)
        total_recheck = len(candidates)
        recheck_done = 0
        
        for start in range(0, len(candidates), ASYNC_BATCH):
            if self._async_stop.is_set():
                break
            while self._paused:
                await asyncio.sleep(0.05)
                if self._async_stop.is_set(): return

            batch = candidates[start : start + ASYNC_BATCH]
            tasks = [
                asyncio.create_task(_async_probe(host, p, RECHECK_TIMEOUT, sem))
                for p in batch
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            for r in results:
                if isinstance(r, ScanResult):
                    old = self._all_results.get(r.port)
                    if old and old.status == PortStatus.FILTERED and r.status != PortStatus.FILTERED:
                        self._all_results[r.port] = r
                        self._push_update(r)

            recheck_done += len(batch)
            progress = int(total_ports * 0.8) + int((recheck_done / total_recheck) * total_ports * 0.2) if total_recheck > 0 else int(total_ports * 0.8)
            self.sig_progress.emit(progress, total_ports)
            await asyncio.sleep(0.005)

        self.sig_progress.emit(total_ports, total_ports)

    def _run_scapy(self, t_start: float) -> None:
        if not SCAPY_OK:
            self.sig_error.emit(
                "Scapy is not installed.\nRun: pip install scapy\n"
                "Also install Npcap on Windows."
            )
            return
        try:
            host = socket.gethostbyname(self._host)
        except Exception:
            host = self._host

        total_ports = len(self._profile.ports)
        
        def progress_wrapper_main(done: int, total: int):
            if self._is_full_scan:
                mapped_done = int(done * 0.8)
            else:
                mapped_done = done
            self.sig_progress.emit(mapped_done, total_ports)
        
        run_scapy_engine(
            host       = host,
            ports      = self._profile.ports,
            timeout    = self._profile.timeout,
            scan_type  = self._scan_type,
            iface      = self._iface,
            throttle   = self.throttle,
            on_result  = self._push_result,
            on_progress= progress_wrapper_main,
            on_throttle= self.sig_throttle.emit,
            stop_event = self._stop_event_th,
            pause_fn   = lambda: self._paused,
        )

        if self._is_full_scan and not self._stop_event_th.is_set():
            self._scapy_recheck(host)

        self.sig_finished.emit(time.perf_counter() - t_start)

    def _scapy_recheck(self, host: str) -> None:
        _PROBE = {
            ScanType.STEALTH_SYN: _scapy_syn_probe,
            ScanType.XMAS_SCAN:   _scapy_xmas_probe,
            ScanType.UDP_SWEEP:   _scapy_udp_probe,
        }.get(self._scan_type)
        
        total_ports = len(self._profile.ports)
        
        if _PROBE is None:
            self.sig_progress.emit(total_ports, total_ports)
            return

        candidates = [
            p for p in RECHECK_PORTS_IMPORTANT
            if self._all_results.get(p) is not None
            and self._all_results[p].status == PortStatus.FILTERED
        ]
        if not candidates:
            self.sig_progress.emit(total_ports, total_ports)
            return

        recheck_throttle = AdaptiveThrottle(
            initial=min(self.throttle.workers, 100),
            minimum=SCAPY_WORKERS_MIN,
        )
        total_recheck = len(candidates)
        recheck_done = 0
        base_progress = int(total_ports * 0.8)
        
        with ThreadPoolExecutor(max_workers=recheck_throttle.workers) as pool:
            fmap = {
                pool.submit(_PROBE, host, p, RECHECK_TIMEOUT, recheck_throttle, self._iface): p
                for p in candidates
            }
            for fut in as_completed(fmap):
                if self._stop_event_th.is_set():
                    pool.shutdown(wait=False, cancel_futures=True)
                    break
                while self._paused:
                    time.sleep(0.05)
                    if self._stop_event_th.is_set(): return
                try:
                    r = fut.result()
                    old = self._all_results.get(r.port)
                    if old and old.status == PortStatus.FILTERED and r.status != PortStatus.FILTERED:
                        self._all_results[r.port] = r
                        self._push_update(r)
                except Exception:
                    pass
                recheck_done += 1
                progress = base_progress + int((recheck_done / total_recheck) * total_ports * 0.2) if total_recheck > 0 else base_progress
                self.sig_progress.emit(progress, total_ports)

        self.sig_progress.emit(total_ports, total_ports)

    def _push_result(self, r: ScanResult) -> None:
        with self._lock:
            self._buffer.append(r)
            self._all_results[r.port] = r

    def _push_update(self, r: ScanResult) -> None:
        with self._lock:
            self._update_buffer.append(r)


# ═════════════════════════════════════════════════════════════════════════════
# METRIC CARD WIDGET
# ═════════════════════════════════════════════════════════════════════════════

class MetricCard(QFrame):
    def __init__(self, label: str, value: str = "0", parent=None):
        super().__init__(parent)
        self.setObjectName("metric_card")
        self.setMinimumHeight(85)
        
        self._label_text = label
        self._value_text = value
        self._value_color = QColor(C_ACCENT)
        self._label_color = QColor(C_TEXT_MUTED)

    def set_value(self, value: str, color: str = C_ACCENT):
        self._value_text = value
        self._value_color = QColor(color)
        self.update() 

    def set_label(self, label: str):
        self._label_text = label
        self.update() 

    def paintEvent(self, event):
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        painter.setRenderHint(QPainter.TextAntialiasing)

        rect = self.contentsRect()
        margin = 14

        val_font = QFont("Segoe UI", 24, QFont.Bold)
        painter.setFont(val_font)
        painter.setPen(self._value_color)
        val_rect = QRect(rect.left() + margin, rect.top() + margin, rect.width() - margin*2, 35)
        painter.drawText(val_rect, Qt.AlignLeft | Qt.AlignTop, self._value_text)

        lbl_font = QFont("Segoe UI", 10, QFont.DemiBold)
        painter.setFont(lbl_font)
        painter.setPen(self._label_color)
        lbl_rect = QRect(rect.left() + margin, rect.bottom() - margin - 20, rect.width() - margin*2, 20)
        painter.drawText(lbl_rect, Qt.AlignLeft | Qt.AlignBottom, self._label_text.upper())

        painter.end()


# ═════════════════════════════════════════════════════════════════════════════
# SCAN TAB
# ═════════════════════════════════════════════════════════════════════════════

class ScanTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._worker: Optional[ScanWorker] = None
        self._model = PortTableModel(self)
        self._paused     = False
        self._t_start    = 0.0
        self._ports_total = 0
        self._speed_done  = 0
        self._speed_time  = 0.0
        
        self._closed_display_start = 0
        self._closed_chunk_size = 100
        self._filtered_display_start = 0
        self._filtered_chunk_size = 100

        self._flush_timer   = QTimer(self)
        self._flush_timer.setInterval(EMIT_INTERVAL_MS)
        self._flush_timer.timeout.connect(self._flush)

        self._elapsed_timer = QTimer(self)
        self._elapsed_timer.setInterval(100)
        self._elapsed_timer.timeout.connect(self._tick_elapsed)

        self._build()
        self._set_scan_state(scanning=False)

    def _build(self):
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(10)
        root.addWidget(self._build_sidebar(), stretch=0)
        root.addLayout(self._build_center(), stretch=1)

    def _build_sidebar(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("sidebar")
        frame.setFixedWidth(250)
        lo = QVBoxLayout(frame)
        lo.setContentsMargins(16, 18, 16, 18)
        lo.setSpacing(10)

        title = QLabel("SHIELDSCAN")
        title.setObjectName("app_title")
        
        sub = QLabel("PROFESSIONAL")
        sub.setObjectName("app_subtitle")
        
        lo.addWidget(title)
        lo.addWidget(sub)
        lo.addSpacing(8)
        lo.addWidget(self._hline())
        lo.addSpacing(8)

        lo.addWidget(self._section_label("Profile"))
        self._combo_profile = QComboBox()
        for p in PROFILES:
            self._combo_profile.addItem(p.label)
        self._combo_profile.currentIndexChanged.connect(self._on_profile_change)
        lo.addWidget(self._combo_profile)

        lo.addWidget(self._section_label("Scan Type"))
        self._combo_type = QComboBox()
        for st in ScanType:
            self._combo_type.addItem(st.value, st)
        if not SCAPY_OK:
            for i in range(1, self._combo_type.count()):
                self._combo_type.model().item(i).setEnabled(False)
        lo.addWidget(self._combo_type)

        lo.addWidget(self._section_label("Target"))
        self._inp_target = QLineEdit()
        self._inp_target.setPlaceholderText("hostname or IP")
        self._inp_target.setMinimumHeight(36)
        lo.addWidget(self._inp_target)

        # Removed the unused "Interface" dropdown here completely

        lo.addSpacing(8)
        lo.addWidget(self._hline())
        lo.addSpacing(8)

        self._btn_launch = QPushButton("▶  LAUNCH SCAN")
        self._btn_launch.setObjectName("btn_launch")
        self._btn_launch.setMinimumHeight(40)
        self._btn_launch.clicked.connect(self._start)
        lo.addWidget(self._btn_launch)

        self._btn_pause = QPushButton("⏸  PAUSE")
        self._btn_pause.setObjectName("btn_pause")
        self._btn_pause.setMinimumHeight(36)
        self._btn_pause.clicked.connect(self._toggle_pause)
        lo.addWidget(self._btn_pause)

        self._btn_stop = QPushButton("■  STOP")
        self._btn_stop.setObjectName("btn_stop")
        self._btn_stop.setMinimumHeight(36)
        self._btn_stop.clicked.connect(self._stop)
        lo.addWidget(self._btn_stop)

        lo.addSpacing(6)
        lo.addWidget(self._hline())
        lo.addSpacing(6)

        self._btn_clear = QPushButton("✕  CLEAR")
        self._btn_clear.setObjectName("btn_clear")
        self._btn_clear.setMinimumHeight(32)
        self._btn_clear.clicked.connect(self._clear)
        lo.addWidget(self._btn_clear)

        self._btn_export = QPushButton("↓  DOWNLOAD REPORT")
        self._btn_export.setObjectName("btn_export")
        self._btn_export.setMinimumHeight(32)
        self._btn_export.clicked.connect(self._export)
        lo.addWidget(self._btn_export)

        lo.addStretch()
        
        self._lbl_portcount = QLabel("0 ports")
        self._lbl_portcount.setObjectName("status_label")
        self._lbl_portcount.setAlignment(Qt.AlignCenter)
        lo.addWidget(self._lbl_portcount)

        self._on_profile_change(0)
        return frame

    def _build_center(self) -> QVBoxLayout:
        lo = QVBoxLayout()
        lo.setSpacing(10)

        metrics_frame = QFrame()
        metrics_frame.setObjectName("metrics_panel")
        metrics_lo = QHBoxLayout(metrics_frame)
        metrics_lo.setContentsMargins(14, 12, 14, 12)
        metrics_lo.setSpacing(10)

        self._metric_scanned = MetricCard("Scanned", "0")
        self._metric_open = MetricCard("Open", "0")
        self._metric_closed = MetricCard("Closed", "0")
        self._metric_filtered = MetricCard("Filtered", "0")
        self._metric_speed = MetricCard("Ports/sec", "—")
        self._metric_elapsed = MetricCard("Elapsed", "00:00.0")

        for m in (self._metric_scanned, self._metric_open, self._metric_closed,
                  self._metric_filtered, self._metric_speed, self._metric_elapsed):
            metrics_lo.addWidget(m)

        lo.addWidget(metrics_frame)

        self._tabs = QTabWidget()

        self._table_live = QTableView()
        self._table_live.setModel(self._model)
        self._table_live.setAlternatingRowColors(True)
        self._table_live.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table_live.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table_live.setShowGrid(False)
        self._table_live.verticalHeader().setVisible(False)
        self._table_live.verticalHeader().setDefaultSectionSize(28)
        hdr = self._table_live.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.Interactive)
        hdr.setStretchLastSection(True)
        self._table_live.setColumnWidth(0, 70)
        self._table_live.setColumnWidth(1, 90)
        self._table_live.setColumnWidth(2, 120)
        self._table_live.setColumnWidth(3, 80)
        self._tabs.addTab(self._table_live, "Live Scan")

        self._table_open = QTableView()
        self._model_open = PortTableModel(self)
        self._table_open.setModel(self._model_open)
        self._table_open.setAlternatingRowColors(True)
        self._table_open.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._table_open.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._table_open.setShowGrid(False)
        self._table_open.verticalHeader().setVisible(False)
        self._table_open.verticalHeader().setDefaultSectionSize(28)
        hdr = self._table_open.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.Interactive)
        hdr.setStretchLastSection(True)
        self._table_open.setColumnWidth(0, 70)
        self._table_open.setColumnWidth(1, 90)
        self._table_open.setColumnWidth(2, 120)
        self._table_open.setColumnWidth(3, 80)
        self._tabs.addTab(self._table_open, "Open Ports")

        closed_widget = self._build_loadmore_tab("closed")
        self._tabs.addTab(closed_widget, "Closed Ports")

        filtered_widget = self._build_loadmore_tab("filtered")
        self._tabs.addTab(filtered_widget, "Filtered Ports")

        lo.addWidget(self._tabs, stretch=1)

        prog_container = QWidget()
        prog_lo = QHBoxLayout(prog_container)
        prog_lo.setContentsMargins(0, 0, 0, 0)
        prog_lo.setSpacing(10)

        prog_lbl = QLabel("SCAN")
        prog_lbl.setObjectName("section_label")
        prog_lbl.setFixedWidth(40)

        self._prog_scan = QProgressBar()
        self._prog_scan.setRange(0, 100)
        self._prog_scan.setValue(0)
        self._prog_scan.setFormat("Idle")
        self._prog_scan.setMinimumHeight(16)

        prog_lo.addWidget(prog_lbl)
        prog_lo.addWidget(self._prog_scan)
        lo.addWidget(prog_container)

        return lo

    def _build_loadmore_tab(self, port_type: str) -> QWidget:
        widget = QWidget()
        lo = QVBoxLayout(widget)
        lo.setContentsMargins(0, 0, 0, 0)
        lo.setSpacing(8)

        table = QTableView()
        if port_type == "closed":
            self._table_closed = table
            self._model_closed = PortTableModel(self)
            table.setModel(self._model_closed)
        else:  
            self._table_filtered = table
            self._model_filtered = PortTableModel(self)
            table.setModel(self._model_filtered)

        table.setAlternatingRowColors(True)
        table.setSelectionBehavior(QAbstractItemView.SelectRows)
        table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        table.setShowGrid(False)
        table.verticalHeader().setVisible(False)
        table.verticalHeader().setDefaultSectionSize(28)
        hdr = table.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.Interactive)
        hdr.setStretchLastSection(True)
        table.setColumnWidth(0, 70)
        table.setColumnWidth(1, 90)
        table.setColumnWidth(2, 120)
        table.setColumnWidth(3, 80)

        lo.addWidget(table, stretch=1)

        btn_container = QWidget()
        btn_lo = QHBoxLayout(btn_container)
        btn_lo.setContentsMargins(0, 0, 0, 0)
        btn_lo.setSpacing(10)

        btn_load = QPushButton("Load More")
        btn_load.setObjectName("btn_load_more")
        btn_load.setMinimumHeight(32)

        lbl_info = QLabel("0 / 0 ports shown")
        lbl_info.setObjectName("status_label")

        btn_lo.addWidget(btn_load)
        btn_lo.addStretch()
        btn_lo.addWidget(lbl_info)

        lo.addWidget(btn_container)

        if port_type == "closed":
            self._btn_load_closed = btn_load
            self._lbl_closed_info = lbl_info
            btn_load.clicked.connect(lambda: self._load_more("closed"))
        else:
            self._btn_load_filtered = btn_load
            self._lbl_filtered_info = lbl_info
            btn_load.clicked.connect(lambda: self._load_more("filtered"))

        return widget

    def _hline(self) -> QFrame:
        f = QFrame()
        f.setFrameShape(QFrame.HLine)
        f.setFrameShadow(QFrame.Plain)
        f.setLineWidth(1)
        f.setStyleSheet(f"color: {C_BORDER};")
        return f

    def _section_label(self, text: str) -> QLabel:
        lbl = QLabel(text.upper())
        lbl.setObjectName("section_label")
        return lbl

    def _on_profile_change(self, idx: int):
        p = PROFILES[idx]
        self._lbl_portcount.setText(
            f"{len(p.ports):,} ports\ntimeout {p.timeout:.2f}s"
        )

    def _validate_domain(self, host: str) -> bool:
        """Strictly validate domain and gracefully handle bad inputs."""
        host = host.strip()
        
        # Auto-remove http:// or https:// if pasted by accident
        if host.startswith("http://") or host.startswith("https://"):
            host = host.split("://")[1].split("/")[0]
            self._inp_target.setText(host)

        if not host or " " in host:
            return False

        try:
            # Force actual DNS check
            socket.gethostbyname(host)
            return True
        except Exception: 
            return False

    def _start(self):
        host = self._inp_target.text().strip()
        
        if host.startswith("http://") or host.startswith("https://"):
            host = host.split("://")[1].split("/")[0]
            self._inp_target.setText(host)

        if not host:
            QMessageBox.warning(self, "No Target", "Enter a hostname or IP address.")
            return

        # Validate domain strictly to avoid background crashes
        if not self._validate_domain(host):
            QMessageBox.critical(self, "Invalid Domain", f"Cannot resolve '{host}'.\nPlease check the domain name or IP address.")
            return

        scan_type = self._combo_type.currentData()
        if scan_type != ScanType.TCP_CONNECT and not SCAPY_OK:
            QMessageBox.critical(self, "Error", "Scapy required for raw socket scans.")
            return

        profile = PROFILES[self._combo_profile.currentIndex()]
        iface   = "" # Hardcoded empty since dropdown was removed

        self._ports_total = len(profile.ports)
        self._t_start     = time.perf_counter()
        self._speed_done  = 0
        self._speed_time  = self._t_start
        self._paused      = False
        
        self._closed_display_start = 0
        self._filtered_display_start = 0

        self._model.clear()
        self._model_open.clear()
        self._model_closed.clear()
        self._model_filtered.clear()

        for m in (self._metric_scanned, self._metric_open, self._metric_closed, self._metric_filtered):
            m.set_value("0")
        self._metric_speed.set_value("—")
        self._metric_elapsed.set_value("00:00.0")

        self._prog_scan.setRange(0, 100)
        self._prog_scan.setValue(0)
        self._prog_scan.setFormat("Scanning…  0 %")
        self._lbl_closed_info.setText("0 / 0 ports shown")
        self._lbl_filtered_info.setText("0 / 0 ports shown")

        self._set_scan_state(scanning=True)

        self._worker = ScanWorker(host, profile, scan_type, iface, parent=self)
        self._worker.sig_progress.connect(self._on_progress)
        self._worker.sig_finished.connect(self._on_finished)
        self._worker.sig_error.connect(self._on_error)
        self._worker.sig_status.connect(self._set_status)
        self._worker.start()

        self._flush_timer.start()
        self._elapsed_timer.start()

    def _toggle_pause(self):
        if not self._worker: return
        self._paused = not self._paused
        if self._paused:
            self._worker.pause()
            self._btn_pause.setText("▶  RESUME")
            self._elapsed_timer.stop()
        else:
            self._worker.resume()
            self._btn_pause.setText("⏸  PAUSE")
            self._elapsed_timer.start()

    def _stop(self):
        if self._worker:
            self._worker.stop()
            self._set_status("Stopping…")

    def _clear(self):
        self._model.clear()
        self._model_open.clear()
        self._model_closed.clear()
        self._model_filtered.clear()
        for m in (self._metric_scanned, self._metric_open, self._metric_closed, self._metric_filtered):
            m.set_value("0")
        self._prog_scan.setValue(0)
        self._prog_scan.setFormat("Idle")
        self._lbl_closed_info.setText("0 / 0 ports shown")
        self._lbl_filtered_info.setText("0 / 0 ports shown")
        self._set_status("Cleared.")

    def _export(self):
        rows = self._model.all_results()
        if not rows:
            QMessageBox.warning(self, "No Results", "No scan results to export.")
            return
        
        path, _ = QFileDialog.getSaveFileName(self, "Save Scan Report", "", "Text Files (*.txt)")
        if not path:
            return
        
        try:
            if not path.lower().endswith(".txt"):
                path += ".txt"
            
            o, f, c = self._model.stats()
            elapsed_sec = time.perf_counter() - self._t_start if self._t_start > 0 else 0
            speed = len(rows) / elapsed_sec if elapsed_sec > 0 else 0
            
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("=" * 80 + "\n")
                fh.write(f"{APP_NAME}  v{APP_VERSION}\n")
                fh.write("Network Port Scan Report\n")
                fh.write("=" * 80 + "\n\n")
                
                fh.write("SCAN DETAILS\n")
                fh.write("-" * 80 + "\n")
                fh.write(f"Target Host: {self._inp_target.text().strip()}\n")
                fh.write(f"Scan Profile: {PROFILES[self._combo_profile.currentIndex()].label}\n")
                fh.write(f"Scan Type: {self._combo_type.currentText()}\n")
                fh.write(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                fh.write("SCAN STATISTICS\n")
                fh.write("-" * 80 + "\n")
                fh.write(f"Total Ports Scanned: {self._ports_total:,}\n")
                fh.write(f"Open Ports: {o}\n")
                fh.write(f"Closed Ports: {c}\n")
                fh.write(f"Filtered Ports: {f}\n")
                fh.write(f"Elapsed Time: {format_time(elapsed_sec)}\n")
                fh.write(f"Scan Speed: {speed:.2f} ports/sec\n\n")
                
                open_ports = [r for r in rows if r.status == PortStatus.OPEN]
                if open_ports:
                    fh.write("OPEN PORTS DETAILS\n")
                    fh.write("-" * 80 + "\n")
                    fh.write(f"{'Port':<8} {'Service':<20} {'Latency (ms)':<15} {'Banner':<35}\n")
                    fh.write("-" * 80 + "\n")
                    for r in open_ports:
                        banner_str = (r.banner[:33] + "...") if r.banner and len(r.banner) > 33 else (r.banner or "—")
                        fh.write(f"{r.port:<8} {r.service:<20} {r.latency:<15.2f} {banner_str:<35}\n")
                    fh.write("\n")
                
                closed_ports = [r for r in rows if r.status == PortStatus.CLOSED]
                if closed_ports:
                    fh.write("CLOSED PORTS\n")
                    fh.write("-" * 80 + "\n")
                    fh.write(f"Total Closed Ports: {len(closed_ports)}\n")
                    fh.write("Ports: ")
                    fh.write(", ".join(str(r.port) for r in closed_ports))
                    fh.write("\n\n")
                
                filtered_ports = [r for r in rows if r.status == PortStatus.FILTERED]
                if filtered_ports:
                    fh.write("FILTERED PORTS\n")
                    fh.write("-" * 80 + "\n")
                    fh.write(f"Total Filtered Ports: {len(filtered_ports)}\n")
                    fh.write("(No response - likely firewall or host-based filtering)\n")
                    fh.write("Ports: ")
                    fh.write(", ".join(str(r.port) for r in filtered_ports[:100]))
                    if len(filtered_ports) > 100:
                        fh.write(f" ... and {len(filtered_ports) - 100} more")
                    fh.write("\n\n")
                
                fh.write("=" * 80 + "\n")
                fh.write("Report generated by " + APP_NAME + "\n")
                fh.write("=" * 80 + "\n")
            
            QMessageBox.information(self, "Export Successful", f"Report saved to:\n{path}")
            self._set_status(f"Report exported to {path}")
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", str(e))

    def _load_more(self, port_type: str):
        if port_type == "closed":
            all_closed = self._model.results_by_status(PortStatus.CLOSED)
            if self._closed_display_start >= len(all_closed):
                self._btn_load_closed.setEnabled(False)
                self._lbl_closed_info.setText(f"All {len(all_closed)} ports shown")
                return
            
            batch = all_closed[self._closed_display_start:self._closed_display_start + self._closed_chunk_size]
            self._model_closed.append_batch(batch)
            self._closed_display_start += len(batch)
            
            if self._closed_display_start >= len(all_closed):
                self._btn_load_closed.setEnabled(False)
            
            self._lbl_closed_info.setText(
                f"{min(self._closed_display_start, len(all_closed))} / {len(all_closed)} ports shown"
            )
        else: 
            all_filtered = self._model.results_by_status(PortStatus.FILTERED)
            if self._filtered_display_start >= len(all_filtered):
                self._btn_load_filtered.setEnabled(False)
                self._lbl_filtered_info.setText(f"All {len(all_filtered)} ports shown")
                return
            
            batch = all_filtered[self._filtered_display_start:self._filtered_display_start + self._filtered_chunk_size]
            self._model_filtered.append_batch(batch)
            self._filtered_display_start += len(batch)
            
            if self._filtered_display_start >= len(all_filtered):
                self._btn_load_filtered.setEnabled(False)
            
            self._lbl_filtered_info.setText(
                f"{min(self._filtered_display_start, len(all_filtered))} / {len(all_filtered)} ports shown"
            )

    def _on_progress(self, done: int, total: int):
        pct = int(done / total * 100) if total else 0
        self._prog_scan.setValue(pct)
        self._prog_scan.setFormat(f"{done:,} / {total:,}   {pct} %")
        self._metric_scanned.set_value(f"{done:,}")

        dt = time.perf_counter() - self._speed_time
        if dt >= 0.3:
            speed = (done - self._speed_done) / dt
            self._metric_speed.set_value(f"{speed:,.0f}")
            self._speed_done = done
            self._speed_time = time.perf_counter()

    def _on_finished(self, elapsed: float):
        self._flush()
        self._elapsed_timer.stop()
        self._flush_timer.stop()
        self._set_scan_state(scanning=False)
        self._prog_scan.setValue(100)
        self._prog_scan.setFormat(f"Complete  ·  {self._ports_total:,} ports  ·  {elapsed:.2f}s")
        self._metric_speed.set_value("—")
        
        self._preload_closed_filtered()
        
        self._set_status(f"Scan complete — {elapsed:.2f}s")

    def _preload_closed_filtered(self):
        all_closed = self._model.results_by_status(PortStatus.CLOSED)
        all_filtered = self._model.results_by_status(PortStatus.FILTERED)
        
        if all_closed:
            initial_batch = all_closed[:100]
            self._model_closed.append_batch(initial_batch)
            self._closed_display_start = len(initial_batch)
            self._lbl_closed_info.setText(f"{len(initial_batch)} / {len(all_closed)} ports shown")
            self._btn_load_closed.setEnabled(len(all_closed) > 100)
        else:
            self._lbl_closed_info.setText("0 / 0 ports shown")
            self._btn_load_closed.setEnabled(False)
        
        if all_filtered:
            initial_batch = all_filtered[:100]
            self._model_filtered.append_batch(initial_batch)
            self._filtered_display_start = len(initial_batch)
            self._lbl_filtered_info.setText(f"{len(initial_batch)} / {len(all_filtered)} ports shown")
            self._btn_load_filtered.setEnabled(len(all_filtered) > 100)
        else:
            self._lbl_filtered_info.setText("0 / 0 ports shown")
            self._btn_load_filtered.setEnabled(False)

    def _on_error(self, msg: str):
        self._elapsed_timer.stop()
        self._flush_timer.stop()
        self._set_scan_state(scanning=False)
        QMessageBox.critical(self, "Scan Error", msg)
        self._set_status("Error.")

    def _flush(self):
        if not self._worker:
            return

        batch = self._worker.drain_results()
        if batch:
            self._model.append_batch(batch)
            open_batch = [r for r in batch if r.status == PortStatus.OPEN]
            if open_batch:
                self._model_open.append_batch(open_batch)

        updates = self._worker.drain_updates()
        if updates:
            for r in updates:
                self._model.update_result(r)

        if batch or updates:
            o, f, c = self._model.stats()
            self._metric_open.set_value(str(o), C_ACCENT)
            self._metric_filtered.set_value(str(f), C_WARNING)
            self._metric_closed.set_value(str(c), C_TEXT_SECONDARY)

    def _tick_elapsed(self):
        s = time.perf_counter() - self._t_start
        m  = int(s // 60)
        ss = int(s % 60)
        ds = int((s % 1) * 10)
        self._metric_elapsed.set_value(f"{m:02d}:{ss:02d}.{ds}")

    def _set_scan_state(self, scanning: bool):
        # removed self._combo_iface as it does not exist anymore
        for w in (self._btn_launch, self._combo_profile, self._combo_type,
                  self._inp_target, self._btn_clear, self._btn_export):
            w.setEnabled(not scanning)
        self._btn_pause.setEnabled(scanning)
        self._btn_stop.setEnabled(scanning)
        if not scanning:
            self._btn_pause.setText("⏸  PAUSE")

    def _set_status(self, msg: str):
        mw = self.window()
        if hasattr(mw, "statusBar"):
            mw.statusBar().showMessage(f"  {msg}")

    def cleanup(self):
        self._flush_timer.stop()
        self._elapsed_timer.stop()
        if self._worker and self._worker.isRunning():
            self._worker.stop()
            self._worker.wait(4000)
            if self._worker.isRunning():
                self._worker.terminate()
                self._worker.wait(1000)

# ═════════════════════════════════════════════════════════════════════════════
# UTILITY FUNCTIONS
# ═════════════════════════════════════════════════════════════════════════════

def format_time(seconds: float) -> str:
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    secs = int(seconds % 60)
    return f"{hours:02d}:{minutes:02d}:{secs:02d}"

# ═════════════════════════════════════════════════════════════════════════════
# MAIN WINDOW
# ═════════════════════════════════════════════════════════════════════════════

class ShieldScanEliteWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME}  v{APP_VERSION}")
        self.setMinimumSize(1200, 750)
        self.showMaximized()

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(12, 12, 12, 8)
        root.setSpacing(0)

        self._scan_tab = ScanTab()
        root.addWidget(self._scan_tab)

        sb = QStatusBar()
        sb.setSizeGripEnabled(True)
        sb.showMessage("Ready  ·  ShieldScan Professional")
        self.setStatusBar(sb)

    def closeEvent(self, event):
        self._scan_tab.cleanup()
        event.accept()

# ═════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def main():
    app = QApplication(sys.argv)
    
    base_pixmap = QPixmap(600, 400)
    base_pixmap.fill(QColor(C_PRIMARY))
    
    painter = QPainter(base_pixmap)
    painter.setRenderHint(QPainter.Antialiasing)
    
    title_font = QFont("Segoe UI", 36, QFont.Bold)
    painter.setFont(title_font)
    painter.setPen(QColor(C_ACCENT))
    painter.drawText(QRect(0, 80, 600, 80), Qt.AlignCenter, APP_NAME)
    
    version_font = QFont("Segoe UI", 12)
    painter.setFont(version_font)
    painter.setPen(QColor(C_TEXT_SECONDARY))
    painter.drawText(QRect(0, 160, 600, 40), Qt.AlignCenter, f"v{APP_VERSION}")
    
    progress_bg = QRect(100, 250, 400, 8)
    painter.fillRect(progress_bg, QColor(C_BORDER))
    painter.end()

    splash = QSplashScreen(base_pixmap, Qt.WindowStaysOnTopHint)
    splash.show()
    QCoreApplication.processEvents()
    
    total_steps = 40
    for i in range(1, total_steps + 1):
        current_pixmap = base_pixmap.copy()
        p = QPainter(current_pixmap)
        
        progress_width = int(400 * (i / float(total_steps)))
        progress_fg = QRect(100, 250, progress_width, 8)
        p.fillRect(progress_fg, QColor(C_ACCENT))
        p.end()
        
        splash.setPixmap(current_pixmap)
        
        pct = int((i / float(total_steps)) * 100)
        splash.showMessage(
            f"Initializing ShieldScan Professional... {pct}%", 
            alignment=Qt.AlignBottom | Qt.AlignCenter,
            color=QColor(C_ACCENT)
        )
        QCoreApplication.processEvents()
        time.sleep(0.1) 
    
    policy = getattr(asyncio, "WindowsSelectorEventLoopPolicy", None)
    if policy:
        asyncio.set_event_loop_policy(policy())

    app.setStyle("Fusion")

    pal = QPalette()
    pal.setColor(QPalette.Window,    QColor(C_PRIMARY))
    pal.setColor(QPalette.Base,      QColor(C_SECONDARY))
    pal.setColor(QPalette.Text,      QColor(C_TEXT_PRIMARY))
    pal.setColor(QPalette.Button,    QColor(C_SECONDARY))
    pal.setColor(QPalette.ButtonText, QColor(C_TEXT_PRIMARY))
    pal.setColor(QPalette.Highlight, QColor(C_ACCENT))
    pal.setColor(QPalette.HighlightedText, QColor(C_PRIMARY))
    app.setPalette(pal)
    app.setStyleSheet(PREMIUM_STYLESHEET)

    win = ShieldScanEliteWindow()
    splash.finish(win)
    win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()