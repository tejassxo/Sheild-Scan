#!/usr/bin/env python3
"""
ShieldScan Elite  v3.1  —  Streamlined Network Auditor
======================================================
Python  : 3.9+
Platform: Windows (primary), Linux / macOS (asyncio engine only)

Improvements over v3.0:
  - Live search/filter bar above results table
  - Right-click context menu (copy row, open in browser, send to scanner)
  - Export dialog: CSV and JSON with scan metadata header
  - ETA + live rate shown in progress bar
  - Scan summary dialog on completion
  - SSL/TLS banner grabbing for HTTPS ports
  - Custom port range input (5th scan profile)
  - Closed-port KPI card (was missing)
  - Keyboard shortcuts: Enter to launch, Escape to stop
  - Copy selected rows to clipboard (Ctrl+C)
  - Topology tab progress bar + found-host KPI
  - Throttle reduction warning badge in status bar
  - Improved status bar with persistent scan metadata
"""

from __future__ import annotations

import asyncio
import csv
import ctypes
import ipaddress
import json
import os
import platform
import random
import re
import socket
import ssl
import sys
import threading
import time
import webbrowser
from collections import deque
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

# ── Optional scapy import ─────────────────────────────────────────────────────
try:
    os.environ.setdefault("SCAPY_OUTPUT_LOCK", "1")
    from scapy.all import (        # type: ignore[import]
        IP, TCP, UDP, ICMP, ARP, Ether,
        sr1, srp, send, conf as scapy_conf, get_if_list,
    )
    try:
        from scapy.arch.windows import get_windows_if_list as _gwil  # type: ignore
        _WIN_IFACES: Dict[str, str] = {
            i["name"]: i.get("description", i["name"]) for i in _gwil()
        }
    except Exception:
        _WIN_IFACES: Dict[str, str] = {}
    scapy_conf.verb = 0
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False
    _WIN_IFACES = {}

# ── PyQt5 ─────────────────────────────────────────────────────────────────────
from PyQt5.QtCore import (
    QAbstractTableModel, QModelIndex, QSortFilterProxyModel,
    Qt, QThread, QTimer, pyqtSignal,
)
from PyQt5.QtGui import QBrush, QColor, QFont, QPalette, QKeySequence
from PyQt5.QtWidgets import (
    QAbstractItemView, QApplication, QComboBox, QDialog, QDialogButtonBox,
    QFileDialog, QFrame, QGridLayout, QHBoxLayout, QHeaderView,
    QLabel, QLineEdit, QMainWindow, QMenu, QMessageBox, QProgressBar,
    QPushButton, QShortcut, QSizePolicy, QStatusBar, QTabWidget,
    QTableView, QTextEdit, QVBoxLayout, QWidget,
)

# ═════════════════════════════════════════════════════════════════════════════
# PRIVILEGE CHECK
# ═════════════════════════════════════════════════════════════════════════════

def _is_admin() -> bool:
    try:
        if platform.system() == "Windows":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return os.geteuid() == 0
    except Exception:
        return False

def _request_elevation() -> None:
    if platform.system() == "Windows" and not _is_admin():
        ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, " ".join(sys.argv), None, 1
        )
        sys.exit(0)

# ═════════════════════════════════════════════════════════════════════════════
# CONSTANTS & CONFIG
# ═════════════════════════════════════════════════════════════════════════════

APP_NAME    = "ShieldScan Elite"
APP_VERSION = "3.1.0"

ASYNC_SEM_LIMIT   = 800
ASYNC_BATCH       = 400
SCAPY_BATCH       = 256
SCAPY_WORKERS_DEF = 300
SCAPY_WORKERS_MIN = 40
THROTTLE_TRIGGER  = 50
EMIT_INTERVAL_MS  = 50
BANNER_TIMEOUT    = 0.20

C_BG        = "#09090B"
C_PANEL     = "#18181B"
C_BORDER    = "#27272A"
C_ACCENT    = "#10B981"
C_WARNING   = "#F59E0B"
C_DANGER    = "#EF4444"
C_INFO      = "#60A5FA"
C_TEXT_PRI  = "#F4F4F5"
C_TEXT_SEC  = "#A1A1AA"
C_TEXT_MUT  = "#52525B"
C_CLOSED    = "#3F3F46"
C_HDR       = "#1C1C1F"
C_ROW_ALT   = "#111113"
C_SEL       = "#1A3028"
C_TOPO      = "#8B5CF6"

# ═════════════════════════════════════════════════════════════════════════════
# PORT LISTS
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

TOP_1000 = sorted(set(TOP_100 + [
    1,3,7,9,13,17,19,24,26,30,37,42,43,49,70,82,83,84,85,89,90,99,100,106,
    109,113,125,144,146,163,199,211,222,254,255,259,264,280,301,306,311,340,
    366,406,416,425,458,464,481,497,512,513,524,541,543,544,555,563,593,616,
    625,648,666,683,687,691,700,705,711,720,722,726,749,765,777,783,787,801,
    808,843,880,898,900,901,902,903,911,981,987,999,1000,1001,1002,1007,1009,
    1010,1021,1022,1023,1024,1025,1026,1027,1028,1029,1030,1031,1032,1033,
    1034,1035,1036,1037,1038,1039,1040,1041,1044,1048,1049,1050,1053,1054,
    1056,1057,1058,1059,1064,1065,1066,1069,1071,1074,1110,1234,1443,1455,
    1494,1500,1501,1503,1524,1533,1556,1580,1583,1600,1641,1658,1666,1687,
    1700,1717,1718,1719,1720,1721,1755,1761,1782,1801,1812,1839,1862,1863,
    1864,1875,1900,1935,1947,1971,1984,1998,1999,2001,2002,2003,2004,2005,
    2007,2008,2009,2010,2013,2020,2021,2022,2030,2033,2034,2038,2040,2041,
    2042,2043,2045,2046,2047,2048,2065,2068,2099,2100,2103,2105,2106,2107,
    2111,2119,2121,2126,2135,2144,2160,2170,2179,2200,2251,2260,2301,2323,
    2366,2381,2382,2383,2393,2399,2401,2492,2500,2522,2525,2557,2601,2602,
    2638,2701,2710,2717,2718,2725,2800,2809,2869,2909,2967,2998,3003,3005,
    3006,3007,3011,3013,3017,3030,3031,3052,3071,3168,3221,3260,3283,3300,
    3301,3322,3323,3324,3325,3333,3351,3367,3390,3404,3476,3493,3527,3546,
    3551,3580,3659,3689,3690,3703,3737,3800,3801,3809,3814,3826,3851,3869,
    3880,3889,3905,3914,3945,3971,3986,3995,3998,4000,4001,4002,4003,4004,
    4005,4006,4045,4111,4125,4126,4224,4242,4279,4321,4343,4445,4446,4449,
    4550,4567,4662,4899,4900,4998,5001,5002,5003,5009,5030,5050,5051,5054,
    5060,5061,5080,5100,5101,5120,5190,5200,5214,5221,5222,5225,5226,5269,
    5280,5298,5357,5405,5414,5431,5440,5500,5510,5544,5550,5566,5631,5633,
    5666,5678,5679,5718,5800,5901,5999,6000,6001,6002,6003,6006,6025,6059,
    6100,6101,6112,6129,6346,6389,6510,6543,6547,6565,6566,6567,6580,6646,
    6666,6667,6668,6669,6689,6692,6699,6779,6789,6881,6901,6969,7000,7002,
    7004,7007,7019,7025,7100,7200,7402,7512,7625,7777,7800,7937,7938,7999,
    8001,8002,8007,8010,8011,8021,8022,8031,8042,8045,8081,8082,8083,8084,
    8085,8086,8087,8088,8089,8090,8099,8100,8180,8181,8200,8222,8290,8291,
    8300,8333,8383,8400,8500,8600,8649,8800,8873,8899,8994,9000,9001,9002,
    9003,9009,9010,9040,9050,9080,9091,9100,9207,9418,9485,9500,9535,9575,
    9618,9666,9876,9898,9900,9943,9968,9999,10001,10002,10003,10024,10025,
    10082,10180,10215,10243,10566,11110,11111,12000,12345,13456,14000,14238,
    14441,15000,15002,15660,16000,16001,16080,16993,17877,18040,18101,19101,
    19315,19350,19780,20000,20005,20031,20221,20222,21571,22939,23502,24444,
    24800,25734,25735,26214,27000,27352,27353,27355,27356,28201,30000,31337,
    32768,32769,32770,32771,32772,32773,32774,32775,33354,33899,34571,34572,
    34573,35500,38292,40193,41511,42510,44176,44442,44443,44501,45100,48080,
    49152,49153,49154,49155,49156,49157,49158,49159,49160,49161,49400,49999,
    50001,50002,50300,50389,50500,50636,50800,51493,52673,52822,54045,55055,
    55555,55600,56737,56738,57294,58080,60020,60443,61532,61900,62078,63331,
    64623,64680,65000,65129,65389
]))

TOP_UDP = [
    53,67,68,69,123,137,138,161,162,443,500,514,520,1194,1701,1900,
    4500,5353,5355,17185,27005
]

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

# Ports where we attempt SSL/TLS banner grab
SSL_PORTS = {443, 8443, 465, 993, 995, 636, 990, 5986, 6443}

BANNER_PROBES = {
    80:  b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    443: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8080:b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8443:b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8888:b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    21:  b"", 22: b"", 25: b"", 110: b"", 143: b"", 3306: b"",
}

# Ports that support "Open in Browser"
HTTP_PORTS  = {80, 8080, 8000, 8008, 8081, 8082, 8099, 8100, 3000, 3001, 5000}
HTTPS_PORTS = {443, 8443, 8888, 9443, 9090, 9200, 6443, 10000}

UDP_PAYLOADS = {
    53:   b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
    123:  b"\x1b" + b"\x00" * 47,
    161:  b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
    1900: b"M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n",
    5353: b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05local\x00\x00\xff\x00\x01",
}

# ═════════════════════════════════════════════════════════════════════════════
# DATA MODELS
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
    custom:  bool = False

@dataclass
class HostResult:
    ip:       str
    mac:      str
    hostname: str
    latency:  float
    alive:    bool
    method:   str

PROFILES: List[ScanProfile] = [
    ScanProfile("⚡  Flash — Top 100",   TOP_100,              0.20),
    ScanProfile("🔍  Quick — Top 1000",  TOP_1000,             0.30),
    ScanProfile("🔬  Full  — 1–65535",   list(range(1, 65536)),0.40),
    ScanProfile("📡  UDP   — Common",    TOP_UDP,              0.50),
    ScanProfile("✏️   Custom Ports",      [],                   0.30, custom=True),
]

# ═════════════════════════════════════════════════════════════════════════════
# PORT RANGE PARSER
# ═════════════════════════════════════════════════════════════════════════════

def parse_port_spec(spec: str) -> Tuple[List[int], str]:
    """Parse a port spec like '22,80,100-200,443' into a sorted unique list.
    Returns (ports, error_message). error_message is empty on success."""
    ports: set[int] = set()
    for part in spec.replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            bounds = part.split("-", 1)
            if len(bounds) != 2 or not bounds[0].isdigit() or not bounds[1].isdigit():
                return [], f"Invalid range: '{part}'"
            lo, hi = int(bounds[0]), int(bounds[1])
            if lo > hi or lo < 1 or hi > 65535:
                return [], f"Range out of bounds: '{part}'"
            ports.update(range(lo, hi + 1))
        elif part.isdigit():
            p = int(part)
            if p < 1 or p > 65535:
                return [], f"Port out of range: {p}"
            ports.add(p)
        else:
            return [], f"Invalid token: '{part}'"
    if not ports:
        return [], "No ports specified"
    return sorted(ports), ""

# ═════════════════════════════════════════════════════════════════════════════
# ADAPTIVE THROTTLE
# ═════════════════════════════════════════════════════════════════════════════

class AdaptiveThrottle:
    def __init__(self, initial: int = SCAPY_WORKERS_DEF,
                 minimum: int = SCAPY_WORKERS_MIN,
                 trigger: int = THROTTLE_TRIGGER):
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
# ENGINES
# ═════════════════════════════════════════════════════════════════════════════

async def _grab_banner(host: str, port: int) -> str:
    """Grab service banner; uses SSL for known TLS ports."""
    probe = BANNER_PROBES.get(port)
    if probe is None:
        return ""
    try:
        if port in SSL_PORTS:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ctx), timeout=BANNER_TIMEOUT
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=BANNER_TIMEOUT
            )
        try:
            if probe:
                writer.write(probe)
                await writer.drain()
            raw = await asyncio.wait_for(reader.read(256), timeout=BANNER_TIMEOUT)
            text = raw.decode("utf-8", errors="replace").strip()
            return " │ ".join(ln.strip() for ln in text.splitlines() if ln.strip())[:120]
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=0.1)
            except Exception:
                pass
    except Exception:
        return ""

async def _async_probe(host: str, port: int, timeout: float,
                       sem: asyncio.Semaphore) -> ScanResult:
    async with sem:
        t0 = time.perf_counter()
        status: PortStatus
        banner = ""
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), timeout=timeout
            )
            status = PortStatus.OPEN
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=0.1)
            except Exception:
                pass
            banner = await _grab_banner(host, port)
        except asyncio.TimeoutError:
            status = PortStatus.FILTERED
        except ConnectionRefusedError:
            status = PortStatus.CLOSED
        except OSError:
            status = PortStatus.FILTERED

        return ScanResult(
            port, status, SERVICE_MAP.get(port, ""), banner,
            round((time.perf_counter() - t0) * 1000.0, 2)
        )

async def run_async_engine(host: str, ports: List[int], timeout: float,
                           on_result: Callable[[ScanResult], None],
                           on_progress: Callable[[int, int], None],
                           stop_event: asyncio.Event,
                           pause_fn: Callable[[], bool]) -> None:
    sem   = asyncio.Semaphore(ASYNC_SEM_LIMIT)
    total = len(ports)
    done  = 0
    for start in range(0, total, ASYNC_BATCH):
        if stop_event.is_set():
            break
        while pause_fn():
            await asyncio.sleep(0.05)
            if stop_event.is_set():
                return
        batch   = ports[start: start + ASYNC_BATCH]
        tasks   = [asyncio.create_task(_async_probe(host, p, timeout, sem)) for p in batch]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, ScanResult):
                on_result(r)
        done += len(batch)
        on_progress(done, total)
        await asyncio.sleep(0.005)
    on_progress(total, total)

# ── Scapy probes (unchanged internals, same signatures) ──────────────────────

def _scapy_syn_probe(host: str, port: int, timeout: float,
                     throttle: AdaptiveThrottle, iface: str) -> ScanResult:
    t0 = time.perf_counter()
    try:
        pkt  = IP(dst=host) / TCP(sport=random.randint(1024, 65000), dport=port,
                                   flags="S", seq=random.randint(0, 0xFFFFFFFF))
        resp = sr1(pkt, timeout=timeout, verbose=0, iface=iface or None)
        lat  = round((time.perf_counter() - t0) * 1000.0, 2)
        if resp is None:
            throttle.record(is_timeout=True)
            return ScanResult(port, PortStatus.FILTERED, SERVICE_MAP.get(port, ""), "", lat)
        throttle.record(is_timeout=False)
        if resp.haslayer(TCP):
            flags = resp[TCP].flags
            if flags & 0x12 == 0x12:
                send(IP(dst=host) / TCP(sport=resp[TCP].dport, dport=port,
                                        flags="R", seq=resp[TCP].ack),
                     verbose=0, iface=iface or None)
                return ScanResult(port, PortStatus.OPEN, SERVICE_MAP.get(port, ""), "", lat)
            if flags & 0x04:
                return ScanResult(port, PortStatus.CLOSED, SERVICE_MAP.get(port, ""), "", lat)
        if resp.haslayer(ICMP) and resp[ICMP].type == 3 and resp[ICMP].code in (1, 2, 3, 9, 10, 13):
            return ScanResult(port, PortStatus.FILTERED, SERVICE_MAP.get(port, ""), "", lat)
    except Exception:
        lat = round((time.perf_counter() - t0) * 1000.0, 2)
    return ScanResult(port, PortStatus.FILTERED, SERVICE_MAP.get(port, ""), "", lat)

def _scapy_xmas_probe(host: str, port: int, timeout: float,
                      throttle: AdaptiveThrottle, iface: str) -> ScanResult:
    t0 = time.perf_counter()
    try:
        pkt  = IP(dst=host) / TCP(sport=random.randint(1024, 65000), dport=port, flags="FPU")
        resp = sr1(pkt, timeout=timeout, verbose=0, iface=iface or None)
        lat  = round((time.perf_counter() - t0) * 1000.0, 2)
        if resp is None:
            throttle.record(is_timeout=True)
            return ScanResult(port, PortStatus.OPEN, SERVICE_MAP.get(port, ""), "Xmas: no RST", lat)
        throttle.record(is_timeout=False)
        if resp.haslayer(TCP) and resp[TCP].flags & 0x04:
            return ScanResult(port, PortStatus.CLOSED, SERVICE_MAP.get(port, ""), "", lat)
        if resp.haslayer(ICMP) and resp[ICMP].type == 3:
            return ScanResult(port, PortStatus.FILTERED, SERVICE_MAP.get(port, ""), "", lat)
    except Exception:
        lat = round((time.perf_counter() - t0) * 1000.0, 2)
    return ScanResult(port, PortStatus.FILTERED, SERVICE_MAP.get(port, ""), "", lat)

def _scapy_udp_probe(host: str, port: int, timeout: float,
                     throttle: AdaptiveThrottle, iface: str) -> ScanResult:
    t0 = time.perf_counter()
    try:
        payload = UDP_PAYLOADS.get(port, b"\x00")
        pkt     = IP(dst=host) / UDP(dport=port) / payload
        resp    = sr1(pkt, timeout=timeout, verbose=0, iface=iface or None)
        lat     = round((time.perf_counter() - t0) * 1000.0, 2)
        if resp is None:
            throttle.record(is_timeout=True)
            return ScanResult(port, PortStatus.OPEN, SERVICE_MAP.get(port, ""), "UDP: open|filtered", lat)
        throttle.record(is_timeout=False)
        if resp.haslayer(UDP):
            return ScanResult(port, PortStatus.OPEN, SERVICE_MAP.get(port, ""), "", lat)
        if resp.haslayer(ICMP) and resp[ICMP].type == 3:
            if resp[ICMP].code == 3:
                return ScanResult(port, PortStatus.CLOSED, SERVICE_MAP.get(port, ""), "", lat)
            return ScanResult(port, PortStatus.FILTERED, SERVICE_MAP.get(port, ""), "", lat)
    except Exception:
        lat = round((time.perf_counter() - t0) * 1000.0, 2)
    return ScanResult(port, PortStatus.FILTERED, SERVICE_MAP.get(port, ""), "", lat)

def run_scapy_engine(host: str, ports: List[int], timeout: float,
                     scan_type: ScanType, iface: str, throttle: AdaptiveThrottle,
                     on_result: Callable[[ScanResult], None],
                     on_progress: Callable[[int, int], None],
                     on_throttle: Callable[[int], None],
                     stop_event: threading.Event,
                     pause_fn: Callable[[], bool]) -> None:
    _PROBE = {
        ScanType.STEALTH_SYN: _scapy_syn_probe,
        ScanType.XMAS_SCAN:   _scapy_xmas_probe,
        ScanType.UDP_SWEEP:   _scapy_udp_probe,
    }[scan_type]
    total = len(ports)
    done  = 0
    for start in range(0, total, SCAPY_BATCH):
        if stop_event.is_set():
            break
        while pause_fn():
            time.sleep(0.05)
            if stop_event.is_set():
                return
        batch = ports[start: start + SCAPY_BATCH]
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
                except Exception:
                    pass
        done += len(batch)
        on_progress(done, total)
    on_progress(total, total)

# ═════════════════════════════════════════════════════════════════════════════
# TOPOLOGY DISCOVERY
# ═════════════════════════════════════════════════════════════════════════════

def _arp_sweep(subnet: str, iface: str) -> List[HostResult]:
    if not SCAPY_OK:
        return []
    results = []
    try:
        ans, _ = srp(
            Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
            timeout=2, verbose=0, iface=iface or None
        )
        for _, rcv in ans:
            ip, mac = rcv[ARP].psrc, rcv[ARP].hwsrc
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except Exception:
                hostname = ""
            results.append(HostResult(ip, mac, hostname, 0.0, True, "ARP"))
    except Exception:
        pass
    return results

def _icmp_ping(host: str, iface: str, timeout: float = 1.0) -> Optional[HostResult]:
    if not SCAPY_OK:
        return None
    t0 = time.perf_counter()
    try:
        resp = sr1(IP(dst=host) / ICMP(), timeout=timeout, verbose=0, iface=iface or None)
        lat  = round((time.perf_counter() - t0) * 1000.0, 2)
        if resp and resp.haslayer(ICMP) and resp[ICMP].type == 0:
            try:
                hostname = socket.gethostbyaddr(host)[0]
            except Exception:
                hostname = ""
            return HostResult(host, "", hostname, lat, True, "ICMP")
    except Exception:
        pass
    return None

def _tcp_ping(host: str, port: int = 80, timeout: float = 0.5) -> Optional[HostResult]:
    t0 = time.perf_counter()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        err  = sock.connect_ex((host, port))
        sock.close()
        lat  = round((time.perf_counter() - t0) * 1000.0, 2)
        if err in (0, 111, 10061):
            try:
                hostname = socket.gethostbyaddr(host)[0]
            except Exception:
                hostname = ""
            return HostResult(host, "", hostname, lat, True, "TCP")
    except Exception:
        pass
    return None

class TopologyWorker(QThread):
    sig_host     = pyqtSignal(object)
    sig_progress = pyqtSignal(int, int)
    sig_finished = pyqtSignal(int)
    sig_error    = pyqtSignal(str)

    def __init__(self, network: str, iface: str, mode: str = "auto", parent=None):
        super().__init__(parent)
        self._network = network
        self._iface   = iface
        self._mode    = mode
        self._stop    = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        try:
            net = ipaddress.IPv4Network(self._network, strict=False)
        except ValueError as exc:
            self.sig_error.emit(f"Invalid network: {exc}")
            return
        hosts = list(net.hosts())
        total = len(hosts)
        if total > 1024:
            self.sig_error.emit(
                f"Topology sweep capped at /22 ({total} hosts). Use a more specific CIDR."
            )
            return

        found, mode = 0, self._mode
        if mode == "auto":
            mode = "arp" if SCAPY_OK and total <= 256 else ("icmp" if SCAPY_OK else "tcp")

        if mode == "arp":
            self.sig_progress.emit(0, total)
            results = _arp_sweep(self._network, self._iface)
            found   = len(results)
            for hr in results:
                self.sig_host.emit(hr)
            self.sig_progress.emit(total, total)
        else:
            with ThreadPoolExecutor(max_workers=64) as pool:
                probe_fn = (
                    (lambda h: _icmp_ping(str(h), self._iface, 0.8))
                    if mode == "icmp"
                    else (lambda h: _tcp_ping(str(h)))
                )
                fmap = {pool.submit(probe_fn, h): i for i, h in enumerate(hosts)}
                done = 0
                for fut in as_completed(fmap):
                    if self._stop.is_set():
                        pool.shutdown(wait=False, cancel_futures=True)
                        break
                    try:
                        hr = fut.result()
                        if hr:
                            found += 1
                            self.sig_host.emit(hr)
                    except Exception:
                        pass
                    done += 1
                    self.sig_progress.emit(done, total)
        self.sig_finished.emit(found)

# ═════════════════════════════════════════════════════════════════════════════
# SCAN WORKER
# ═════════════════════════════════════════════════════════════════════════════

class ScanWorker(QThread):
    sig_progress = pyqtSignal(int, int)
    sig_throttle = pyqtSignal(int)
    sig_finished = pyqtSignal(float)
    sig_error    = pyqtSignal(str)
    sig_status   = pyqtSignal(str)

    def __init__(self, host: str, profile: ScanProfile, scan_type: ScanType,
                 iface: str, parent=None):
        super().__init__(parent)
        self._host      = host
        self._profile   = profile
        self._scan_type = scan_type
        self._iface     = iface
        self.throttle   = AdaptiveThrottle()
        self._buffer: Deque[ScanResult] = deque()
        self._lock       = threading.Lock()
        self._paused     = False
        self._stop_event_th  = threading.Event()
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._async_stop: Optional[asyncio.Event]       = None

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
        if policy:
            asyncio.set_event_loop_policy(policy())
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
            info     = await asyncio.get_event_loop().getaddrinfo(
                self._host, None, type=socket.SOCK_STREAM
            )
            resolved = info[0][4][0]
        except Exception:
            resolved = self._host

        await run_async_engine(
            host=resolved,
            ports=self._profile.ports,
            timeout=self._profile.timeout,
            on_result=self._push_result,
            on_progress=lambda d, t: self.sig_progress.emit(d, t),
            stop_event=self._async_stop,
            pause_fn=lambda: self._paused,
        )
        self.sig_finished.emit(time.perf_counter() - t_start)

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

        run_scapy_engine(
            host=host,
            ports=self._profile.ports,
            timeout=self._profile.timeout,
            scan_type=self._scan_type,
            iface=self._iface,
            throttle=self.throttle,
            on_result=self._push_result,
            on_progress=lambda d, t: self.sig_progress.emit(d, t),
            on_throttle=self.sig_throttle.emit,
            stop_event=self._stop_event_th,
            pause_fn=lambda: self._paused,
        )
        self.sig_finished.emit(time.perf_counter() - t_start)

    def _push_result(self, r: ScanResult) -> None:
        with self._lock:
            self._buffer.append(r)

# ═════════════════════════════════════════════════════════════════════════════
# TABLE MODELS
# ═════════════════════════════════════════════════════════════════════════════

_COLS = ["Port", "Status", "Service", "Latency ms", "Banner"]
_C_PORT=0; _C_STAT=1; _C_SVC=2; _C_LAT=3; _C_BAN=4

_FG = {
    PortStatus.OPEN:     QColor(C_ACCENT),
    PortStatus.FILTERED: QColor(C_WARNING),
    PortStatus.CLOSED:   QColor(C_CLOSED),
}
_BG_BRUSH = {
    PortStatus.OPEN:     QBrush(QColor(16, 185, 129, 22)),
    PortStatus.FILTERED: QBrush(QColor(245, 158, 11, 18)),
    PortStatus.CLOSED:   None,
}

class PortTableModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._rows: List[ScanResult] = []
        self._mono = QFont("Consolas", 9)
        self._bold = QFont("Consolas", 9)
        self._bold.setBold(True)

    def rowCount(self, parent=QModelIndex())    -> int: return len(self._rows)
    def columnCount(self, parent=QModelIndex()) -> int: return len(_COLS)

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
            if col == _C_STAT: return QBrush(_FG[r.status])
            if col == _C_BAN:  return QBrush(QColor(C_TEXT_MUT if not r.banner else C_TEXT_SEC))
            return QBrush(QColor(C_TEXT_SEC))
        if role == Qt.BackgroundRole:
            bg = _BG_BRUSH.get(r.status)
            return bg if bg else QBrush(QColor(C_ROW_ALT if index.row() % 2 == 0 else C_PANEL))
        if role == Qt.TextAlignmentRole:
            return (Qt.AlignVCenter | Qt.AlignRight
                    if col in (_C_PORT, _C_LAT)
                    else Qt.AlignVCenter | Qt.AlignLeft)
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

    def clear(self) -> None:
        self.beginResetModel()
        self._rows.clear()
        self.endResetModel()

    def all_results(self) -> List[ScanResult]:
        return list(self._rows)

    def result_at(self, row: int) -> Optional[ScanResult]:
        return self._rows[row] if 0 <= row < len(self._rows) else None

    def stats(self) -> Tuple[int, int, int]:
        o = f = c = 0
        for r in self._rows:
            if   r.status is PortStatus.OPEN:     o += 1
            elif r.status is PortStatus.FILTERED:  f += 1
            else:                                  c += 1
        return o, f, c

# ── Proxy: status filter + text search ───────────────────────────────────────

class PortFilterProxyModel(QSortFilterProxyModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.show_open     = True
        self.show_filtered = True
        self.show_closed   = True
        self._search       = ""

    def set_search(self, text: str) -> None:
        self._search = text.strip().lower()
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row: int, source_parent: QModelIndex) -> bool:
        src = self.sourceModel()
        val = src.data(src.index(source_row, _C_STAT, source_parent), Qt.DisplayRole)
        if val == "OPEN"     and not self.show_open:     return False
        if val == "FILTERED" and not self.show_filtered: return False
        if val == "CLOSED"   and not self.show_closed:   return False
        if self._search:
            row_text = " ".join(
                str(src.data(src.index(source_row, c, source_parent), Qt.DisplayRole) or "")
                for c in range(src.columnCount())
            ).lower()
            if self._search not in row_text:
                return False
        return True

# ── Topology table ────────────────────────────────────────────────────────────

_HOST_COLS = ["IP Address", "MAC Address", "Hostname", "Method", "Latency ms"]

class HostTableModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._rows: List[HostResult] = []
        self._mono = QFont("Consolas", 9)

    def rowCount(self, parent=QModelIndex())    -> int: return len(self._rows)
    def columnCount(self, parent=QModelIndex()) -> int: return len(_HOST_COLS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return _HOST_COLS[section]
        return None

    def data(self, index: QModelIndex, role: int = Qt.DisplayRole):
        if not index.isValid():
            return None
        r, col = self._rows[index.row()], index.column()
        if role == Qt.DisplayRole:
            if col == 0: return r.ip
            if col == 1: return r.mac or "—"
            if col == 2: return r.hostname or "—"
            if col == 3: return r.method
            if col == 4: return f"{r.latency:.1f}" if r.latency else "—"
        if role == Qt.FontRole:
            return self._mono
        if role == Qt.ForegroundRole:
            if col == 0: return QBrush(QColor(C_TOPO))
            if col == 3:
                return QBrush(QColor({
                    "ARP": C_ACCENT, "ICMP": C_WARNING, "TCP": C_INFO
                }.get(r.method, C_TEXT_SEC)))
            return QBrush(QColor(C_TEXT_SEC))
        if role == Qt.BackgroundRole:
            return QBrush(QColor(C_ROW_ALT if index.row() % 2 == 0 else C_PANEL))
        if role == Qt.TextAlignmentRole:
            return (Qt.AlignVCenter | Qt.AlignRight if col == 4
                    else Qt.AlignVCenter | Qt.AlignLeft)
        return None

    def add_host(self, hr: HostResult):
        self.beginInsertRows(QModelIndex(), len(self._rows), len(self._rows))
        self._rows.append(hr)
        self.endInsertRows()

    def clear(self):
        self.beginResetModel()
        self._rows.clear()
        self.endResetModel()

    def ip_at(self, row: int) -> str:
        return self._rows[row].ip if 0 <= row < len(self._rows) else ""

# ═════════════════════════════════════════════════════════════════════════════
# UI HELPERS & QSS
# ═════════════════════════════════════════════════════════════════════════════

def _list_interfaces() -> List[Tuple[str, str]]:
    pairs = [("", "Auto (system default)")]
    if SCAPY_OK:
        if _WIN_IFACES:
            for name, desc in _WIN_IFACES.items():
                pairs.append((name, f"{desc}  [{name[:24]}]" if desc != name else name))
        else:
            for iface in get_if_list():
                pairs.append((iface, iface))
    return pairs

def _local_network_guess() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ".".join(ip.split(".")[:3]) + ".0/24"
    except Exception:
        return "192.168.1.0/24"

def _fmt_elapsed(secs: float) -> str:
    return f"{int(secs // 60):02d}:{int(secs % 60):02d}.{int((secs % 1) * 10)}"

class KpiCard(QFrame):
    def __init__(self, label: str, init: str = "—", accent: str = C_TEXT_PRI, parent=None):
        super().__init__(parent)
        self.setObjectName("kpi_card")
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.setMinimumWidth(90)
        lo = QVBoxLayout(self)
        lo.setContentsMargins(12, 8, 12, 8)
        lo.setSpacing(2)
        self._val = QLabel(init)
        self._val.setObjectName("kpi_val")
        self._val.setAlignment(Qt.AlignCenter)
        self._val.setStyleSheet(f"color:{accent};")
        self._lbl = QLabel(label.upper())
        self._lbl.setObjectName("kpi_lbl")
        self._lbl.setAlignment(Qt.AlignCenter)
        lo.addWidget(self._val)
        lo.addWidget(self._lbl)

    def set(self, text: str):
        self._val.setText(text)

    def set_color(self, color: str):
        self._val.setStyleSheet(f"color:{color};")

def _btn(label: str, obj: str, tip: str = "") -> QPushButton:
    b = QPushButton(label)
    b.setObjectName(obj)
    b.setCursor(Qt.PointingHandCursor)
    b.setMinimumHeight(34)
    if tip:
        b.setToolTip(tip)
    return b

def _hline() -> QFrame:
    f = QFrame()
    f.setObjectName("divider")
    f.setFrameShape(QFrame.HLine)
    return f

def _sec(text: str) -> QLabel:
    l = QLabel(text.upper())
    l.setObjectName("sec_lbl")
    return l

QSS = f"""
* {{ font-family:"Segoe UI","SF Pro Display",sans-serif; font-size:13px; outline:none; }}
QWidget  {{ background-color:{C_BG}; color:{C_TEXT_PRI}; }}
QMainWindow {{ background-color:{C_BG}; }}
QFrame#sidebar, QFrame#header, QFrame#footer_f, QFrame#topo_panel {{
    background:{C_PANEL}; border:1px solid {C_BORDER}; border-radius:10px; }}
QFrame#kpi_card {{ background:{C_BG}; border:1px solid {C_BORDER}; border-radius:8px; }}
QFrame#divider  {{ background:{C_BORDER}; max-height:1px; min-height:1px; border:none; }}
QLabel#app_title   {{ color:{C_ACCENT}; font-size:18px; font-weight:700; letter-spacing:3px; }}
QLabel#app_sub     {{ color:{C_TEXT_MUT}; font-size:10px; letter-spacing:2px; }}
QLabel#sec_lbl     {{ color:{C_TEXT_MUT}; font-size:10px; font-weight:600; letter-spacing:1.5px; }}
QLabel#kpi_val     {{ color:{C_TEXT_PRI}; font-size:20px; font-weight:700; font-family:"Consolas",monospace; }}
QLabel#kpi_lbl     {{ color:{C_TEXT_MUT}; font-size:10px; font-weight:600; }}
QLabel#status_lbl  {{ color:{C_TEXT_SEC}; font-size:11px; font-family:"Consolas",monospace; }}
QLabel#warn_badge  {{ color:{C_DANGER}; font-size:10px; font-weight:700; padding:3px 8px;
    border:1px solid {C_DANGER}; border-radius:4px; }}
QLabel#throttle_badge {{ color:{C_WARNING}; font-size:10px; font-weight:700; padding:2px 7px;
    border:1px solid {C_WARNING}; border-radius:4px; background:rgba(245,158,11,0.08); }}
QLineEdit, QComboBox {{
    background:{C_BG}; border:1px solid {C_BORDER}; border-radius:6px;
    padding:8px 12px; color:{C_TEXT_PRI}; font-family:"Consolas",monospace; }}
QLineEdit:focus, QComboBox:focus {{ border-color:{C_ACCENT}; }}
QLineEdit#search_bar {{
    background:{C_PANEL}; border:1px solid {C_BORDER}; border-radius:5px;
    padding:5px 10px; font-size:12px; }}
QLineEdit#search_bar:focus {{ border-color:{C_INFO}; }}
QPushButton {{ border-radius:6px; padding:8px 14px; font-weight:600; border:none; }}
QPushButton#btn_launch {{
    background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #059669,stop:1 {C_ACCENT});
    color:#021A0E; }}
QPushButton#btn_launch:hover {{
    background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 {C_ACCENT},stop:1 #6EE7B7); }}
QPushButton#btn_launch:disabled {{ background:#152A1E; color:{C_TEXT_MUT}; }}
QPushButton#btn_pause   {{ background:transparent; color:{C_WARNING}; border:1px solid {C_WARNING}; }}
QPushButton#btn_stop    {{ background:transparent; color:{C_DANGER};  border:1px solid {C_DANGER};  }}
QPushButton#btn_topo    {{ background:transparent; color:{C_TOPO};    border:1px solid {C_TOPO};    }}
QPushButton#btn_clear, QPushButton#btn_export, QPushButton#btn_use_host, QPushButton#btn_rescan {{
    background:transparent; color:{C_TEXT_SEC}; border:1px solid {C_BORDER}; }}
QPushButton#btn_clear:hover, QPushButton#btn_export:hover, QPushButton#btn_rescan:hover {{
    color:{C_TEXT_PRI}; border-color:{C_TEXT_SEC}; background:rgba(255,255,255,0.04); }}
QPushButton#tog_open   {{ background:rgba(16,185,129,0.12); color:{C_ACCENT};  border:1px solid {C_ACCENT};  border-radius:5px; padding:5px 12px; font-size:11px; }}
QPushButton#tog_open:checked   {{ background:{C_ACCENT};  color:#021A0E; }}
QPushButton#tog_filt   {{ background:rgba(245,158,11,0.12); color:{C_WARNING}; border:1px solid {C_WARNING}; border-radius:5px; padding:5px 12px; font-size:11px; }}
QPushButton#tog_filt:checked   {{ background:{C_WARNING}; color:#1A0F00; }}
QPushButton#tog_closed {{ background:rgba(63,63,70,0.20); color:{C_CLOSED};   border:1px solid {C_CLOSED};  border-radius:5px; padding:5px 12px; font-size:11px; }}
QPushButton#tog_closed:checked {{ background:{C_CLOSED};  color:{C_TEXT_PRI}; }}
QTabWidget::pane {{ border:1px solid {C_BORDER}; border-radius:8px; background:{C_PANEL}; }}
QTabBar::tab {{
    background:{C_BG}; color:{C_TEXT_MUT}; padding:9px 22px; font-weight:600;
    border:1px solid {C_BORDER}; border-bottom:none;
    border-top-left-radius:7px; border-top-right-radius:7px; margin-right:2px; }}
QTabBar::tab:selected {{ background:{C_PANEL}; color:{C_TEXT_PRI}; border-bottom:2px solid {C_ACCENT}; }}
QTableView {{
    background:{C_PANEL}; alternate-background-color:{C_ROW_ALT}; border:none;
    gridline-color:{C_BORDER}; selection-background-color:{C_SEL};
    selection-color:{C_TEXT_PRI}; font-family:"Consolas",monospace; font-size:12px; }}
QTableView::item {{ padding:5px 10px; border-bottom:1px solid rgba(39,39,42,0.8); }}
QTableView::item:selected {{ background:{C_SEL}; color:{C_ACCENT}; }}
QHeaderView::section {{
    background:{C_HDR}; color:{C_TEXT_MUT}; font-weight:700; font-size:10px;
    letter-spacing:1.5px; padding:9px 10px; border:none;
    border-right:1px solid {C_BORDER}; border-bottom:2px solid {C_ACCENT}; }}
QScrollBar:vertical {{ background:transparent; width:7px; margin:2px; }}
QScrollBar::handle:vertical {{ background:{C_BORDER}; border-radius:3px; min-height:24px; }}
QProgressBar {{
    background:{C_BG}; border:1px solid {C_BORDER}; border-radius:5px;
    text-align:center; color:{C_TEXT_SEC}; font-family:"Consolas",monospace; height:16px; }}
QProgressBar::chunk {{
    background:qlineargradient(x1:0,y1:0,x2:1,y2:0,stop:0 #059669,stop:1 {C_ACCENT});
    border-radius:4px; }}
QStatusBar {{ background:{C_BG}; color:{C_TEXT_MUT}; border-top:1px solid {C_BORDER}; }}
QMenu {{
    background:{C_PANEL}; border:1px solid {C_BORDER}; border-radius:6px;
    padding:4px; color:{C_TEXT_PRI}; }}
QMenu::item {{ padding:7px 22px; border-radius:4px; }}
QMenu::item:selected {{ background:{C_SEL}; color:{C_ACCENT}; }}
QMenu::separator {{ background:{C_BORDER}; height:1px; margin:4px 8px; }}
"""

# ═════════════════════════════════════════════════════════════════════════════
# SCAN SUMMARY DIALOG
# ═════════════════════════════════════════════════════════════════════════════

class ScanSummaryDialog(QDialog):
    def __init__(self, host: str, scan_type: str, profile: str,
                 elapsed: float, open_c: int, filtered_c: int, closed_c: int,
                 open_results: List[ScanResult], parent=None):
        super().__init__(parent)
        self.setWindowTitle("Scan Complete — Summary")
        self.setMinimumWidth(480)
        self.setModal(True)
        lo = QVBoxLayout(self)
        lo.setSpacing(12)
        lo.setContentsMargins(20, 18, 20, 18)

        # Title row
        title = QLabel("✅  Scan Finished")
        title.setStyleSheet(f"color:{C_ACCENT}; font-size:16px; font-weight:700;")
        lo.addWidget(title)
        lo.addWidget(_hline())

        # Stats grid
        grid = QGridLayout()
        grid.setSpacing(8)
        def _stat(label, value, color=C_TEXT_SEC):
            lbl = QLabel(label.upper())
            lbl.setObjectName("sec_lbl")
            val = QLabel(str(value))
            val.setStyleSheet(f"color:{color}; font-family:'Consolas'; font-weight:700;")
            return lbl, val

        rows = [
            ("Target",   host,                          C_TEXT_PRI),
            ("Type",     scan_type,                     C_INFO),
            ("Profile",  profile,                       C_INFO),
            ("Elapsed",  _fmt_elapsed(elapsed),         C_TEXT_PRI),
            ("Open",     str(open_c),                   C_ACCENT),
            ("Filtered", str(filtered_c),               C_WARNING),
            ("Closed",   str(closed_c),                 C_TEXT_MUT),
            ("Total",    str(open_c + filtered_c + closed_c), C_TEXT_SEC),
        ]
        for i, (lbl, val, col) in enumerate(rows):
            l, v = _stat(lbl, val, col)
            grid.addWidget(l, i, 0)
            grid.addWidget(v, i, 1)
        lo.addLayout(grid)

        # Open ports list
        if open_results:
            lo.addWidget(_hline())
            lo.addWidget(_sec(f"Open Ports ({len(open_results)})"))
            txt = QTextEdit()
            txt.setReadOnly(True)
            txt.setMaximumHeight(140)
            txt.setStyleSheet(
                f"background:{C_BG}; border:1px solid {C_BORDER}; border-radius:5px;"
                f"font-family:'Consolas'; font-size:11px; color:{C_ACCENT}; padding:6px;"
            )
            lines = [
                f"{r.port:>5}  {(r.service or '—'):<18}  {r.banner[:60] if r.banner else ''}"
                for r in sorted(open_results, key=lambda x: x.port)
            ]
            txt.setPlainText("\n".join(lines))
            lo.addWidget(txt)

        bb = QDialogButtonBox(QDialogButtonBox.Ok)
        bb.accepted.connect(self.accept)
        bb.button(QDialogButtonBox.Ok).setStyleSheet(
            f"background:{C_ACCENT}; color:#021A0E; font-weight:700;"
            f"padding:8px 24px; border-radius:6px;"
        )
        lo.addWidget(bb)

# ═════════════════════════════════════════════════════════════════════════════
# EXPORT DIALOG
# ═════════════════════════════════════════════════════════════════════════════

class ExportDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Export Results")
        self.setFixedWidth(340)
        self.chosen_format = "csv"
        lo = QVBoxLayout(self)
        lo.setContentsMargins(16, 14, 16, 14)
        lo.setSpacing(10)
        lo.addWidget(_sec("Export Format"))
        self._combo = QComboBox()
        self._combo.addItem("CSV  — comma-separated (.csv)", "csv")
        self._combo.addItem("JSON — structured with metadata (.json)", "json")
        lo.addWidget(self._combo)
        bb = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        bb.accepted.connect(self._accept)
        bb.rejected.connect(self.reject)
        lo.addWidget(bb)

    def _accept(self):
        self.chosen_format = self._combo.currentData()
        self.accept()

# ═════════════════════════════════════════════════════════════════════════════
# SCAN TAB
# ═════════════════════════════════════════════════════════════════════════════

class ScanTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._worker: Optional[ScanWorker] = None
        self._model  = PortTableModel(self)
        self._proxy  = PortFilterProxyModel(self)
        self._proxy.setSourceModel(self._model)
        self._paused = False
        self._iface_map  = _list_interfaces()
        self._t_start    = 0.0
        self._ports_total = 0
        self._speed_done = 0
        self._speed_time = 0.0
        self._scan_host  = ""
        self._scan_meta  = ("", "")  # (type_label, profile_label)
        self._throttle_reductions = 0

        self._flush_timer   = QTimer(self)
        self._flush_timer.setInterval(EMIT_INTERVAL_MS)
        self._flush_timer.timeout.connect(self._flush)

        self._elapsed_timer = QTimer(self)
        self._elapsed_timer.setInterval(100)
        self._elapsed_timer.timeout.connect(self._tick_elapsed)

        self._build()
        self._set_scan_state(scanning=False)

    # ── Build UI ──────────────────────────────────────────────────────────────

    def _build(self):
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(8)
        root.addWidget(self._build_sidebar(), stretch=0)
        root.addLayout(self._build_center(),  stretch=1)

    def _build_sidebar(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("sidebar")
        frame.setFixedWidth(242)
        lo = QVBoxLayout(frame)
        lo.setContentsMargins(16, 18, 16, 18)
        lo.setSpacing(9)

        lo.addWidget(_sec("Scan Profile"))
        self._combo_profile = QComboBox()
        for p in PROFILES:
            self._combo_profile.addItem(p.label)
        lo.addWidget(self._combo_profile)

        # Custom port range (shown only for Custom profile)
        self._lbl_custom = _sec("Port Range  (e.g. 22,80,100-200)")
        self._inp_custom  = QLineEdit()
        self._inp_custom.setPlaceholderText("22,80,443,1000-2000")
        lo.addWidget(self._lbl_custom)
        lo.addWidget(self._inp_custom)

        lo.addWidget(_sec("Scan Type"))
        self._combo_type = QComboBox()
        for st in ScanType:
            self._combo_type.addItem(st.value, st)
        if not SCAPY_OK:
            for i in range(1, self._combo_type.count()):
                self._combo_type.model().item(i).setEnabled(False)
        lo.addWidget(self._combo_type)

        lo.addWidget(_sec("Network Interface"))
        self._combo_iface = QComboBox()
        for _, label in self._iface_map:
            self._combo_iface.addItem(label)
        lo.addWidget(self._combo_iface)

        lo.addWidget(_sec("Target Host / IP"))
        self._inp_target = QLineEdit()
        self._inp_target.setPlaceholderText("e.g. 192.168.1.1")
        lo.addWidget(self._inp_target)

        lo.addSpacing(4)
        lo.addWidget(_hline())
        lo.addSpacing(4)

        self._btn_launch = _btn("▶   LAUNCH SCAN", "btn_launch", "Enter")
        self._btn_pause  = _btn("⏸   PAUSE",       "btn_pause")
        self._btn_stop   = _btn("■   STOP",         "btn_stop",  "Escape")
        for b in (self._btn_launch, self._btn_pause, self._btn_stop):
            lo.addWidget(b)

        lo.addSpacing(4)
        lo.addWidget(_hline())
        lo.addSpacing(4)

        self._btn_rescan = _btn("🔁   RESCAN OPEN", "btn_rescan",
                                 "Rescan only the open ports from last result")
        self._btn_clear  = _btn("🗑   CLEAR",  "btn_clear")
        self._btn_export = _btn("📤   EXPORT", "btn_export")
        lo.addWidget(self._btn_rescan)
        lo.addWidget(self._btn_clear)
        lo.addWidget(self._btn_export)

        lo.addStretch()

        self._lbl_portcount = QLabel("")
        self._lbl_portcount.setObjectName("status_lbl")
        self._lbl_portcount.setAlignment(Qt.AlignCenter)
        lo.addWidget(self._lbl_portcount)

        self._lbl_throttle = QLabel("")
        self._lbl_throttle.setObjectName("throttle_badge")
        self._lbl_throttle.setAlignment(Qt.AlignCenter)
        self._lbl_throttle.setVisible(False)
        lo.addWidget(self._lbl_throttle)

        # Wire signals
        self._btn_launch.clicked.connect(self._start)
        self._btn_pause.clicked.connect(self._toggle_pause)
        self._btn_stop.clicked.connect(self._stop)
        self._btn_clear.clicked.connect(self._clear)
        self._btn_export.clicked.connect(self._export)
        self._btn_rescan.clicked.connect(self._rescan_open)
        self._combo_profile.currentIndexChanged.connect(self._on_profile_change)
        self._on_profile_change(0)

        return frame

    def _build_center(self) -> QVBoxLayout:
        lo = QVBoxLayout()
        lo.setSpacing(8)

        # ── Header ────────────────────────────────────────────────────────────
        frame = QFrame()
        frame.setObjectName("header")
        h_lo = QHBoxLayout(frame)
        h_lo.setContentsMargins(18, 12, 18, 12)
        h_lo.setSpacing(12)

        brand = QVBoxLayout()
        brand.setSpacing(1)
        t = QLabel("SHIELDSCAN  ELITE"); t.setObjectName("app_title")
        s = QLabel("v3.1 · HYBRID ENGINE"); s.setObjectName("app_sub")
        brand.addWidget(t); brand.addWidget(s)
        h_lo.addLayout(brand)
        h_lo.addSpacing(14)

        self._kpi_scanned  = KpiCard("Scanned",  "0")
        self._kpi_open     = KpiCard("Open",     "0", C_ACCENT)
        self._kpi_filtered = KpiCard("Filtered", "0", C_WARNING)
        self._kpi_closed   = KpiCard("Closed",   "0", C_CLOSED)
        self._kpi_speed    = KpiCard("Ports / s", "—")
        self._kpi_elapsed  = KpiCard("Elapsed",  "00:00.0")
        for c in (self._kpi_scanned, self._kpi_open, self._kpi_filtered,
                  self._kpi_closed, self._kpi_speed, self._kpi_elapsed):
            h_lo.addWidget(c)
        h_lo.addStretch()
        lo.addWidget(frame)

        # ── Filter + Search bar ───────────────────────────────────────────────
        fw = QWidget()
        f_lo = QHBoxLayout(fw)
        f_lo.setContentsMargins(2, 0, 2, 0)
        f_lo.setSpacing(8)

        self._tog_open   = QPushButton("● OPEN")
        self._tog_filt   = QPushButton("● FILTERED")
        self._tog_closed = QPushButton("● CLOSED")
        for obj, btn in [("tog_open", self._tog_open), ("tog_filt", self._tog_filt),
                         ("tog_closed", self._tog_closed)]:
            btn.setObjectName(obj)
            btn.setCheckable(True)
            btn.setChecked(True)
            btn.setCursor(Qt.PointingHandCursor)
            btn.setMinimumHeight(28)
            btn.toggled.connect(self._apply_filter)
            f_lo.addWidget(btn)

        f_lo.addSpacing(8)
        self._search_bar = QLineEdit()
        self._search_bar.setObjectName("search_bar")
        self._search_bar.setPlaceholderText("🔍  Search port, service, banner…")
        self._search_bar.setMinimumHeight(28)
        self._search_bar.setMaximumWidth(280)
        self._search_bar.textChanged.connect(self._proxy.set_search)
        self._search_bar.textChanged.connect(self._update_row_count)
        f_lo.addWidget(self._search_bar)

        f_lo.addStretch()
        self._lbl_row_count = QLabel("0 rows")
        self._lbl_row_count.setObjectName("status_lbl")
        f_lo.addWidget(self._lbl_row_count)
        lo.addWidget(fw)

        # ── Results Table ─────────────────────────────────────────────────────
        self._view = QTableView()
        self._view.setModel(self._proxy)
        self._view.setAlternatingRowColors(True)
        self._view.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._view.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._view.setShowGrid(False)
        self._view.verticalHeader().setVisible(False)
        self._view.verticalHeader().setDefaultSectionSize(29)
        hdr = self._view.horizontalHeader()
        hdr.setSectionResizeMode(QHeaderView.Interactive)
        hdr.setStretchLastSection(True)
        hdr.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self._view.setColumnWidth(0, 76)
        self._view.setColumnWidth(1, 96)
        self._view.setColumnWidth(2, 130)
        self._view.setColumnWidth(3, 90)
        self._view.setContextMenuPolicy(Qt.CustomContextMenu)
        self._view.customContextMenuRequested.connect(self._show_context_menu)
        lo.addWidget(self._view, stretch=1)

        # ── Footer Progress ───────────────────────────────────────────────────
        foot = QFrame()
        foot.setObjectName("footer_f")
        foot_lo = QHBoxLayout(foot)
        foot_lo.setContentsMargins(14, 8, 14, 8)
        lbl1 = QLabel("SCAN"); lbl1.setObjectName("sec_lbl"); lbl1.setFixedWidth(48)
        self._prog_scan = QProgressBar()
        self._prog_scan.setRange(0, 100)
        self._prog_scan.setValue(0)
        self._prog_scan.setFormat("Idle")
        foot_lo.addWidget(lbl1)
        foot_lo.addWidget(self._prog_scan)
        lo.addWidget(foot)

        return lo

    # ── Keyboard shortcuts ────────────────────────────────────────────────────

    def _install_shortcuts(self, window):
        QShortcut(QKeySequence(Qt.Key_Return), window, self._start)
        QShortcut(QKeySequence(Qt.Key_Escape), window, self._stop)
        QShortcut(QKeySequence("Ctrl+C"),      window, self._copy_selected)

    # ── Right-click context menu ──────────────────────────────────────────────

    def _show_context_menu(self, pos):
        idx = self._view.indexAt(pos)
        if not idx.isValid():
            return
        src_row = self._proxy.mapToSource(idx).row()
        result  = self._model.result_at(src_row)
        if not result:
            return

        menu = QMenu(self)
        port, host = result.port, self._scan_host

        act_copy_row   = menu.addAction("📋  Copy Row")
        act_copy_port  = menu.addAction(f"📋  Copy Port  ({port})")
        menu.addSeparator()

        is_http  = port in HTTP_PORTS  and result.status is PortStatus.OPEN
        is_https = port in HTTPS_PORTS and result.status is PortStatus.OPEN
        if is_http or is_https:
            scheme = "https" if is_https else "http"
            act_browser = menu.addAction(f"🌐  Open in Browser  ({scheme}://…:{port})")
        else:
            act_browser = None

        if result.banner:
            menu.addSeparator()
            act_copy_banner = menu.addAction("📋  Copy Banner")
        else:
            act_copy_banner = None

        chosen = menu.exec_(self._view.viewport().mapToGlobal(pos))
        if not chosen:
            return

        clipboard = QApplication.clipboard()
        if chosen == act_copy_row:
            row_text = "\t".join([
                str(result.port), result.status.value,
                result.service or "—", f"{result.latency:.1f}", result.banner or "—"
            ])
            clipboard.setText(row_text)
        elif chosen == act_copy_port:
            clipboard.setText(str(port))
        elif act_copy_banner and chosen == act_copy_banner:
            clipboard.setText(result.banner)
        elif act_browser and chosen == act_browser:
            scheme = "https" if is_https else "http"
            webbrowser.open(f"{scheme}://{host}:{port}")

    # ── Copy selected rows to clipboard (Ctrl+C) ──────────────────────────────

    def _copy_selected(self):
        rows = set()
        for idx in self._view.selectedIndexes():
            rows.add(self._proxy.mapToSource(idx).row())
        if not rows:
            return
        lines = []
        for r in sorted(rows):
            result = self._model.result_at(r)
            if result:
                lines.append("\t".join([
                    str(result.port), result.status.value,
                    result.service or "—", f"{result.latency:.1f}", result.banner or "—"
                ]))
        QApplication.clipboard().setText("\n".join(lines))

    # ── Scan control ──────────────────────────────────────────────────────────

    def _start(self, ports_override: Optional[List[int]] = None):
        if self._worker and self._worker.isRunning():
            return
        host = self._inp_target.text().strip()
        if not host:
            QMessageBox.warning(self, "No Target", "Enter a hostname or IP address.")
            return

        scan_type = self._combo_type.currentData()
        if scan_type != ScanType.TCP_CONNECT and not SCAPY_OK:
            QMessageBox.critical(self, "Error", "Scapy required for raw socket scans.")
            return

        profile_idx = self._combo_profile.currentIndex()
        profile     = PROFILES[profile_idx]

        # Resolve ports
        if ports_override is not None:
            ports = ports_override
        elif profile.custom:
            ports, err = parse_port_spec(self._inp_custom.text())
            if err:
                QMessageBox.warning(self, "Invalid Port Range", err)
                return
        else:
            ports = profile.ports

        effective_profile = ScanProfile(
            label=profile.label, ports=ports,
            timeout=profile.timeout, custom=profile.custom
        )

        iface_i = self._combo_iface.currentIndex()
        iface   = self._iface_map[iface_i][0] if iface_i < len(self._iface_map) else ""

        self._scan_host      = host
        self._scan_meta      = (scan_type.value, profile.label.split("—")[-1].strip())
        self._ports_total    = len(ports)
        self._t_start        = time.perf_counter()
        self._speed_done     = 0
        self._speed_time     = self._t_start
        self._paused         = False
        self._throttle_reductions = 0

        self._model.clear()
        self._proxy.invalidateFilter()
        for k in (self._kpi_scanned, self._kpi_open, self._kpi_filtered, self._kpi_closed):
            k.set("0")
        self._kpi_speed.set("—")
        self._kpi_elapsed.set("00:00.0")
        self._prog_scan.setRange(0, self._ports_total)
        self._prog_scan.setValue(0)
        self._prog_scan.setFormat("Scanning…  0 %")
        self._lbl_throttle.setVisible(False)
        self._set_scan_state(scanning=True)

        self._worker = ScanWorker(host, effective_profile, scan_type, iface, parent=self)
        self._worker.sig_progress.connect(self._on_progress)
        self._worker.sig_throttle.connect(self._on_throttle)
        self._worker.sig_finished.connect(self._on_finished)
        self._worker.sig_error.connect(self._on_error)
        self._worker.sig_status.connect(self._set_status)
        self._worker.start()

        self._flush_timer.start()
        self._elapsed_timer.start()

    def _rescan_open(self):
        open_ports = [r.port for r in self._model.all_results()
                      if r.status is PortStatus.OPEN]
        if not open_ports:
            QMessageBox.information(self, "Rescan", "No open ports to rescan.")
            return
        self._start(ports_override=open_ports)

    def _toggle_pause(self):
        if not self._worker:
            return
        self._paused = not self._paused
        if self._paused:
            self._worker.pause()
            self._btn_pause.setText("▶   RESUME")
            self._elapsed_timer.stop()
        else:
            self._worker.resume()
            self._btn_pause.setText("⏸   PAUSE")
            self._elapsed_timer.start()

    def _stop(self):
        if self._worker:
            self._worker.stop()
            self._set_status("Stopping…")

    def _clear(self):
        self._model.clear()
        self._proxy.invalidateFilter()
        for k in (self._kpi_scanned, self._kpi_open, self._kpi_filtered, self._kpi_closed):
            k.set("0")
        self._prog_scan.setValue(0)
        self._prog_scan.setFormat("Idle")
        self._lbl_row_count.setText("0 rows")
        self._lbl_throttle.setVisible(False)
        self._set_status("Cleared.")

    # ── Export ────────────────────────────────────────────────────────────────

    def _export(self):
        rows = self._model.all_results()
        if not rows:
            QMessageBox.information(self, "Export", "No results to export.")
            return

        dlg = ExportDialog(self)
        if dlg.exec_() != QDialog.Accepted:
            return
        fmt = dlg.chosen_format

        ext   = ".csv" if fmt == "csv" else ".json"
        filt  = "CSV Files (*.csv)" if fmt == "csv" else "JSON Files (*.json)"
        path, _ = QFileDialog.getSaveFileName(self, "Export Results", "", filt)
        if not path:
            return
        if not path.lower().endswith(ext):
            path += ext

        meta = {
            "tool":       f"{APP_NAME} v{APP_VERSION}",
            "timestamp":  datetime.now().isoformat(),
            "target":     self._scan_host,
            "scan_type":  self._scan_meta[0],
            "profile":    self._scan_meta[1],
        }

        try:
            if fmt == "csv":
                with open(path, "w", newline="", encoding="utf-8") as fh:
                    w = csv.writer(fh)
                    # metadata as comment rows
                    for k, v in meta.items():
                        w.writerow([f"# {k}: {v}"])
                    w.writerow([])
                    w.writerow(["Port", "Status", "Service", "Latency_ms", "Banner"])
                    for r in rows:
                        w.writerow([r.port, r.status.value, r.service,
                                    f"{r.latency:.2f}", r.banner])
            else:
                payload = {
                    "meta":    meta,
                    "results": [
                        {
                            "port":    r.port,
                            "status":  r.status.value,
                            "service": r.service,
                            "latency": r.latency,
                            "banner":  r.banner,
                        }
                        for r in rows
                    ]
                }
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump(payload, fh, indent=2)
            self._set_status(f"Exported {len(rows):,} rows → {os.path.basename(path)}")
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", str(e))

    # ── Signal handlers ───────────────────────────────────────────────────────

    def _on_progress(self, done: int, total: int):
        self._prog_scan.setValue(done)
        elapsed = time.perf_counter() - self._t_start
        pct     = int(done / total * 100) if total else 0

        if done > 0 and elapsed > 0:
            rate     = done / elapsed
            remaining = (total - done) / rate if rate > 0 else 0
            eta_str  = f"  ETA {_fmt_elapsed(remaining)}" if remaining > 2 else ""
            rate_str = f"  {rate:,.0f} p/s"
        else:
            eta_str = rate_str = ""

        self._prog_scan.setFormat(
            f"{done:,} / {total:,}  ({pct} %){rate_str}{eta_str}"
        )
        self._kpi_scanned.set(f"{done:,}")

        dt = time.perf_counter() - self._speed_time
        if dt >= 0.3:
            self._kpi_speed.set(f"{(done - self._speed_done) / dt:,.0f}")
            self._speed_done = done
            self._speed_time = time.perf_counter()

    def _on_throttle(self, new_workers: int):
        self._throttle_reductions += 1
        self._lbl_throttle.setText(f"⚡ Throttle  ×{self._throttle_reductions}  ({new_workers} w)")
        self._lbl_throttle.setVisible(True)

    def _on_finished(self, elapsed: float):
        self._flush()
        self._elapsed_timer.stop()
        self._flush_timer.stop()
        self._set_scan_state(scanning=False)
        self._prog_scan.setValue(self._ports_total)
        self._prog_scan.setFormat(
            f"Done  {self._ports_total:,} ports  {elapsed:.2f} s"
        )
        self._kpi_speed.set("—")
        self._set_status(
            f"Scan complete — {self._scan_host}  "
            f"[{self._scan_meta[0]}, {self._scan_meta[1]}]  {elapsed:.1f}s"
        )

        # Show summary dialog
        o, f, c = self._model.stats()
        open_results = [r for r in self._model.all_results()
                        if r.status is PortStatus.OPEN]
        dlg = ScanSummaryDialog(
            host=self._scan_host, scan_type=self._scan_meta[0],
            profile=self._scan_meta[1], elapsed=elapsed,
            open_c=o, filtered_c=f, closed_c=c,
            open_results=open_results, parent=self
        )
        dlg.exec_()

    def _on_error(self, msg: str):
        self._elapsed_timer.stop()
        self._flush_timer.stop()
        self._set_scan_state(scanning=False)
        QMessageBox.critical(self, "Error", msg)
        self._set_status("Error.")

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _flush(self):
        if not self._worker:
            return
        batch = self._worker.drain_results()
        if batch:
            self._model.append_batch(batch)
            o, f, c = self._model.stats()
            self._kpi_open.set(str(o))
            self._kpi_filtered.set(str(f))
            self._kpi_closed.set(str(c))
            self._update_row_count()

    def _update_row_count(self):
        self._lbl_row_count.setText(f"{self._proxy.rowCount():,} rows")

    def _tick_elapsed(self):
        self._kpi_elapsed.set(_fmt_elapsed(time.perf_counter() - self._t_start))

    def _apply_filter(self):
        self._proxy.show_open     = self._tog_open.isChecked()
        self._proxy.show_filtered = self._tog_filt.isChecked()
        self._proxy.show_closed   = self._tog_closed.isChecked()
        self._proxy.invalidateFilter()
        self._update_row_count()

    def _on_profile_change(self, idx: int):
        profile   = PROFILES[idx]
        is_custom = profile.custom
        self._lbl_custom.setVisible(is_custom)
        self._inp_custom.setVisible(is_custom)
        if not is_custom:
            self._lbl_portcount.setText(
                f"{len(profile.ports):,} ports\ntimeout {profile.timeout:.2f} s"
            )
        else:
            self._lbl_portcount.setText("Enter range above\ntimeout 0.30 s")

    def _set_scan_state(self, scanning: bool):
        for w in (self._btn_launch, self._combo_profile, self._combo_type,
                  self._combo_iface, self._inp_target, self._btn_clear,
                  self._btn_export, self._btn_rescan, self._inp_custom):
            w.setEnabled(not scanning)
        self._btn_pause.setEnabled(scanning)
        self._btn_stop.setEnabled(scanning)
        if not scanning:
            self._btn_pause.setText("⏸   PAUSE")

    def _set_status(self, msg: str):
        mw = self.window()
        if hasattr(mw, "statusBar"):
            mw.statusBar().showMessage(f"  {msg}")

    def request_target(self, ip: str):
        self._inp_target.setText(ip)

# ═════════════════════════════════════════════════════════════════════════════
# TOPOLOGY TAB
# ═════════════════════════════════════════════════════════════════════════════

class TopologyTab(QWidget):
    request_scan = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._worker: Optional[TopologyWorker] = None
        self._model    = HostTableModel(self)
        self._iface_map = _list_interfaces()
        self._build()

    def _build(self):
        root = QHBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(8)

        # Sidebar
        frame = QFrame()
        frame.setObjectName("sidebar")
        frame.setFixedWidth(242)
        lo = QVBoxLayout(frame)
        lo.setContentsMargins(16, 18, 16, 18)
        lo.setSpacing(9)

        lo.addWidget(_sec("Subnet (CIDR)"))
        self._inp_subnet = QLineEdit()
        self._inp_subnet.setText(_local_network_guess())
        lo.addWidget(self._inp_subnet)

        lo.addWidget(_sec("Discovery Mode"))
        self._combo_mode = QComboBox()
        for label, val in [("Auto", "auto"), ("ARP", "arp"), ("ICMP", "icmp"), ("TCP", "tcp")]:
            self._combo_mode.addItem(label, val)
        if not SCAPY_OK:
            for i in (1, 2):
                self._combo_mode.model().item(i).setEnabled(False)
        lo.addWidget(self._combo_mode)
        lo.addStretch()

        # KPI for found hosts
        self._kpi_found = KpiCard("Hosts Found", "0", C_TOPO)
        lo.addWidget(self._kpi_found)
        lo.addSpacing(6)

        self._btn_sweep = _btn("📡  START SWEEP", "btn_topo")
        self._btn_stop  = _btn("■   STOP SWEEP",  "btn_stop")
        self._btn_use   = _btn("🎯  SCAN TARGET",  "btn_use_host",
                               "Send selected IP to the Scanner tab")
        lo.addWidget(self._btn_sweep)
        lo.addWidget(self._btn_stop)
        lo.addWidget(self._btn_use)

        self._btn_sweep.clicked.connect(self._start_sweep)
        self._btn_stop.clicked.connect(self._stop_sweep)
        self._btn_use.clicked.connect(self._use)
        self._btn_stop.setEnabled(False)

        root.addWidget(frame, stretch=0)

        # Right column — progress + table
        c_lo = QVBoxLayout()
        c_lo.setSpacing(8)

        # Progress bar for topology sweep
        prog_frame = QFrame()
        prog_frame.setObjectName("footer_f")
        prog_lo = QHBoxLayout(prog_frame)
        prog_lo.setContentsMargins(14, 8, 14, 8)
        lbl = QLabel("SWEEP"); lbl.setObjectName("sec_lbl"); lbl.setFixedWidth(58)
        self._prog_topo = QProgressBar()
        self._prog_topo.setRange(0, 100)
        self._prog_topo.setValue(0)
        self._prog_topo.setFormat("Idle")
        prog_lo.addWidget(lbl)
        prog_lo.addWidget(self._prog_topo)
        c_lo.addWidget(prog_frame)

        self._view = QTableView()
        self._view.setModel(self._model)
        self._view.setSelectionBehavior(QAbstractItemView.SelectRows)
        self._view.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self._view.verticalHeader().setVisible(False)
        self._view.verticalHeader().setDefaultSectionSize(29)
        hdr = self._view.horizontalHeader()
        hdr.setStretchLastSection(True)
        hdr.setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        self._view.setContextMenuPolicy(Qt.CustomContextMenu)
        self._view.customContextMenuRequested.connect(self._show_context_menu)
        self._view.doubleClicked.connect(self._on_double_click)
        c_lo.addWidget(self._view, stretch=1)

        root.addLayout(c_lo, stretch=1)

    def _start_sweep(self):
        self._model.clear()
        self._kpi_found.set("0")
        self._prog_topo.setValue(0)
        self._prog_topo.setFormat("Sweeping…")
        self._btn_sweep.setEnabled(False)
        self._btn_stop.setEnabled(True)

        self._worker = TopologyWorker(
            self._inp_subnet.text(),
            "",
            self._combo_mode.currentData(),
            self
        )
        self._worker.sig_host.connect(self._on_host)
        self._worker.sig_progress.connect(self._on_progress)
        self._worker.sig_finished.connect(self._on_finished)
        self._worker.sig_error.connect(self._on_error)
        self._worker.start()

    def _stop_sweep(self):
        if self._worker:
            self._worker.stop()
        self._btn_sweep.setEnabled(True)
        self._btn_stop.setEnabled(False)

    def _on_host(self, hr: HostResult):
        self._model.add_host(hr)
        self._kpi_found.set(str(self._model.rowCount()))

    def _on_progress(self, done: int, total: int):
        self._prog_topo.setRange(0, total)
        self._prog_topo.setValue(done)
        pct = int(done / total * 100) if total else 0
        self._prog_topo.setFormat(
            f"{done:,} / {total:,}  ({pct} %)  —  {self._model.rowCount()} found"
        )

    def _on_finished(self, found: int):
        self._btn_sweep.setEnabled(True)
        self._btn_stop.setEnabled(False)
        self._prog_topo.setFormat(f"Done — {found} host(s) found")

    def _on_error(self, msg: str):
        self._btn_sweep.setEnabled(True)
        self._btn_stop.setEnabled(False)
        QMessageBox.critical(self, "Topology Error", msg)

    def _use(self):
        idx = self._view.currentIndex()
        if idx.isValid():
            self.request_scan.emit(self._model.ip_at(idx.row()))

    def _on_double_click(self, idx: QModelIndex):
        if idx.isValid():
            self.request_scan.emit(self._model.ip_at(idx.row()))

    def _show_context_menu(self, pos):
        idx = self._view.indexAt(pos)
        if not idx.isValid():
            return
        ip = self._model.ip_at(idx.row())
        menu = QMenu(self)
        act_copy   = menu.addAction(f"📋  Copy IP  ({ip})")
        act_scan   = menu.addAction("⚡  Scan in Scanner Tab")
        chosen = menu.exec_(self._view.viewport().mapToGlobal(pos))
        if chosen == act_copy:
            QApplication.clipboard().setText(ip)
        elif chosen == act_scan:
            self.request_scan.emit(ip)

# ═════════════════════════════════════════════════════════════════════════════
# MAIN WINDOW
# ═════════════════════════════════════════════════════════════════════════════

class ShieldScanEliteWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"{APP_NAME}  v{APP_VERSION}")
        self.setMinimumSize(1060, 720)

        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(10, 10, 10, 8)

        self._tabs     = QTabWidget()
        self._scan_tab = ScanTab()
        self._topo_tab = TopologyTab()

        self._tabs.addTab(self._scan_tab, "⚡  Scanner")
        self._tabs.addTab(self._topo_tab, "📡  Topology")
        root.addWidget(self._tabs)

        # Wire topology → scanner
        self._topo_tab.request_scan.connect(
            lambda ip: (
                self._scan_tab.request_target(ip),
                self._tabs.setCurrentIndex(0),
            )
        )

        sb = QStatusBar()
        sb.setSizeGripEnabled(False)
        self.setStatusBar(sb)

        # Install keyboard shortcuts bound to main window
        self._scan_tab._install_shortcuts(self)

    def closeEvent(self, event):
        # Gracefully stop any running worker
        if self._scan_tab._worker and self._scan_tab._worker.isRunning():
            self._scan_tab._worker.stop()
            self._scan_tab._worker.wait(2000)
        event.accept()

# ═════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═════════════════════════════════════════════════════════════════════════════

def main():
    if platform.system() == "Windows" and not _is_admin() and SCAPY_OK:
        _request_elevation()

    policy = getattr(asyncio, "WindowsSelectorEventLoopPolicy", None)
    if policy:
        asyncio.set_event_loop_policy(policy())

    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    pal = QPalette()
    pal.setColor(QPalette.Window,      QColor(C_BG))
    pal.setColor(QPalette.Base,        QColor(C_PANEL))
    pal.setColor(QPalette.Text,        QColor(C_TEXT_PRI))
    pal.setColor(QPalette.WindowText,  QColor(C_TEXT_PRI))
    app.setPalette(pal)
    app.setStyleSheet(QSS)

    win = ShieldScanEliteWindow()
    win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
