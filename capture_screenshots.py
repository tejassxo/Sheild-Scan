"""Screenshot Automation for ShieldScan.
Captures pixel-perfect screenshots of all primary UI views for documentation and presentation embedding.
"""

from __future__ import annotations
import os
import sys
from pathlib import Path


from PyQt5.QtWidgets import QApplication
from PyQt5.QtCore import QSize
from src.ui.main_window import MainWindow
from src.storage.scan_store import ScanStore
from src.models.assessment import ScanResult
from src.models.host import HostRecord, HostStatus
from src.models.port import PortRecord, PortState, TransportProtocol
from src.models.service import ServiceInfo
from src.models.evidence import EvidenceRecord, ConfidenceLevel
from src.analysis.findings_engine import analyze_host_findings


def create_demo_assessment() -> ScanResult:
    """Builds a rich demonstration assessment based on real network observations."""
    res = ScanResult(
        id="scan_college_demo",
        target="192.168.1.0/28",
        target_hosts_count=14,
        profile_id="standard_assessment",
        profile_name="Standard Assessment",
        duration_seconds=42.18,
    )

    # Host 1: 192.168.1.1 (Gateway Router / Web Admin)
    h1 = HostRecord(ip="192.168.1.1", hostname="gateway.local", status=HostStatus.REACHABLE, latency_ms=1.8)
    h1.ports[80] = PortRecord(
        port=80, protocol=TransportProtocol.TCP, state=PortState.OPEN, latency_ms=1.9,
        service=ServiceInfo(name="HTTP", product="lighttpd", version="1.4.59", banner="lighttpd/1.4.59"),
        evidence=EvidenceRecord(probe_type="HTTP_HEAD_PROBE", observation="HTTP 200 OK | Server: lighttpd/1.4.59", confidence=ConfidenceLevel.HIGH)
    )
    h1.ports[443] = PortRecord(
        port=443, protocol=TransportProtocol.TCP, state=PortState.OPEN, latency_ms=2.1,
        service=ServiceInfo(name="HTTPS", product="TLS Gateway Admin", version="TLSv1.3", banner="TLSv1.3 (CN: gateway.local)"),
        evidence=EvidenceRecord(probe_type="TLS_CERT_INSPECTION", observation="TLS 1.3 Handshake completed. CN: gateway.local", confidence=ConfidenceLevel.HIGH)
    )
    h1.ports[53] = PortRecord(
        port=53, protocol=TransportProtocol.TCP, state=PortState.OPEN, latency_ms=1.2,
        service=ServiceInfo(name="DNS", product="dnsmasq", version="2.85", banner="dnsmasq-2.85"),
        evidence=EvidenceRecord(probe_type="PORT_OBSERVATION", observation="DNS TCP port listening", confidence=ConfidenceLevel.HIGH)
    )
    h1.findings = analyze_host_findings(h1)
    res.hosts[h1.ip] = h1

    # Host 2: 192.168.1.10 (Linux Application Server)
    h2 = HostRecord(ip="192.168.1.10", hostname="app-prod.internal", status=HostStatus.REACHABLE, latency_ms=4.2)
    h2.ports[22] = PortRecord(
        port=22, protocol=TransportProtocol.TCP, state=PortState.OPEN, latency_ms=4.1,
        service=ServiceInfo(name="SSH", product="OpenSSH", version="8.9p1", banner="SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"),
        evidence=EvidenceRecord(probe_type="SSH_PROTOCOL_BANNER", observation="SSH banner: SSH-2.0-OpenSSH_8.9p1", confidence=ConfidenceLevel.HIGH)
    )
    h2.ports[3306] = PortRecord(
        port=3306, protocol=TransportProtocol.TCP, state=PortState.OPEN, latency_ms=5.0,
        service=ServiceInfo(name="MySQL", product="MySQL Server", version="8.0.35", banner="MySQL 8.0.35 Community"),
        evidence=EvidenceRecord(probe_type="MYSQL_HANDSHAKE", observation="MySQL Initial Handshake parsed", confidence=ConfidenceLevel.HIGH)
    )
    h2.ports[6379] = PortRecord(
        port=6379, protocol=TransportProtocol.TCP, state=PortState.OPEN, latency_ms=3.8,
        service=ServiceInfo(name="Redis", product="Redis Key-Value Store", version="6.2.6", banner="Redis RESP (+PONG)"),
        evidence=EvidenceRecord(probe_type="REDIS_COMMAND", observation="Redis PING returned +PONG", confidence=ConfidenceLevel.HIGH)
    )
    h2.findings = analyze_host_findings(h2)
    res.hosts[h2.ip] = h2

    # Host 3: 192.168.1.15 (Legacy Testing Box with Insecure Services)
    h3 = HostRecord(ip="192.168.1.15", hostname="lab-test.local", status=HostStatus.REACHABLE, latency_ms=6.1)
    h3.ports[21] = PortRecord(
        port=21, protocol=TransportProtocol.TCP, state=PortState.OPEN, latency_ms=5.8,
        service=ServiceInfo(name="FTP", product="vsftpd", version="3.0.3", banner="220 (vsFTPd 3.0.3)"),
        evidence=EvidenceRecord(probe_type="FTP_GREETING", observation="220 vsftpd 3.0.3 banner received", confidence=ConfidenceLevel.HIGH)
    )
    h3.ports[23] = PortRecord(
        port=23, protocol=TransportProtocol.TCP, state=PortState.OPEN, latency_ms=6.3,
        service=ServiceInfo(name="Telnet", product="Linux Telnetd", banner="Debian GNU/Linux login:"),
        evidence=EvidenceRecord(probe_type="TCP_CONNECT", observation="Telnet connection accepted without encryption", confidence=ConfidenceLevel.HIGH)
    )
    h3.ports[3389] = PortRecord(
        port=3389, protocol=TransportProtocol.TCP, state=PortState.OPEN, latency_ms=7.0,
        service=ServiceInfo(name="RDP", product="Remote Desktop Protocol", banner="MS RDP Listener"),
        evidence=EvidenceRecord(probe_type="PORT_OBSERVATION", observation="RDP port open", confidence=ConfidenceLevel.HIGH)
    )
    h3.findings = analyze_host_findings(h3)
    res.hosts[h3.ip] = h3

    res.recompute_stats()
    return res


def capture_all_views(output_dir: Path):
    output_dir.mkdir(parents=True, exist_ok=True)
    app = QApplication(sys.argv)
    
    store = ScanStore()
    demo_scan = create_demo_assessment()
    store.save(demo_scan)

    # 1. Capture Standard 1280x800
    win = MainWindow(store=store)
    win.resize(QSize(1280, 800))
    win.show()
    win._propagate_scan(demo_scan)

    views = [
        ("overview", "01_dashboard_overview.png"),
        ("scans", "02_scan_controller.png"),
        ("hosts", "03_host_explorer.png"),
        ("services", "04_service_inventory.png"),
        ("findings", "05_findings_workspace.png"),
        ("compare", "06_historical_comparison.png"),
        ("reports", "07_report_center.png"),
        ("settings", "08_settings_view.png"),
    ]

    for key, filename in views:
        win._switch_view(key)
        app.processEvents()
        pixmap = win.grab()
        save_path = output_dir / filename
        pixmap.save(str(save_path), "PNG")
        print(f"[+] Standard 1280x800 screenshot: {save_path.name}")

    # 2. Capture Maximized 1920x1080
    win.resize(QSize(1920, 1080))
    app.processEvents()
    for key, filename in views:
        win._switch_view(key)
        app.processEvents()
        pixmap = win.grab()
        max_filename = filename.replace(".png", "_1080p.png")
        save_path = output_dir / max_filename
        pixmap.save(str(save_path), "PNG")
        print(f"[+] Full HD 1920x1080 screenshot: {save_path.name}")

    print("[*] All UI screenshots successfully generated.")


if __name__ == "__main__":
    out_dir = Path(__file__).resolve().parent / "screenshots"
    capture_all_views(out_dir)

