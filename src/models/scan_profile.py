"""Scan profiles and techniques for ShieldScan.
Supports standard IANA sets, full 65,535 port spectrum, UDP services, and custom port parsing.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List


class ScanTechnique(str, Enum):
    TCP_CONNECT = "TCP Connect (-sT)"
    STEALTH_SYN = "Stealth SYN (-sS)"
    UDP_SWEEP   = "UDP Sweep (-sU)"
    XMAS_SCAN   = "Xmas Scan (-sX)"
    FIN_SCAN    = "FIN Scan (-sF)"
    NULL_SCAN   = "Null Scan (-sN)"


# Standard curated ports for fast scanning
COMMON_TOP_100 = [
    20, 21, 22, 23, 25, 53, 67, 69, 79, 80, 81, 88, 102, 110, 111, 119, 123,
    135, 137, 138, 139, 143, 161, 179, 194, 389, 427, 443, 444, 445, 465,
    500, 514, 515, 540, 548, 554, 587, 631, 636, 646, 873, 990, 992, 993,
    994, 995, 1080, 1194, 1433, 1521, 1723, 2000, 2049, 2082, 2083, 2086,
    2087, 2095, 2096, 2181, 2222, 2375, 2376, 3000, 3001, 3128, 3268, 3269,
    3306, 3389, 4444, 4848, 5000, 5432, 5555, 5672, 5900, 5985, 5986, 6379,
    6443, 7001, 7070, 7443, 8000, 8008, 8009, 8080, 8443, 8888, 9090, 9200,
    9443, 10000, 27017, 27018, 28017, 50000
]

COMMON_TOP_1000 = sorted(set(COMMON_TOP_100 + list(range(1, 1001))))

UDP_COMMON_PORTS = [
    53, 67, 68, 69, 88, 123, 135, 137, 138, 161, 162, 389, 500, 514, 520,
    631, 1194, 1434, 1900, 2049, 4500, 5353, 5355, 8000, 8080
]


def parse_port_range(port_spec: str) -> List[int]:
    """
    Parses complex port specifications like:
      - "80,443"
      - "1-1024"
      - "1-65535"
      - "21-25,80,443,8000-8080"
    """
    ports: set[int] = set()
    tokens = [t.strip() for t in port_spec.replace(";", ",").split(",") if t.strip()]
    for token in tokens:
        if "-" in token:
            parts = token.split("-")
            if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                start = max(1, min(65535, int(parts[0])))
                end = max(1, min(65535, int(parts[1])))
                if start <= end:
                    ports.update(range(start, end + 1))
        elif token.isdigit():
            p = int(token)
            if 1 <= p <= 65535:
                ports.add(p)
    return sorted(list(ports))


@dataclass
class ScanProfile:
    """Configuration profile for network assessment."""
    id: str
    name: str
    description: str
    scope_desc: str
    depth_desc: str
    resource_desc: str
    ports: List[int]
    technique: ScanTechnique = ScanTechnique.TCP_CONNECT
    timeout: float = 0.25
    concurrency: int = 500
    discover_hosts: bool = True
    deep_service_detection: bool = True
    enable_vulnerability_intel: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "scope_desc": self.scope_desc,
            "depth_desc": self.depth_desc,
            "resource_desc": self.resource_desc,
            "ports_count": len(self.ports),
            "technique": self.technique.value,
            "timeout": self.timeout,
            "concurrency": self.concurrency,
            "discover_hosts": self.discover_hosts,
            "deep_service_detection": self.deep_service_detection,
            "enable_vulnerability_intel": self.enable_vulnerability_intel,
        }


BUILTIN_PROFILES = [
    ScanProfile(
        id="quick_discovery",
        name="Quick Discovery (Top 100)",
        description="Fast host and common-port discovery across target network.",
        scope_desc="Top 100 common attack-surface & administration ports",
        depth_desc="Fast TCP connect & initial service identification",
        resource_desc="Low bandwidth, ~2-8 seconds per target host",
        ports=COMMON_TOP_100,
        technique=ScanTechnique.TCP_CONNECT,
        timeout=0.20,
        concurrency=400,
        discover_hosts=True,
        deep_service_detection=True,
    ),
    ScanProfile(
        id="standard_assessment",
        name="Standard Assessment (Top 1,000)",
        description="Balanced host, port and deep service enumeration with vulnerability intelligence.",
        scope_desc="Top 1,000 registered IANA and common enterprise ports",
        depth_desc="Comprehensive service version probing, TLS inspection & evidence collection",
        resource_desc="Moderate bandwidth, ~10-25 seconds per host",
        ports=COMMON_TOP_1000,
        technique=ScanTechnique.TCP_CONNECT,
        timeout=0.25,
        concurrency=600,
        discover_hosts=True,
        deep_service_detection=True,
    ),
    ScanProfile(
        id="full_65k",
        name="Full 65K Range (1–65,535)",
        description="Complete RFC port spectrum covering all 65,535 ports.",
        scope_desc="Full 65,535 TCP/UDP port spectrum (All ports 1–65535)",
        depth_desc="Ultra-fast async concurrent sweep + deep fingerprinting on open listeners",
        resource_desc="High concurrency (800-1200 workers), completes in seconds on LAN",
        ports=list(range(1, 65536)),
        technique=ScanTechnique.TCP_CONNECT,
        timeout=0.18,
        concurrency=800,
        discover_hosts=True,
        deep_service_detection=True,
    ),
    ScanProfile(
        id="extended_inventory",
        name="Extended Inventory (1–10,000)",
        description="Expanded port range covering privileged and registered system services.",
        scope_desc="Ports 1–10,000 + critical high cloud & database listeners",
        depth_desc="Thorough fingerprinting and evidence collection",
        resource_desc="Fast batching, ~15-30 seconds per host",
        ports=sorted(set(list(range(1, 10001)) + [11211, 27017, 27018, 50000, 50070, 61616])),
        technique=ScanTechnique.TCP_CONNECT,
        timeout=0.20,
        concurrency=600,
        discover_hosts=True,
        deep_service_detection=True,
    ),
    ScanProfile(
        id="udp_services",
        name="UDP Critical Services",
        description="Focused enumeration of critical UDP infrastructure services (DNS, NTP, SNMP, NetBIOS).",
        scope_desc="Core UDP daemons (53, 123, 161, 137, 500, 1900, etc.)",
        depth_desc="Payload-driven UDP requests with response verification",
        resource_desc="Targeted protocol packet sweeps",
        ports=UDP_COMMON_PORTS,
        technique=ScanTechnique.UDP_SWEEP,
        timeout=0.40,
        concurrency=100,
        discover_hosts=True,
        deep_service_detection=True,
    ),
]
