"""Host record model for ShieldScan.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from src.models.port import PortRecord, PortState
from src.models.finding import Finding
from src.models.evidence import EvidenceRecord


class HostStatus(str, Enum):
    REACHABLE = "REACHABLE"
    UNREACHABLE = "UNREACHABLE"
    UNCERTAIN = "UNCERTAIN"


@dataclass
class HostRecord:
    """Represents an assessed host system in the target network."""
    ip: str
    hostname: str = ""
    status: HostStatus = HostStatus.REACHABLE
    os_hint: str = ""
    mac_address: str = ""
    vendor: str = ""
    latency_ms: float = 0.0
    ports: Dict[int, PortRecord] = field(default_factory=dict)
    findings: List[Finding] = field(default_factory=list)
    discovery_evidence: Optional[EvidenceRecord] = None

    @property
    def open_ports(self) -> List[PortRecord]:
        return [p for p in self.ports.values() if p.state == PortState.OPEN]

    @property
    def closed_ports(self) -> List[PortRecord]:
        return [p for p in self.ports.values() if p.state == PortState.CLOSED]

    @property
    def filtered_ports(self) -> List[PortRecord]:
        return [p for p in self.ports.values() if p.state == PortState.FILTERED]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "status": self.status.value,
            "os_hint": self.os_hint,
            "mac_address": self.mac_address,
            "vendor": self.vendor,
            "latency_ms": round(self.latency_ms, 2),
            "ports": {str(p): rec.to_dict() for p, rec in self.ports.items()},
            "findings": [f.to_dict() for f in self.findings],
            "discovery_evidence": self.discovery_evidence.to_dict() if self.discovery_evidence else None,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> HostRecord:
        ports_dict = {}
        for p_str, p_data in data.get("ports", {}).items():
            ports_dict[int(p_str)] = PortRecord.from_dict(p_data)

        findings_list = [Finding.from_dict(f) for f in data.get("findings", [])]
        
        disc_ev = None
        if data.get("discovery_evidence"):
            disc_ev = EvidenceRecord.from_dict(data["discovery_evidence"])

        try:
            st = HostStatus(data.get("status", "REACHABLE"))
        except ValueError:
            st = HostStatus.REACHABLE

        return cls(
            ip=data["ip"],
            hostname=data.get("hostname", ""),
            status=st,
            os_hint=data.get("os_hint", ""),
            mac_address=data.get("mac_address", ""),
            vendor=data.get("vendor", ""),
            latency_ms=data.get("latency_ms", 0.0),
            ports=ports_dict,
            findings=findings_list,
            discovery_evidence=disc_ev,
        )
