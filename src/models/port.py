"""Port result model for ShieldScan.
"""

from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional
from src.models.service import ServiceInfo
from src.models.evidence import EvidenceRecord


class PortState(str, Enum):
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    FILTERED = "FILTERED"
    UNTESTED = "UNTESTED"


class TransportProtocol(str, Enum):
    TCP = "TCP"
    UDP = "UDP"


@dataclass
class PortRecord:
    """Status and attributes of an individual network port on a host."""
    port: int
    protocol: TransportProtocol = TransportProtocol.TCP
    state: PortState = PortState.FILTERED
    service: Optional[ServiceInfo] = None
    latency_ms: float = 0.0
    evidence: Optional[EvidenceRecord] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "port": self.port,
            "protocol": self.protocol.value,
            "state": self.state.value,
            "service": self.service.to_dict() if self.service else None,
            "latency_ms": round(self.latency_ms, 2),
            "evidence": self.evidence.to_dict() if self.evidence else None,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PortRecord:
        svc_data = data.get("service")
        svc = ServiceInfo.from_dict(svc_data) if svc_data else None
        
        ev_data = data.get("evidence")
        ev = EvidenceRecord.from_dict(ev_data) if ev_data else None

        try:
            proto = TransportProtocol(data.get("protocol", "TCP"))
        except ValueError:
            proto = TransportProtocol.TCP

        try:
            st = PortState(data.get("state", "FILTERED"))
        except ValueError:
            st = PortState.FILTERED

        return cls(
            port=data["port"],
            protocol=proto,
            state=st,
            service=svc,
            latency_ms=data.get("latency_ms", 0.0),
            evidence=ev,
        )
