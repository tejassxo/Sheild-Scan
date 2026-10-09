"""Service model for ShieldScan.
Represents an identified network service with protocol, product, version and banner.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
from src.models.evidence import EvidenceRecord, ConfidenceLevel


@dataclass
class ServiceInfo:
    """Detailed identification of a network service."""
    name: str                       # Generic name, e.g. "HTTP", "SSH", "MySQL"
    product: str = ""               # Detected software product, e.g. "Apache httpd", "OpenSSH"
    version: str = ""               # Detected version string, e.g. "2.4.52", "8.9p1"
    banner: str = ""                # Cleaned banner string
    tunnel: str = ""                # e.g. "TLS", "SSL" if encrypted
    evidence: Optional[EvidenceRecord] = None
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH
    cpe: str = ""                   # Common Platform Enumeration string if deduced

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "product": self.product,
            "version": self.version,
            "banner": self.banner,
            "tunnel": self.tunnel,
            "evidence": self.evidence.to_dict() if self.evidence else None,
            "confidence": self.confidence.value,
            "cpe": self.cpe,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ServiceInfo:
        ev_data = data.get("evidence")
        ev = EvidenceRecord.from_dict(ev_data) if ev_data else None
        try:
            conf = ConfidenceLevel(data.get("confidence", "HIGH"))
        except ValueError:
            conf = ConfidenceLevel.HIGH

        return cls(
            name=data.get("name", "Unknown"),
            product=data.get("product", ""),
            version=data.get("version", ""),
            banner=data.get("banner", ""),
            tunnel=data.get("tunnel", ""),
            evidence=ev,
            confidence=conf,
            cpe=data.get("cpe", ""),
        )
