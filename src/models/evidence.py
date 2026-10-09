"""Evidence models for ShieldScan.
Traceable evidence collection for network discoveries and security findings.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional


class ConfidenceLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    UNKNOWN = "UNKNOWN"


@dataclass
class EvidenceRecord:
    """Represents concrete, auditable evidence supporting an observation."""
    probe_type: str                  # e.g., "TCP_CONNECT", "TLS_CLIENT_HELLO", "BANNER_GRAB", "HTTP_REQUEST"
    observation: str                 # Human readable observation
    raw_data: str = ""               # Truncated raw banner, hex payload or response header
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "probe_type": self.probe_type,
            "observation": self.observation,
            "raw_data": self.raw_data,
            "confidence": self.confidence.value if isinstance(self.confidence, ConfidenceLevel) else str(self.confidence),
            "timestamp": self.timestamp,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EvidenceRecord:
        conf_str = data.get("confidence", "UNKNOWN")
        try:
            conf = ConfidenceLevel(conf_str)
        except ValueError:
            conf = ConfidenceLevel.UNKNOWN
        return cls(
            probe_type=data.get("probe_type", "UNKNOWN"),
            observation=data.get("observation", ""),
            raw_data=data.get("raw_data", ""),
            confidence=conf,
            timestamp=data.get("timestamp", datetime.now().isoformat()),
            metadata=data.get("metadata", {}),
        )
