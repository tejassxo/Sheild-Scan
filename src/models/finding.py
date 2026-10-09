"""Security Finding model for ShieldScan.
Grounds every observation in evidence with strict severity classification.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional
from src.models.evidence import EvidenceRecord, ConfidenceLevel


class FindingSeverity(str, Enum):
    INFORMATIONAL = "INFORMATIONAL"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class FindingCategory(str, Enum):
    SERVICE_EXPOSURE = "SERVICE_EXPOSURE"
    UNENCRYPTED_COMMUNICATION = "UNENCRYPTED_COMMUNICATION"
    OUTDATED_SOFTWARE = "OUTDATED_SOFTWARE"
    DEFAULT_CONFIGURATION = "DEFAULT_CONFIGURATION"
    DATABASE_EXPOSURE = "DATABASE_EXPOSURE"
    ADMIN_INTERFACE = "ADMIN_INTERFACE"
    POLICY_VIOLATION = "POLICY_VIOLATION"


@dataclass
class Finding:
    """Security assessment finding derived directly from collected network evidence."""
    id: str                                # e.g. "SHIELD-2026-001"
    title: str
    severity: FindingSeverity
    category: FindingCategory
    host: str
    port: Optional[int] = None
    service: Optional[str] = None
    description: str = ""
    evidence: Optional[EvidenceRecord] = None
    impact: str = ""
    recommendation: str = ""
    cve_references: List[str] = field(default_factory=list)
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "category": self.category.value,
            "host": self.host,
            "port": self.port,
            "service": self.service,
            "description": self.description,
            "evidence": self.evidence.to_dict() if self.evidence else None,
            "impact": self.impact,
            "recommendation": self.recommendation,
            "cve_references": self.cve_references,
            "confidence": self.confidence.value,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Finding:
        ev_data = data.get("evidence")
        ev = EvidenceRecord.from_dict(ev_data) if ev_data else None
        
        try:
            sev = FindingSeverity(data.get("severity", "INFORMATIONAL"))
        except ValueError:
            sev = FindingSeverity.INFORMATIONAL
            
        try:
            cat = FindingCategory(data.get("category", "SERVICE_EXPOSURE"))
        except ValueError:
            cat = FindingCategory.SERVICE_EXPOSURE
            
        try:
            conf = ConfidenceLevel(data.get("confidence", "HIGH"))
        except ValueError:
            conf = ConfidenceLevel.HIGH

        return cls(
            id=data.get("id", "SHIELD-000"),
            title=data.get("title", ""),
            severity=sev,
            category=cat,
            host=data.get("host", ""),
            port=data.get("port"),
            service=data.get("service"),
            description=data.get("description", ""),
            evidence=ev,
            impact=data.get("impact", ""),
            recommendation=data.get("recommendation", ""),
            cve_references=data.get("cve_references", []),
            confidence=conf,
        )
