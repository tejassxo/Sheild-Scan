"""Historical Scan Comparison and Change Detection model.
Tracks network evolution across time.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from src.models.assessment import ScanResult
from src.models.port import PortState


@dataclass
class HostChange:
    ip: str
    change_type: str        # "ADDED", "REMOVED", "UNCHANGED", "CHANGED"
    hostname: str = ""
    details: str = ""


@dataclass
class PortChange:
    host: str
    port: int
    protocol: str
    old_state: Optional[str]
    new_state: Optional[str]
    service: str = ""


@dataclass
class ServiceChange:
    host: str
    port: int
    old_service: str
    new_service: str
    old_version: str
    new_version: str


@dataclass
class FindingChange:
    finding_id: str
    title: str
    host: str
    severity: str
    status: str             # "NEW", "RESOLVED", "PERSISTENT"


@dataclass
class ScanComparison:
    """Detailed diff comparison between two assessments."""
    baseline_id: str
    baseline_target: str
    baseline_time: str
    current_id: str
    current_target: str
    current_time: str
    
    new_hosts: List[str] = field(default_factory=list)
    removed_hosts: List[str] = field(default_factory=list)
    retained_hosts: List[str] = field(default_factory=list)
    
    new_open_ports: List[PortChange] = field(default_factory=list)
    closed_ports: List[PortChange] = field(default_factory=list)
    
    service_changes: List[ServiceChange] = field(default_factory=list)
    
    new_findings: List[FindingChange] = field(default_factory=list)
    resolved_findings: List[FindingChange] = field(default_factory=list)
    retained_findings: List[FindingChange] = field(default_factory=list)

    @property
    def summary_metrics(self) -> Dict[str, Any]:
        return {
            "net_hosts": len(self.new_hosts) - len(self.removed_hosts),
            "new_hosts_count": len(self.new_hosts),
            "removed_hosts_count": len(self.removed_hosts),
            "new_open_ports_count": len(self.new_open_ports),
            "closed_ports_count": len(self.closed_ports),
            "service_changes_count": len(self.service_changes),
            "new_findings_count": len(self.new_findings),
            "resolved_findings_count": len(self.resolved_findings),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "baseline_id": self.baseline_id,
            "baseline_target": self.baseline_target,
            "baseline_time": self.baseline_time,
            "current_id": self.current_id,
            "current_target": self.current_target,
            "current_time": self.current_time,
            "summary_metrics": self.summary_metrics,
            "new_hosts": self.new_hosts,
            "removed_hosts": self.removed_hosts,
            "new_open_ports": [
                {"host": p.host, "port": p.port, "protocol": p.protocol, "service": p.service}
                for p in self.new_open_ports
            ],
            "closed_ports": [
                {"host": p.host, "port": p.port, "protocol": p.protocol, "service": p.service}
                for p in self.closed_ports
            ],
            "service_changes": [
                {
                    "host": s.host, "port": s.port,
                    "old": f"{s.old_service} {s.old_version}".strip(),
                    "new": f"{s.new_service} {s.new_version}".strip(),
                }
                for s in self.service_changes
            ],
            "new_findings": [
                {"id": f.finding_id, "title": f.title, "host": f.host, "severity": f.severity}
                for f in self.new_findings
            ],
            "resolved_findings": [
                {"id": f.finding_id, "title": f.title, "host": f.host, "severity": f.severity}
                for f in self.resolved_findings
            ],
        }
