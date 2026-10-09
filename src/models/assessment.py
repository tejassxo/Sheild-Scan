"""Canonical ScanResult / Assessment model for ShieldScan.
Single Source of Truth across Dashboard, Host Explorer, Services, Findings, History, DOCX, and PPTX.
"""

from __future__ import annotations
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
from src.models.host import HostRecord, HostStatus
from src.models.port import PortRecord, PortState
from src.models.service import ServiceInfo
from src.models.finding import Finding, FindingSeverity


@dataclass
class ScanStats:
    total_hosts: int = 0
    reachable_hosts: int = 0
    total_ports_tested: int = 0
    open_ports: int = 0
    closed_ports: int = 0
    filtered_ports: int = 0
    services_identified: int = 0
    total_findings: int = 0
    findings_by_severity: Dict[str, int] = field(default_factory=lambda: {
        "INFORMATIONAL": 0,
        "LOW": 0,
        "MEDIUM": 0,
        "HIGH": 0,
    })

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_hosts": self.total_hosts,
            "reachable_hosts": self.reachable_hosts,
            "total_ports_tested": self.total_ports_tested,
            "open_ports": self.open_ports,
            "closed_ports": self.closed_ports,
            "filtered_ports": self.filtered_ports,
            "services_identified": self.services_identified,
            "total_findings": self.total_findings,
            "findings_by_severity": self.findings_by_severity,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ScanStats:
        return cls(
            total_hosts=data.get("total_hosts", 0),
            reachable_hosts=data.get("reachable_hosts", 0),
            total_ports_tested=data.get("total_ports_tested", 0),
            open_ports=data.get("open_ports", 0),
            closed_ports=data.get("closed_ports", 0),
            filtered_ports=data.get("filtered_ports", 0),
            services_identified=data.get("services_identified", 0),
            total_findings=data.get("total_findings", 0),
            findings_by_severity=data.get("findings_by_severity", {
                "INFORMATIONAL": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0
            }),
        )


@dataclass
class ScanResult:
    """Canonical assessment result representing a completed or active network scan."""
    id: str = field(default_factory=lambda: f"scan_{uuid.uuid4().hex[:8]}")
    target: str = ""                         # Target specification (IP, CIDR, hostname)
    target_hosts_count: int = 1
    profile_id: str = "standard_assessment"
    profile_name: str = "Standard Assessment"
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    completed_at: Optional[str] = None
    duration_seconds: float = 0.0
    status: str = "COMPLETED"                # PENDING, RUNNING, COMPLETED, CANCELLED, FAILED
    hosts: Dict[str, HostRecord] = field(default_factory=dict)
    stats: ScanStats = field(default_factory=ScanStats)
    config_summary: Dict[str, Any] = field(default_factory=dict)
    notes: str = ""

    def recompute_stats(self) -> None:
        """Derive all statistics deterministically from internal host and port data."""
        s = ScanStats()
        s.total_hosts = len(self.hosts)
        s.reachable_hosts = sum(1 for h in self.hosts.values() if h.status == HostStatus.REACHABLE)
        
        open_p = 0
        closed_p = 0
        filtered_p = 0
        svc_count = 0
        findings_count = 0
        sev_counts = {"INFORMATIONAL": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0}

        for h in self.hosts.values():
            for p in h.ports.values():
                s.total_ports_tested += 1
                if p.state == PortState.OPEN:
                    open_p += 1
                    if p.service and p.service.name:
                        svc_count += 1
                elif p.state == PortState.CLOSED:
                    closed_p += 1
                elif p.state == PortState.FILTERED:
                    filtered_p += 1

            for f in h.findings:
                findings_count += 1
                s_val = f.severity.value
                sev_counts[s_val] = sev_counts.get(s_val, 0) + 1

        s.open_ports = open_p
        s.closed_ports = closed_p
        s.filtered_ports = filtered_p
        s.services_identified = svc_count
        s.total_findings = findings_count
        s.findings_by_severity = sev_counts
        self.stats = s

    @property
    def all_findings(self) -> List[Finding]:
        res = []
        for h in self.hosts.values():
            res.extend(h.findings)
        return res

    @property
    def all_services(self) -> List[Dict[str, Any]]:
        services = []
        for h in self.hosts.values():
            for p in h.open_ports:
                if p.service:
                    services.append({
                        "host": h.ip,
                        "hostname": h.hostname,
                        "port": p.port,
                        "protocol": p.protocol.value,
                        "name": p.service.name,
                        "product": p.service.product,
                        "version": p.service.version,
                        "banner": p.service.banner,
                        "confidence": p.service.confidence.value,
                        "latency_ms": p.latency_ms,
                    })
        return services

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target,
            "target_hosts_count": self.target_hosts_count,
            "profile_id": self.profile_id,
            "profile_name": self.profile_name,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration_seconds": round(self.duration_seconds, 2),
            "status": self.status,
            "stats": self.stats.to_dict(),
            "config_summary": self.config_summary,
            "notes": self.notes,
            "hosts": {ip: h.to_dict() for ip, h in self.hosts.items()},
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ScanResult:
        hosts_dict = {}
        for ip, h_data in data.get("hosts", {}).items():
            hosts_dict[ip] = HostRecord.from_dict(h_data)

        stats = ScanStats.from_dict(data.get("stats", {}))

        return cls(
            id=data.get("id", "scan_unknown"),
            target=data.get("target", ""),
            target_hosts_count=data.get("target_hosts_count", 1),
            profile_id=data.get("profile_id", "standard_assessment"),
            profile_name=data.get("profile_name", "Standard Assessment"),
            started_at=data.get("started_at", datetime.now().isoformat()),
            completed_at=data.get("completed_at"),
            duration_seconds=data.get("duration_seconds", 0.0),
            status=data.get("status", "COMPLETED"),
            hosts=hosts_dict,
            stats=stats,
            config_summary=data.get("config_summary", {}),
            notes=data.get("notes", ""),
        )

    @classmethod
    def from_json(cls, json_str: str) -> ScanResult:
        return cls.from_dict(json.loads(json_str))
