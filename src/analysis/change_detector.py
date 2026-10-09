"""Historical Change Detection Engine for ShieldScan.
Compares two canonical ScanResult assessments and detects host, port, service, and finding differentials.
"""

from __future__ import annotations
from typing import Dict, Set
from src.models.assessment import ScanResult
from src.models.comparison import (
    ScanComparison, PortChange, ServiceChange, FindingChange
)
from src.models.port import PortState


def compare_assessments(baseline: ScanResult, current: ScanResult) -> ScanComparison:
    """
    Computes precise delta between a baseline assessment and a current assessment.
    Identifies:
      - New & removed hosts
      - New open ports & newly closed/filtered ports
      - Changed services and updated versions
      - New findings & resolved findings
    """
    comparison = ScanComparison(
        baseline_id=baseline.id,
        baseline_target=baseline.target,
        baseline_time=baseline.started_at,
        current_id=current.id,
        current_target=current.target,
        current_time=current.started_at,
    )

    baseline_ips: Set[str] = set(baseline.hosts.keys())
    current_ips: Set[str] = set(current.hosts.keys())

    comparison.new_hosts = sorted(list(current_ips - baseline_ips))
    comparison.removed_hosts = sorted(list(baseline_ips - current_ips))
    comparison.retained_hosts = sorted(list(baseline_ips & current_ips))

    # Port changes across common hosts
    for ip in comparison.retained_hosts:
        base_h = baseline.hosts[ip]
        curr_h = current.hosts[ip]

        base_open_ports = {p.port: p for p in base_h.open_ports}
        curr_open_ports = {p.port: p for p in curr_h.open_ports}

        # Newly opened ports
        for p_num, p_rec in curr_open_ports.items():
            if p_num not in base_open_ports:
                svc_str = p_rec.service.name if p_rec.service else "Unknown"
                comparison.new_open_ports.append(PortChange(
                    host=ip,
                    port=p_num,
                    protocol=p_rec.protocol.value,
                    old_state="CLOSED/FILTERED",
                    new_state="OPEN",
                    service=svc_str,
                ))

        # Closed ports
        for p_num, p_rec in base_open_ports.items():
            if p_num not in curr_open_ports:
                svc_str = p_rec.service.name if p_rec.service else "Unknown"
                comparison.closed_ports.append(PortChange(
                    host=ip,
                    port=p_num,
                    protocol=p_rec.protocol.value,
                    old_state="OPEN",
                    new_state="CLOSED/FILTERED",
                    service=svc_str,
                ))

        # Service version updates on continuously open ports
        for p_num in (set(base_open_ports.keys()) & set(curr_open_ports.keys())):
            b_svc = base_open_ports[p_num].service
            c_svc = curr_open_ports[p_num].service
            if b_svc and c_svc:
                if (b_svc.product != c_svc.product) or (b_svc.version != c_svc.version):
                    comparison.service_changes.append(ServiceChange(
                        host=ip,
                        port=p_num,
                        old_service=b_svc.product or b_svc.name,
                        new_service=c_svc.product or c_svc.name,
                        old_version=b_svc.version,
                        new_version=c_svc.version,
                    ))

    # Finding differential
    base_findings_map = {f.title + f.host: f for f in baseline.all_findings}
    curr_findings_map = {f.title + f.host: f for f in current.all_findings}

    for key, f in curr_findings_map.items():
        if key not in base_findings_map:
            comparison.new_findings.append(FindingChange(
                finding_id=f.id,
                title=f.title,
                host=f.host,
                severity=f.severity.value,
                status="NEW",
            ))
        else:
            comparison.retained_findings.append(FindingChange(
                finding_id=f.id,
                title=f.title,
                host=f.host,
                severity=f.severity.value,
                status="PERSISTENT",
            ))

    for key, f in base_findings_map.items():
        if key not in curr_findings_map:
            comparison.resolved_findings.append(FindingChange(
                finding_id=f.id,
                title=f.title,
                host=f.host,
                severity=f.severity.value,
                status="RESOLVED",
            ))

    return comparison
