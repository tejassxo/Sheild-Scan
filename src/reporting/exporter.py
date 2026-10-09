"""Export utilities for ShieldScan.
Generates structured JSON and CSV exports from canonical ScanResult models.
"""

from __future__ import annotations
import csv
from pathlib import Path
from typing import Dict, List, Tuple
from src.models.assessment import ScanResult
from src.models.port import PortState


def export_json(scan_result: ScanResult, output_path: Path) -> Path:
    """Exports assessment result to structured JSON file."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(scan_result.to_json(indent=2))
    return output_path


def export_csv_bundle(scan_result: ScanResult, output_dir: Path) -> Dict[str, Path]:
    """
    Exports a suite of clean CSV tables:
      1. hosts.csv
      2. ports_services.csv
      3. findings.csv
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    paths = {}

    # 1. Hosts CSV
    hosts_path = output_dir / f"{scan_result.id}_hosts.csv"
    with open(hosts_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["IP", "Hostname", "Status", "Latency_ms", "Open_Ports", "Closed_Ports", "Filtered_Ports", "Findings_Count"])
        for h in scan_result.hosts.values():
            writer.writerow([
                h.ip,
                h.hostname or "—",
                h.status.value,
                f"{h.latency_ms:.2f}",
                len(h.open_ports),
                len(h.closed_ports),
                len(h.filtered_ports),
                len(h.findings),
            ])
    paths["hosts"] = hosts_path

    # 2. Ports and Services CSV
    ports_path = output_dir / f"{scan_result.id}_ports_services.csv"
    with open(ports_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Host", "Port", "Protocol", "State", "Service", "Product", "Version", "Confidence", "Latency_ms", "Banner"])
        for h in scan_result.hosts.values():
            for p in h.ports.values():
                svc = p.service
                writer.writerow([
                    h.ip,
                    p.port,
                    p.protocol.value,
                    p.state.value,
                    svc.name if svc else "—",
                    svc.product if svc else "—",
                    svc.version if svc else "—",
                    svc.confidence.value if svc else "—",
                    f"{p.latency_ms:.2f}",
                    svc.banner.replace("\n", " ") if svc and svc.banner else "—",
                ])
    paths["ports_services"] = ports_path

    # 3. Findings CSV
    findings_path = output_dir / f"{scan_result.id}_findings.csv"
    with open(findings_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["Finding_ID", "Severity", "Host", "Port", "Service", "Title", "Category", "Confidence", "CVE_References", "Recommendation"])
        for f_item in scan_result.all_findings:
            writer.writerow([
                f_item.id,
                f_item.severity.value,
                f_item.host,
                f_item.port or "—",
                f_item.service or "—",
                f_item.title,
                f_item.category.value,
                f_item.confidence.value,
                ";".join(f_item.cve_references) if f_item.cve_references else "—",
                f_item.recommendation,
            ])
    paths["findings"] = findings_path

    return paths
