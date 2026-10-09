"""Automated Test Suite for ShieldScan.
Tests target parsing, 65K port range parsing, models, discovery, findings, change detection, and reporting.
"""

from __future__ import annotations
import asyncio
from pathlib import Path
import unittest

from src.models.evidence import EvidenceRecord, ConfidenceLevel
from src.models.finding import Finding, FindingSeverity, FindingCategory
from src.models.port import PortRecord, PortState, TransportProtocol
from src.models.service import ServiceInfo
from src.models.host import HostRecord, HostStatus
from src.models.assessment import ScanResult, ScanStats
from src.models.scan_profile import BUILTIN_PROFILES, ScanTechnique, parse_port_range
from src.scanner.target_parser import parse_targets
from src.analysis.findings_engine import analyze_host_findings
from src.analysis.vuln_intel import check_potential_vulnerabilities
from src.analysis.change_detector import compare_assessments
from src.storage.scan_store import ScanStore
from src.reporting.docx_report import generate_docx_report
from src.reporting.exporter import export_json, export_csv_bundle
from src.presentation.pptx_deck import generate_presentation


class TestShieldScan(unittest.TestCase):

    def test_target_parser(self):
        # Single IP
        res1 = parse_targets("127.0.0.1")
        self.assertEqual(len(res1), 1)
        self.assertEqual(res1[0][0], "127.0.0.1")

        # CIDR expansion
        res2 = parse_targets("192.168.1.0/30")
        self.assertEqual(len(res2), 2)  # .1 and .2 are host addresses

        # Range expansion
        res3 = parse_targets("10.0.0.1-10.0.0.3")
        self.assertEqual(len(res3), 3)

    def test_port_range_and_65k_profile(self):
        # 65k port parsing
        all_ports = parse_port_range("1-65535")
        self.assertEqual(len(all_ports), 65535)
        self.assertEqual(all_ports[0], 1)
        self.assertEqual(all_ports[-1], 65535)

        # Discontinuous range
        custom = parse_port_range("21-25, 80, 443, 8000-8005")
        self.assertEqual(len(custom), 5 + 1 + 1 + 6)
        self.assertIn(80, custom)
        self.assertIn(443, custom)
        self.assertIn(8003, custom)

        # Builtin 65K profile verification
        full_prof = next((p for p in BUILTIN_PROFILES if p.id == "full_65k"), None)
        self.assertIsNotNone(full_prof)
        self.assertEqual(len(full_prof.ports), 65535)

    def test_canonical_model_and_stats(self):
        res = ScanResult(target="192.168.1.1")
        host = HostRecord(ip="192.168.1.1", status=HostStatus.REACHABLE)
        
        # Add open port
        p80 = PortRecord(
            port=80,
            protocol=TransportProtocol.TCP,
            state=PortState.OPEN,
            service=ServiceInfo(name="HTTP", product="Apache", version="2.4.50"),
            latency_ms=12.5
        )
        # Add closed port
        p81 = PortRecord(port=81, state=PortState.CLOSED)

        host.ports[80] = p80
        host.ports[81] = p81
        res.hosts["192.168.1.1"] = host

        # Recompute stats
        res.recompute_stats()
        self.assertEqual(res.stats.total_hosts, 1)
        self.assertEqual(res.stats.reachable_hosts, 1)
        self.assertEqual(res.stats.open_ports, 1)
        self.assertEqual(res.stats.closed_ports, 1)
        self.assertEqual(res.stats.services_identified, 1)

        # JSON Round-trip
        json_str = res.to_json()
        loaded = ScanResult.from_json(json_str)
        self.assertEqual(loaded.target, "192.168.1.1")
        self.assertEqual(loaded.stats.open_ports, 1)

    def test_findings_engine(self):
        host = HostRecord(ip="192.168.1.50", status=HostStatus.REACHABLE)
        # Telnet
        p23 = PortRecord(
            port=23,
            state=PortState.OPEN,
            service=ServiceInfo(name="Telnet"),
            evidence=EvidenceRecord(probe_type="TCP_CONNECT", observation="Telnet connected")
        )
        host.ports[23] = p23

        findings = analyze_host_findings(host)
        self.assertTrue(any(f.severity == FindingSeverity.HIGH for f in findings))
        self.assertTrue(any(f.category == FindingCategory.UNENCRYPTED_COMMUNICATION for f in findings))

    def test_change_detection(self):
        s1 = ScanResult(id="scan_1", target="192.168.1.0/24")
        h1 = HostRecord(ip="192.168.1.10", status=HostStatus.REACHABLE)
        h1.ports[80] = PortRecord(port=80, state=PortState.OPEN, service=ServiceInfo(name="HTTP"))
        s1.hosts["192.168.1.10"] = h1

        s2 = ScanResult(id="scan_2", target="192.168.1.0/24")
        h1_updated = HostRecord(ip="192.168.1.10", status=HostStatus.REACHABLE)
        h1_updated.ports[80] = PortRecord(port=80, state=PortState.OPEN, service=ServiceInfo(name="HTTP"))
        h1_updated.ports[443] = PortRecord(port=443, state=PortState.OPEN, service=ServiceInfo(name="HTTPS"))
        h2 = HostRecord(ip="192.168.1.20", status=HostStatus.REACHABLE)
        s2.hosts["192.168.1.10"] = h1_updated
        s2.hosts["192.168.1.20"] = h2

        diff = compare_assessments(s1, s2)
        self.assertIn("192.168.1.20", diff.new_hosts)
        self.assertEqual(len(diff.new_open_ports), 1)
        self.assertEqual(diff.new_open_ports[0].port, 443)

    def test_docx_and_pptx_generation(self):
        test_dir = Path("C:/Users/tejas/.gemini/antigravity-ide/scratch/ShieldScan/reports/generated")
        test_dir.mkdir(parents=True, exist_ok=True)

        res = ScanResult(id="test_scan", target="127.0.0.1", duration_seconds=1.25)
        h = HostRecord(ip="127.0.0.1", hostname="localhost", status=HostStatus.REACHABLE)
        h.ports[80] = PortRecord(
            port=80, state=PortState.OPEN,
            service=ServiceInfo(name="HTTP", product="Python http.server", version="3.13"),
            evidence=EvidenceRecord(probe_type="HTTP_HEAD", observation="HTTP 200 OK")
        )
        h.findings = analyze_host_findings(h)
        res.hosts["127.0.0.1"] = h
        res.recompute_stats()

        # Generate DOCX
        docx_path = test_dir / "test_report.docx"
        out_docx = generate_docx_report(res, docx_path)
        self.assertTrue(out_docx.exists())
        self.assertGreater(out_docx.stat().st_size, 5000)

        # Generate PPTX
        pptx_path = test_dir / "test_presentation.pptx"
        out_pptx = generate_presentation(res, pptx_path)
        self.assertTrue(out_pptx.exists())
        self.assertGreater(out_pptx.stat().st_size, 10000)


if __name__ == "__main__":
    unittest.main()
