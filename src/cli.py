"""Command Line Interface for ShieldScan.
Enables headless automated assessment, report generation, and pipeline testing.
Supports Full 65K scans, UDP, Scapy SYN/Xmas techniques, and custom port ranges.
"""

from __future__ import annotations
import argparse
import asyncio
import sys
from pathlib import Path
from src.models.scan_profile import (
    BUILTIN_PROFILES, ScanProfile, ScanTechnique, parse_port_range
)
from src.scanner.controller import ScanController
from src.storage.scan_store import ScanStore
from src.reporting.docx_report import generate_docx_report
from src.reporting.exporter import export_json, export_csv_bundle
from src.presentation.pptx_deck import generate_presentation


def run_cli():
    parser = argparse.ArgumentParser(description="ShieldScan — Modern Network Visibility Platform")
    parser.add_argument("--target", "-t", default="127.0.0.1", help="Target IP, hostname, CIDR, or range")
    parser.add_argument("--profile", "-p", default="quick_discovery",
                        choices=["quick_discovery", "standard_assessment", "full_65k", "extended_inventory", "udp_services"],
                        help="Scan profile")
    parser.add_argument("--technique", choices=["connect", "syn", "udp", "xmas", "fin", "null"],
                        default="connect", help="Scan technique (Nmap equivalents: connect=-sT, syn=-sS, udp=-sU, xmas=-sX)")
    parser.add_argument("--ports", help="Custom ports specification, e.g. '1-65535' or '80,443,8000-8080'")
    parser.add_argument("--concurrency", "-c", type=int, default=800, help="Parallel worker concurrency limit (default 800)")
    parser.add_argument("--timeout", type=float, default=0.20, help="Probe socket timeout in seconds (default 0.20)")
    parser.add_argument("--docx", action="store_true", help="Generate Word (.docx) assessment report")
    parser.add_argument("--pptx", action="store_true", help="Generate PowerPoint (.pptx) presentation")
    parser.add_argument("--json", action="store_true", help="Export canonical JSON model")
    parser.add_argument("--csv", action="store_true", help="Export CSV bundle")
    parser.add_argument("--outdir", "-o", default=None, help="Output directory for generated files")
    args = parser.parse_args()

    # Map technique
    tech_map = {
        "connect": ScanTechnique.TCP_CONNECT,
        "syn":     ScanTechnique.STEALTH_SYN,
        "udp":     ScanTechnique.UDP_SWEEP,
        "xmas":    ScanTechnique.XMAS_SCAN,
        "fin":     ScanTechnique.FIN_SCAN,
        "null":    ScanTechnique.NULL_SCAN,
    }
    selected_tech = tech_map.get(args.technique, ScanTechnique.TCP_CONNECT)

    # Determine ports
    if args.ports:
        ports = parse_port_range(args.ports)
        profile_name = f"Custom ({len(ports):,} ports)"
        profile_id = "custom"
    else:
        selected_prof = next(p for p in BUILTIN_PROFILES if p.id == args.profile)
        ports = selected_prof.ports
        profile_name = selected_prof.name
        profile_id = selected_prof.id

    prof = ScanProfile(
        id=profile_id,
        name=profile_name,
        description=f"Scanning {len(ports):,} ports via {selected_tech.value}",
        scope_desc=f"{len(ports):,} ports via {selected_tech.value}",
        depth_desc="Deep service fingerprinting",
        resource_desc=f"{args.concurrency} concurrent workers",
        ports=ports,
        technique=selected_tech,
        timeout=args.timeout,
        concurrency=args.concurrency,
        discover_hosts=True,
        deep_service_detection=True,
    )

    print(f"[*] Starting ShieldScan assessment against '{args.target}' [{prof.name}]...")
    print(f"    Technique:   {selected_tech.value}")
    print(f"    Port Count:  {len(ports):,} ports")
    print(f"    Concurrency: {args.concurrency} workers | Timeout: {args.timeout}s")

    controller = ScanController(
        target_spec=args.target,
        profile=prof,
        on_status=lambda s: print(f"    [STATUS] {s}"),
        on_progress=lambda d, t, pct, speed: print(f"    [PROGRESS] {d:,}/{t:,} ports ({pct:.1f}%) · {speed:,.0f} ports/s", end="\r", flush=True),
    )

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    result = loop.run_until_complete(controller.run())
    loop.close()

    print(f"\n[+] Assessment Complete! Duration: {result.duration_seconds:.2f}s")
    print(f"    Alive Hosts: {result.stats.reachable_hosts}/{result.stats.total_hosts}")
    print(f"    Open Ports:  {result.stats.open_ports}")
    print(f"    Services:    {result.stats.services_identified}")
    print(f"    Findings:    {result.stats.total_findings} (High: {result.stats.findings_by_severity.get('HIGH',0)})")

    # Persist
    store = ScanStore()
    store.save(result)

    base_out = Path(args.outdir) if args.outdir else Path(".")

    if args.docx:
        d_path = base_out / "reports" / "generated" / f"ShieldScan_Assessment_{result.id}.docx"
        generate_docx_report(result, d_path)
        print(f"[+] DOCX Report generated: {d_path}")

    if args.pptx:
        p_path = base_out / "presentations" / "generated" / f"ShieldScan_Presentation_{result.id}.pptx"
        generate_presentation(result, p_path)
        print(f"[+] PPTX Deck generated: {p_path}")

    if args.json:
        j_path = base_out / "exports" / "json" / f"shieldscan_{result.id}.json"
        export_json(result, j_path)
        print(f"[+] JSON model exported: {j_path}")

    if args.csv:
        c_dir = base_out / "exports" / "csv"
        export_csv_bundle(result, c_dir)
        print(f"[+] CSV bundle exported to: {c_dir}")


if __name__ == "__main__":
    run_cli()
