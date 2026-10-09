"""Scan Controller for ShieldScan.
Coordinates discovery, multi-technique port enumeration, service detection, analysis, and result packaging.
"""

from __future__ import annotations
import asyncio
from datetime import datetime
import time
from typing import Callable, Dict, List, Optional
from src.models.assessment import ScanResult
from src.models.scan_profile import ScanProfile, BUILTIN_PROFILES, ScanTechnique
from src.models.host import HostRecord, HostStatus
from src.models.port import PortRecord
from src.scanner.target_parser import parse_targets
from src.scanner.discovery import probe_host_alive
from src.scanner.port_scanner import scan_host_ports
from src.analysis.findings_engine import analyze_host_findings


class ScanController:
    """Orchestrates an end-to-end network security assessment."""

    def __init__(
        self,
        target_spec: str,
        profile: ScanProfile,
        on_status: Optional[Callable[[str], None]] = None,
        on_progress: Optional[Callable[[int, int, float, float], None]] = None,
        on_host_discovered: Optional[Callable[[HostRecord], None]] = None,
        on_port_result: Optional[Callable[[str, PortRecord], None]] = None,
        on_finished: Optional[Callable[[ScanResult], None]] = None,
        on_error: Optional[Callable[[str], None]] = None,
    ):
        self.target_spec = target_spec.strip()
        self.profile = profile
        self.on_status = on_status
        self.on_progress = on_progress
        self.on_host_discovered = on_host_discovered
        self.on_port_result = on_port_result
        self.on_finished = on_finished
        self.on_error = on_error

        self._stop_event = asyncio.Event()
        self._paused = False
        self._current_result: Optional[ScanResult] = None
        self._t_start: float = 0.0

    def stop(self) -> None:
        """Signals active workers to stop safely."""
        self._paused = False
        self._stop_event.set()
        if self.on_status:
            self.on_status("Cancelling scan gracefully…")

    def pause(self) -> None:
        self._paused = True
        if self.on_status:
            self.on_status("Scan paused.")

    def resume(self) -> None:
        self._paused = False
        if self.on_status:
            self.on_status("Scan resumed.")

    @property
    def is_paused(self) -> bool:
        return self._paused

    @property
    def is_cancelled(self) -> bool:
        return self._stop_event.is_set()

    async def run(self) -> ScanResult:
        """Executes full assessment pipeline."""
        self._t_start = time.perf_counter()
        started_iso = datetime.now().isoformat()

        result = ScanResult(
            target=self.target_spec,
            profile_id=self.profile.id,
            profile_name=self.profile.name,
            started_at=started_iso,
            config_summary={
                "technique": self.profile.technique.value,
                "timeout": self.profile.timeout,
                "concurrency": self.profile.concurrency,
                "ports_count": len(self.profile.ports),
                "discover_hosts": self.profile.discover_hosts,
                "deep_service": self.profile.deep_service_detection,
            }
        )
        self._current_result = result

        try:
            # 1. Target Resolution
            if self.on_status:
                self.on_status(f"Resolving targets for '{self.target_spec}'…")
            target_list = parse_targets(self.target_spec)
            if not target_list:
                raise ValueError(f"Unable to parse or resolve any valid targets from '{self.target_spec}'")

            result.target_hosts_count = len(target_list)

            # 2. Host Discovery
            active_hosts: List[HostRecord] = []
            if self.profile.discover_hosts and len(target_list) > 1:
                if self.on_status:
                    self.on_status(f"Discovering reachable hosts among {len(target_list)} targets…")

                for ip, label in target_list:
                    if self._stop_event.is_set():
                        break
                    while self._paused:
                        await asyncio.sleep(0.1)

                    h = await probe_host_alive(ip, label, timeout=self.profile.timeout)
                    result.hosts[ip] = h
                    if self.on_host_discovered:
                        self.on_host_discovered(h)
                    if h.status == HostStatus.REACHABLE:
                        active_hosts.append(h)
            else:
                # Single host or discovery bypassed
                for ip, label in target_list:
                    h = HostRecord(ip=ip, hostname=label, status=HostStatus.REACHABLE)
                    result.hosts[ip] = h
                    active_hosts.append(h)
                    if self.on_host_discovered:
                        self.on_host_discovered(h)

            if self._stop_event.is_set():
                result.status = "CANCELLED"
                result.duration_seconds = time.perf_counter() - self._t_start
                result.completed_at = datetime.now().isoformat()
                result.recompute_stats()
                if self.on_finished:
                    self.on_finished(result)
                return result

            # 3. Port Enumeration & Service Detection
            total_target_ports = len(active_hosts) * len(self.profile.ports)
            cumulative_done = 0

            for host in active_hosts:
                if self._stop_event.is_set():
                    break

                if self.on_status:
                    self.on_status(f"Scanning {host.ip} ({len(self.profile.ports):,} ports via {self.profile.technique.value})…")

                def _host_port_cb(p_rec: PortRecord, h_ip=host.ip):
                    if self.on_port_result:
                        self.on_port_result(h_ip, p_rec)

                def _host_prog_cb(done_h: int, total_h: int, pct_h: float, speed_h: float):
                    current_total = cumulative_done + done_h
                    pct = (current_total / total_target_ports * 100.0) if total_target_ports else 100.0
                    if self.on_progress:
                        self.on_progress(current_total, total_target_ports, pct, speed_h)

                port_map = await scan_host_ports(
                    host=host.ip,
                    ports=self.profile.ports,
                    technique=self.profile.technique,
                    timeout=self.profile.timeout,
                    concurrency=self.profile.concurrency,
                    deep_service=self.profile.deep_service_detection,
                    on_port_result=_host_port_cb,
                    on_progress=_host_prog_cb,
                    stop_event=self._stop_event,
                    pause_fn=lambda: self._paused,
                )
                host.ports.update(port_map)
                cumulative_done += len(self.profile.ports)

                # 4. Findings & Vulnerability Analysis
                if self.on_status:
                    self.on_status(f"Analyzing security findings for {host.ip}…")
                host_findings = analyze_host_findings(host)
                host.findings = host_findings

            # 5. Finalize Result
            result.duration_seconds = time.perf_counter() - self._t_start
            result.completed_at = datetime.now().isoformat()
            result.status = "CANCELLED" if self._stop_event.is_set() else "COMPLETED"
            result.recompute_stats()

            if self.on_status:
                self.on_status(f"Scan complete — {result.stats.open_ports} open ports across {result.stats.reachable_hosts} alive hosts in {result.duration_seconds:.2f}s")

            if self.on_finished:
                self.on_finished(result)

            return result

        except Exception as exc:
            err_msg = f"{type(exc).__name__}: {str(exc)}"
            if self.on_error:
                self.on_error(err_msg)
            result.status = "FAILED"
            result.notes = err_msg
            result.duration_seconds = time.perf_counter() - self._t_start
            result.completed_at = datetime.now().isoformat()
            result.recompute_stats()
            return result
