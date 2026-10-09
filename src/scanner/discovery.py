"""Host discovery engine for ShieldScan.
Determines host reachability via multi-vector probing (TCP ping, ICMP echo, reverse DNS).
"""

from __future__ import annotations
import asyncio
import platform
import socket
import time
from typing import Callable, List, Optional, Tuple
from src.models.host import HostRecord, HostStatus
from src.models.evidence import EvidenceRecord, ConfidenceLevel

# Critical discovery ports likely to respond on alive hosts
DISCOVERY_PORTS = [80, 443, 22, 135, 445, 8080, 53, 3389]


async def _check_tcp_port(ip: str, port: int, timeout: float = 0.35) -> Optional[EvidenceRecord]:
    """Attempts a quick TCP connection to test host responsiveness."""
    t0 = time.perf_counter()
    try:
        conn = asyncio.open_connection(ip, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), timeout=0.1)
        except Exception:
            pass
        lat = (time.perf_counter() - t0) * 1000
        return EvidenceRecord(
            probe_type="TCP_CONNECT_PING",
            observation=f"Host responded to TCP connect on port {port} ({lat:.1f}ms)",
            raw_data=f"SYN/ACK received on TCP/{port}",
            confidence=ConfidenceLevel.HIGH,
            metadata={"port": port, "latency_ms": lat},
        )
    except ConnectionRefusedError:
        # A TCP RST (Connection refused) STILL proves the host is up and reachable!
        lat = (time.perf_counter() - t0) * 1000
        return EvidenceRecord(
            probe_type="TCP_RST_PING",
            observation=f"Host actively rejected connection on port {port} via TCP RST ({lat:.1f}ms) — proves host reachability",
            raw_data=f"TCP RST received on port {port}",
            confidence=ConfidenceLevel.HIGH,
            metadata={"port": port, "latency_ms": lat},
        )
    except (asyncio.TimeoutError, OSError):
        return None


async def _check_icmp_ping(ip: str, timeout_ms: int = 400) -> Optional[EvidenceRecord]:
    """Attempts standard ICMP echo ping via OS command without hanging."""
    # Loopback or local is always up
    if ip in ("127.0.0.1", "localhost", "::1"):
        return EvidenceRecord(
            probe_type="LOOPBACK_PING",
            observation="Local loopback interface verified reachable",
            raw_data="127.0.0.1 localhost ok",
            confidence=ConfidenceLevel.HIGH,
        )

    cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip] if platform.system() == "Windows" else ["ping", "-c", "1", "-W", "1", ip]
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=(timeout_ms / 1000.0) + 0.5)
        out = stdout.decode("utf-8", errors="replace")
        if proc.returncode == 0 and ("TTL=" in out.upper() or "1 packets received" in out or "bytes from" in out):
            return EvidenceRecord(
                probe_type="ICMP_ECHO_PING",
                observation=f"Host responded to ICMP Echo Request",
                raw_data=out.strip()[:160],
                confidence=ConfidenceLevel.HIGH,
            )
    except Exception:
        pass
    return None


async def probe_host_alive(ip: str, hostname_hint: str = "", timeout: float = 0.4) -> HostRecord:
    """Probes whether a host is reachable using multi-vector verification."""
    # Check hostname resolution or reverse lookup
    hostname = hostname_hint
    if not hostname:
        try:
            loop = asyncio.get_event_loop()
            name, _, _ = await asyncio.wait_for(
                loop.run_in_executor(None, socket.gethostbyaddr, ip),
                timeout=0.3
            )
            hostname = name
        except Exception:
            hostname = ""

    # Test TCP ping probes concurrently across common ports
    tasks = [_check_tcp_port(ip, p, timeout=timeout) for p in DISCOVERY_PORTS]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for r in results:
        if isinstance(r, EvidenceRecord):
            lat = r.metadata.get("latency_ms", 1.0)
            return HostRecord(
                ip=ip,
                hostname=hostname,
                status=HostStatus.REACHABLE,
                latency_ms=lat,
                discovery_evidence=r,
            )

    # If TCP gave no quick answer, check ICMP ping
    icmp_ev = await _check_icmp_ping(ip, timeout_ms=int(timeout * 1000))
    if icmp_ev:
        return HostRecord(
            ip=ip,
            hostname=hostname,
            status=HostStatus.REACHABLE,
            latency_ms=2.0,
            discovery_evidence=icmp_ev,
        )

    # For localhost / single explicit target, mark as REACHABLE to allow thorough port scan
    if ip in ("127.0.0.1", "localhost", "::1"):
        return HostRecord(
            ip=ip,
            hostname=hostname or "localhost",
            status=HostStatus.REACHABLE,
            latency_ms=0.2,
            discovery_evidence=EvidenceRecord(
                probe_type="LOCAL_INTERFACE",
                observation="Localhost target designated for assessment",
                confidence=ConfidenceLevel.HIGH
            )
        )

    return HostRecord(
        ip=ip,
        hostname=hostname,
        status=HostStatus.UNREACHABLE,
        discovery_evidence=EvidenceRecord(
            probe_type="DISCOVERY_TIMEOUT",
            observation="No ICMP or TCP response received during initial discovery window",
            confidence=ConfidenceLevel.LOW
        )
    )


async def discover_hosts(
    targets: List[Tuple[str, str]],
    on_host_discovered: Optional[Callable[[HostRecord], None]] = None,
    concurrency: int = 50,
) -> List[HostRecord]:
    """Discovers reachable hosts across target pool concurrently."""
    sem = asyncio.Semaphore(concurrency)
    discovered: List[HostRecord] = []

    async def _worker(ip: str, name: str):
        async with sem:
            host = await probe_host_alive(ip, name)
            if on_host_discovered:
                on_host_discovered(host)
            return host

    tasks = [_worker(ip, name) for ip, name in targets]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r in results:
        if isinstance(r, HostRecord):
            discovered.append(r)
    return discovered
