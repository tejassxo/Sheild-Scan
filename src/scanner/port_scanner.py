"""High-performance multi-technique port scanner for ShieldScan.
Supports TCP Connect, Stealth SYN, UDP Service Sweep, Xmas, FIN, and Null scans.
Features ultra-fast async batching capable of scanning all 65,535 ports in seconds.
"""

from __future__ import annotations
import asyncio
import os
import random
import socket
import time
from typing import Callable, Dict, List, Optional
from src.models.port import PortRecord, PortState, TransportProtocol
from src.models.scan_profile import ScanTechnique
from src.models.evidence import EvidenceRecord, ConfidenceLevel
from src.scanner.service_detector import detect_service

# Scapy optional import
try:
    os.environ.setdefault("SCAPY_OUTPUT_LOCK", "1")
    from scapy.all import IP, TCP, UDP, ICMP, sr1, send, conf as scapy_conf
    scapy_conf.verb = 0
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

UDP_PAYLOADS = {
    53:   b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
    123:  b"\x1b" + b"\x00" * 47,
    137:  b"\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01",
    161:  b"\x30\x26\x02\x01\x00\x04\x06public\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00",
    1900: b"M-SEARCH * HTTP/1.1\r\nHost: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n",
    5353: b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05local\x00\x00\xff\x00\x01",
}


# ─────────────────────────────────────────────────────────────────────────────
# 1. TCP CONNECT PROBE (HIGH-SPEED ASYNC SOCKET)
# ─────────────────────────────────────────────────────────────────────────────
async def _probe_tcp_connect(
    host: str,
    port: int,
    timeout: float,
    sem: asyncio.Semaphore,
    deep_service: bool = True,
) -> PortRecord:
    """Non-blocking TCP socket connect probe."""
    async with sem:
        t0 = time.perf_counter()
        try:
            conn = asyncio.open_connection(host, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout)
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=0.08)
            except Exception:
                pass
            lat = (time.perf_counter() - t0) * 1000

            port_ev = EvidenceRecord(
                probe_type="TCP_CONNECT_FULL",
                observation=f"Full TCP 3-way handshake accepted in {lat:.2f}ms",
                raw_data=f"Connection accepted on {host}:{port}",
                confidence=ConfidenceLevel.HIGH,
            )

            svc_info = await detect_service(host, port, timeout=min(0.5, timeout + 0.15)) if deep_service else None

            return PortRecord(
                port=port,
                protocol=TransportProtocol.TCP,
                state=PortState.OPEN,
                service=svc_info,
                latency_ms=lat,
                evidence=port_ev,
            )

        except ConnectionRefusedError:
            lat = (time.perf_counter() - t0) * 1000
            return PortRecord(
                port=port,
                protocol=TransportProtocol.TCP,
                state=PortState.CLOSED,
                latency_ms=lat,
                evidence=EvidenceRecord(
                    probe_type="TCP_RST",
                    observation=f"Target returned TCP RST in {lat:.2f}ms",
                    confidence=ConfidenceLevel.HIGH,
                )
            )
        except (asyncio.TimeoutError, OSError):
            lat = (time.perf_counter() - t0) * 1000
            return PortRecord(
                port=port,
                protocol=TransportProtocol.TCP,
                state=PortState.FILTERED,
                latency_ms=lat,
                evidence=EvidenceRecord(
                    probe_type="TIMEOUT_NO_RESPONSE",
                    observation=f"Filtered (no TCP response within {timeout:.2f}s)",
                    confidence=ConfidenceLevel.MEDIUM,
                )
            )


# ─────────────────────────────────────────────────────────────────────────────
# 2. UDP PROBE (SOCKET & SCAPY HYBRID)
# ─────────────────────────────────────────────────────────────────────────────
def _sync_udp_probe(host: str, port: int, timeout: float) -> PortRecord:
    """Performs UDP socket probe with payload analysis."""
    t0 = time.perf_counter()
    payload = UDP_PAYLOADS.get(port, b"\x00")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(timeout)
            s.sendto(payload, (host, port))
            try:
                data, _ = s.recvfrom(512)
                lat = (time.perf_counter() - t0) * 1000
                raw_preview = data[:60].decode("latin1", errors="replace")
                return PortRecord(
                    port=port,
                    protocol=TransportProtocol.UDP,
                    state=PortState.OPEN,
                    latency_ms=lat,
                    evidence=EvidenceRecord(
                        probe_type="UDP_RECV_RESPONSE",
                        observation=f"UDP response packet received on port {port} ({lat:.1f}ms)",
                        raw_data=raw_preview,
                        confidence=ConfidenceLevel.HIGH,
                    )
                )
            except socket.timeout:
                lat = (time.perf_counter() - t0) * 1000
                # In UDP, no response is either Open or Filtered (RFC 792)
                return PortRecord(
                    port=port,
                    protocol=TransportProtocol.UDP,
                    state=PortState.FILTERED,
                    latency_ms=lat,
                    evidence=EvidenceRecord(
                        probe_type="UDP_TIMEOUT_OPEN_FILTERED",
                        observation="UDP timeout (Open|Filtered)",
                        confidence=ConfidenceLevel.LOW,
                    )
                )
            except ConnectionResetError:
                lat = (time.perf_counter() - t0) * 1000
                return PortRecord(
                    port=port,
                    protocol=TransportProtocol.UDP,
                    state=PortState.CLOSED,
                    latency_ms=lat,
                )
    except Exception:
        lat = (time.perf_counter() - t0) * 1000
        return PortRecord(port=port, protocol=TransportProtocol.UDP, state=PortState.FILTERED, latency_ms=lat)


async def _probe_udp_async(host: str, port: int, timeout: float, sem: asyncio.Semaphore) -> PortRecord:
    async with sem:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _sync_udp_probe, host, port, timeout)


# ─────────────────────────────────────────────────────────────────────────────
# 3. SCAPY RAW PACKET PROBE (SYN, XMAS, FIN, NULL)
# ─────────────────────────────────────────────────────────────────────────────
def _scapy_raw_tcp_probe(host: str, port: int, timeout: float, flags: str, probe_name: str) -> PortRecord:
    """Sends raw Scapy TCP packet with custom flags (S, FPU, F, or empty)."""
    t0 = time.perf_counter()
    try:
        sport = random.randint(20000, 65000)
        pkt = IP(dst=host) / TCP(sport=sport, dport=port, flags=flags, seq=1000)
        resp = sr1(pkt, timeout=timeout, verbose=0)
        lat = (time.perf_counter() - t0) * 1000

        if resp is None:
            # If Xmas/Null/FIN: no response indicates OPEN|FILTERED
            if flags in ("FPU", "F", ""):
                return PortRecord(
                    port=port,
                    protocol=TransportProtocol.TCP,
                    state=PortState.OPEN,
                    latency_ms=lat,
                    evidence=EvidenceRecord(
                        probe_type=f"SCAPY_{probe_name}",
                        observation=f"No RST response returned to {flags} probe (RFC 793 open)",
                        confidence=ConfidenceLevel.MEDIUM,
                    )
                )
            return PortRecord(port=port, protocol=TransportProtocol.TCP, state=PortState.FILTERED, latency_ms=lat)

        if resp.haslayer(TCP):
            tcp_flags = resp[TCP].flags
            # SYN/ACK received -> Port is OPEN
            if tcp_flags & 0x12 == 0x12:
                # Send RST to tear down half-open connection politely
                send(IP(dst=host)/TCP(sport=sport, dport=port, flags="R", seq=resp[TCP].ack), verbose=0)
                return PortRecord(
                    port=port,
                    protocol=TransportProtocol.TCP,
                    state=PortState.OPEN,
                    latency_ms=lat,
                    evidence=EvidenceRecord(
                        probe_type="SCAPY_SYN_ACK",
                        observation=f"Stealth SYN received SYN/ACK ({lat:.1f}ms)",
                        confidence=ConfidenceLevel.HIGH,
                    )
                )
            # RST received -> Port is CLOSED
            if tcp_flags & 0x04:
                return PortRecord(port=port, protocol=TransportProtocol.TCP, state=PortState.CLOSED, latency_ms=lat)

        if resp.haslayer(ICMP) and resp[ICMP].type == 3:
            return PortRecord(port=port, protocol=TransportProtocol.TCP, state=PortState.FILTERED, latency_ms=lat)

    except Exception:
        pass

    lat = (time.perf_counter() - t0) * 1000
    return PortRecord(port=port, protocol=TransportProtocol.TCP, state=PortState.FILTERED, latency_ms=lat)


async def _probe_scapy_async(host: str, port: int, timeout: float, flags: str, name: str, sem: asyncio.Semaphore) -> PortRecord:
    async with sem:
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _scapy_raw_tcp_probe, host, port, timeout, flags, name)


# ─────────────────────────────────────────────────────────────────────────────
# MAIN SCAN ORCHESTRATION WITH FAST BATCHING
# ─────────────────────────────────────────────────────────────────────────────
async def scan_host_ports(
    host: str,
    ports: List[int],
    technique: ScanTechnique = ScanTechnique.TCP_CONNECT,
    timeout: float = 0.20,
    concurrency: int = 800,
    deep_service: bool = True,
    on_port_result: Optional[Callable[[PortRecord], None]] = None,
    on_progress: Optional[Callable[[int, int, float, float], None]] = None,  # (done, total, pct, speed)
    stop_event: Optional[asyncio.Event] = None,
    pause_fn: Optional[Callable[[], bool]] = None,
) -> Dict[int, PortRecord]:
    """
    Executes high-throughput port scan across specified ports.
    Optimized for smooth 60 FPS UI performance with batching and rate-limited GUI updates.
    """
    results: Dict[int, PortRecord] = {}
    total = len(ports)
    if total == 0:
        return results

    # Determine probe function
    use_scapy_raw = SCAPY_OK and technique in (
        ScanTechnique.STEALTH_SYN, ScanTechnique.XMAS_SCAN,
        ScanTechnique.FIN_SCAN, ScanTechnique.NULL_SCAN
    )

    # Adjust concurrency & batching for large scans
    actual_concurrency = max(50, min(concurrency, 1200))
    sem = asyncio.Semaphore(actual_concurrency)
    batch_size = 400 if total > 2000 else 100

    t_scan_start = time.perf_counter()
    last_ui_update = 0.0
    done = 0

    def _select_coro(p: int):
        if technique == ScanTechnique.UDP_SWEEP:
            return _probe_udp_async(host, p, timeout, sem)
        elif use_scapy_raw:
            flag_map = {
                ScanTechnique.STEALTH_SYN: ("S", "SYN"),
                ScanTechnique.XMAS_SCAN:   ("FPU", "XMAS"),
                ScanTechnique.FIN_SCAN:    ("F", "FIN"),
                ScanTechnique.NULL_SCAN:   ("", "NULL"),
            }
            flags, name = flag_map.get(technique, ("S", "SYN"))
            return _probe_scapy_async(host, p, timeout, flags, name, sem)
        else:
            return _probe_tcp_connect(host, p, timeout, sem, deep_service=deep_service)

    for start_idx in range(0, total, batch_size):
        if stop_event and stop_event.is_set():
            break

        # Cooperative pause
        while pause_fn and pause_fn():
            await asyncio.sleep(0.08)
            if stop_event and stop_event.is_set():
                break

        batch = ports[start_idx : start_idx + batch_size]
        tasks = [_select_coro(p) for p in batch]
        batch_results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in batch_results:
            if isinstance(r, PortRecord):
                results[r.port] = r
                # Only dispatch individual port results for OPEN or FILTERED to avoid UI flooding
                if on_port_result and r.state == PortState.OPEN:
                    on_port_result(r)

        done += len(batch)

        # Rate-limited progress dispatch (every ~40ms to keep Qt main thread silky smooth)
        now = time.perf_counter()
        if (now - last_ui_update) >= 0.04 or done >= total:
            el = now - t_scan_start
            speed = (done / el) if el > 0 else 0.0
            pct = (done / total * 100.0)
            if on_progress:
                on_progress(done, total, pct, speed)
            last_ui_update = now

        # Tiny yield to allow GUI event loop to process clicks instantly
        await asyncio.sleep(0.002)

    if on_progress and (not stop_event or not stop_event.is_set()):
        el = time.perf_counter() - t_scan_start
        speed = (total / el) if el > 0 else 0.0
        on_progress(total, total, 100.0, speed)

    return results
