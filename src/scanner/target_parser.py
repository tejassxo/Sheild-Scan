"""Target Parser for ShieldScan.
Parses single IPs, hostnames, CIDR blocks, ranges, and comma-separated targets.
"""

from __future__ import annotations
import ipaddress
import socket
from typing import List, Set, Tuple


MAX_EXPANDED_HOSTS = 256  # Safe guardrail for college lab & demonstration scans


def resolve_hostname(host: str) -> Tuple[str, str]:
    """Resolves a hostname to an IP, returning (ip, resolved_name)."""
    host = host.strip()
    try:
        ip = socket.gethostbyname(host)
        return ip, host
    except Exception:
        return host, host


def parse_targets(target_str: str, max_hosts: int = MAX_EXPANDED_HOSTS) -> List[Tuple[str, str]]:
    """
    Parses a target string into a list of (ip, hostname_or_label) tuples.
    Supports:
      - Single IP: "192.168.1.1" or "127.0.0.1"
      - Hostname: "localhost", "gateway.local"
      - CIDR: "192.168.1.0/28"
      - Range: "192.168.1.10-192.168.1.15"
      - Comma-delimited: "127.0.0.1, 192.168.1.1"
    """
    targets: List[Tuple[str, str]] = []
    seen_ips: Set[str] = set()

    tokens = [t.strip() for t in target_str.replace(";", ",").split(",") if t.strip()]

    for token in tokens:
        # Check CIDR
        if "/" in token:
            try:
                network = ipaddress.ip_network(token, strict=False)
                # If /32 or /31 or single host
                hosts = list(network.hosts()) if network.num_addresses > 1 else [network.network_address]
                for h in hosts:
                    ip_s = str(h)
                    if ip_s not in seen_ips:
                        seen_ips.add(ip_s)
                        targets.append((ip_s, ""))
                        if len(targets) >= max_hosts:
                            break
            except ValueError:
                # Fallback to single host resolution
                ip_s, label = resolve_hostname(token)
                if ip_s not in seen_ips:
                    seen_ips.add(ip_s)
                    targets.append((ip_s, label))
            continue

        # Check IP range (e.g., 192.168.1.10-192.168.1.15 or 192.168.1.10-15)
        if "-" in token and not any(c.isalpha() for c in token):
            parts = token.split("-")
            if len(parts) == 2:
                start_str = parts[0].strip()
                end_str = parts[1].strip()
                try:
                    start_ip = ipaddress.ip_address(start_str)
                    if "." in end_str:
                        end_ip = ipaddress.ip_address(end_str)
                    else:
                        # short suffix like 192.168.1.10-15
                        prefix = ".".join(start_str.split(".")[:-1])
                        end_ip = ipaddress.ip_address(f"{prefix}.{end_str}")

                    start_int = int(start_ip)
                    end_int = int(end_ip)
                    if start_int <= end_int and (end_int - start_int) <= max_hosts:
                        for current_int in range(start_int, end_int + 1):
                            ip_s = str(ipaddress.ip_address(current_int))
                            if ip_s not in seen_ips:
                                seen_ips.add(ip_s)
                                targets.append((ip_s, ""))
                                if len(targets) >= max_hosts:
                                    break
                        continue
                except ValueError:
                    pass

        # Single IP or hostname
        ip_s, label = resolve_hostname(token)
        if ip_s not in seen_ips:
            seen_ips.add(ip_s)
            targets.append((ip_s, label if label != ip_s else ""))

        if len(targets) >= max_hosts:
            break

    return targets
