"""Deep service detection & fingerprinting engine for ShieldScan.
Extracts products, versions, banners, and TLS certificates with strict evidence auditing.
"""

from __future__ import annotations
import asyncio
import re
import socket
import ssl
from typing import Optional, Tuple
from src.models.service import ServiceInfo
from src.models.evidence import EvidenceRecord, ConfidenceLevel

# Standard IANA Port-to-Service Mapping (Fallback baseline)
PORT_DEFAULTS = {
    21: ("FTP", "File Transfer Protocol"),
    22: ("SSH", "Secure Shell"),
    23: ("Telnet", "Telnet Remote Shell"),
    25: ("SMTP", "Simple Mail Transfer Protocol"),
    53: ("DNS", "Domain Name System"),
    80: ("HTTP", "Hypertext Transfer Protocol"),
    110: ("POP3", "Post Office Protocol v3"),
    111: ("RPCBind", "RPC Portmapper"),
    135: ("MSRPC", "Microsoft Windows RPC"),
    139: ("NetBIOS-SSN", "NetBIOS Session Service"),
    143: ("IMAP", "Internet Message Access Protocol"),
    389: ("LDAP", "Lightweight Directory Access Protocol"),
    443: ("HTTPS", "HTTP over TLS/SSL"),
    445: ("Microsoft-DS", "SMB File Sharing / Active Directory"),
    465: ("SMTPS", "SMTP over TLS"),
    587: ("SMTP-Submission", "Mail Message Submission"),
    993: ("IMAPS", "IMAP over TLS"),
    995: ("POP3S", "POP3 over TLS"),
    1433: ("MSSQL", "Microsoft SQL Server"),
    1521: ("Oracle", "Oracle Database Listener"),
    2049: ("NFS", "Network File System"),
    3000: ("Node.js/Dev", "Development Web Server"),
    3306: ("MySQL", "MySQL Database Server"),
    3389: ("RDP", "Remote Desktop Protocol"),
    5432: ("PostgreSQL", "PostgreSQL Database Server"),
    5900: ("VNC", "Virtual Network Computing"),
    6379: ("Redis", "Redis In-Memory Data Store"),
    8000: ("HTTP-Alt", "Alternative Web Server"),
    8080: ("HTTP-Proxy", "HTTP Alternate / Proxy"),
    8443: ("HTTPS-Alt", "HTTPS Alternate"),
    9200: ("Elasticsearch", "Elasticsearch REST API"),
    27017: ("MongoDB", "MongoDB NoSQL Database"),
}


async def _probe_raw_socket(host: str, port: int, payload: bytes = b"", timeout: float = 0.5) -> bytes:
    """Connects, optionally sends payload, reads response up to 1024 bytes."""
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        try:
            if payload:
                writer.write(payload)
                await writer.drain()
            data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            return data
        finally:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=0.1)
            except Exception:
                pass
    except Exception:
        return b""


async def _probe_tls_certificate(host: str, port: int, timeout: float = 0.8) -> Optional[Tuple[str, str, str]]:
    """Connects using SSL/TLS context to read server certificate and TLS version."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        loop = asyncio.get_event_loop()
        def _get_cert():
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    version = ssock.version() or "TLS"
                    cipher = ssock.cipher()
                    c_name = cipher[0] if cipher else ""
                    return cert, version, c_name

        cert, tls_ver, cipher_name = await asyncio.wait_for(
            loop.run_in_executor(None, _get_cert),
            timeout=timeout + 0.2
        )
        subject_dict = {}
        for sub in cert.get("subject", []):
            for k, v in sub:
                subject_dict[k] = v
        cn = subject_dict.get("commonName", host)
        issuer_dict = {}
        for iss in cert.get("issuer", []):
            for k, v in iss:
                issuer_dict[k] = v
        issuer_cn = issuer_dict.get("commonName", issuer_dict.get("organizationName", "Self-signed"))
        desc = f"{tls_ver} (Cipher: {cipher_name}) | Subject CN: {cn} | Issuer: {issuer_cn}"
        return desc, tls_ver, cn
    except Exception:
        return None


async def detect_service(host: str, port: int, timeout: float = 0.6) -> ServiceInfo:
    """
    Performs multi-protocol active fingerprinting and returns ServiceInfo with EvidenceRecord.
    """
    default_name, default_desc = PORT_DEFAULTS.get(port, ("Unknown", f"Port {port} service"))

    # 1. Check if port is TLS/HTTPS (Port 443, 8443 or default HTTPS)
    if port in (443, 8443, 9443) or "HTTPS" in default_name:
        tls_info = await _probe_tls_certificate(host, port, timeout=timeout)
        if tls_info:
            desc, tls_ver, cn = tls_info
            # Send HTTP HEAD probe over SSL
            ev = EvidenceRecord(
                probe_type="TLS_CERT_INSPECTION",
                observation=f"Established TLS handshake. Certificate Common Name: {cn} via {tls_ver}",
                raw_data=desc,
                confidence=ConfidenceLevel.HIGH,
            )
            return ServiceInfo(
                name="HTTPS",
                product="TLS Web Service",
                version=tls_ver,
                banner=desc,
                tunnel="TLS",
                evidence=ev,
                confidence=ConfidenceLevel.HIGH,
            )

    # 2. HTTP Probe for Web Ports (80, 8080, 8000, 3000, 8888, 5000, etc.)
    if port in (80, 8080, 8000, 3000, 5000, 8888, 9090, 9200) or default_name.startswith("HTTP"):
        http_req = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: ShieldScan/1.0\r\nConnection: close\r\n\r\n".encode("utf-8")
        raw = await _probe_raw_socket(host, port, http_req, timeout=timeout)
        text = raw.decode("utf-8", errors="replace").strip()
        if text.startswith("HTTP/"):
            server_match = re.search(r"Server:\s*([^\r\n]+)", text, re.IGNORECASE)
            server_header = server_match.group(1).strip() if server_match else ""
            status_match = re.search(r"HTTP/\d\.\d\s+(\d+)\s+([^\r\n]*)", text)
            status_line = status_match.group(0) if status_match else "HTTP/1.1 200 OK"
            
            product = "Web Server"
            version = ""
            if server_header:
                parts = server_header.split("/")
                product = parts[0]
                if len(parts) > 1:
                    version = parts[1].split()[0]
                elif " " in server_header:
                    subparts = server_header.split()
                    product = subparts[0]
                    version = subparts[1]
                else:
                    product = server_header

            banner_line = f"{status_line} | Server: {server_header or 'Hidden'}"
            ev = EvidenceRecord(
                probe_type="HTTP_HEAD_PROBE",
                observation=f"HTTP handshake successful. Response: '{status_line}'. Server Header: '{server_header or 'None'}'",
                raw_data=text[:250],
                confidence=ConfidenceLevel.HIGH if server_header else ConfidenceLevel.MEDIUM,
            )
            return ServiceInfo(
                name="HTTP",
                product=product,
                version=version,
                banner=banner_line,
                evidence=ev,
                confidence=ConfidenceLevel.HIGH if server_header else ConfidenceLevel.MEDIUM,
            )

    # 3. Passive Banner Grab (SSH, FTP, SMTP, MySQL send greeting on connect)
    raw_banner = await _probe_raw_socket(host, port, b"", timeout=timeout)
    banner_text = raw_banner.decode("utf-8", errors="replace").strip()

    # SSH Inspection
    if banner_text.startswith("SSH-"):
        # e.g., SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6
        match = re.match(r"SSH-([\d\.]+)-([A-Za-z0-9_\-\.]+)(?:\s+(.*))?", banner_text)
        proto_ver = match.group(1) if match else "2.0"
        software = match.group(2) if match else "OpenSSH"
        os_info = match.group(3) if match and match.group(3) else ""
        
        prod = software
        ver = ""
        if "_" in software:
            prod, ver = software.split("_", 1)

        ev = EvidenceRecord(
            probe_type="SSH_PROTOCOL_BANNER",
            observation=f"Received standard SSH identification string: {banner_text}",
            raw_data=banner_text,
            confidence=ConfidenceLevel.HIGH,
            metadata={"protocol_version": proto_ver, "os_hint": os_info},
        )
        return ServiceInfo(
            name="SSH",
            product=prod,
            version=ver,
            banner=banner_text,
            evidence=ev,
            confidence=ConfidenceLevel.HIGH,
        )

    # FTP Inspection (220 Greeting)
    if banner_text.startswith("220") and ("FTP" in banner_text.upper() or port == 21):
        prod = "FTP Server"
        ver = ""
        if "vsftpd" in banner_text.lower():
            prod = "vsftpd"
            m = re.search(r"vsftpd\s*([\d\.]+)", banner_text, re.I)
            ver = m.group(1) if m else ""
        elif "proftpd" in banner_text.lower():
            prod = "ProFTPD"
            m = re.search(r"proftpd\s*([\d\.]+)", banner_text, re.I)
            ver = m.group(1) if m else ""
        elif "pure-ftpd" in banner_text.lower():
            prod = "Pure-FTPd"

        ev = EvidenceRecord(
            probe_type="FTP_GREETING_BANNER",
            observation=f"FTP server 220 greeting returned: {banner_text}",
            raw_data=banner_text,
            confidence=ConfidenceLevel.HIGH,
        )
        return ServiceInfo(
            name="FTP",
            product=prod,
            version=ver,
            banner=banner_text[:120],
            evidence=ev,
            confidence=ConfidenceLevel.HIGH,
        )

    # SMTP Inspection (220 Greeting with ESMTP)
    if banner_text.startswith("220") and ("ESMTP" in banner_text.upper() or "MAIL" in banner_text.upper() or port in (25, 587)):
        prod = "SMTP Mail Server"
        if "postfix" in banner_text.lower(): prod = "Postfix ESMTP"
        elif "exim" in banner_text.lower(): prod = "Exim ESMTP"
        elif "microsoft" in banner_text.lower(): prod = "Microsoft Exchange SMTP"

        ev = EvidenceRecord(
            probe_type="SMTP_GREETING_BANNER",
            observation=f"SMTP mail agent 220 banner observed: {banner_text}",
            raw_data=banner_text,
            confidence=ConfidenceLevel.HIGH,
        )
        return ServiceInfo(
            name="SMTP",
            product=prod,
            version="",
            banner=banner_text[:120],
            evidence=ev,
            confidence=ConfidenceLevel.HIGH,
        )

    # MySQL Handshake Inspection
    if len(raw_banner) > 5 and (port == 3306 or b"mysql" in raw_banner.lower()):
        # MySQL packet format: protocol version (byte 4), followed by null-terminated version string
        try:
            proto_num = raw_banner[4]
            null_idx = raw_banner.find(b"\x00", 5)
            if null_idx > 5:
                version_str = raw_banner[5:null_idx].decode("ascii", errors="replace")
                ev = EvidenceRecord(
                    probe_type="MYSQL_HANDSHAKE_PACKET",
                    observation=f"MySQL initial handshake packet parsed. Protocol v{proto_num}, Server Version: {version_str}",
                    raw_data=raw_banner[:60].hex(),
                    confidence=ConfidenceLevel.HIGH,
                )
                return ServiceInfo(
                    name="MySQL",
                    product="MySQL Server",
                    version=version_str,
                    banner=f"MySQL {version_str} (Protocol {proto_num})",
                    evidence=ev,
                    confidence=ConfidenceLevel.HIGH,
                )
        except Exception:
            pass

    # Redis Probe
    if port == 6379 or default_name == "Redis":
        redis_resp = await _probe_raw_socket(host, port, b"PING\r\n", timeout=timeout)
        if b"+PONG" in redis_resp or b"-NOAUTH" in redis_resp:
            banner_msg = "PONG received" if b"+PONG" in redis_resp else "Protected mode (Authentication required)"
            ev = EvidenceRecord(
                probe_type="REDIS_COMMAND_PROBE",
                observation=f"Redis RESP protocol verified. Response: {banner_msg}",
                raw_data=redis_resp.decode("ascii", errors="replace").strip(),
                confidence=ConfidenceLevel.HIGH,
            )
            return ServiceInfo(
                name="Redis",
                product="Redis Key-Value Store",
                version="",
                banner=f"Redis RESP ({banner_msg})",
                evidence=ev,
                confidence=ConfidenceLevel.HIGH,
            )

    # Generic Port Fallback with observation
    obs = f"TCP connection accepted on port {port} matching standard service '{default_name}'"
    raw_sample = banner_text[:100] if banner_text else f"TCP connection established to {host}:{port}"
    ev = EvidenceRecord(
        probe_type="TCP_PORT_MAPPING",
        observation=obs,
        raw_data=raw_sample,
        confidence=ConfidenceLevel.MEDIUM if default_name != "Unknown" else ConfidenceLevel.LOW,
    )
    return ServiceInfo(
        name=default_name,
        product=default_desc if default_name != "Unknown" else "",
        version="",
        banner=banner_text[:120] if banner_text else f"Standard {default_name} port",
        evidence=ev,
        confidence=ConfidenceLevel.MEDIUM if default_name != "Unknown" else ConfidenceLevel.LOW,
    )
