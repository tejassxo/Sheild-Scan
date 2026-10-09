"""Evidence-Based Findings Engine for ShieldScan.
Generates auditable findings with strict severity classification and clear remediation guidance.
"""

from __future__ import annotations
import uuid
from typing import List
from src.models.host import HostRecord
from src.models.port import PortRecord, PortState
from src.models.finding import Finding, FindingSeverity, FindingCategory
from src.models.evidence import EvidenceRecord, ConfidenceLevel
from src.analysis.vuln_intel import check_potential_vulnerabilities


def analyze_host_findings(host: HostRecord) -> List[Finding]:
    """
    Analyzes an assessed host and produces evidence-grounded security findings.
    Never manufactures findings without direct observational proof.
    """
    findings: List[Finding] = []
    finding_idx = 1

    for p in host.open_ports:
        port_num = p.port
        svc = p.service
        svc_name = (svc.name if svc else "").upper()
        product = (svc.product if svc else "")
        version = (svc.version if svc else "")
        banner = (svc.banner if svc else "")
        evidence = p.evidence or (svc.evidence if svc else None)

        # 1. Plaintext Telnet Protocol (TCP 23)
        if port_num == 23 or "TELNET" in svc_name:
            f_id = f"FIND-{host.ip.replace('.', '')[:6]}-{finding_idx:03d}"
            finding_idx += 1
            findings.append(Finding(
                id=f_id,
                title="Unencrypted Telnet Remote Administration Service Exposed",
                severity=FindingSeverity.HIGH,
                category=FindingCategory.UNENCRYPTED_COMMUNICATION,
                host=host.ip,
                port=port_num,
                service="Telnet",
                description=f"Port {port_num} accepts Telnet connections. The Telnet protocol transmits credentials, session tokens, and commands in cleartext.",
                evidence=evidence or EvidenceRecord(
                    probe_type="PORT_OBSERVATION",
                    observation=f"Telnet service active on TCP/{port_num}",
                    raw_data=f"Port {port_num} open",
                    confidence=ConfidenceLevel.HIGH,
                ),
                impact="Network eavesdroppers on the transit path can intercept administrative credentials and execute unauthorized commands.",
                recommendation="Disable the Telnet daemon immediately and transition all remote access workflows to SSH (port 22).",
                confidence=ConfidenceLevel.HIGH,
            ))

        # 2. Plaintext FTP Service (TCP 21)
        elif port_num == 21 or "FTP" in svc_name:
            f_id = f"FIND-{host.ip.replace('.', '')[:6]}-{finding_idx:03d}"
            finding_idx += 1
            findings.append(Finding(
                id=f_id,
                title="Unencrypted FTP Protocol Exposure",
                severity=FindingSeverity.MEDIUM,
                category=FindingCategory.UNENCRYPTED_COMMUNICATION,
                host=host.ip,
                port=port_num,
                service="FTP",
                description=f"Standard FTP service detected on port {port_num}. FTP transmits authentication credentials and transferred data without transport encryption.",
                evidence=evidence or EvidenceRecord(
                    probe_type="BANNER_OBSERVATION",
                    observation=f"FTP server response observed on port {port_num}: {banner or 'Greeting received'}",
                    raw_data=banner,
                    confidence=ConfidenceLevel.HIGH,
                ),
                impact="Sensitive files and credentials may be subject to packet sniffing and credential theft over unsegmented networks.",
                recommendation="Replace legacy FTP with SFTP (SSH File Transfer Protocol) or require FTPS with explicit TLS enforcement.",
                confidence=ConfidenceLevel.HIGH,
            ))

        # 3. Direct Database Exposure (MySQL, Redis, PostgreSQL, MongoDB, MSSQL)
        elif port_num in (3306, 6379, 5432, 27017, 1433) or any(db in svc_name for db in ("MYSQL", "REDIS", "POSTGRES", "MONGODB", "MSSQL")):
            f_id = f"FIND-{host.ip.replace('.', '')[:6]}-{finding_idx:03d}"
            finding_idx += 1
            db_name = svc_name or f"Database (Port {port_num})"
            findings.append(Finding(
                id=f_id,
                title=f"Direct Database Management Port Exposure ({db_name})",
                severity=FindingSeverity.HIGH if port_num == 6379 else FindingSeverity.MEDIUM,
                category=FindingCategory.DATABASE_EXPOSURE,
                host=host.ip,
                port=port_num,
                service=db_name,
                description=f"Database service {db_name} is listening on external network port {port_num}. Direct exposure increases risk of unauthorized queries and brute force.",
                evidence=evidence or EvidenceRecord(
                    probe_type="DATABASE_PORT_OBSERVATION",
                    observation=f"Database port {port_num} ({db_name}) accepted connection. Banner: {banner}",
                    raw_data=banner,
                    confidence=ConfidenceLevel.HIGH,
                ),
                impact="Potential exposure of sensitive records, denial of service, or unauthorized administrative actions if weak credentials exist.",
                recommendation=f"Bind the {db_name} daemon strictly to localhost (127.0.0.1) or an internal private subnet; mandate VPN tunnels or application proxy access.",
                confidence=ConfidenceLevel.HIGH,
            ))

        # 4. Remote Desktop / Administrative Protocol Exposure (RDP 3389, VNC 5900, SMB 445/139)
        elif port_num in (3389, 5900, 445, 139) or any(adm in svc_name for db in ("RDP", "VNC", "SMB", "MICROSOFT-DS") for adm in [db]):
            f_id = f"FIND-{host.ip.replace('.', '')[:6]}-{finding_idx:03d}"
            finding_idx += 1
            adm_name = "Remote Desktop (RDP)" if port_num == 3389 else ("VNC Remote Desktop" if port_num == 5900 else "SMB File Sharing")
            findings.append(Finding(
                id=f_id,
                title=f"Administrative Service Exposed ({adm_name})",
                severity=FindingSeverity.MEDIUM,
                category=FindingCategory.ADMIN_INTERFACE,
                host=host.ip,
                port=port_num,
                service=adm_name,
                description=f"Administrative access interface {adm_name} detected listening on TCP/{port_num}.",
                evidence=evidence or EvidenceRecord(
                    probe_type="ADMIN_PORT_OBSERVATION",
                    observation=f"Established connection to {adm_name} port {port_num}",
                    raw_data=f"Port {port_num} OPEN",
                    confidence=ConfidenceLevel.HIGH,
                ),
                impact="Exposed administration endpoints are frequent targets of brute-force password guessing and lateral movement attacks.",
                recommendation="Enforce Network Level Authentication (NLA), place administration behind a dedicated VPN / bastion host, and restrict firewall access rules.",
                confidence=ConfidenceLevel.HIGH,
            ))

        # 5. Vulnerability Intelligence Correlation (CVE advisory checks)
        if product and version:
            advisories = check_potential_vulnerabilities(product, version)
            for adv in advisories:
                f_id = f"FIND-{host.ip.replace('.', '')[:6]}-{finding_idx:03d}"
                finding_idx += 1
                sev_enum = FindingSeverity.HIGH if adv.severity == "HIGH" else (FindingSeverity.MEDIUM if adv.severity == "MEDIUM" else FindingSeverity.LOW)
                findings.append(Finding(
                    id=f_id,
                    title=f"Potential Vulnerability: {adv.title} ({adv.cve})",
                    severity=sev_enum,
                    category=FindingCategory.OUTDATED_SOFTWARE,
                    host=host.ip,
                    port=port_num,
                    service=svc.name if svc else product,
                    description=(
                        f"Observed Product: {product} {version}\n"
                        f"Advisory Description: {adv.description}\n"
                        f"[NOTE: Classified as POTENTIAL. Manual validation recommended to confirm exploitability in this environment.]"
                    ),
                    evidence=EvidenceRecord(
                        probe_type="VERSION_FINGERPRINT_CORRELATION",
                        observation=f"Banner matched product '{product}' and version string '{version}'. Advisory: {adv.cve}",
                        raw_data=banner,
                        confidence=ConfidenceLevel.MEDIUM,
                    ),
                    impact=f"If unpatched, this version may be vulnerable to {adv.title}.",
                    recommendation=adv.recommendation,
                    cve_references=[adv.cve],
                    confidence=ConfidenceLevel.MEDIUM,
                ))

        # 6. Informational Service Observations (SSH, HTTPS, DNS)
        if port_num in (22, 443, 80, 53) or svc_name in ("SSH", "HTTPS", "DNS"):
            f_id = f"FIND-{host.ip.replace('.', '')[:6]}-{finding_idx:03d}"
            finding_idx += 1
            findings.append(Finding(
                id=f_id,
                title=f"Active Service Verification: {svc_name or 'TCP/' + str(port_num)}",
                severity=FindingSeverity.INFORMATIONAL,
                category=FindingCategory.SERVICE_EXPOSURE,
                host=host.ip,
                port=port_num,
                service=svc_name or str(port_num),
                description=f"Standard network service {svc_name} verified operational on host {host.ip} port {port_num}. Latency: {p.latency_ms:.1f}ms.",
                evidence=evidence or EvidenceRecord(
                    probe_type="SERVICE_VERIFIED",
                    observation=f"Verified {svc_name} service on port {port_num}. Banner: {banner}",
                    raw_data=banner,
                    confidence=ConfidenceLevel.HIGH,
                ),
                impact="Normal operational service exposure.",
                recommendation="Maintain standard patch cycle and audit authorized access logs periodically.",
                confidence=ConfidenceLevel.HIGH,
            ))

    return findings
