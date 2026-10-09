"""Vulnerability Intelligence Knowledge Base for ShieldScan.
Grounds software advisories in observed products and version strings without exploitation.
"""

from __future__ import annotations
import re
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class VulnerabilityRecord:
    cve: str
    product: str
    version_affected: str
    severity: str               # "LOW", "MEDIUM", "HIGH"
    title: str
    description: str
    source: str
    recommendation: str


# Curated, authoritative CVE advisories mapped to common network services
KNOWN_ADVISORIES: List[VulnerabilityRecord] = [
    VulnerabilityRecord(
        cve="CVE-2023-48795",
        product="OpenSSH",
        version_affected="< 9.6",
        severity="MEDIUM",
        title="Terrapin Attack: SSH Channel Prefix Truncation",
        description="Vulnerability in SSH transport protocol allowing MITM attackers to truncate initial extension messages.",
        source="NVD / OpenSSH Advisory",
        recommendation="Upgrade OpenSSH to version 9.6p1 or newer, or disable ChaCha20-Poly1305 and CBC ciphers.",
    ),
    VulnerabilityRecord(
        cve="CVE-2023-38408",
        product="OpenSSH",
        version_affected="< 9.3p2",
        severity="HIGH",
        title="OpenSSH PKCS#11 Provider Remote Code Execution",
        description="Condition in ssh-agent forwarding allows arbitrary shared library loading via PKCS#11 providers.",
        source="NVD / Qualys Security Advisory",
        recommendation="Update OpenSSH to 9.3p2 or disable remote agent forwarding.",
    ),
    VulnerabilityRecord(
        cve="CVE-2021-41773",
        product="Apache",
        version_affected="2.4.49, 2.4.50",
        severity="HIGH",
        title="Apache HTTP Server Path Traversal and File Disclosure",
        description="Flaw in path normalization allows path traversal and potential remote code execution.",
        source="NVD / Apache HTTP Server Project",
        recommendation="Upgrade Apache HTTP Server to version 2.4.51 or later immediately.",
    ),
    VulnerabilityRecord(
        cve="CVE-2022-22720",
        product="Apache",
        version_affected="< 2.4.53",
        severity="HIGH",
        title="Apache HTTP Server HTTP Request Smuggling",
        description="Incomplete inbound limit check leading to HTTP request smuggling vulnerability.",
        source="NVD / Apache Security",
        recommendation="Upgrade to Apache HTTP Server 2.4.53 or higher.",
    ),
    VulnerabilityRecord(
        cve="CVE-2022-0778",
        product="OpenSSL",
        version_affected="1.1.1, < 1.1.1n",
        severity="HIGH",
        title="OpenSSL BN_mod_sqrt Infinite Loop Denial of Service",
        description="Adverse parsing of malformed elliptic curve certificates triggers infinite loop in BN_mod_sqrt().",
        source="NVD / OpenSSL Security",
        recommendation="Update OpenSSL libraries to 1.1.1n, 3.0.2 or higher.",
    ),
    VulnerabilityRecord(
        cve="CVE-2015-1849",
        product="vsftpd",
        version_affected="< 3.0.3",
        severity="LOW",
        title="vsftpd Denial of Service via Resource Exhaustion",
        description="Improper resource limits in specific non-standard configurations may lead to denial of service.",
        source="NVD / Red Hat Security",
        recommendation="Upgrade vsftpd to 3.0.3 or implement strict per-IP connection limits.",
    ),
    VulnerabilityRecord(
        cve="CVE-2022-0543",
        product="Redis",
        version_affected="< 6.0.16, < 6.2.6",
        severity="HIGH",
        title="Redis Lua Sandbox Escape and Remote Code Execution",
        description="Debian package initialization flaw allows sandbox escape via Lua environment package module.",
        source="NVD / Debian Security Advisory",
        recommendation="Ensure Redis is bound to localhost/VPN and updated to 6.2.6+ with requirepass configured.",
    ),
    VulnerabilityRecord(
        cve="CVE-2020-0601",
        product="Microsoft-DS",
        version_affected="Windows 10, Server 2016/2019",
        severity="HIGH",
        title="Windows CryptoAPI Spoofing Vulnerability (CurveBall)",
        description="Flaw in Windows CryptoAPI validation allows forging of ECC certificates.",
        source="NSA / Microsoft MSRC",
        recommendation="Apply Microsoft cumulative security update KB4534273.",
    ),
]


def check_potential_vulnerabilities(product: str, version: str) -> List[VulnerabilityRecord]:
    """
    Checks whether detected product and version string match known security advisories.
    Clearly classified as POTENTIAL advisory matches, requiring manual confirmation.
    """
    matches: List[VulnerabilityRecord] = []
    if not product:
        return matches

    prod_lower = product.lower()
    for adv in KNOWN_ADVISORIES:
        if adv.product.lower() in prod_lower or prod_lower in adv.product.lower():
            if not version:
                # If product matches but version is unknown, don't trigger false positives
                continue
            
            # Simple version prefix / comparison
            v_clean = re.sub(r"[^\d\.]", "", version)
            aff_clean = re.sub(r"[^\d\.]", "", adv.version_affected)
            if aff_clean and v_clean and v_clean.startswith(aff_clean[:3]):
                matches.append(adv)
            elif adv.product.lower() in prod_lower and any(num in version for num in ["2.4.49", "2.4.50", "8.9", "1.1.1"]):
                matches.append(adv)

    return matches
