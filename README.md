# ShieldScan

> **Network Visibility. Simplified.**  
> *A Modern Network Visibility & Security Assessment Platform for Computer Networks Engineering.*

---

## 01. Overview

**ShieldScan** transforms raw network scanning into understandable, actionable network intelligence. Built specifically for defensive network assessments, laboratory demonstrations, and academic evaluation, ShieldScan bridges the gap between raw socket probes and executive-level visibility.

Unlike traditional terminal scanners that produce overwhelming walls of unformatted text, ShieldScan provides:
- **Full 65,535 Port Spectrum**: High-concurrency async batching scanning all 65,535 TCP/UDP ports in seconds.
- **Nmap-Grade Scanning Techniques**: Native support for **TCP Connect (`-sT`)**, **Stealth SYN (`-sS`)**, **UDP Service Sweep (`-sU`)**, **TCP Xmas Tree (`-sX`)**, **FIN Scan (`-sF`)**, and **Null Scan (`-sN`)**.
- **Evidence-First Security**: Every observation is grounded in directly verifiable network probes (raw banners, TLS handshakes, protocol packets) with explicit confidence scoring.
- **Apple-Inspired Design Philosophy**: High-clarity, light engineering aesthetics (`#F5F5F2` canvas, `#FFFFFF` surfaces, `#1D1D1F` charcoal typography, and restrained `#B42318` vermilion accents). Absolutely zero dark hacker tropes, glowing neon, or distracting cyber gradients.
- **Single Source of Truth**: All dashboards, host explorers, service inventories, security findings, DOCX reports, and PowerPoint slide decks derive deterministically from a single canonical `ScanResult` model.
- **Historical Change Detection**: Instantly compares assessments across time to detect network drift (+/- hosts, newly opened ports, closed services, version upgrades).
- **Automated Deliverables**: One-click generation of professional Word assessment reports (`.docx`) and 7-slide academic presentation decks (`.pptx`).

---

## 02. System Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                       ShieldScan UI                         │
│       PyQt5 · Apple-Inspired Engineering Layout             │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                      Scan Controller                        │
│       Target Resolution · Concurrency · Event Dispatch      │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                       Scanner Engine                        │
├─────────────────────────────────────────────────────────────┤
│ • Multi-Vector Host Discovery (ICMP, TCP Ping, Reverse DNS) │
│ • 65K Asynchronous Port Enumeration (800-1200 Workers)      │
│ • Nmap Techniques (Connect -sT, SYN -sS, UDP -sU, Xmas -sX) │
│ • Deep Service Fingerprinting (HTTP, TLS, SSH, MySQL, Redis)│
│ • Forensic Evidence Collection & Confidence Scoring         │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                   Analysis & Intel Engine                   │
├─────────────────────────────────────────────────────────────┤
│ • Evidence-Based Risk Classification (Info, Low, Med, High) │
│ • Curated Vulnerability Intelligence (Observed vs Potential)│
│ • Historical Differential Engine (Network Drift Tracking)   │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│                    Canonical ScanResult                     │
│               Single Source of Truth Model                  │
└──────────────────────────────┬──────────────────────────────┘
                               │
       ┌───────────────────────┼───────────────────────┐
       ↓                       ↓                       ↓
  Dashboard & UI       Executive Reports      Structured Exports
 (Overview, Explorer)       (.docx / .pptx)         (JSON / CSV)
```

---

## 03. Key Features

### Full 65,535 Port Enumeration & High Concurrency
- Non-blocking socket workers with managed semaphore pools (default 800 workers, up to 1,500 selectable).
- Adaptive timeouts (0.15s–0.25s) allowing full 65k port scans to complete in seconds on local/lab targets.
- Measures precise round-trip latency in milliseconds.
- Categorizes port status cleanly into `OPEN`, `CLOSED`, and `FILTERED`.

### Nmap-Grade Scan Techniques
- **TCP Connect (`-sT`)**: Non-blocking full 3-way handshake. Fast, reliable, and requires zero administrative/root privileges.
- **Stealth SYN (`-sS`)**: Half-open SYN packet scan via raw socket engine (Scapy). Identifies listening ports without completing TCP handshake.
- **UDP Service Sweep (`-sU`)**: Specialized UDP protocol probes for core network infrastructure (DNS 53, NTP 123, SNMP 161, NetBIOS 137, SSDP 1900, mDNS 5353).
- **TCP Xmas Tree (`-sX`)**: RFC 793 packet scan setting FIN, PSH, and URG flags.
- **FIN (`-sF`) & Null (`-sN`) Scans**: Protocol boundary tests analyzing RFC 793 closed port reset behavior.

### Smooth UI Performance & Interactive Controls
- **60 FPS Non-Blocking Event Loop**: Progress updates are throttled at 50ms intervals so the PyQt5 main GUI thread remains fluid and responsive during large scans.
- **Interactive Controls**: Dedicated **Start Assessment**, **Pause / Resume (`⏸` / `▶`)**, **Stop Scan**, and **Clear Results** buttons.
- **Live Open Port Stream**: Streams only verified open ports into the operational view table to avoid table recalculation lag.

### Deep Service Fingerprinting
- **HTTP / HTTPS**: Inspects server response status codes, extracts `Server` headers, and analyzes TLS certificate common names, issuers, and cipher suites.
- **SSH**: Parses protocol version, OpenSSH release, and operating system hints.
- **FTP & SMTP**: Captures 220 greeting banners and identifies mail agents (Postfix, Exim, Sendmail).
- **Databases**: Interrogates MySQL protocol handshakes and sends Redis `PING` commands to verify authentication states.

### Evidence-Grounded Findings Engine
- **Informational**: Baseline service verifications and active listener certificates.
- **Low Risk**: Information disclosure via verbose headers or non-standard banner configurations.
- **Medium Risk**: Cleartext transmission (FTP), unsegmented database ports, or exposed remote desktop interfaces.
- **High Risk**: Cleartext remote administration (Telnet), unauthenticated Redis instances, or outdated versions matching known critical CVE advisories.

### Historical Change Detection
- Compares any two historical assessments and generates an auditable delta:
  - Added and removed hosts
  - Newly opened and closed ports
  - Daemon version changes
  - New and resolved security findings

---

## 04. Scan Profiles

| Profile | Port Scope | Technique | Typical Speed |
| :--- | :--- | :--- | :--- |
| **Quick Discovery** | Top 100 attack-surface ports | TCP Connect (`-sT`) | ~2–8s per target |
| **Standard Assessment** | Top 1,000 IANA & enterprise ports | TCP Connect (`-sT`) | ~10–25s per host |
| **Full 65K Range** | All 65,535 ports (1–65535) | Fast Async (`800` workers) | ~15–40s on LAN |
| **Extended Inventory** | Ports 1–10,000 + critical high services | TCP Connect (`-sT`) | ~15–30s per host |
| **UDP Critical Services** | Ports 53, 123, 161, 137, 500, 1900 | UDP Sweep (`-sU`) | ~5–15s per host |
| **Custom Port Range** | User-defined (e.g. `1-65535`, `80,443,8000-8080`) | Configurable | Configurable |

---

## 05. Color System & Aesthetics

ShieldScan strictly honors a refined, light Apple-inspired engineering palette:
- **Canvas**: `#F5F5F2` (Warm light gray)
- **Primary Surface**: `#FFFFFF` (Clean white cards and panels)
- **Secondary Surface**: `#F0F0EC` (Subtle hover and table headers)
- **Primary Text**: `#1D1D1F` (High contrast charcoal)
- **Secondary Text**: `#6E6E73` (Muted labels)
- **Hairline Borders**: `#D2D2CC` (Crisp neutral dividers)
- **ShieldScan Accent**: `#B42318` (Muted vermilion / deep red)
- **Positive State**: `#2F6B4F` (Muted green)
- **Warning State**: `#9A6700` (Muted amber)

*Zero gradients. Zero neon. Zero cyberpunk aesthetics.*

---

## 06. Installation & Prerequisites

ShieldScan runs on Python 3.9+ (tested on Python 3.13 on Windows).

### Dependencies
```bash
pip install PyQt5 python-docx python-pptx matplotlib
```
*(Optional: `pip install scapy` for low-level packet capture if Npcap is present).*

---

## 07. Usage

### Launch Graphical Interface
```bash
python main.py
```

### Command Line & Headless Automation
```bash
# 1. Full 65K Scan with DOCX and PPTX output
python main.py --target 127.0.0.1 --profile full_65k --concurrency 800 --docx --pptx

# 2. UDP Service Sweep on critical infrastructure ports
python main.py --target 192.168.1.1 --profile udp_services --technique udp

# 3. Custom Port Range with Stealth SYN scan
python main.py --target 192.168.1.10 --ports 1-1000 --technique syn

# 4. Standard Quick Discovery with JSON and CSV exports
python main.py --target 127.0.0.1 --profile quick_discovery --json --csv
```

---

## 08. Project Structure

```text
Sheild-Scan/
├── main.py                     # Primary GUI / CLI entry point
├── capture_screenshots.py      # Automated offscreen screenshot utility
├── README.md                   # Complete product documentation
│
├── src/
│   ├── models/                 # Canonical ScanResult, HostRecord, Finding, ScanProfile
│   ├── scanner/                # Target parser, discovery, port scanner, service detector
│   ├── analysis/               # Findings engine, CVE advisories, change detector
│   ├── storage/                # Local scan store repository
│   ├── reporting/              # DOCX generator, JSON and CSV exporters
│   ├── presentation/           # 7-slide PPTX deck and technical diagram generators
│   └── ui/                     # Design tokens, QSS styles, views, and components
│
├── tests/
│   └── test_shieldscan.py      # Automated unit & integration test suite
│
├── reports/
│   └── generated/              # Generated Word (.docx) reports
│
├── presentations/
│   └── generated/              # Generated PowerPoint (.pptx) presentations
│
├── exports/
│   ├── json/                   # Canonical JSON assessment models
│   └── csv/                    # Tabular CSV datasets
│
└── screenshots/                # Pixel-perfect UI captures for presentations
```

---

## 09. Ethical Use & Academic Limitations

ShieldScan is engineered strictly for authorized security assessments, defensive network administration, and academic demonstrations. 

### Security Boundaries
- **No Exploitation**: ShieldScan never attempts credential bruteforcing, buffer overflows, or remote code execution.
- **No Evasion**: Does not implement IDS/IPS bypass or fragmented evasion techniques.
- **Non-Destructive**: Designed to safeguard target systems and avoid denial-of-service conditions.

### Known Technical Limitations
- Host-based firewalls (e.g. Windows Defender Firewall, Linux iptables) dropping TCP SYN probes will cause ports to be classified as `FILTERED`.
- Banner obfuscation (e.g., custom web server tokens) may result in lower fingerprinting confidence.

---

## 10. Future Scope

1. **Heuristic OS Fingerprinting**: TCP/IP stack window size and TTL analysis.
2. **Interactive Topology Visualization**: Dynamic force-directed network map of discovered subnets.
3. **Continuous Monitoring Daemon**: Background agent alerting on real-time network port drift.
  