# ShieldScan Professional v4.1 — Refined Network Auditor

ShieldScan Professional is a high-performance, asynchronous network auditing and port scanning tool. Built with Python, PyQt5, and Scapy, it combines a sleek, premium dark-themed UI with powerful scanning engines. It's designed to be fast, reliable, and stealthy, utilizing adaptive throttling to ensure accuracy without overwhelming the network.

## 🚀 Features

*   **Multiple Scan Modes**: 
    *   **TCP Connect**: Fast, highly-concurrent standard connection scanning using `asyncio`.
    *   **Stealth SYN**: Low-profile scanning utilizing raw sockets via `scapy`.
    *   **UDP Sweep**: Targeted UDP port discovery.
    *   **Xmas Scan**: Advanced firewall bypassing techniques.
*   **Adaptive Throttling**: Intelligently adjusts network concurrency in real-time to avoid triggering rate limits or dropping packets.
*   **Built-in Scan Profiles**:
    *   **Flash**: Top 100 ports
    *   **Quick**: Top 1000 ports
    *   **Full**: All 65535 ports
*   **Service & Banner Grabbing**: Automatically identifies underlying services and captures banners (e.g., HTTP, SSH, FTP).
*   **Premium Interface**: A modern PyQt5 GUI featuring real-time metric cards, an interactive live-results table, sorting, filtering, and a custom dark mode palette.
*   **Silent Recheck**: Automatically re-probes filtered important ports in the background to guarantee high accuracy.
*   **Exportable Reports**: Generate detailed `.txt` network audit reports with one click.

## 🛠️ Tech Stack

*   **Python 3.x**
*   **PyQt5** (UI Design & Threading)
*   **Scapy** (Packet Manipulation & Raw Sockets)
*   **Asyncio** (High-concurrency TCP operations)

## 📦 Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/shieldscan.git
   cd shieldscan
   ```
2. Install the required dependencies:
   ```bash
   pip install PyQt5 scapy
   ```
   *(Note: On Windows, you will also need to install [Npcap](https://npcap.com/) for Scapy to function properly).*

3. Run the application:
   ```bash
   python main8.py
   ```

## ⚠️ Disclaimer
This tool is designed for educational purposes and authorized network auditing only. Do not use it against networks or systems you do not have explicit permission to scan.
