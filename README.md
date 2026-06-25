# ShieldScan Elite v3.1 — Streamlined Network Auditor

ShieldScan Elite is a high-performance, asynchronous network auditing and port scanning tool. Built with Python, PyQt5, and Scapy, it combines a sleek, premium dark-themed UI with powerful scanning engines. It's designed to be fast, reliable, and stealthy, utilizing adaptive throttling to ensure accuracy without overwhelming the network.

## 1. 🚀 Features

1. **Multiple Scan Modes**: 
   * **TCP Connect**: Fast, highly-concurrent standard connection scanning using `asyncio`.
   * **Stealth SYN**: Low-profile scanning utilizing raw sockets via `scapy`.
   * **UDP Sweep**: Targeted UDP port discovery.
   * **Xmas Scan**: Advanced firewall bypassing techniques.
2. **Adaptive Throttling**: Intelligently adjusts network concurrency in real-time to avoid triggering rate limits or dropping packets.
3. **Built-in Scan Profiles**:
   * **Flash**: Top 100 ports
   * **Quick**: Top 1000 ports
   * **Full**: All 65535 ports
   * **UDP**: Common UDP ports
   * **Custom**: Support for user-defined custom port ranges
4. **Service & Banner Grabbing**: Automatically identifies underlying services and captures banners (e.g., HTTP, SSH, FTP).
5. **Premium Interface**: A modern PyQt5 GUI featuring real-time metric cards, an interactive live-results table, sorting, filtering, and a custom dark mode palette.
6. **Silent Recheck**: Automatically re-probes filtered important ports in the background to guarantee high accuracy.
7. **Exportable Reports**: Generate detailed `.csv` or `.json` network audit reports with one click.

## 2. 🛠️ Tech Stack

1. **Python 3.x**
2. **PyQt5** (UI Design & Threading)
3. **Scapy** (Packet Manipulation & Raw Sockets)
4. **Asyncio** (High-concurrency TCP operations)

## 3. 📦 Installation & Usage

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
   python shieldscan_elite.py
   ```

## 4. ⚠️ Disclaimer

This tool is designed for educational purposes and authorized network auditing only. Do not use it against networks or systems you do not have explicit permission to scan.
