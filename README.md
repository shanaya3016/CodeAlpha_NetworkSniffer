# CodeAlpha_NetworkSniffer

**Task 1 – Basic Network Sniffer** | CodeAlpha Cyber Security Internship

A Python network sniffer built with Scapy that captures live packets on a network interface and displays source/destination IPs, protocol, ports, and payload for each packet.

## What is inside

| File | Purpose |
|---|---|
| `sniffer.py` | Main program: captures live packets and logs them |
| `captured_packets.txt` | Sample output from a live capture session |
| `REPORT.md` | Full analysis and documentation of the capture sessions |
| `requirements.txt` | Python dependencies |

## Task requirements checklist

| Requirement | Where |
|---|---|
| Build a Python program to capture network traffic packets | `sniffer.py`, using the `scapy` library |
| Analyze captured packets to understand structure and content | REPORT.md §2-3 (protocol breakdown, payload analysis) |
| Learn how data flows and protocol basics | REPORT.md §1 and §4 |
| Use libraries like scapy or socket | `scapy.all` (`sniff`, `IP`, `TCP`, `UDP`, `Raw`) |
| Display source/destination IPs, protocols and payloads | Printed live to console and saved to `captured_packets.txt` |

## Run it

> ⚠️ Requires Administrator privileges on Windows (raw packet capture needs elevated access) and [Npcap](https://npcap.com/) installed in WinPcap-compatible mode.

```bash
pip install -r requirements.txt
python sniffer.py
```

The program will:
1. List available network interfaces and let you choose one (or press Enter for default).
2. Ask how many packets to capture (press Enter for unlimited; stop anytime with Ctrl+C).
3. Print each packet's timestamp, protocol, source/destination IP:port, and first 50 bytes of payload.
4. Save the full log to `captured_packets.txt`.

## Result

Captured and analyzed both encrypted (HTTPS, port 443) and unencrypted (HTTP, port 80) traffic:

| Traffic type | Port | Payload observed |
|---|---|---|
| HTTPS | 443 | Encrypted, unreadable (e.g. random bytes) |
| HTTP | 80 | Plain readable text (e.g. `HTTP/1.1 200 OK Date: ...`) |

This demonstrates how TLS/SSL encryption protects data in transit even when packets are successfully intercepted.

Author: Noor ul Aien
