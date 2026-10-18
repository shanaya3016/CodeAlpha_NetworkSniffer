# Network Sniffer – Analysis Report

**Project:** CodeAlpha Cyber Security Internship – Task 1
**Author:** [Your Name] · **Date:** 16 October 2026
**Tool:** Python 3 + Scapy, run on Windows with Npcap

---

## 1. Objective and Methodology

The goal of this task was to build a basic network sniffer capable of capturing live packets, understanding their structure, and observing how data flows across a network.

**Tool used:** `scapy`, a Python library that provides low-level access to network packets via Npcap (Windows packet capture driver).

**How it works:**
1. `scapy.sniff()` captures live packets from a chosen network interface.
2. For each packet, a callback function (`process_packet`) extracts:
   - Source and destination IP address (from the IP layer)
   - Protocol (TCP, UDP, ICMP, or other — mapped from the IP protocol number)
   - Source and destination port (from the TCP/UDP layer, if present)
   - The first 50 bytes of the payload (raw application data, if present)
3. Each packet is printed to the console and appended to `captured_packets.txt` for later review.

The program requires Administrator privileges because raw packet capture bypasses the normal network stack and needs elevated OS permissions.

## 2. Capture Session 1 — HTTPS Traffic (Port 443)

**Setup:** Browsed to a standard HTTPS website while capturing 20 packets.

**Sample output:**

**Observation:** The IP addresses, ports and protocol (TCP) were clearly visible — this metadata is never encrypted and can always be seen by anyone monitoring the network. However, the **payload was completely unreadable**, appearing as random bytes. This is because HTTPS traffic is encrypted end-to-end with TLS; only the sender and recipient can decrypt the actual content.

## 3. Capture Session 2 — HTTP Traffic (Port 80)

**Setup:** Browsed to `neverssl.com`, a site deliberately served over plain HTTP (no encryption), while capturing 60 packets.

**Sample output:**

**Observation:** This time the payload was **fully readable plain text** — the HTTP response status line and headers were captured exactly as sent. Anyone sniffing this traffic (for example, on a public Wi-Fi network) could read the entire request and response, including any data such as form submissions or cookies sent without encryption.

## 4. Protocol and Traffic Analysis

| Protocol | Observed role |
|---|---|
| TCP | Used for most web traffic (HTTP and HTTPS); establishes a reliable connection before data is exchanged (visible as separate handshake packets with no payload, followed by data packets) |
| UDP | Observed on port 443 as well — modern browsers increasingly use QUIC/HTTP-3, which runs over UDP instead of TCP, while still using TLS encryption |
| Ports | Port 80 = HTTP (unencrypted), Port 443 = HTTPS/QUIC (encrypted) — the port number alone is a strong indicator of whether traffic is protected |

**Key comparison:**

| | HTTPS (443) | HTTP (80) |
|---|---|---|
| Metadata (IP, port, protocol) | Visible | Visible |
| Payload | Encrypted / unreadable | Fully readable plain text |
| Risk if intercepted | Low — content protected by TLS | High — content fully exposed |

## 5. Conclusions and Best Practices

1. **Network metadata is never private.** Source/destination IPs, ports, and protocol are visible to anyone who can capture traffic on the network path (e.g. on shared Wi-Fi), regardless of encryption.
2. **Encryption protects content, not metadata.** HTTPS stops attackers from reading the actual data, but does not hide who is talking to whom.
3. **Plain HTTP exposes everything.** As shown in Session 2, HTTP traffic can be read in full by anyone sniffing the network — including any sensitive data sent without TLS.
4. **Practical recommendations:**
   - Always use HTTPS; browsers now flag plain HTTP sites as "Not Secure" for this reason.
   - Avoid entering sensitive information on any site without a padlock/HTTPS.
   - Use a VPN on untrusted networks (e.g. public Wi-Fi) to encrypt all traffic, not just browser traffic.
   - Network administrators should monitor for unexpected plaintext protocols on their networks as a security hygiene check.

## 6. Limitations

- This sniffer only inspects IP/TCP/UDP headers and the first 50 bytes of payload; it does not reassemble full application-layer data (e.g. complete HTTP requests/responses or file transfers).
- Capturing traffic on a shared or corporate network may require explicit authorization; this test was performed only on traffic from the author's own machine.
- Npcap and Administrator access are Windows-specific requirements; on Linux/macOS, scapy can typically run with `sudo` and no additional driver.

## 7. References

- Scapy documentation: https://scapy.readthedocs.io/
- Npcap: https://npcap.com/
- OWASP Transport Layer Protection Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html