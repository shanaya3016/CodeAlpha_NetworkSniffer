"""Basic Network Sniffer - CodeAlpha Cyber Security Internship, Task 1.
Captures live network packets and displays source/destination IPs, protocol and payload.
Must be run with Administrator privileges on Windows."""

from datetime import datetime

from scapy.all import IP, TCP, UDP, Raw, sniff, get_if_list

LOG_FILE = "captured_packets.txt"
PROTOCOLS = {1: "ICMP", 6: "TCP", 17: "UDP"}


def process_packet(packet):
    if not packet.haslayer(IP):
        return

    ip_layer = packet[IP]
    proto_num = ip_layer.proto
    proto_name = PROTOCOLS.get(proto_num, f"OTHER({proto_num})")

    src_port = dst_port = None
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    timestamp = datetime.now().strftime("%H:%M:%S")
    line = f"[{timestamp}] {proto_name}  {ip_layer.src}"
    if src_port:
        line += f":{src_port}"
    line += f" -> {ip_layer.dst}"
    if dst_port:
        line += f":{dst_port}"

    payload = b""
    if packet.haslayer(Raw):
        payload = bytes(packet[Raw].load)[:50]

    print(line)
    if payload:
        printable = payload.decode(errors="replace").replace("\n", " ").replace("\r", "")
        print(f"    Payload (first 50 bytes): {printable}")

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")
        if payload:
            f.write(f"    Payload: {payload}\n")


def choose_interface():
    interfaces = get_if_list()
    print("\nAvailable network interfaces:")
    for i, iface in enumerate(interfaces):
        print(f"  [{i}] {iface}")
    choice = input("\nEnter the number of the interface to sniff on (or press Enter for default): ").strip()
    if choice == "":
        return None
    try:
        return interfaces[int(choice)]
    except (ValueError, IndexError):
        print("Invalid choice, using default interface.")
        return None

def main():
    print("=" * 60)
    print("  Basic Network Sniffer - CodeAlpha Task 1")
    print("=" * 60)
    print("This tool captures live packets on your network and shows")
    print("their source/destination IP, protocol and payload.")
    print("Run as Administrator. Press Ctrl+C to stop.\n")

    iface = choose_interface()

    try:
        count_str = input("How many packets to capture? (Enter for unlimited): ").strip()
        count = int(count_str) if count_str else 0
    except ValueError:
        count = 0

    print(f"\nStarting capture{' on ' + iface if iface else ''}... Press Ctrl+C to stop.\n")

    try:
        sniff(iface=iface, prn=process_packet, count=count, store=False)
    except PermissionError:
        print("\nPermission denied. Please run VS Code / this terminal as Administrator.")
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")

    print(f"\nDone. Packet log saved to {LOG_FILE}")


if __name__ == "__main__":
    main()