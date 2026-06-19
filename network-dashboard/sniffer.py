from scapy.all import *
import json
import os

DATA_FILE = "packets.json"

if not os.path.exists(DATA_FILE):
    with open(DATA_FILE, "w") as f:
        json.dump([], f)

packet_count = 0


def save_packet(packet_info):

    try:
        with open(DATA_FILE, "r") as f:
            packets = json.load(f)
    except:
        packets = []

    packets.append(packet_info)

    packets = packets[-100:]

    with open(DATA_FILE, "w") as f:
        json.dump(packets, f, indent=4)


def packet_callback(packet):

    global packet_count
    packet_count += 1

    packet_info = {
        "id": packet_count,
        "src": "",
        "dst": "",
        "protocol": "Unknown"
    }

    if packet.haslayer(ARP):

        packet_info["src"] = packet[ARP].psrc
        packet_info["dst"] = packet[ARP].pdst
        packet_info["protocol"] = "ARP"

    elif packet.haslayer(IP):

        packet_info["src"] = packet[IP].src
        packet_info["dst"] = packet[IP].dst

        if packet.haslayer(TCP):
            packet_info["protocol"] = "TCP"

        elif packet.haslayer(UDP):
            packet_info["protocol"] = "UDP"

        elif packet.haslayer(ICMP):
            packet_info["protocol"] = "ICMP"

        else:
            packet_info["protocol"] = "Other"

    print(
        f"[{packet_count}] "
        f"{packet_info['src']} -> "
        f"{packet_info['dst']} "
        f"({packet_info['protocol']})"
    )

    save_packet(packet_info)


print("Network Sniffer Started...")
print("Press CTRL+C to stop.\n")

sniff(prn=packet_callback, store=False)