#!/usr/bin/env python3
"""
extract_welcome.py - Pull the host's Welcome packet body out of a real
SFG2 capture and save it as welcome_body.bin, so hubjoin.py and
replay_server.py have a real Welcome to send (map + game mode).

The Welcome is the first packet the host sends back that is LARGER than
100 bytes, sent right after it receives the player's Login (also >100
bytes, itself sent right after the Challenge). In our own captures this
was frame-wise: Hello(27) -> Challenge(31) -> Login(176-193, re-sends the
Hello) -> Welcome(101 bytes on the wire -> 92-byte body here).

Usage:
    pip install scapy --break-system-packages
    python3 extract_welcome.py rain_host.pcap <host_port> welcome_body.bin

where <host_port> is the player's relay port for the session you want
(find it with: tshark -r rain_host.pcap -q -z conv,udp).
"""
import sys

from scapy.all import PcapReader, IP, UDP  # noqa: E402

sys.path.insert(0, __file__.rsplit("/", 1)[0])
from ue4_packet import parse_conn  # noqa: E402


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    pcap_path = sys.argv[1]
    port = int(sys.argv[2])
    out_path = sys.argv[3] if len(sys.argv) > 3 else "welcome_body.bin"

    stage = 0  # 0=wait Hello, 1=wait Login(>100B from player), 2=found Welcome
    for pkt in PcapReader(pcap_path):
        if UDP not in pkt or pkt[UDP].sport != port and pkt[UDP].dport != port:
            continue
        data = bytes(pkt[UDP].payload)
        c = parse_conn(data)
        if c is None:
            continue
        if stage == 0 and len(data) == 27:
            stage = 1
            continue
        if stage == 1 and len(data) > 100:
            stage = 2  # this was the Login; the NEXT >100B packet from the
            continue    # host is the Welcome
        if stage == 2 and len(data) > 60:
            body_bytes = ((c["body"] << 0) | (1 << c["body_len"])).to_bytes(
                (c["body_len"] + 8) // 8, "little"
            )
            with open(out_path, "wb") as f:
                f.write(body_bytes)
            print(f"wrote {out_path}: {len(body_bytes)} bytes "
                  f"({c['body_len']} body bits), seq={c['seq']} ack={c['ack']}")
            return
    sys.exit("Welcome not found - check the port number and capture file")


if __name__ == "__main__":
    main()
