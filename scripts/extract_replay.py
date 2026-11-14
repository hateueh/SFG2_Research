#!/usr/bin/env python3
"""
extract_replay.py - Build replay.bin for replay_server.py from a real
capture: every host -> client packet sent after the recorded player's
Join, with its delay from the Join and the session's ChSequence base.

Usage:
    pip install scapy --break-system-packages
    python3 extract_replay.py rain_play.pcap <relay_port> replay.bin

<relay_port> is the player's relay port for the session to record (find
candidates with: tshark -r rain_play.pcap -q -z conv,udp - pick one with
a long packet exchange after its Welcome).
"""
import os
import pickle
import sys

from scapy.all import PcapReader, UDP  # noqa: E402

sys.path.insert(0, os.path.dirname(__file__))
from ue4_packet import parse_conn, chseq_base  # noqa: E402


def main():
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    pcap_path = sys.argv[1]
    port = int(sys.argv[2])
    out_path = sys.argv[3] if len(sys.argv) > 3 else "replay.bin"

    host_to_client = []
    client_to_host = []
    server_initial_seq = None

    for pkt in PcapReader(pcap_path):
        if UDP not in pkt:
            continue
        if pkt[UDP].sport != port and pkt[UDP].dport != port:
            continue
        data = bytes(pkt[UDP].payload)
        c = parse_conn(data)
        if c is None:
            continue
        from_host = pkt[UDP].sport == port
        if server_initial_seq is None and not from_host:
            # player's ack on their first packet == server's initial seq - 1
            server_initial_seq = (c["ack"] + 1) & 0x3FFF
        (host_to_client if from_host else client_to_host).append(
            (float(pkt.time), c, data)
        )

    if server_initial_seq is None:
        sys.exit("could not determine the server's initial sequence number")
    base = chseq_base(server_initial_seq)

    # find the player's Join (18 or 29 bytes) to use as t=0 for the replay
    join_t = None
    for t, c, data in client_to_host:
        if len(data) in (18, 29):
            join_t = t
            break
    if join_t is None:
        sys.exit("could not find the player's Join packet (18 or 29 bytes)")

    out = []
    for t, c, data in host_to_client:
        if t < join_t:
            continue
        out.append((round(t - join_t, 4), c["body"], c["body_len"], base))

    with open(out_path, "wb") as f:
        pickle.dump(out, f)
    print(f"wrote {out_path}: {len(out)} packets, base={base}, "
          f"first delay={out[0][0] if out else None}s")


if __name__ == "__main__":
    main()
