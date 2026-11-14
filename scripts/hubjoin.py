#!/usr/bin/env python3
"""
hubjoin.py - Registers on the SFG2 hub (like hubreg.py), opens the five
relay endpoints the hub assigns, and runs the UE4 stateless handshake plus
the control-channel sequence (Hello -> Challenge -> Login -> Welcome ->
Netspeed -> Join) for any player who joins.

This gets a real phone into the match lobby: the map loads and the
Welcome's game mode / map are shown. It has NO game logic beyond that -
after Join, it only acknowledges whatever the player sends. For a version
that also replays a recorded host session so the player sees the map and
other players rendered, see replay_server.py.

Usage:
    python3 hubjoin.py <server-name> <minutes 1-5> <password|none>

Protocol notes and full background: see ../docs/Work.txt sections 10-11.
"""
import os
import select
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from ue4_packet import parse_conn, build_conn, set_chseq, chseq_base  # noqa: E402

HUB = os.environ.get("HUB", "94.26.249.123")
HUB_PORTS = list(range(7790, 7800))
GAME_PORT = 7777
GAME_VERSION = "4.3"

# Challenge body captured from a real session, 176 bits, with its
# ChSequence field (bits 23-32) left as-is; set_chseq() overwrites it
# per-connection before sending.
H1_BODY = 0x8018229b991c9a9b18800000048181c00bff7e800800
H1_LEN = 176

# A Welcome body (map=Desert, mode=GameModeBP) must be captured from a real
# session and saved as welcome_body.bin next to this script. It is NOT
# included in this repo because it is player-identifying capture data, not
# code. Use extract_welcome.py (same folder) on your own rain_play.pcap /
# rain_host.pcap to generate it; see docs/packet_notes.md.
_wpath = os.path.join(os.path.dirname(__file__), "welcome_body.bin")
if not os.path.exists(_wpath):
    sys.exit(
        "missing scripts/welcome_body.bin - run extract_welcome.py on your "
        "own capture first (see docs/packet_notes.md)"
    )
with open(_wpath, "rb") as f:
    _w = f.read()
W_BODY = int.from_bytes(_w, "little")
W_LEN = len(_w) * 8 - 1   # last byte's top bit is the terminator; see docs

ACK_BODY, ACK_LEN = 0, 10  # an empty "ack-only" packet


def log(*a):
    print("[%6.1f]" % (time.time() - START), *a, flush=True)


def send_conn(sock, addr, st, body, body_len, label):
    seen = st["seen"]
    ack = max(seen) if seen else 0
    hist = 0
    for i in range(32):
        if (ack - 1 - i) in seen:
            hist |= 1 << i
    pkt = build_conn(st["next_seq"] & 0x3FFF, ack, [hist], body, body_len)
    sock.sendto(pkt, addr)
    log("sent", label, "->", addr, "seq", st["next_seq"], "ack", ack, len(pkt), "bytes")
    st["next_seq"] = (st["next_seq"] + 1) & 0x3FFF


def on_relay_packet(sock, data, port, conns):
    c = parse_conn(data)
    if c is None:
        return  # handshake / keepalive / unparseable, ignore here

    st = conns.setdefault(
        port, dict(seen=set(), next_seq=None, stage=0, base=None)
    )
    if st["next_seq"] is None:
        st["next_seq"] = (c["ack"] + 1) & 0x3FFF
        st["base"] = chseq_base(st["next_seq"])
    st["seen"].add(c["seq"])

    n = len(data)
    addr = (HUB, port)

    if st["stage"] == 0 and n == 27:          # Hello
        body = set_chseq(H1_BODY, st["base"] + 1, bit_offset=23)
        send_conn(sock, addr, st, body, H1_LEN, "Challenge")
        st["stage"] = 1

    elif st["stage"] == 1 and n > 100:        # Login (carries a re-sent Hello)
        body = set_chseq(W_BODY, st["base"] + 2, bit_offset=23)
        send_conn(sock, addr, st, body, W_LEN, "Welcome")
        send_conn(sock, addr, st, ACK_BODY, ACK_LEN, "ack")
        st["stage"] = 2

    elif n > 10:                              # Netspeed / Join / anything else
        send_conn(sock, addr, st, ACK_BODY, ACK_LEN, "ack")
    # n == 10: a pure ack from the player, nothing to send back


def main():
    global START
    START = time.time()

    name = sys.argv[1] if len(sys.argv) > 1 else "TEST-not-joinable"
    minutes = min(float(sys.argv[2]) if len(sys.argv) > 2 else 3, 5)
    pw_arg = sys.argv[3] if len(sys.argv) > 3 else "none"
    password = "" if pw_arg == "none" else pw_arg

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", GAME_PORT))
    s.setblocking(False)

    relay_ports = []
    conns = {}
    last_register = 0
    last_keepalive = 0
    end = time.time() + minutes * 60

    while time.time() < end:
        now = time.time()

        if now - last_register >= 20:
            msg = (
                "_Function_=RegistrationServerHub~_Data_="
                f"Po={GAME_PORT};SV={GAME_VERSION};SN={name};M=Desert;"
                f"CP=0;MP=6;GM=CaptureTheFlag(0);Pa={password};~"
            ).encode() + b"\x00" * 4
            for p in HUB_PORTS[:3]:
                s.sendto(msg, (HUB, p))
            log("registering", name, "password:", repr(password), "for", minutes, "minutes")
            last_register = now

        if relay_ports and now - last_keepalive >= 10:
            for p in relay_ports:
                s.sendto(b"IamServer", (HUB, p))
            last_keepalive = now

        r, _, _ = select.select([s], [], [], 1.0)
        if not r:
            continue
        data, addr = s.recvfrom(2048)

        if b"OKRegisterHub" in data:
            # _Function_=OKRegisterHub;_MSG_=ip:port~ip:port~...;_RoomLink_=...
            try:
                msg = data.split(b"_MSG_=")[1].split(b";")[0].decode()
                relay_ports = [int(e.split(":")[1]) for e in msg.split("~")]
                log("relay ports:", relay_ports)
            except Exception as e:
                log("failed to parse OKRegisterHub:", e)
            continue

        if data == b"Ping":
            s.sendto(b"\x07", addr)
            continue

        if addr[1] in relay_ports:
            if data == b"OK":
                log("OK from relay", addr[1])
            elif len(data) <= 4 and data == b"\x00" * len(data):
                pass  # 3-byte keepalive from the relay, ignore
            else:
                on_relay_packet(s, data, addr[1], conns)


if __name__ == "__main__":
    main()
