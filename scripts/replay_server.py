#!/usr/bin/env python3
"""
replay_server.py - hubjoin.py plus a replay of a recorded real host
session. After the player's Join packet, it replays (with the original
timing) every packet a real host sent to a real player after its own
Join, with two fixes applied to each reliable bunch:

  1. GUID rewrite: the recorded player's GUID is replaced with the
     actual joining player's GUID (read from their Login packet).
  2. ChSequence rebase: every reliable bunch's ChSequence is shifted so
     it continues from THIS connection's base instead of the recorded
     session's base (see ue4_packet.rebase_reliable_chseq and Work.txt
     section 11.5 - without this the player silently stops processing
     the replayed state).

Result reached with this script (see docs/Work.txt section 12.3, run
"rain7"): the player's screen shows the full map, the team-selection
prompt, a recorded character walking around, and the recorded chat
messages. This is a REPLAY, not a live match - nothing the real player
does is read back by the game. The player's client sends a Close bunch
and leaves 4-7 seconds after the Welcome in every run so far; see
docs/open_questions.md.

Usage:
    python3 replay_server.py <server-name> <minutes 1-5> <password|none>

Needs, next to this script:
    welcome_body.bin   - see extract_welcome.py
    replay.bin         - see extract_replay.py (the recorded post-Join
                          packet stream to replay)
"""
import os
import pickle
import select
import socket
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))
from ue4_packet import (  # noqa: E402
    parse_conn, build_conn, set_chseq, chseq_base, rebase_reliable_chseq,
)

HUB = os.environ.get("HUB", "94.26.249.123")
HUB_PORTS = list(range(7790, 7800))
GAME_PORT = 7777
GAME_VERSION = "4.3"

H1_BODY = 0x8018229b991c9a9b18800000048181c00bff7e800800
H1_LEN = 176

HERE = os.path.dirname(__file__)
with open(os.path.join(HERE, "welcome_body.bin"), "rb") as f:
    _w = f.read()
W_BODY = int.from_bytes(_w, "little")
W_LEN = len(_w) * 8 - 1

ACK_BODY, ACK_LEN = 0, 10

# replay.bin: a pickled list of (delay_seconds, body_int, body_len,
# recorded_base) tuples, produced by extract_replay.py. recorded_base is
# the ChSequence base of the SESSION THAT WAS CAPTURED (constant for the
# whole file), carried alongside each packet so rebasing doesn't need a
# second source of truth.
with open(os.path.join(HERE, "replay.bin"), "rb") as f:
    REPLAY = pickle.load(f)


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
    log("sent", label, "->", addr, "seq", st["next_seq"], len(pkt), "bytes")
    st["next_seq"] = (st["next_seq"] + 1) & 0x3FFF


def rewrite_guid(body: int, body_len: int, old_guid_hex: str, new_guid_hex: str) -> int:
    """Replace every occurrence of the recorded GUID (16 bytes) with the
    joining player's GUID, inside the packet body. Both are compared/written
    as raw bytes at every bit offset (UE4 bunch payloads are not
    byte-aligned, so a byte-level replace on the packed integer's bytes
    only works when the GUID happens to start byte-aligned in that bunch;
    this is true for the recorded capture used in our tests - see
    docs/packet_notes.md for the one bunch where it was not and had to be
    patched by hand)."""
    nbytes = (body_len + 7) // 8
    raw = bytearray(body.to_bytes(nbytes, "little"))
    old = bytes.fromhex(old_guid_hex)
    new = bytes.fromhex(new_guid_hex)
    raw = bytearray(bytes(raw).replace(old, new))
    return int.from_bytes(raw, "little")


def schedule_replay(sock, addr, st, player_guid_hex):
    t0 = time.time()

    def run_one(i=0):
        if i >= len(REPLAY):
            log("replay done", addr[1])
            return
        delay, body, body_len, recorded_base = REPLAY[i]
        elapsed = time.time() - t0
        wait = delay - elapsed
        if wait > 0:
            time.sleep(min(wait, 0.05))
            return  # caller's loop will call us again; see main loop below
        body = rebase_reliable_chseq(
            body, body_len, (st["base"] - recorded_base) & 1023
        )
        body = rewrite_guid(body, body_len, st["recorded_guid"], player_guid_hex)
        send_conn(sock, addr, st, body, body_len, "replay")
        st["replay_i"] = i + 1

    return run_one


def extract_player_guid(login_body_bytes: bytes) -> str:
    """The Login packet's URL contains '...?Name=localhost-<32 hex chars>'."""
    marker = b"localhost-"
    i = login_body_bytes.find(marker)
    if i == -1:
        return None
    return login_body_bytes[i + len(marker): i + len(marker) + 32].decode(
        "ascii", "ignore"
    )


def on_relay_packet(sock, data, port, conns):
    c = parse_conn(data)
    if c is None:
        return

    st = conns.setdefault(
        port,
        dict(seen=set(), next_seq=None, stage=0, base=None,
             replay_i=0, closed=False, need_join=True,
             recorded_guid="00030EA508DF3037159F9A16D5BD9326"),  # from capture
    )
    if st["closed"]:
        return
    if st["next_seq"] is None:
        st["next_seq"] = (c["ack"] + 1) & 0x3FFF
        st["base"] = chseq_base(st["next_seq"])
    st["seen"].add(c["seq"])

    n = len(data)
    addr = (HUB, port)

    # Close bunch: bControl=1 bOpen=0 bClose=1 CloseReason=0, reliable,
    # ChIndex=0, 0 data bits. Packet ends in ff 05 00 c0 in every capture
    # of it so far.
    if st["stage"] >= 2 and 10 < n <= 40 and data[-4:] == bytes.fromhex("ff0500c0"):
        st["closed"] = True
        log("CLIENT CLOSED the connection - stopping replay for", port)
        return

    if st["stage"] == 0 and n == 27:
        body = set_chseq(H1_BODY, st["base"] + 1, bit_offset=23)
        send_conn(sock, addr, st, body, H1_LEN, "Challenge")
        st["stage"] = 1
        return

    if st["stage"] == 1 and n > 100:
        st["player_guid"] = extract_player_guid(data)
        body = set_chseq(W_BODY, st["base"] + 2, bit_offset=23)
        send_conn(sock, addr, st, body, W_LEN, "Welcome")
        send_conn(sock, addr, st, ACK_BODY, ACK_LEN, "ack")
        st["stage"] = 2
        return

    # stage 2: wait for the Join (18 or 29 bytes) before replaying anything;
    # starting the replay before the Join reaches the client made it close
    # the connection immediately in our tests (see Work.txt 12.3, "joinable7").
    if st["stage"] == 2 and st["need_join"] and n in (18, 29):
        st["need_join"] = False
        st["replay_t0"] = time.time()
        return

    send_conn(sock, addr, st, ACK_BODY, ACK_LEN, "ack")


def pump_replay(sock, conns):
    """Call frequently from the main loop: sends any due replay packets."""
    now = time.time()
    for port, st in conns.items():
        if st["closed"] or st.get("need_join", True):
            continue
        i = st["replay_i"]
        if i >= len(REPLAY):
            continue
        delay, body, body_len, recorded_base = REPLAY[i]
        if now - st["replay_t0"] < delay:
            continue
        guid = st.get("player_guid") or st["recorded_guid"]
        body = rebase_reliable_chseq(body, body_len, (st["base"] - recorded_base) & 1023)
        body = rewrite_guid(body, body_len, st["recorded_guid"], guid)
        send_conn(sock, (HUB, port), st, body, body_len, "replay")
        st["replay_i"] = i + 1
        if st["replay_i"] == len(REPLAY):
            log("replay done", port)


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

        pump_replay(s, conns)

        r, _, _ = select.select([s], [], [], 0.2)
        if not r:
            continue
        data, addr = s.recvfrom(2048)

        if b"OKRegisterHub" in data:
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
            if data == b"OK" or (len(data) <= 4 and data == b"\x00" * len(data)):
                continue
            on_relay_packet(s, data, addr[1], conns)


if __name__ == "__main__":
    main()
