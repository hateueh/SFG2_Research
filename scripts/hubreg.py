#!/usr/bin/env python3
"""
hubreg.py - Register a server on the SFG2 hub so it appears in the
in-game server list ("Russia" origin). Registration only: it does not
receive or answer any player traffic (see hubjoin.py for that).

Protocol (plain text UDP, no encryption, no token):
    host -> hub :  "Ping"
    hub  -> host:  "Ping" (echo)
    host -> hub :  0x07                                  (ack byte)
    host -> hub :  _Function_=RegistrationServerHub~_Data_=
                   Po=<port>;SV=<game version>;SN=<name>;M=<map>;
                   CP=<current players>;MP=<max players>;
                   GM=<game mode>(0);Pa=<password>;~    + 4 zero bytes
                   (sent every ~20s, to 2-3 random hub ports each time)
    hub  -> host:  _Function_=OKRegisterHub;_MSG_=<relay1>~<relay2>~...~<relay5>;
                   _RoomLink_=<ip>:<port>/<name>;!Pass=<password>;;
                or _Function_=ERROR;_MSG_=<reason>

Usage:
    python3 hubreg.py <server-name> <minutes 1-5> [password]
"""
import socket
import sys
import time
import random
import select

HUB = "94.26.249.123"          # Selectel, Russia - the hub that lists our test servers
PORTS = list(range(7790, 7800))
GAME_PORT = 7777
GAME_VERSION = "4.3"


def main():
    name = sys.argv[1] if len(sys.argv) > 1 else "TEST-not-joinable"
    minutes = min(float(sys.argv[2]) if len(sys.argv) > 2 else 3, 5)
    password = sys.argv[3] if len(sys.argv) > 3 else ""

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("0.0.0.0", GAME_PORT))
    s.setblocking(False)

    oks = 0

    def recv_all(wait):
        end = time.time() + wait
        got = []
        while time.time() < end:
            r, _, _ = select.select([s], [], [], max(0, end - time.time()))
            if not r:
                break
            got.append(s.recvfrom(2048))
        return got

    def ping(port):
        s.sendto(b"Ping", (HUB, port))
        if any(d == b"Ping" and a[1] == port for d, a in recv_all(1.0)):
            s.sendto(b"\x07", (HUB, port))

    def register(port):
        nonlocal oks
        msg = (
            "_Function_=RegistrationServerHub~_Data_="
            f"Po={GAME_PORT};SV={GAME_VERSION};SN={name};M=Desert;"
            f"CP=0;MP=6;GM=CaptureTheFlag(0);Pa={password};~"
        ).encode() + b"\x00" * 4
        s.sendto(msg, (HUB, port))
        for data, addr in recv_all(1.5):
            print(f"  [{addr}] {data[:120]!r}")
            if b"OKRegisterHub" in data:
                oks += 1

    print(f"registering '{name}' password={password!r} for {minutes} minutes")
    end = time.time() + minutes * 60
    while time.time() < end:
        t0 = time.time()
        ports = random.sample(PORTS, 3)
        for p in ports:
            ping(p)
        for p in ports:
            register(p)
        time.sleep(max(0, 20 - (time.time() - t0)))

    print("stopped. OKRegisterHub replies received:", oks)


if __name__ == "__main__":
    main()
