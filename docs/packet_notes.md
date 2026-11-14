# SFG2 network protocol — quick reference

Full narrative and every test result: `Work.txt`. This file is the
short, lookup-friendly version of the same facts, matching the code in
`scripts/ue4_packet.py`.

## Services

| Service | Address | Notes |
|---|---|---|
| API backend | sfg2api.forge-games.com (51.91.73.205) | HTTPS, no useful endpoints found |
| Legacy master (dead) | 85.25.194.37:7500 | hard-coded in `libUE4.so`, times out |
| Master servers (pak config) | 43.249.37.193, 198.44.48.154, 85.25.194.37 : 7600 | from `DefaultEngine.ini` |
| JOIN service | 198.44.48.154:7790 | plain HTTP POST, see below |
| **HUB (used by this project)** | **94.26.249.123**, UDP 7790-7799 | registration + relay, "Russia" region in-game |
| Example 3rd-party dedicated server | 2.56.246.77:17092 | nagoory's server, listed and joinable |

## JOIN service (TCP, plain HTTP, no TLS)

Request:
```
POST / HTTP/1.1
Host: 198.44.48.154:7790
User-Agent: SpecialForcesGroup2
Version: 4.3
Content-Type: application/json
_Function_: JoinServer
Content-Length: 0
_Data_: 2.56.246.77:17092/nagoory-dedicated
```
Reply:
```
_Function_=JoinServer;_MSG_=2.56.246.77:17092;_RoomLink_=2.56.246.77:17092/nagoory-dedicated;!Pass=;;
```

## HUB registration (UDP, plain text, no token, no encryption)

1. Ping: send `"Ping"`, hub echoes `"Ping"`, reply with one byte `0x07`.
2. Register (repeat every ~20s, to 2-3 of the ten hub ports):
   ```
   _Function_=RegistrationServerHub~_Data_=Po=7777;SV=4.3;SN=<name>;M=Desert;CP=0;MP=6;GM=CaptureTheFlag(0);Pa=<password>;~
   ```
   + 4 trailing zero bytes.
3. Reply `OKRegisterHub`:
   ```
   _Function_=OKRegisterHub;_MSG_=<ip:port>~<ip:port>~<ip:port>~<ip:port>~<ip:port>;_RoomLink_=<ip>:7777/<name>;!Pass=<password>;;
   ```
   Five relay endpoints.
4. Reply `ERROR` when a registration is refused, e.g.:
   ```
   _Function_=ERROR;_MSG_=You can not create a room while other room are not filled
   ```
   Seen repeatedly while registering under conditions that are not yet
   fully understood — see "Open questions" below.
5. Open each relay: send `"IamServer"` repeated every ~10s to every
   relay port; each relay answers `"OK"`. Every ~50s each relay also
   sends an unsolicited 3-byte all-zero keepalive.
6. From then on, player packets for this registration arrive FROM a
   relay port TO the host's port 7777; reply to that same relay port.

There is a second, unused registration function visible as a string in
`libUE4.so`: `RegistrationServerWhite`. Sending it to the hub (same
message format, just the function name changed) got **zero replies**,
while `RegistrationServerHub` got three `ERROR` replies in the same
test. It behaves as a different, gated channel — see "Open questions".

## UE4 stateless handshake (4 packets, 25 bytes each)

```
client -> host   all-zero packet            (start)
host   -> client challenge: timestamp + 20-byte random cookie
client -> host   same cookie echoed back
host   -> client ack: timestamp field = -1.0, same cookie
```
Bit layout (LSB first): `handshake_flag(1) reserved(1) session_id(1)
timestamp_float(32) cookie(160) terminator(1)`. See
`ue4_packet.handshake_packet` / `decode_handshake`.

The 14-bit initial sequence numbers for both sides are visible inside
the cookie bytes of a real handshake (server's at bit 35, client's at
bit 51 of the packet) — but our server does not need to read them; it
learns its own initial sequence from the `ack` field of the client's
first game packet (see `chseq_base` usage in `hubjoin.py`).

## Game packet (post-handshake)

See the full bit layout in `scripts/ue4_packet.py` module docstring.
Key functions: `parse_conn`, `build_conn`.

## Bunch header and the ChSequence rule

See `scripts/ue4_packet.py` (`parse_bunches`, `set_chseq`,
`chseq_base`, `rebase_reliable_chseq`) — this is the central discovery
of the project:

> Every channel's reliable sequence starts from `base = (that side's own
> initial packet sequence number) mod 1024`. The first reliable bunch on
> ANY channel of that side carries `base + 1`.

Position of the ChSequence field inside the body:
- Hello (`bOpen=1`): bits 25–34
- Challenge / Welcome (reliable, not open): bits 23–32

Wrong values are not merely ignored — the client stalls or closes the
connection. Every test before this rule was found ended with the
client closing a fraction of a second after the Challenge.

## Connection sequence observed

```
player -> Hello (27 B)
server -> Challenge (31 B)
player -> Hello (resent) + Login (176-193 B)
server -> Welcome (101 B): map + game mode class
player -> Netspeed (22 B, value 100000) [+ Join, sometimes combined, 29 B]
player -> Join (18 B) if separate
server -> (within ~9 ms of the Join in a real session) first state burst:
          ~17 packets / ~3.5 KB within 320 ms, then a steady ~60 Hz stream
player -> (≈0.34 s after the first burst) reliable bunches on channel 2:
          951, 479, 263 B, ChSequence continuing from base+1 on that channel
```

Channels opened by the server in the first burst in the recorded
session: 2, 3, 8, 11 (reliable, `bOpen=1`, with package-map exports).
Channel 5 carries unreliable voice data (a 0a31 marker was used as a
cheap filter for it in early scripts, but is not required — see
Work.txt section 12.3, run "rain11").

A **Close bunch** (`bControl=1 bOpen=0 bClose=1 CloseReason=0`,
reliable, `ChIndex=0`, no data) is how the client ends the connection.
On the wire it is a 17-byte packet (34 bytes if it also carries a
re-sent Hello), always ending in the 4 bytes `ff 05 00 c0`.

## Open questions (as of the last session worked on this)

1. **Why does the client close the connection 4–7 seconds after the
   Welcome**, even once the replay server sends real recorded state?
   The client never sends anything on channel 2 in our tests (only
   10-byte acks, then the Close) — unlike the recorded real session.
   A Frida backtrace of the client's own `sendto()` call for the Close
   bunch was captured (see `analysis/frida_close_tracer.js`) but not
   yet matched address-by-address against the Ghidra decompilation of
   `libUE4.so` for a definitive answer. This is the project's current
   stopping point.
2. **What does `RegistrationServerWhite` actually require?** It is a
   distinct, silently-gated registration path (zero replies, vs. three
   `ERROR` replies for `RegistrationServerHub` in the same test), and
   is the leading hypothesis for how dedicated/trusted servers (the
   official ones, and possibly nagoory's) register without competing
   for the "one room while others are not filled" slot that
   `RegistrationServerHub` enforces.
3. **The `"You can not create a room while other room are not filled"`**
   error from `RegistrationServerHub` — exact trigger condition (per-IP?
   per account? a stale prior registration?) is not confirmed.
