# SFG2 Server Emulation

Reverse-engineering the server-list, join and in-match network protocol
of **Special Forces Group 2** (Android, Unreal Engine 4.21, developer
ForgeGames, support discontinued) in order to run a private server that
real, unmodified copies of the game can find and join.

## Status

- ✅ A server we run **registers on the real hub and appears in the
  in-game server list**.
- ✅ A real player can **join** it: the full UE4 handshake, login and
  welcome exchange completes, and the correct map loads.
- ✅ Feeding the connection a **replay of a recorded real match**
  (`replay_server.py`) gets the player as far as the team-selection
  screen with the map and recorded players rendered.
- ⏳ **Not solved yet:** the client closes the connection 4–7 seconds
  after joining, because the server has no real game logic — it cannot
  spawn the player, process their input, or update the match state.
  That logic is compiled, unsymbolicated, inside `libUE4.so`.

See `docs/packet_notes.md` for the protocol in one page, or
`docs/Work.txt` for the full chronological record: every tool, command,
test and result from the first probe to the current stopping point.

## Why this exists

ForgeGames stopped maintaining the game and does not answer players.
There is no official server binary, no SDK, no documentation. Everything
here was recovered by analyzing the APK/OBB and the game's own network
traffic — `strings`, `radare2`, `readelf` relocations, Ghidra headless
decompilation, Frida (no root needed — see `docs/frida_setup.md`),
`tshark`/`scapy` packet capture analysis, and plain Python UDP servers.

A third party, **nagoory**, already runs a private dedicated server for
this game that real players use — proof this is achievable. His
implementation is not open source; this repository is an independent
effort using only what could be observed from the game itself.

## Repository layout

```
scripts/      Working Python servers — see below
analysis/     Static/dynamic analysis tools (pak, .so strings, Ghidra, Frida)
docs/         Protocol reference, Frida setup notes, full project log
```

## Scripts

| File | What it does |
|---|---|
| `scripts/ue4_packet.py` | Shared module: packet/bunch parsing, the handshake, the ChSequence rule. Everything else imports this. |
| `scripts/hubreg.py` | Registers a server name on the hub so it shows in the in-game list. Registration only, answers no player traffic. |
| `scripts/hubjoin.py` | Registration **plus** the relay + UE4 handshake, so a player can actually join and load the map. No game logic beyond that. |
| `scripts/replay_server.py` | `hubjoin.py` plus replaying a recorded real session's packets (with GUID rewriting and ChSequence rebasing) so the player sees a populated, moving map. Current best result. |
| `scripts/extract_welcome.py` | Pulls a real `Welcome` packet body out of your own `.pcap` capture (required input for the two servers above — not included, see below). |
| `scripts/extract_replay.py` | Builds the recorded-session replay data `replay_server.py` needs, from your own capture. |

### Running a server

```bash
# one-time, from your own packet capture (see docs/packet_notes.md)
python3 scripts/extract_welcome.py rain_host.pcap <port> scripts/welcome_body.bin
python3 scripts/extract_replay.py  rain_play.pcap  <port> scripts/replay.bin

HUB=94.26.249.123 python3 scripts/replay_server.py <name> <minutes 1-5> none
```
Use a clearly test-labelled name, a short lifetime, and no password —
this registers on the **real, shared** hub, visible to real players.

## Analysis tools

| File | What it does |
|---|---|
| `analysis/read_pak.py` | List/extract files from the encrypted `.pak` (needs the AES-256 key, see below). |
| `analysis/so_strings.py` | Read ASCII and UE4's UTF-16 strings out of `libUE4.so`, including the overlapping-chunk cases plain `strings` mangles. |
| `analysis/find_native_thunk.sh` | Finds a UFunction's native implementation address via ELF relocations (UE4's reflection table defeats normal xref search). |
| `analysis/DecompAt.py` | Ghidra headless post-script: decompiles specific addresses without a full analysis pass. |
| `analysis/frida_close_tracer.js` | Frida script: backtraces the client's own code path when it sends the connection-close packet. Requires only an injected gadget, not root — see `docs/frida_setup.md`. |

## What is intentionally not in this repo

- **The pak's AES-256 key.** It was found published online, not
  extracted by us; set it as `SFG2_PAK_KEY` before running
  `read_pak.py`.
- **`welcome_body.bin` / `replay.bin`.** These are extracted straight
  from real packet captures of real players and are not code —
  generate your own with the `extract_*.py` scripts above from your own
  captures.
- **Raw `.pcap` files, the `.pak`, `libUE4.so` itself.** Game assets and
  player-identifying capture data, not something this repo should
  redistribute.

## Note on the pak

The `.pak` only contains cooked Unreal assets (Blueprints, meshes,
textures, sounds, animations) and `.ini` config — no executables and no
source code. All of the game's actual network and match logic is
compiled into `libUE4.so`. The pak's `DefaultEngine.ini` is still
useful: it is where the master-server addresses and the dedicated-server
settings object (`[/Script/MySettings]`) were found.
