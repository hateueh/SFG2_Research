"""
ue4_packet.py - Reverse-engineered Unreal Engine 4.21 packet and bunch
layout used by SFG2's UDP game protocol, plus the stateless-handshake
helper and the ChSequence rule that made the join sequence work.

All offsets below are bit offsets, LSB first (bit 0 = least significant
bit of the first byte), verified against real captured packets
(rain_host.pcap, rain_play.pcap) and against our test servers.

Packet layout (after the stateless handshake):
    bit 0          handshake flag (0 for normal game packets)
    bits 1-4       history word count minus one (hwc-1)
    bits 5-18      AckedSeq (14 bits)
    bits 19-32     Seq (14 bits)
    bits 33..      hwc history words, 32 bits each
                   (bit i of a word == packet (AckedSeq-1-i) was received)
    then           body, starting at bit 33 + 32*hwc
    last bit       a terminating 1 bit (counted inside body_len)

Bunch header, read from the start of the body:
    bits 0-8       packet-level fields (9 bits, observed on every real packet)
    then per bunch:
        bControl (1)
          if bControl: bOpen(1), bClose(1); if bClose: CloseReason(4)
        bIsReplicationPaused (1)
        bReliable (1)
        ChIndex           packed int, 8 bits/byte, bit0 = "more bytes follow"
        bHasPackageMapExports (1)
        bHasMustBeMappedGUIDs (1)
        bPartial (1)
        if bReliable:  ChSequence (10 bits)
        if bPartial:   bPartialInitial(1), bPartialFinal(1)
        if bReliable or bOpen:  channel name
                                17 bits for the control channel
                                9 bits for an opened actor channel
        BunchDataBits (13 bits)
        <data, BunchDataBits bits>

ChSequence rule (section 11.5 of Work.txt - the key discovery):
    base = (that side's own initial packet sequence number) mod 1024
    first reliable bunch on ANY channel of that side = base + 1
    (Hello.ChSequence for the player, Challenge.ChSequence for the server,
    Welcome.ChSequence = base + 2 on channel 0, and so on.)

ChSequence field position inside the body:
    Hello     (bOpen=1, not Challenge/Welcome): bits 25-34
    Challenge / Welcome (reliable, not open):   bits 23-32
"""
import struct


# ---------------------------------------------------------------------------
# Low-level bit helpers
# ---------------------------------------------------------------------------

def rd(v: int, pos: int, n: int):
    """Read n bits starting at bit `pos` of integer v (LSB first)."""
    return (v >> pos) & ((1 << n) - 1), pos + n


# ---------------------------------------------------------------------------
# Stateless handshake (the 4-packet UDP handshake before any game packet)
# ---------------------------------------------------------------------------

def put_bits(bits: list, value: int, n: int):
    for i in range(n):
        bits.append((value >> i) & 1)


def bits_to_bytes(bits: list) -> bytes:
    out = bytearray((len(bits) + 7) // 8)
    for i, b in enumerate(bits):
        if b:
            out[i >> 3] |= 1 << (i & 7)
    return bytes(out)


def handshake_packet(session_id: int, timestamp: float, cookie: bytes) -> bytes:
    """Build one of the 4 stateless-handshake packets (25 bytes).

    timestamp is the sender's uptime in seconds as a packed float;
    the host's acknowledgement packet uses timestamp = -1.0.
    cookie is 20 random bytes chosen by whichever side issues the challenge.
    """
    bits = []
    put_bits(bits, 1, 1)          # handshake flag
    put_bits(bits, 0, 1)
    put_bits(bits, session_id, 1)
    put_bits(bits, int.from_bytes(struct.pack("<f", timestamp), "little"), 32)
    put_bits(bits, int.from_bytes(cookie, "little"), 160)
    bits.append(1)                 # terminator
    return bits_to_bytes(bits)


def decode_handshake(data: bytes):
    """Decode one of the 4 stateless-handshake packets. Returns
    (handshake_flag, reserved, session_id, timestamp, cookie_hex)."""
    pos = [0]

    def take(n):
        v = 0
        for i in range(n):
            b = pos[0]
            v |= ((data[b >> 3] >> (b & 7)) & 1) << i
            pos[0] += 1
        return v

    hs, rs, sid = take(1), take(1), take(1)
    ts = struct.unpack("<f", take(32).to_bytes(4, "little"))[0]
    cookie = take(160).to_bytes(20, "little").hex()
    return hs, rs, sid, round(ts, 3), cookie


# ---------------------------------------------------------------------------
# Game packet (post-handshake)
# ---------------------------------------------------------------------------

def parse_conn(data: bytes):
    """Parse a post-handshake game packet. Returns a dict with seq, ack,
    body (as an int) and body_len (in bits), or None if not a game packet."""
    v = int.from_bytes(data, "little")
    if v == 0 or (v & 1):
        return None
    t = v.bit_length() - 1
    hwc = ((v >> 1) & 0xF) + 1
    ack = (v >> 5) & 0x3FFF
    seq = (v >> 19) & 0x3FFF
    start = 33 + 32 * hwc
    if t < start:
        return None
    body_len = t - start
    body = (v >> start) & ((1 << body_len) - 1)
    return dict(seq=seq, ack=ack, hwc=hwc, body=body, body_len=body_len)


def build_conn(seq: int, ack: int, history_words: list, body: int, body_len: int) -> bytes:
    """Build a post-handshake game packet from its fields."""
    v = (len(history_words) - 1) << 1
    v |= ack << 5
    v |= seq << 19
    pos = 33
    for w in history_words:
        v |= w << pos
        pos += 32
    v |= body << pos
    pos += body_len
    v |= 1 << pos
    pos += 1
    return v.to_bytes((pos + 7) // 8, "little")


def set_chseq(body: int, chseq: int, bit_offset: int = 23) -> int:
    """Overwrite the 10-bit ChSequence field of a reliable bunch body.

    bit_offset=23 for Challenge/Welcome (reliable, not open).
    bit_offset=25 for Hello (bOpen=1).
    """
    mask = ((1 << 10) - 1) << bit_offset
    return (body & ~mask) | ((chseq & 0x3FF) << bit_offset)


def chseq_base(initial_seq: int) -> int:
    """The ChSequence base for one side of a connection: its own initial
    packet sequence number, mod 1024. The first reliable bunch on any
    channel of that side carries base + 1."""
    return initial_seq & 1023


# ---------------------------------------------------------------------------
# Bunch header parser (back-tracking: the channel-name field is 17 bits on
# the control channel and 9 bits on an opened actor channel, and there is
# no flag that says which, so we try both and keep the parse that consumes
# the packet exactly).
# ---------------------------------------------------------------------------

def parse_bunches(body: int, body_len: int, start: int = 9, acc=()):
    """Recursively parse every bunch in a packet body. Returns a tuple of
    (ch_index, reliable, chseq_bit_pos_or_None) per bunch, or None if the
    packet cannot be parsed as a sequence of bunches ending exactly at the
    terminating bit."""
    if start == body_len - 1:
        return list(acc) if (body >> start) & 1 else None
    if start >= body_len - 1:
        return None

    p = start
    ctrl, p = rd(body, p, 1)
    opn = cls = 0
    if ctrl:
        opn, p = rd(body, p, 1)
        cls, p = rd(body, p, 1)
        if cls:
            _, p = rd(body, p, 4)
    _, p = rd(body, p, 1)                 # bIsReplicationPaused
    rel, p = rd(body, p, 1)

    ch = 0
    sh = 0
    while True:
        by, p = rd(body, p, 8)
        ch |= (by >> 1) << sh
        sh += 7
        if not (by & 1) or sh > 14:
            break
    if ch >= 512:
        return None

    _, p = rd(body, p, 2)                 # exports / mustBeMappedGUIDs
    part, p = rd(body, p, 1)

    chseq_pos = None
    if rel:
        chseq_pos = p
        _, p = rd(body, p, 10)
    if part:
        _, p = rd(body, p, 2)

    for name_width in ((9, 17) if (rel or opn) else (0,)):
        nb, r2 = rd(body, p + name_width, 13)
        end = r2 + nb
        if end > body_len - 1:
            continue
        result = parse_bunches(body, body_len, end, acc + ((ch, bool(rel), chseq_pos),))
        if result is not None:
            return result
    return None


def reliable_chseq_positions(body: int, body_len: int):
    """Convenience wrapper: bit positions of every reliable bunch's
    ChSequence field in this packet body, or None if unparseable."""
    bunches = parse_bunches(body, body_len)
    if bunches is None:
        return None
    return [pos for (_ch, reliable, pos) in bunches if reliable and pos is not None]


def rebase_reliable_chseq(body: int, body_len: int, delta: int) -> int:
    """Shift every reliable bunch's ChSequence in this packet body by
    `delta` (mod 1024). Used to replay packets recorded in one session
    (with its own ChSequence base) into a new session with a different
    base. Returns the body unchanged if the packet cannot be parsed."""
    positions = reliable_chseq_positions(body, body_len)
    if not positions:
        return body
    for p in positions:
        old, _ = rd(body, p, 10)
        mask = 1023 << p
        body = (body & ~mask) | (((old + delta) & 1023) << p)
    return body
