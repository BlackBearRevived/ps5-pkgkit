"""Kraken, as a PS5 package stores it: 128 KiB halves of LZ-coded data.

Each half is ``[8-byte seed][excess framing][literals][commands][offset
marker][offsets][lengths][offset bit streams][excess stream]``; each array is
Huffman-coded (type 2) when that is smaller, raw otherwise. This module has both
the encoder and the decoder, so a block can be proven before a package keeps it.
"""

from __future__ import annotations

from dataclasses import dataclass
import heapq
import math
import struct


def f32(value: float) -> float:
    return struct.unpack("<f", struct.pack("<f", value))[0]

HALF = 0x20000
BLOCK = 0x40000
SEED = 8
MIN_DISTANCE = 8
MIN_MATCH = 4
MAX_DISTANCE = (15 << 26) - 16
HASH_BITS = 16
LIT_BITS = 8
NICE_LEN = 96
SHORT_CUTS = 18
MAX_LEN = 11
LUT = 1 << MAX_LEN
MIN_ARRAY = 256


class KrakenError(ValueError):
    """A Kraken chunk is malformed."""


# ─────────────────────────────── bit streams ───────────────────────────────


class BitWriter:
    __slots__ = ("bytes", "acc", "n")

    def __init__(self) -> None:
        self.bytes = bytearray()
        self.acc = 0
        self.n = 0

    def put(self, value: int, bits: int) -> None:
        if bits == 0:
            return
        self.acc = ((self.acc << bits) | (value & ((1 << bits) - 1))) & ((1 << 64) - 1)
        self.n += bits
        while self.n >= 8:
            self.n -= 8
            self.bytes.append((self.acc >> self.n) & 0xFF)

    def finish(self) -> bytes:
        if self.n > 0:
            self.bytes.append((self.acc << (8 - self.n)) & 0xFF)
            self.n = 0
        return bytes(self.bytes)

    def put_length(self, value: int) -> None:
        y = value + 64
        bits = y.bit_length()
        self.put(0, bits - 7)
        self.put(y, bits)


class BitReader:
    __slots__ = ("src", "pos", "end", "back", "bits", "bitpos")

    def __init__(self, src: bytes, start: int, end: int, back: bool) -> None:
        self.src = src
        self.pos = end if back else start
        self.end = start if back else end
        self.back = back
        self.bits = 0
        self.bitpos = 24
        self.refill()

    def refill(self) -> None:
        while self.bitpos > 0:
            if self.back:
                self.pos -= 1
                byte = self.src[self.pos] if self.pos >= self.end else 0
            else:
                byte = self.src[self.pos] if self.pos < self.end else 0
                self.pos += 1
            self.bits |= byte << self.bitpos
            self.bitpos -= 8

    def get(self, n: int) -> int:
        if n == 0:
            return 0
        value = 0
        left = n
        while left > 0:
            take = min(left, 24)
            piece = (self.bits >> (32 - take)) & ((1 << take) - 1)
            self.bits = (self.bits << take) & 0xFFFFFFFF
            self.bitpos += take
            self.refill()
            value = (value << take) | piece
            left -= take
        return value

    def get_length(self) -> int:
        zeros = 32 - self.bits.bit_length() if self.bits else 32
        if zeros > 12:
            raise KrakenError("kraken: bad length code")
        self.get(zeros)
        return self.get(zeros + 7) - 64

    def seam(self) -> int:
        pending = (24 - self.bitpos) >> 3
        return self.pos + pending if self.back else self.pos - pending


class LsbWriter:
    __slots__ = ("bytes", "acc", "n")

    def __init__(self) -> None:
        self.bytes = bytearray()
        self.acc = 0
        self.n = 0

    def put(self, value: int, bits: int) -> None:
        self.acc |= value << self.n
        self.n += bits
        while self.n >= 8:
            self.bytes.append(self.acc & 0xFF)
            self.acc >>= 8
            self.n -= 8

    def finish(self) -> bytes:
        if self.n > 0:
            self.bytes.append(self.acc & 0xFF)
        return bytes(self.bytes)


class LsbReader:
    __slots__ = ("src", "next", "left", "back", "acc", "n", "used")

    def __init__(self, src: bytes, start: int, end: int, back: bool) -> None:
        self.src = src
        self.next = end if back else start
        self.left = end - start
        self.back = back
        self.acc = 0
        self.n = 0
        self.used = 0

    def peek(self) -> int:
        while self.n < MAX_LEN:
            if self.left == 0:
                byte = 0
            else:
                self.left -= 1
                if self.back:
                    self.next -= 1
                    byte = self.src[self.next]
                else:
                    byte = self.src[self.next]
                    self.next += 1
            self.acc |= byte << self.n
            self.n += 8
        return self.acc & (LUT - 1)

    def skip(self, bits: int) -> None:
        self.acc >>= bits
        self.n -= bits
        self.used += bits

    def bytes_used(self) -> int:
        return (self.used + 7) // 8


# ─────────────────────────────── Huffman ───────────────────────────────


def _huffman_lengths(freq: list[int]) -> list[int]:
    parent: list[int] = []
    leaf = [-1] * 256
    heap: list[tuple[int, int]] = []
    for symbol, weight in enumerate(freq):
        if weight > 0:
            leaf[symbol] = len(parent)
            heapq.heappush(heap, (weight, len(parent)))
            parent.append(-1)
    while len(heap) > 1:
        wa, a = heapq.heappop(heap)
        wb, b = heapq.heappop(heap)
        node = len(parent)
        parent.append(-1)
        parent[a] = node
        parent[b] = node
        heapq.heappush(heap, (wa + wb, node))
    lengths = [0] * 256
    for symbol, node in enumerate(leaf):
        if node == -1:
            continue
        depth = 0
        while parent[node] != -1:
            node = parent[node]
            depth += 1
        lengths[symbol] = depth
    return lengths


def code_lengths(freq: list[int]) -> list[int]:
    values = list(freq)
    while True:
        lengths = _huffman_lengths(values)
        if all(length <= MAX_LEN for length in lengths):
            return lengths
        values = [(value + 1) // 2 if value > 0 else 0 for value in values]


def _canonical(lengths: list[int]) -> list[tuple[int, int]]:
    codes = [(0, 0)] * 256
    slot = 0
    for length in range(1, MAX_LEN + 1):
        for symbol in range(256):
            if lengths[symbol] == length:
                code = slot >> (MAX_LEN - length)
                reversed_code = int(f"{code:032b}"[::-1], 2) >> (32 - length)
                codes[symbol] = (reversed_code, length)
                slot += 1 << (MAX_LEN - length)
    if slot != LUT:
        raise ValueError("kraken: incomplete code")
    return codes


def _gamma(w: BitWriter, run: int) -> None:
    value = run + 1
    bits = value.bit_length()
    w.put(0, bits - 2)
    w.put(value, bits)


def _table(lengths: list[int], forced_bits: int) -> bytes | None:
    writer = BitWriter()
    writer.put(0, 1)
    writer.put(1, 1)
    writer.put(forced_bits, 2)
    first = lengths[0] != 0
    writer.put(1 if first else 0, 1)
    limit = 20 >> forced_bits
    symbol = 0
    average = 32
    while True:
        if not (symbol == 0 and first):
            run = 0
            while symbol + run < 256 and lengths[symbol + run] == 0:
                run += 1
            _gamma(writer, run)
            symbol += run
            if symbol >= 256:
                break
        run = 0
        while symbol + run < 256 and lengths[symbol + run] != 0:
            run += 1
        _gamma(writer, run)
        for length in lengths[symbol:symbol + run]:
            delta = length - ((average + 2) >> 2)
            value = 2 * delta if delta >= 0 else -2 * delta - 1
            leading = value >> forced_bits
            if leading > limit:
                return None
            writer.put(0, leading)
            writer.put(1, 1)
            writer.put(value & ((1 << forced_bits) - 1), forced_bits)
            average = length + ((3 * average + 2) >> 2)
        symbol += run
        if symbol == 256:
            break
    return writer.finish()


def huff_encode(data: bytes) -> bytes | None:
    if len(data) < MIN_ARRAY or len(data) > 0x40000:
        return None
    freq = [0] * 256
    for byte in data:
        freq[byte] += 1
    if sum(1 for value in freq if value > 0) < 2:
        freq[1 if data[0] == 0 else 0] = 1
    lengths = code_lengths(freq)
    tables = [table for fb in range(4) if (table := _table(lengths, fb)) is not None]
    if not tables:
        return None
    best = min(tables, key=len)
    codes = _canonical(lengths)
    streams = [LsbWriter(), LsbWriter(), LsbWriter()]
    for index, byte in enumerate(data):
        code, length = codes[byte]
        streams[index % 3].put(code, length)
    a, b, c = (stream.finish() for stream in streams)
    if len(a) > 0xFFFF:
        return None
    return best + len(a).to_bytes(2, "little") + a + c + b[::-1]


def _get_gamma(reader: BitReader) -> int:
    bits = reader.bits & 0xFFFFFFFF
    leading = 32 - bits.bit_length() if bits else 32
    if leading > 7:
        raise KrakenError("kraken: bad Huffman table run")
    return reader.get(2 * (leading + 1)) - 1


def huff_decode(src: bytes, count: int) -> bytes:
    reader = BitReader(src, 0, len(src), False)
    if reader.get(1) != 0:
        raise KrakenError("kraken: unsupported Huffman table form")
    by_length: list[list[int]] = [[] for _ in range(MAX_LEN + 1)]
    if reader.get(1) == 1:
        forced = reader.get(2)
        limit = 20 >> forced
        skip = reader.get(1) == 1
        symbol = 0
        average = 32
        total = 0
        while symbol != 256:
            if skip:
                skip = False
            else:
                symbol += _get_gamma(reader)
                if symbol >= 256:
                    break
            run = _get_gamma(reader)
            if symbol + run > 256:
                raise KrakenError("kraken: Huffman table overruns")
            total += run
            for _ in range(run):
                bits = reader.bits & 0xFFFFFFFF
                leading = 32 - bits.bit_length() if bits else 32
                if leading > limit:
                    raise KrakenError("kraken: bad Huffman code length")
                reader.get(leading + 1)
                value = (leading << forced | reader.get(forced))
                length = (-(value & 1) ^ (value >> 1)) + ((average + 2) >> 2)
                if not 1 <= length <= MAX_LEN:
                    raise KrakenError("kraken: bad Huffman code length")
                average = length + ((3 * average + 2) >> 2)
                by_length[length].append(symbol)
                symbol += 1
        if symbol != 256 or total < 2:
            raise KrakenError("kraken: bad Huffman table")
    else:
        total = reader.get(8)
        if total == 0:
            raise KrakenError("kraken: empty Huffman table")
        if total == 1:
            return bytes([reader.get(8)]) * count
        bits = reader.get(3)
        if bits > 4:
            raise KrakenError("kraken: bad Huffman table")
        for _ in range(total):
            symbol = reader.get(8)
            length = reader.get(bits) + 1
            if length > MAX_LEN:
                raise KrakenError("kraken: bad Huffman code length")
            by_length[length].append(symbol)
    lut = [(0, 0)] * LUT
    slot = 0
    for length in range(1, MAX_LEN + 1):
        step = 1 << (MAX_LEN - length)
        for symbol in by_length[length]:
            if slot + step > LUT:
                raise KrakenError("kraken: oversubscribed Huffman code")
            for k in range(slot, slot + step):
                lut[_reverse11(k)] = (symbol, length)
            slot += step
    if slot != LUT:
        raise KrakenError("kraken: incomplete Huffman code")

    start = reader.seam()
    if start + 3 > len(src):
        raise KrakenError("kraken: truncated Huffman array")
    split = int.from_bytes(src[start:start + 2], "little")
    a0 = start + 2
    if a0 + split > len(src):
        raise KrakenError("kraken: bad Huffman split")
    streams = [
        LsbReader(src, a0, a0 + split, False),
        LsbReader(src, a0 + split, len(src), True),
        LsbReader(src, a0 + split, len(src), False),
    ]
    output = bytearray()
    for index in range(count):
        stream = streams[index % 3]
        symbol, length = lut[stream.peek()]
        stream.skip(length)
        output.append(symbol)
    a, b, c = streams
    if a.bytes_used() != split or b.bytes_used() + c.bytes_used() != len(src) - a0 - split:
        raise KrakenError("kraken: Huffman streams do not meet")
    return bytes(output)


def _reverse11(value: int) -> int:
    result = 0
    for _ in range(11):
        result = (result << 1) | (value & 1)
        value >>= 1
    return result


# ─────────────────────────────── arrays ───────────────────────────────


def put_raw_array(out: bytearray, data: bytes) -> None:
    size = len(data)
    out += bytes([(size >> 16) & 0xFF, (size >> 8) & 0xFF, size & 0xFF])
    out += data


def put_array(out: bytearray, data: bytes) -> None:
    body = huff_encode(data)
    if body is not None and len(body) + 5 < len(data) + 3:
        d = len(data) - 1
        out.append(0x20 | ((d >> 14) & 0xFF))
        out += ((((d & 0x3FFF) << 18) | len(body)) & 0xFFFFFFFF).to_bytes(4, "big")
        out += body
        return
    put_raw_array(out, data)


def get_array(src: bytes, at: int, end: int, maximum: int) -> tuple[bytes, int]:
    if end < at + 2:
        raise KrakenError("kraken: truncated array")
    first = src[at]
    kind = (first >> 4) & 7
    if kind == 0:
        if first >= 0x80:
            size = ((first << 8) | src[at + 1]) & 0xFFF
            header = 2
        else:
            if end < at + 3:
                raise KrakenError("kraken: truncated array")
            size = (first << 16) | (src[at + 1] << 8) | src[at + 2]
            if size & ~0x3FFFF:
                raise KrakenError("kraken: bad array size")
            header = 3
        if size > maximum or at + header + size > end:
            raise KrakenError("kraken: array overruns its chunk")
        return src[at + header:at + header + size], header + size
    if kind == 2:
        if first >= 0x80:
            if end < at + 3:
                raise KrakenError("kraken: truncated array")
            value = (first << 16) | (src[at + 1] << 8) | src[at + 2]
            source_size = value & 0x3FF
            dest_size = source_size + ((value >> 10) & 0x3FF) + 1
            header = 3
        else:
            if end < at + 5:
                raise KrakenError("kraken: truncated array")
            value = int.from_bytes(src[at + 1:at + 5], "big")
            source_size = value & 0x3FFFF
            dest_size = (((value >> 18) | (first << 14)) & 0x3FFFF) + 1
            header = 5
        if source_size >= dest_size or dest_size > maximum or at + header + source_size > end:
            raise KrakenError("kraken: bad Huffman array size")
        body = src[at + header:at + header + source_size]
        return huff_decode(body, dest_size), header + source_size
    raise KrakenError("kraken: unsupported array type")


def traditional_offset(distance: int) -> tuple[int, int, int]:
    t = distance + 248
    low = t & 0xF
    high = t >> 4
    n = high.bit_length() - 1
    if not 4 <= n <= 18:
        raise ValueError(f"distance {distance} outside the traditional code")
    return (((n - 4) << 4) | low), high - (1 << n), n


# ─────────────────────────────── decoder ───────────────────────────────


def _put_literals(out: bytearray, dst: int, literals: bytes, delta: bool,
                  last: int) -> None:
    if delta:
        for index, literal in enumerate(literals):
            out[dst + index] = (literal + out[dst + index - last]) & 0xFF
    else:
        out[dst:dst + len(literals)] = literals


def decode_half(src: bytes, out: bytearray, at: int, length: int,
                delta: bool) -> None:
    end = at + length
    p = 0
    dst = at
    if len(src) < 13:
        raise KrakenError("kraken: chunk too short")
    if at == 0:
        if len(src) < SEED or length < SEED:
            raise KrakenError("kraken: truncated seed")
        out[:SEED] = src[:SEED]
        p = SEED
        dst = SEED
    flag = src[p]
    p += 1
    if flag & 0xC0 != 0x80:
        raise KrakenError("kraken: expected the excess framing")
    excess = flag & 0x3F
    if excess > 0x1F:
        excess += src[p] * 0x20
        p += 1
    if excess > len(src) - p:
        raise KrakenError("kraken: excess overruns the chunk")
    main_end = len(src) - excess
    literals, used = get_array(src, p, main_end, length)
    p += used
    commands, used = get_array(src, p, main_end, length)
    p += used
    if p >= main_end:
        raise KrakenError("kraken: truncated offsets")
    scaled = src[p] == 0x80
    if src[p] > 0x80:
        raise KrakenError("kraken: unsupported offset scaling")
    if scaled:
        p += 1
    offsets_codes, used = get_array(src, p, main_end, len(commands))
    p += used
    raw_lens, used = get_array(src, p, main_end, length // 4)
    p += used

    forward = BitReader(src, p, main_end, False)
    backward = BitReader(src, p, main_end, True)
    offsets = []
    for index, code in enumerate(offsets_codes):
        reader = forward if index % 2 == 0 else backward
        if scaled:
            bits = code >> 3
            if bits > 26:
                raise KrakenError("kraken: bad offset code")
            offsets.append((((8 + (code & 7)) << bits) | reader.get(bits)) - 8)
        else:
            if code >= 0xF0:
                raise KrakenError("kraken: offset beyond a block")
            bits = (code >> 4) + 4
            offsets.append((((1 << bits) | reader.get(bits)) << 4) + (code & 0xF) - 248)
    if forward.seam() != backward.seam():
        raise KrakenError("kraken: offset streams do not meet")

    escapes = sum(1 for value in raw_lens if value == 255)
    escape_forward = BitReader(src, main_end, len(src), False)
    escape_backward = BitReader(src, main_end, len(src), True)
    escape_values = [escape_forward.get_length() if index % 2 == 0
                     else escape_backward.get_length() for index in range(escapes)]
    escape_iter = iter(escape_values)
    length_iter = iter(raw_lens)

    def length_value(raw: int) -> int:
        return 3 + (255 + next(escape_iter) if raw == 255 else raw)

    offset_iter = iter(offsets)
    literal_at = 0
    recent = [8, 8, 8]
    for command in commands:
        literal_run = command & 3
        if literal_run == 3:
            literal_run = length_value(next(length_iter))
        kind = command >> 6
        code = (command >> 2) & 0xF
        if literal_at + literal_run > len(literals) or dst + literal_run > end:
            raise KrakenError("kraken: literal run overruns")
        _put_literals(out, dst, literals[literal_at:literal_at + literal_run], delta,
                      recent[0])
        dst += literal_run
        literal_at += literal_run
        if kind == 3:
            distance = next(offset_iter)
            recent = [distance, recent[0], recent[1]]
        else:
            distance = recent[kind]
            for slot in range(kind, 0, -1):
                recent[slot] = recent[slot - 1]
            recent[0] = distance
        if code == 15:
            match_length = 14 + length_value(next(length_iter))
        else:
            match_length = code + 2
        if distance < MIN_DISTANCE or distance > dst or dst + match_length > end:
            raise KrakenError("kraken: match out of bounds")
        for index in range(match_length):
            out[dst + index] = out[dst + index - distance]
        dst += match_length
    tail = end - dst
    if len(literals) - literal_at != tail:
        raise KrakenError("kraken: trailing literals do not fill the half")
    _put_literals(out, dst, literals[literal_at:], delta, recent[0])
    if next(offset_iter, None) is not None or next(length_iter, None) is not None:
        raise KrakenError("kraken: unused offsets or lengths")


@dataclass(slots=True)
class Half:
    kind: str  # raw, lz, delta, entropy
    data: bytes

    @property
    def is_lz(self) -> bool:
        return self.kind in ("lz", "delta")

    @property
    def is_delta(self) -> bool:
        return self.kind == "delta"


def decode_block(halves: list[Half], length: int) -> bytes:
    out = bytearray(length)
    at = 0
    for half in halves:
        half_length = min(length - at, HALF)
        if half.kind == "raw":
            if len(half.data) != half_length:
                raise KrakenError("kraken: raw half has the wrong length")
            out[at:at + half_length] = half.data
        elif half.kind in ("lz", "delta"):
            decode_half(half.data, out, at, half_length, half.kind == "delta")
        elif half.kind == "entropy":
            body, used = get_array(half.data, 0, len(half.data), half_length)
            if used != len(half.data) or len(body) != half_length:
                raise KrakenError("kraken: entropy half does not fill the half")
            out[at:at + half_length] = body
        else:
            raise KrakenError("kraken: unknown half kind")
        at += half_length
    if at != length:
        raise KrakenError("kraken: halves do not cover the block")
    return bytes(out)


# ─────────────────────────────── encoder ───────────────────────────────

LEVEL_CHAIN = {"fast": 16, "balanced": 32, "smallest": 128, "stored": 0}
LEVEL_PASSES = {"fast": 0, "balanced": 2, "smallest": 3, "stored": 0}


def match_len(buf: bytes, candidate: int, at: int, limit: int) -> int:
    length = 0
    while at + length + 8 <= limit:
        a = int.from_bytes(buf[candidate + length:candidate + length + 8], "little")
        b = int.from_bytes(buf[at + length:at + length + 8], "little")
        if a != b:
            difference = a ^ b
            return length + ((difference & -difference).bit_length() - 1) // 8
        length += 8
    while at + length < limit and buf[candidate + length] == buf[at + length]:
        length += 1
    return length


def gain(length: int, distance: int, recent: bool) -> int:
    cost = 7
    if length > 16:
        cost += 8
    if not recent:
        cost += 7 + traditional_offset(distance)[2]
    return length * LIT_BITS - cost


class Matcher:
    __slots__ = ("head", "prev", "chain")

    def __init__(self, length: int, level: str) -> None:
        self.head = [-1] * (1 << HASH_BITS)
        self.prev = [-1] * length
        self.chain = LEVEL_CHAIN[level]

    @staticmethod
    def hash(buf: bytes, at: int) -> int:
        value = int.from_bytes(buf[at:at + 4], "little")
        return ((value * 0x9E3779B1) & 0xFFFFFFFF) >> (32 - HASH_BITS)

    def insert(self, buf: bytes, at: int) -> None:
        if at + 4 <= len(buf):
            index = self.hash(buf, at)
            self.prev[at] = self.head[index]
            self.head[index] = at

    def best(self, buf: bytes, at: int, limit: int) -> tuple[int, int]:
        best = (0, 0)
        if at + 4 > limit:
            return best
        candidate = self.head[self.hash(buf, at)]
        depth = 0
        while candidate >= 0 and depth < self.chain:
            distance = at - candidate
            if distance > MAX_DISTANCE:
                break
            probe = min(best[0], limit - at - 1)
            if (distance >= MIN_DISTANCE
                    and buf[candidate + probe] == buf[at + probe]):
                length = match_len(buf, candidate, at, limit)
                if length > best[0]:
                    best = (length, distance)
                    if at + length == limit:
                        break
            candidate = self.prev[candidate]
            depth += 1
        return best

    def candidates(self, buf: bytes, at: int, limit: int,
                   output: list[tuple[int, int]]) -> None:
        if at + 4 > limit:
            return
        longest = MIN_MATCH - 1
        candidate = self.head[self.hash(buf, at)]
        depth = 0
        while candidate >= 0 and depth < self.chain:
            distance = at - candidate
            if distance > MAX_DISTANCE:
                break
            probe = min(longest, limit - at - 1)
            if (distance >= MIN_DISTANCE
                    and buf[candidate + probe] == buf[at + probe]):
                length = match_len(buf, candidate, at, limit)
                if length > longest:
                    longest = length
                    output.append((length, distance))
                    if at + length == limit:
                        break
            candidate = self.prev[candidate]
            depth += 1


def _choose(buf: bytes, at: int, limit: int, recent: list[int],
            hashed: tuple[int, int]) -> tuple[int, int, int]:
    best = (0, 0, 0)
    for distance in recent:
        if distance <= at:
            length = match_len(buf, at - distance, at, limit)
            if length >= 2:
                value = gain(length, distance, True)
                if value > best[0]:
                    best = (value, length, distance)
    length, distance = hashed
    if length >= MIN_MATCH:
        value = gain(length, distance, distance in recent)
        if value > best[0]:
            best = (value, length, distance)
    return best


@dataclass(slots=True)
class Cmd:
    lit: int
    length: int
    dist: int


def _remember(recent: list[int], distance: int) -> None:
    if distance in recent:
        kind = recent.index(distance)
        for slot in range(kind, 0, -1):
            recent[slot] = recent[slot - 1]
        recent[0] = distance
    else:
        recent[:] = [distance, recent[0], recent[1]]


def parse_lazy(buf: bytes, start: int, end: int, matcher: Matcher) -> list[Cmd]:
    commands: list[Cmd] = []
    recent = [8, 8, 8]
    anchor = start
    at = start
    inserted = start

    def longest(position: int) -> tuple[int, int]:
        nonlocal inserted
        while inserted < position:
            matcher.insert(buf, inserted)
            inserted += 1
        return matcher.best(buf, position, end)

    while at + 2 <= end:
        pick = _choose(buf, at, end, recent, longest(at))
        chosen_at = at
        if pick[0] > 0 and at + 3 <= end:
            following = _choose(buf, at + 1, end, recent, longest(at + 1))
            if following[0] > pick[0]:
                pick = following
                chosen_at = at + 1
        if pick[0] > 0:
            _, length, distance = pick
            commands.append(Cmd(chosen_at - anchor, length, distance))
            _remember(recent, distance)
            at = chosen_at + length
            anchor = at
        else:
            at += 1
    return commands


@dataclass(slots=True)
class Streams:
    literals: bytearray
    delta_literals: bytearray
    commands: bytearray
    offset_codes: bytearray
    offset_bits: list[tuple[int, int]]
    lengths: bytearray
    escapes: list[int]


def streams(buf: bytes, start: int, end: int, commands: list[Cmd]) -> Streams:
    result = Streams(bytearray(), bytearray(), bytearray(), bytearray(), [],
                     bytearray(), [])
    recent = [8, 8, 8]

    def push_length(value: int) -> None:
        p = value - 3
        if p < 255:
            result.lengths.append(p)
        else:
            result.lengths.append(255)
            result.escapes.append(p - 255)

    p = start
    for command in commands:
        result.literals += buf[p:p + command.lit]
        result.delta_literals += bytes(
            (buf[q] - buf[q - recent[0]]) & 0xFF for q in range(p, p + command.lit))
        p += command.lit + command.length
        if command.lit < 3:
            literal_code = command.lit
        else:
            push_length(command.lit)
            literal_code = 3
        if command.dist in recent:
            kind = recent.index(command.dist)
        else:
            code, bits, count = traditional_offset(command.dist)
            result.offset_codes.append(code)
            result.offset_bits.append((bits, count))
            kind = 3
        _remember(recent, command.dist)
        if command.length - 2 < 15:
            length_code = command.length - 2
        else:
            push_length(command.length - 14)
            length_code = 15
        result.commands.append((kind << 6) | (length_code << 2) | literal_code)
    result.literals += buf[p:end]
    result.delta_literals += bytes(
        (buf[q] - buf[q - recent[0]]) & 0xFF for q in range(p, end))
    return result


def coded_size(s: Streams) -> int:
    def array(data: bytes) -> int:
        out = bytearray()
        put_array(out, data)
        return len(out)

    bits = sum(count for _, count in s.offset_bits)
    return (min(array(bytes(s.literals)), array(bytes(s.delta_literals)))
            + array(bytes(s.commands)) + array(bytes(s.offset_codes))
            + array(bytes(s.lengths)) + (bits + 7) // 8 + len(s.escapes) * 3)


def _symbol_bits(data: bytes, default: float) -> list[float]:
    if not data:
        return [default] * 256
    if len(data) < MIN_ARRAY:
        return [8.0] * 256
    hist = [0] * 256
    for byte in data:
        hist[byte] += 1
    total = f32(len(data) + 128.0)
    return [f32(min(max(f32(math.log2(f32(total / f32(hist[byte] + 0.5)))), 1.0), 11.0))
            for byte in range(256)]


@dataclass(slots=True)
class Costs:
    lit: list[float]
    cmd: list[float]
    offs: list[float]
    lens: list[float]
    delta: bool

    @classmethod
    def measured(cls, s: Streams) -> "Costs":
        raw = _symbol_bits(bytes(s.literals), 8.0)
        sub = _symbol_bits(bytes(s.delta_literals), 8.0)
        raw_sum = 0.0
        for byte in s.literals:
            raw_sum = f32(raw_sum + raw[byte])
        sub_sum = 0.0
        for byte in s.delta_literals:
            sub_sum = f32(sub_sum + sub[byte])
        delta = sub_sum < raw_sum
        return cls(sub if delta else raw, _symbol_bits(bytes(s.commands), 6.0),
                   _symbol_bits(bytes(s.offset_codes), 5.0),
                   _symbol_bits(bytes(s.lengths), 6.0), delta)

    def len_value(self, value: int) -> float:
        if value < 255:
            return self.lens[value]
        scaled = f32(self.lens[255] + f32(2.0 * f32((value - 255 + 64).bit_length())))
        return f32(scaled - 7.0)

    def matched(self, run: int, length: int, kind: int) -> float:
        literal_code = min(run, 3)
        length_code = min(length - 2, 15)
        bits = self.cmd[(kind << 6) | (length_code << 2) | literal_code]
        if run >= 3:
            bits = f32(bits + self.len_value(run - 3))
        if length_code == 15:
            bits = f32(bits + self.len_value(length - 17))
        return bits


def priced_lengths(lo: int, length: int):
    short_end = lo if length >= NICE_LEN else min(length, SHORT_CUTS) + 1
    yield from range(lo, short_end)
    if length >= lo and length >= short_end:
        yield length


def all_candidates(buf: bytes, start: int, end: int,
                   matcher: Matcher) -> tuple[list[int], list[tuple[int, int]]]:
    starts = []
    all_found: list[tuple[int, int]] = []
    found: list[tuple[int, int]] = []
    skip_until = start
    for position in range(start, end):
        starts.append(len(all_found))
        if position >= skip_until:
            found.clear()
            matcher.candidates(buf, position, end, found)
            for length, distance in found:
                all_found.append((length, distance))
                if length >= NICE_LEN:
                    skip_until = max(skip_until, position + length)
        matcher.insert(buf, position)
    starts.append(len(all_found))
    return starts, all_found


@dataclass(slots=True)
class Node:
    cost: float
    length: int
    dist: int
    recent: list[int]
    run: int


def parse_optimal(buf: bytes, start: int, end: int,
                  candidates: tuple[list[int], list[tuple[int, int]]],
                  costs: Costs) -> list[Cmd]:
    n = end - start
    nodes = [Node(float("inf"), 0, 0, [8, 8, 8], 0) for _ in range(n + 1)]
    nodes[0].cost = 0.0
    starts, all_found = candidates
    skip_until = 0
    for i in range(n):
        p = start + i
        node = nodes[i]
        byte = ((buf[p] - buf[p - node.recent[0]]) & 0xFF) if costs.delta else buf[p]
        literal = f32(node.cost + costs.lit[byte])
        if literal < nodes[i + 1].cost:
            nodes[i + 1] = Node(literal, 0, 0, list(node.recent), node.run + 1)
        if p + 2 > end or p < skip_until:
            continue
        run = node.run

        def relax(length: int, distance: int, bits: float, recent: list[int]) -> None:
            value = f32(node.cost + bits)
            target = nodes[i + length]
            if value < target.cost:
                nodes[i + length] = Node(value, length, distance, recent, 0)

        for kind, distance in enumerate(node.recent):
            if distance > p or distance in node.recent[:kind]:
                continue
            length = match_len(buf, p - distance, p, end)
            if length < 2:
                continue
            if length >= NICE_LEN:
                skip_until = max(skip_until, p + length)
            recent = list(node.recent)
            _remember(recent, distance)
            for cut in priced_lengths(2, length):
                relax(cut, distance, costs.matched(run, cut, kind), recent)
        next_length = MIN_MATCH
        for length, distance in all_found[starts[i]:starts[i + 1]]:
            if length >= NICE_LEN:
                skip_until = max(skip_until, p + length)
            if distance in node.recent:
                next_length = max(next_length, length + 1)
                continue
            code, _, nbits = traditional_offset(distance)
            offset_bits = f32(costs.offs[code] + f32(nbits))
            recent = [distance, node.recent[0], node.recent[1]]
            for cut in priced_lengths(next_length, length):
                relax(cut, distance, f32(costs.matched(run, cut, 3) + offset_bits), recent)
            next_length = max(next_length, length + 1)
    steps = []
    i = n
    while i > 0:
        node = nodes[i]
        if node.length == 0:
            i -= 1
        else:
            steps.append((i - node.length, node.length, node.dist))
            i -= node.length
    commands = []
    anchor = 0
    for at, length, distance in reversed(steps):
        commands.append(Cmd(at - anchor, length, distance))
        anchor = at + length
    return commands


def encode_half(buf: bytes, start: int, end: int, seed: bool, matcher: Matcher,
                level: str) -> tuple[bytes, bool] | None:
    data_start = start + SEED if seed else start
    if end < data_start + 16:
        return None
    for position in range(start, data_start):
        matcher.insert(buf, position)
    if LEVEL_PASSES[level] == 0:
        commands = parse_lazy(buf, data_start, end, matcher)
    else:
        candidates = all_candidates(buf, data_start, end, matcher)
        starts, all_found = candidates
        lazy = parse_lazy_from_candidates(buf, data_start, end, starts, all_found)
        s = streams(buf, data_start, end, lazy)
        best = (coded_size(s), lazy)
        costs = Costs.measured(s)
        for _ in range(LEVEL_PASSES[level]):
            parsed = parse_optimal(buf, data_start, end, candidates, costs)
            s = streams(buf, data_start, end, parsed)
            size = coded_size(s)
            costs = Costs.measured(s)
            if size < best[0]:
                best = (size, parsed)
        commands = best[1]
    s = streams(buf, data_start, end, commands)
    if len(s.escapes) > 512:
        return None
    forward = BitWriter()
    backward = BitWriter()
    for index, (value, bits) in enumerate(s.offset_bits):
        (forward if index % 2 == 0 else backward).put(value, bits)
    escape_forward = BitWriter()
    escape_backward = BitWriter()
    for index, value in enumerate(s.escapes):
        (escape_forward if index % 2 == 0 else escape_backward).put_length(value)
    excess = escape_forward.finish()
    excess += escape_backward.finish()[::-1]
    if len(excess) > 0x1F + 0xFF * 0x20:
        return None
    out = bytearray()
    if seed:
        out += buf[start:data_start]
    e = len(excess)
    if e > 0x1F:
        high = (e - 0x20) // 0x20
        low = e - high * 0x20
        out.append(0x80 | low)
        out.append(high)
    else:
        out.append(0x80 | e)
    raw_literals = bytearray()
    put_array(raw_literals, bytes(s.literals))
    sub_literals = bytearray()
    put_array(sub_literals, bytes(s.delta_literals))
    delta = len(sub_literals) < len(raw_literals)
    out += sub_literals if delta else raw_literals
    put_array(out, bytes(s.commands))
    put_array(out, bytes(s.offset_codes))
    put_array(out, bytes(s.lengths))
    out += forward.finish()
    out += backward.finish()[::-1]
    out += excess
    raw = end - start
    if len(out) + raw // 50 >= raw or len(out) < 13:
        return None
    return bytes(out), delta


def parse_lazy_from_candidates(buf: bytes, start: int, end: int,
                               starts: list[int],
                               all_found: list[tuple[int, int]]) -> list[Cmd]:
    commands = []
    recent = [8, 8, 8]
    anchor = start
    at = start

    def longest(position: int) -> tuple[int, int]:
        index = position - start
        chunk = all_found[starts[index]:starts[index + 1]]
        return chunk[-1] if chunk else (0, 0)

    while at + 2 <= end:
        pick = _choose(buf, at, end, recent, longest(at))
        chosen_at = at
        if pick[0] > 0 and at + 3 <= end:
            following = _choose(buf, at + 1, end, recent, longest(at + 1))
            if following[0] > pick[0]:
                pick = following
                chosen_at = at + 1
        if pick[0] > 0:
            _, length, distance = pick
            commands.append(Cmd(chosen_at - anchor, length, distance))
            _remember(recent, distance)
            at = chosen_at + length
            anchor = at
        else:
            at += 1
    return commands


def encode_block_at(block: bytes, level: str = "balanced") -> list[Half]:
    if not block or len(block) > BLOCK:
        raise ValueError("a Kraken block is 1..256 KiB")
    matcher = Matcher(len(block), level)
    even_end = min(len(block), HALF)
    encoded = encode_half(block, 0, even_end, True, matcher, level)
    halves = [_half_from(encoded, block[:even_end])]
    if len(block) > HALF:
        matcher = Matcher(len(block), level)
        for position in range(even_end):
            matcher.insert(block, position)
        encoded = encode_half(block, HALF, len(block), False, matcher, level)
        halves.append(_half_from(encoded, block[HALF:]))
    return halves


def _half_from(encoded: tuple[bytes, bool] | None, raw: bytes) -> Half:
    if encoded is None:
        return Half("raw", raw)
    return Half("delta" if encoded[1] else "lz", encoded[0])


def encode_block(block: bytes) -> list[Half]:
    return encode_block_at(block, "balanced")
