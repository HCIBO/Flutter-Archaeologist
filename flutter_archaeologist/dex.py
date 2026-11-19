from __future__ import annotations

import bisect
import re
import struct
from dataclasses import dataclass


def _uleb(b: bytes, p: int) -> tuple[int, int]:
    result = shift = 0
    while True:
        x = b[p]
        p += 1
        result |= (x & 0x7F) << shift
        if x < 0x80:
            return result, p
        shift += 7


@dataclass
class Ref:
    cls: str
    method: str
    kind: str
    value: str


def _width_table() -> list[int]:
    w = [1] * 256
    def setr(a, b, n):
        for i in range(a, b + 1):
            w[i] = n
    w[0x02], w[0x03], w[0x05], w[0x06], w[0x08], w[0x09] = 2, 3, 2, 3, 2, 3
    w[0x13], w[0x14], w[0x15], w[0x16], w[0x17], w[0x18], w[0x19] = 2, 3, 2, 2, 3, 5, 2
    w[0x1a], w[0x1b], w[0x1c], w[0x1f], w[0x20], w[0x22], w[0x23] = 2, 3, 2, 2, 2, 2, 2
    w[0x24], w[0x25], w[0x26], w[0x29], w[0x2a], w[0x2b], w[0x2c] = 3, 3, 3, 2, 3, 3, 3
    setr(0x2d, 0x3d, 2)
    setr(0x44, 0x6d, 2)
    setr(0x6e, 0x72, 3)
    setr(0x74, 0x78, 3)
    setr(0x90, 0xaf, 2)
    setr(0xd0, 0xe2, 2)
    w[0xfa], w[0xfb], w[0xfc], w[0xfd], w[0xfe], w[0xff] = 4, 4, 3, 3, 2, 2
    return w


WIDTH = _width_table()


class Dex:
    def __init__(self, data: bytes):
        if not data.startswith(b"dex\n"):
            raise ValueError("not a DEX file")
        self.data = data
        (self.n_str, self.o_str, self.n_type, self.o_type, _np, _op, _nf, _of,
         self.n_meth, self.o_meth, self.n_cls, self.o_cls) = struct.unpack_from("<12I", data, 0x38)
        self._strings: list[str] | None = None
        self._code: tuple[list[int], list[int], list[int]] | None = None
        self._bounds: dict[int, set[int]] = {}

    @property
    def strings(self) -> list[str]:
        if self._strings is None:
            d = self.data
            offs = struct.unpack_from(f"<{self.n_str}I", d, self.o_str)
            out = []
            for o in offs:
                _n, p = _uleb(d, o)
                e = d.find(b"\0", p)
                out.append(d[p:e].decode("utf-8", "replace"))
            self._strings = out
        return self._strings

    def type_name(self, idx: int) -> str:
        sidx = struct.unpack_from("<I", self.data, self.o_type + 4 * idx)[0]
        return self.strings[sidx]

    def method(self, idx: int) -> tuple[str, str]:
        cls_idx, _proto, name_idx = struct.unpack_from("<HHI", self.data, self.o_meth + 8 * idx)
        return self.type_name(cls_idx), self.strings[name_idx]

    def method_index(self) -> dict[tuple[str, str], list[int]]:
        out: dict[tuple[str, str], list[int]] = {}
        for i in range(self.n_meth):
            out.setdefault(self.method(i), []).append(i)
        return out

    def _code_ranges(self) -> tuple[list[int], list[int], list[int]]:
        if self._code is None:
            d = self.data
            items = []
            for c in range(self.n_cls):
                cdo = struct.unpack_from("<I", d, self.o_cls + 32 * c + 24)[0]
                if not cdo:
                    continue
                sf, p = _uleb(d, cdo)
                inf, p = _uleb(d, p)
                dm, p = _uleb(d, p)
                vm, p = _uleb(d, p)
                for _ in range(sf + inf):
                    _x, p = _uleb(d, p)
                    _x, p = _uleb(d, p)
                for count in (dm, vm):
                    midx = 0
                    for _ in range(count):
                        diff, p = _uleb(d, p)
                        _acc, p = _uleb(d, p)
                        code_off, p = _uleb(d, p)
                        midx += diff
                        if code_off:
                            n_units = struct.unpack_from("<I", d, code_off + 12)[0]
                            start = code_off + 16
                            items.append((start, start + 2 * n_units, midx))
            items.sort()
            self._code = ([a for a, _, _ in items], [b for _, b, _ in items], [m for _, _, m in items])
        return self._code

    def _boundaries(self, start: int, end: int) -> set[int]:
        b = self._bounds.get(start)
        if b is not None:
            return b
        d = self.data
        b = set()
        p = start
        while p < end:
            unit = d[p] | (d[p + 1] << 8)
            op = unit & 0xFF
            if op == 0 and unit in (0x0100, 0x0200, 0x0300):
                size = d[p + 2] | (d[p + 3] << 8)
                if unit == 0x0100:
                    n = size * 2 + 4
                elif unit == 0x0200:
                    n = size * 4 + 2
                else:
                    width = size
                    count = struct.unpack_from("<I", d, p + 4)[0]
                    n = (count * width + 1) // 2 + 4
            else:
                b.add(p)
                n = WIDTH[op]
            p += 2 * n
        self._bounds[start] = b
        return b

    def _owner(self, pos: int) -> int | None:
        starts, ends, meths = self._code_ranges()
        k = bisect.bisect_right(starts, pos) - 1
        if k < 0 or pos >= ends[k] or (pos - starts[k]) % 2:
            return None
        if pos not in self._boundaries(starts[k], ends[k]):
            return None
        return meths[k]

    def string_refs(self, idxs: set[int]) -> list[tuple[int, int]]:
        out = []
        small = [i for i in idxs if i <= 0xFFFF]
        big = [i for i in idxs if i > 0xFFFF]
        for op, fmt, group in ((b"\x1a", "<H", small), (b"\x1b", "<I", big)):
            if not group:
                continue
            alt = b"|".join(re.escape(struct.pack(fmt, i)) for i in group)
            rx = re.compile(re.escape(op) + b"[\\x00-\\xff](" + alt + b")", re.S)
            for m in rx.finditer(self.data):
                owner = self._owner(m.start())
                if owner is not None:
                    out.append((struct.unpack(fmt, m.group(1))[0], owner))
        return out

    def invoke_refs(self, idxs: set[int]) -> list[tuple[int, int]]:
        if not idxs:
            return []
        out = []
        alt = b"|".join(re.escape(struct.pack("<H", i)) for i in idxs if i <= 0xFFFF)
        if not alt:
            return out
        rx = re.compile(b"[\\x6e-\\x72\\x74-\\x78][\\x00-\\xff](" + alt + b")", re.S)
        for m in rx.finditer(self.data):
            owner = self._owner(m.start())
            if owner is not None:
                out.append((struct.unpack("<H", m.group(1))[0], owner))
        return out


def dotted(descriptor: str) -> str:
    if descriptor.startswith("L") and descriptor.endswith(";"):
        return descriptor[1:-1].replace("/", ".")
    return descriptor
