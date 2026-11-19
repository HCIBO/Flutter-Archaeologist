from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field

MAGIC = b"\x90\xab\xcd\xef"


def _uint(b: bytes, p: int) -> tuple[int, int]:
    x = b[p]
    if x & 0x80 == 0:
        return x, 1
    if x & 0xC0 == 0x80:
        return ((x & 0x3F) << 8) | b[p + 1], 2
    return ((x & 0x3F) << 24) | (b[p + 1] << 16) | (b[p + 2] << 8) | b[p + 3], 4


@dataclass
class Component:
    offset: int
    size: int
    libraries: int
    strings: list[str] = field(default_factory=list)


def components(kb: bytes) -> list[Component]:
    out = []
    end = len(kb)
    while end >= 16:
        size = struct.unpack_from(">I", kb, end - 4)[0]
        base = end - size
        if size < 16 or base < 0 or kb[base:base + 4] != MAGIC:
            break
        libc = struct.unpack_from(">I", kb, end - 8)[0]
        out.append(Component(base, size, libc))
        end = base
    out.reverse()
    return out


def _string_table(kb: bytes, comp: Component, off: int) -> list[str] | None:
    st = comp.offset + off
    limit = comp.offset + comp.size
    if not (comp.offset < st < limit):
        return None
    try:
        n, u = _uint(kb, st)
        p = st + u
        if n == 0 or n > 5_000_000:
            return None
        ends, prev = [], 0
        for _ in range(n):
            if p >= limit:
                return None
            v, u = _uint(kb, p)
            p += u
            if v < prev:
                return None
            ends.append(v)
            prev = v
        if p + ends[-1] > limit:
            return None
        blob = kb[p:p + ends[-1]]
        blob.decode("utf-8")
    except (IndexError, UnicodeDecodeError):
        return None
    res, prev = [], 0
    for e in ends:
        res.append(blob[prev:e].decode("utf-8"))
        prev = e
    return res


def strings(kb: bytes) -> tuple[list[str], int]:
    seen: set[str] = set()
    out: list[str] = []
    comps = components(kb)
    for c in comps:
        end = c.offset + c.size
        idx_end = end - 8 - (c.libraries + 1) * 4
        nfields = min(16, max(0, (idx_end - c.offset) // 4))
        fields = struct.unpack_from(f">{nfields}I", kb, idx_end - nfields * 4) if nfields else ()
        best: list[str] | None = None
        for off in fields:
            t = _string_table(kb, c, off)
            if t and (best is None or len(t) > len(best)):
                best = t
        for s in best or []:
            if s and s not in seen:
                seen.add(s)
                out.append(s)
    return out, len(comps)


def _safe_uint(b: bytes, p: int) -> tuple[int, int] | None:
    try:
        return _uint(b, p)
    except IndexError:
        return None


def sources(kb: bytes, skip_prefixes=("package:flutter/", "dart:")) -> dict[str, str]:
    out: dict[str, str] = {}
    for m in re.finditer(rb"(package:[a-z0-9_]+/[A-Za-z0-9_/\-.]+\.dart|file:///[^\x00-\x1f]{1,300}?\.dart)", kb):
        uri = m.group(1).decode("latin-1")
        if uri in out or uri.startswith(skip_prefixes):
            continue
        if not any(m.start() - k >= 0 and _safe_uint(kb, m.start() - k) == (len(m.group(1)), k)
                   for k in (1, 2, 4)):
            continue
        pos = m.end()
        try:
            n, used = _uint(kb, pos)
        except IndexError:
            continue
        if not (8 < n < 8 * 1024 * 1024):
            continue
        text = kb[pos + used:pos + used + n]
        try:
            s = text.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if re.search(r"\b(import|class|void|final|library|part of|export)\b", s) and "\n" in s:
            out[uri] = s
    return out
