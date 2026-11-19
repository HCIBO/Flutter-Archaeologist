from __future__ import annotations

import bisect
import re
import struct
from array import array
from dataclasses import dataclass, field

STRINGS = (b"ssl_client", b"ssl_server")
LOOKUP_ONLY = (b"pkcs7", b"smime_sign")


@dataclass
class Section:
    name: str
    addr: int
    offset: int
    size: int


@dataclass
class TlsTarget:
    arch: str
    status: str
    offset: int | None = None
    size: int | None = None
    prologue: str | None = None
    candidates: list[dict] = field(default_factory=list)
    detail: str = ""

    def as_dict(self) -> dict:
        return {"arch": self.arch, "status": self.status,
                "offset": hex(self.offset) if self.offset is not None else None,
                "size": self.size, "prologue": self.prologue, "candidates": self.candidates,
                "detail": self.detail}


def _sections(data: bytes) -> tuple[str, dict[str, Section], list[tuple[int, int, int]]]:
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise ValueError("only 64-bit little-endian ELF is supported")
    machine = struct.unpack_from("<H", data, 18)[0]
    arch = {0xB7: "arm64", 0x3E: "x86_64"}.get(machine, f"machine-{machine:#x}")
    phoff, shoff = struct.unpack_from("<QQ", data, 32)
    phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from("<HHHHH", data, 54)
    loads = []
    for i in range(phnum):
        p_type, _f, p_off, p_vaddr, _pa, p_filesz = struct.unpack_from("<IIQQQQ", data, phoff + i * phentsize)
        if p_type == 1:
            loads.append((p_vaddr, p_off, p_filesz))
    raw = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize) for i in range(shnum)]
    _n, _t, _f, _a, str_off, str_size, *_ = raw[shstrndx]
    names = data[str_off:str_off + str_size]
    secs = {}
    for name, _t, _f, addr, off, size, *_ in raw:
        end = names.find(b"\0", name)
        nm = names[name:end].decode("latin-1")
        secs[nm] = Section(nm, addr, off, size)
    return arch, secs, loads


def _v2o(loads, va: int) -> int | None:
    for v, o, s in loads:
        if v <= va < v + s:
            return va - v + o
    return None


def _string_addrs(data: bytes, loads) -> dict[bytes, list[int]]:
    out: dict[bytes, list[int]] = {}
    for s in STRINGS + LOOKUP_ONLY:
        hits = []
        for m in re.finditer(re.escape(s) + b"\x00", data):
            off = m.start()
            prev = data[off - 1:off]
            if prev and (prev.isalnum() or prev == b"_"):
                pass
            for v, o, sz in loads:
                if o <= off < o + sz:
                    hits.append(off - o + v)
        out[s] = hits
    return out


def _function_table(data: bytes, secs: dict[str, Section]) -> tuple[list[int], list[int]]:
    hdr = secs.get(".eh_frame_hdr")
    if hdr is None:
        return [], []
    base = hdr.offset
    version, eh_ptr_enc, fde_count_enc, table_enc = data[base:base + 4]
    if version != 1 or table_enc != 0x3B:
        return [], []
    p = base + 4
    p += _enc_size(eh_ptr_enc)
    count = _read_enc(data, p, fde_count_enc)
    p += _enc_size(fde_count_enc)
    starts, sizes = [], []
    tab = array("i")
    tab.frombytes(data[p:p + count * 8])
    for i in range(count):
        loc = hdr.addr + tab[2 * i]
        fde_va = hdr.addr + tab[2 * i + 1]
        starts.append(loc)
        sizes.append(_fde_range(data, secs, fde_va))
    order = sorted(range(count), key=lambda k: starts[k])
    return [starts[k] for k in order], [sizes[k] for k in order]


def _enc_size(enc: int) -> int:
    return {0x03: 4, 0x0B: 4, 0x1B: 4, 0x3B: 4, 0x04: 8, 0x0C: 8, 0x02: 2, 0x0A: 2}.get(enc & 0x0F | (enc & 0x0F), 4) \
        if enc != 0xFF else 0


def _read_enc(data: bytes, p: int, enc: int) -> int:
    fmt = {0x03: "<I", 0x0B: "<i", 0x04: "<Q", 0x0C: "<q", 0x02: "<H", 0x0A: "<h"}[enc & 0x0F]
    return struct.unpack_from(fmt, data, p)[0]


def _fde_range(data: bytes, secs: dict[str, Section], fde_va: int) -> int:
    eh = secs.get(".eh_frame")
    if eh is None or not (eh.addr <= fde_va < eh.addr + eh.size):
        return 0
    off = eh.offset + (fde_va - eh.addr)
    length = struct.unpack_from("<I", data, off)[0]
    if length == 0xFFFFFFFF:
        return 0
    return struct.unpack_from("<i", data, off + 12)[0]


def _xrefs_arm64(data: bytes, text: Section, targets: set[int]) -> list[tuple[int, int]]:
    words = array("I")
    words.frombytes(data[text.offset:text.offset + (text.size // 4) * 4])
    pages = {t & ~0xFFF for t in targets}
    out = []
    n = len(words)
    for i in range(n):
        w = words[i]
        if w & 0x9F000000 != 0x90000000:
            continue
        pc = text.addr + i * 4
        immlo = (w >> 29) & 3
        immhi = (w >> 5) & 0x7FFFF
        imm = (immhi << 2) | immlo
        if imm & (1 << 20):
            imm -= 1 << 21
        page = (pc & ~0xFFF) + (imm << 12)
        if page not in pages:
            continue
        rd = w & 0x1F
        for j in range(i + 1, min(i + 9, n)):
            w2 = words[j]
            if w2 & 0xFF800000 == 0x91000000 and (w2 >> 5) & 0x1F == rd:
                sh = (w2 >> 22) & 1
                tgt = page + (((w2 >> 10) & 0xFFF) << (12 * sh))
                if tgt in targets:
                    out.append((text.addr + j * 4, tgt))
                break
            if (w2 & 0x1F) == rd and w2 & 0x9F000000 == 0x90000000:
                break
    return out


LEA_RX = re.compile(rb"[\x48\x4c]\x8d[\x05\x0d\x15\x1d\x25\x2d\x35\x3d]", re.S)


def _xrefs_x64(data: bytes, text: Section, targets: set[int]) -> list[tuple[int, int]]:
    out = []
    blob = data[text.offset:text.offset + text.size]
    for m in LEA_RX.finditer(blob):
        p = m.start()
        if p + 7 > len(blob):
            break
        disp = struct.unpack_from("<i", blob, p + 3)[0]
        nxt = text.addr + p + 7
        tgt = nxt + disp
        if tgt in targets:
            out.append((text.addr + p, tgt))
    return out


def find(data: bytes) -> TlsTarget:
    try:
        arch, secs, loads = _sections(data)
    except (ValueError, struct.error) as exc:
        return TlsTarget("unknown", "unsupported", detail=str(exc))
    if arch not in ("arm64", "x86_64"):
        return TlsTarget(arch, "unsupported", detail="only arm64 and x86_64 engines are supported")
    text = secs.get(".text")
    if text is None:
        return TlsTarget(arch, "not-found", detail="no .text section")
    strs = _string_addrs(data, loads)
    if not all(strs[s] for s in STRINGS):
        return TlsTarget(arch, "not-found", detail="'ssl_client'/'ssl_server' strings not present")
    addr_to_name = {a: s for s, addrs in strs.items() for a in addrs}
    targets = set(addr_to_name)
    refs = (_xrefs_arm64 if arch == "arm64" else _xrefs_x64)(data, text, targets)
    starts, sizes = _function_table(data, secs)
    if not starts:
        return TlsTarget(arch, "not-found", detail="no .eh_frame_hdr unwind table to delimit functions")

    funcs: dict[int, set] = {}
    fsize: dict[int, int] = {}
    for at, tgt in refs:
        k = bisect.bisect_right(starts, at) - 1
        if k < 0:
            continue
        st, sz = starts[k], sizes[k]
        if sz and not (st <= at < st + sz):
            continue
        funcs.setdefault(st, set()).add(addr_to_name[tgt])
        fsize[st] = sz
    want = set(STRINGS)
    lookup = set(LOOKUP_ONLY)
    both = [f for f, names in funcs.items() if want <= names and not (names & lookup)]
    cands = [{"offset": hex(f), "size": fsize[f], "refs": sorted(n.decode() for n in funcs[f]),
              "role": ("X509_VERIFY_PARAM_lookup" if funcs[f] & lookup else
                       "session_verify_cert_chain" if want <= funcs[f] else "other")}
             for f in sorted(funcs)]
    if len(both) != 1:
        return TlsTarget(arch, "ambiguous" if both else "not-found", candidates=cands,
                         detail=f"{len(refs)} references, {len(both)} function(s) reference both strings")
    f = both[0]
    fo = _v2o(loads, f)
    prologue = data[fo:fo + 24].hex() if fo is not None else None
    return TlsTarget(arch, "found", offset=f, size=fsize[f], prologue=prologue, candidates=cands,
                     detail=f"{len(refs)} code references; one function selects between 'ssl_client' and "
                            f"'ssl_server' without being the X509_VERIFY_PARAM_lookup table")
