from __future__ import annotations

import struct
from dataclasses import dataclass, field

ELF_MACHINES = {
    0x03: "x86",
    0x28: "arm",
    0x3E: "x86_64",
    0xB7: "arm64",
    0xF3: "riscv",
}

MACHO_CPUS = {
    7: "x86",
    0x01000007: "x86_64",
    12: "arm",
    0x0100000C: "arm64",
    0x0200000C: "arm64_32",
}


@dataclass
class Symbol:
    name: str
    value: int
    size: int
    offset: int | None


@dataclass
class Binary:
    fmt: str
    arch: str = "unknown"
    bits: int = 0
    symbols: dict[str, Symbol] = field(default_factory=dict)
    build_id: str | None = None
    slice_offset: int = 0
    errors: list[str] = field(default_factory=list)

    def dart_symbol(self, short: str) -> Symbol | None:
        want = short.lstrip("_")
        for name, sym in self.symbols.items():
            if name.lstrip("_") == want:
                return sym
        return None


def parse(data: bytes) -> Binary:
    if data[:4] == b"\x7fELF":
        return _parse_elf(data)
    magic = data[:4]
    if magic in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
        return _parse_macho(data)
    return Binary(fmt="unknown")


def _parse_elf(data: bytes) -> Binary:
    b = Binary(fmt="elf")
    try:
        ei_class, ei_data = data[4], data[5]
        b.bits = 64 if ei_class == 2 else 32
        e = "<" if ei_data == 1 else ">"
        machine = struct.unpack_from(e + "H", data, 18)[0]
        b.arch = ELF_MACHINES.get(machine, f"elf-machine-{machine:#x}")

        if b.bits == 64:
            phoff, shoff = struct.unpack_from(e + "QQ", data, 32)
            phentsize, phnum, shentsize, shnum = struct.unpack_from(e + "HHHH", data, 54)
        else:
            phoff, shoff = struct.unpack_from(e + "II", data, 28)
            phentsize, phnum, shentsize, shnum = struct.unpack_from(e + "HHHH", data, 42)

        loads = []
        for i in range(phnum):
            o = phoff + i * phentsize
            if b.bits == 64:
                p_type, _flags, p_offset, p_vaddr, _pa, p_filesz = struct.unpack_from(e + "IIQQQQ", data, o)
            else:
                p_type, p_offset, p_vaddr, _pa, p_filesz = struct.unpack_from(e + "IIIII", data, o)
            if p_type == 1:
                loads.append((p_vaddr, p_offset, p_filesz))

        def v2o(vaddr: int) -> int | None:
            for va, off, sz in loads:
                if va <= vaddr < va + sz:
                    return vaddr - va + off
            return None

        sections = []
        for i in range(shnum):
            o = shoff + i * shentsize
            if b.bits == 64:
                name, typ, _fl, _addr, off, size, link, _info, _al, entsize = struct.unpack_from(e + "IIQQQQIIQQ", data, o)
            else:
                name, typ, _fl, _addr, off, size, link, _info, _al, entsize = struct.unpack_from(e + "IIIIIIIIII", data, o)
            sections.append((typ, off, size, link, entsize))

        for typ, off, size, link, entsize in sections:
            if typ == 7 and b.build_id is None:
                b.build_id = _elf_build_id(data[off:off + size], e)
            if typ not in (11, 2):
                continue
            if not (0 <= link < len(sections)):
                continue
            _st, str_off, str_size, _l, _es = sections[link]
            strtab = data[str_off:str_off + str_size]
            entsize = entsize or (24 if b.bits == 64 else 16)
            for j in range(1, size // entsize):
                so = off + j * entsize
                if b.bits == 64:
                    st_name, _info, _other, _shndx, st_value, st_size = struct.unpack_from(e + "IBBHQQ", data, so)
                else:
                    st_name, st_value, st_size, _info, _other, _shndx = struct.unpack_from(e + "IIIBBH", data, so)
                nm = _cstr(strtab, st_name)
                if nm and nm not in b.symbols:
                    b.symbols[nm] = Symbol(nm, st_value, st_size, v2o(st_value))
    except (struct.error, IndexError) as exc:
        b.errors.append(f"ELF parse error: {exc}")
    return b


def _elf_build_id(note: bytes, e: str) -> str | None:
    pos = 0
    while pos + 12 <= len(note):
        namesz, descsz, ntype = struct.unpack_from(e + "III", note, pos)
        pos += 12
        name = note[pos:pos + namesz]
        pos += (namesz + 3) & ~3
        desc = note[pos:pos + descsz]
        pos += (descsz + 3) & ~3
        if ntype == 3 and name.rstrip(b"\0") == b"GNU":
            return desc.hex()
    return None


def _cstr(buf: bytes, off: int) -> str:
    if off >= len(buf):
        return ""
    end = buf.find(b"\0", off)
    return buf[off:end if end != -1 else len(buf)].decode("latin-1")


def _parse_macho(data: bytes) -> Binary:
    magic = data[:4]
    if magic in (b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca"):
        try:
            nfat = struct.unpack_from(">I", data, 4)[0]
            if nfat > 32:
                return Binary(fmt="unknown")
            slices = []
            for i in range(nfat):
                cpu, _sub, off, size, _al = struct.unpack_from(">iiIII", data, 8 + i * 20)
                slices.append((cpu & 0xFFFFFFFF, off, size))
            slices.sort(key=lambda s: 0 if s[0] == 0x0100000C else 1)
            for _cpu, off, size in slices:
                sub = _parse_macho_thin(data[off:off + size])
                if sub.fmt == "macho":
                    sub.slice_offset = off
                    for s in sub.symbols.values():
                        if s.offset is not None:
                            s.offset += off
                    return sub
        except struct.error as exc:
            return Binary(fmt="macho", errors=[f"fat parse error: {exc}"])
        return Binary(fmt="macho", errors=["no usable fat slice"])
    return _parse_macho_thin(data)


def _parse_macho_thin(data: bytes) -> Binary:
    b = Binary(fmt="macho")
    try:
        magic = struct.unpack_from("<I", data, 0)[0]
        if magic == 0xFEEDFACF:
            b.bits, hdr = 64, 32
        elif magic == 0xFEEDFACE:
            b.bits, hdr = 32, 28
        else:
            return Binary(fmt="unknown")
        cputype, _sub, _ft, ncmds, _sz = struct.unpack_from("<iiIII", data, 4)
        b.arch = MACHO_CPUS.get(cputype & 0xFFFFFFFF, f"macho-cpu-{cputype:#x}")
        segs = []
        symtab = None
        off = hdr
        for _ in range(ncmds):
            cmd, cmdsize = struct.unpack_from("<II", data, off)
            if cmd == 0x19:
                vmaddr, _vms, fileoff, filesize = struct.unpack_from("<QQQQ", data, off + 24)
                segs.append((vmaddr, fileoff, filesize))
            elif cmd == 0x1:
                vmaddr, _vms, fileoff, filesize = struct.unpack_from("<IIII", data, off + 24)
                segs.append((vmaddr, fileoff, filesize))
            elif cmd == 0x2:
                symtab = struct.unpack_from("<IIII", data, off + 8)
            elif cmd == 0x1B:
                b.build_id = data[off + 8:off + 24].hex()
            if cmdsize == 0:
                break
            off += cmdsize

        def v2o(vaddr: int) -> int | None:
            for va, fo, fs in segs:
                if fs and va <= vaddr < va + fs:
                    return vaddr - va + fo
            return None

        if symtab:
            symoff, nsyms, stroff, strsize = symtab
            strtab = data[stroff:stroff + strsize]
            esz = 16 if b.bits == 64 else 12
            for i in range(nsyms):
                so = symoff + i * esz
                if b.bits == 64:
                    n_strx, n_type, _sect, _desc, n_value = struct.unpack_from("<IBBHQ", data, so)
                else:
                    n_strx, n_type, _sect, _desc, n_value = struct.unpack_from("<IBBHI", data, so)
                if n_type & 0xE0:
                    continue
                nm = _cstr(strtab, n_strx)
                if nm and nm not in b.symbols:
                    b.symbols[nm] = Symbol(nm, n_value, 0, v2o(n_value))
    except struct.error as exc:
        b.errors.append(f"Mach-O parse error: {exc}")
    return b
