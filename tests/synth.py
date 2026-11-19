from __future__ import annotations

import io
import plistlib
import struct
import zipfile

HASH = b"0123456789abcdef0123456789abcdef"


def snapshot_header(features: bytes, kind: int = 3, body: bytes = b"") -> bytes:
    feats = features + b"\0"
    payload = HASH + feats + body
    return b"\xf5\xf5\xdc\xdc" + struct.pack("<qq", len(payload) + 16, kind) + payload


def string_stream(strings: list[str]) -> bytes:
    out = bytearray()
    for s in strings:
        try:
            raw = s.encode("latin-1")
            val = len(s) << 1
        except UnicodeEncodeError:
            raw = s.encode("utf-16-le")
            val = (len(s) << 1) | 1
        while val >= 0x80:
            out.append(val & 0x7F)
            val >>= 7
        out.append(val | 0x80)
        out += raw
    return bytes(out)


def elf_libapp(data_body: bytes, merged: bool = True, machine: int = 0xB7) -> bytes:
    names = [b"_kDartSnapshotData", b"_kDartSnapshotText"] if merged else \
        [b"_kDartVmSnapshotData", b"_kDartIsolateSnapshotData", b"_kDartIsolateSnapshotInstructions"]
    dynstr = b"\0" + b"".join(n + b"\0" for n in names)
    rodata_off = 0x200
    vm = snapshot_header(b"product no-asan arm64 android compressed-pointers")
    iso = snapshot_header(b"product no-asan arm64 android compressed-pointers", body=data_body)
    if merged:
        rodata = iso
        sym_vals = [(rodata_off, len(iso)), (rodata_off + len(rodata), 16)]
    else:
        rodata = vm + iso
        sym_vals = [(rodata_off, len(vm)), (rodata_off + len(vm), len(iso)), (rodata_off + len(rodata), 16)]
    text = b"\xc0\x03\x5f\xd6" * 4
    dynstr_off = rodata_off + len(rodata) + len(text)
    dynsym_off = (dynstr_off + len(dynstr) + 7) & ~7
    syms = b"\0" * 24
    pos = 1
    for (val, size), n in zip(sym_vals, names):
        syms += struct.pack("<IBBHQQ", pos, 0x11, 0, 1, val, size)
        pos += len(n) + 1
    shoff = (dynsym_off + len(syms) + 7) & ~7
    total_before_sh = shoff
    sh = b"\0" * 64
    sh += struct.pack("<IIQQQQIIQQ", 0, 3, 2, dynstr_off, dynstr_off, len(dynstr), 0, 0, 1, 0)
    sh += struct.pack("<IIQQQQIIQQ", 0, 11, 2, dynsym_off, dynsym_off, len(syms), 1, 1, 8, 24)
    sh += struct.pack("<IIQQQQIIQQ", 0, 1, 2, rodata_off, rodata_off, len(rodata), 0, 0, 64, 0)
    phoff = 64
    ph = struct.pack("<IIQQQQQQ", 1, 5, 0, 0, 0, total_before_sh, total_before_sh, 0x1000)
    ehdr = (b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\0" * 8 +
            struct.pack("<HHIQQQIHHHHHH", 3, machine, 1, 0, phoff, shoff, 0, 64, 56, 1, 64, 4, 0))
    buf = bytearray(total_before_sh)
    buf[0:64] = ehdr
    buf[phoff:phoff + 56] = ph
    buf[rodata_off:rodata_off + len(rodata)] = rodata
    buf[rodata_off + len(rodata):rodata_off + len(rodata) + len(text)] = text
    buf[dynstr_off:dynstr_off + len(dynstr)] = dynstr
    buf[dynsym_off:dynsym_off + len(syms)] = syms
    return bytes(buf) + sh


def macho_app(data_body: bytes) -> bytes:
    vm = snapshot_header(b"product arm64 ios compressed-pointers")
    iso = snapshot_header(b"product arm64 ios compressed-pointers", body=data_body)
    names = [b"_kDartVmSnapshotData", b"_kDartIsolateSnapshotData", b"_kDartIsolateSnapshotInstructions"]
    hdr_size = 32
    seg_cmd = 72
    symtab_cmd = 24
    data_off = 0x400
    blob = vm + iso + b"\0" * 16
    vals = [data_off, data_off + len(vm), data_off + len(vm) + len(iso)]
    strtab = b"\0" + b"".join(n + b"\0" for n in names)
    sym_off = data_off + len(blob)
    nl = b""
    pos = 1
    for v, n in zip(vals, names):
        nl += struct.pack("<IBBHQ", pos, 0x0F, 1, 0, v)
        pos += len(n) + 1
    str_off = sym_off + len(nl)
    total = str_off + len(strtab)
    out = bytearray(total)
    out[0:hdr_size] = struct.pack("<IiiIIII", 0xFEEDFACF, 0x0100000C, 0, 6, 2, seg_cmd + symtab_cmd, 0) + b"\0" * 4
    seg = struct.pack("<II16sQQQQiiII", 0x19, seg_cmd, b"__TEXT", 0, total, 0, total, 5, 5, 0, 0)
    out[hdr_size:hdr_size + seg_cmd] = seg
    out[hdr_size + seg_cmd:hdr_size + seg_cmd + symtab_cmd] = struct.pack(
        "<IIIIII", 0x2, symtab_cmd, sym_off, len(names), str_off, len(strtab))
    out[data_off:data_off + len(blob)] = blob
    out[sym_off:sym_off + len(nl)] = nl
    out[str_off:str_off + len(strtab)] = strtab
    return bytes(out)


def ipa(app_bin: bytes, engine: bytes, assets: dict[str, bytes], info: dict) -> bytes:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, "w") as z:
        base = "Payload/Runner.app/"
        z.writestr(base + "Info.plist", plistlib.dumps(info, fmt=plistlib.FMT_BINARY))
        z.writestr(base + "Frameworks/App.framework/App", app_bin)
        z.writestr(base + "Frameworks/Flutter.framework/Flutter", engine)
        for k, v in assets.items():
            z.writestr(base + "Frameworks/App.framework/flutter_assets/" + k, v)
    return bio.getvalue()
