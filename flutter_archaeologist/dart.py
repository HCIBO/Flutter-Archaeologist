from __future__ import annotations

import json
import re
import struct
from dataclasses import dataclass, field
from importlib import resources

from . import binfmt

SNAPSHOT_MAGIC = b"\xf5\xf5\xdc\xdc"
SNAPSHOT_SYMBOLS = (
    "kDartVmSnapshotData",
    "kDartVmSnapshotInstructions",
    "kDartIsolateSnapshotData",
    "kDartIsolateSnapshotInstructions",
    "kDartSnapshotData",
    "kDartSnapshotText",
)
DATA_SYMBOLS = ("kDartIsolateSnapshotData", "kDartSnapshotData")
CODE_SYMBOLS = ("kDartIsolateSnapshotInstructions", "kDartVmSnapshotInstructions", "kDartSnapshotText")

DART_VERSION_RX = re.compile(
    rb"(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?) \((stable|beta|dev|main|be)\)"
    rb"(?: \(([^)]{6,60})\))?(?: on \"([a-z0-9_]+)\")?")


@dataclass
class SnapshotHeader:
    offset: int
    length: int
    kind: int
    hash: str
    features: list[str]

    @property
    def product(self) -> bool:
        return "product" in self.features


@dataclass
class Region:
    name: str
    offset: int | None
    size: int


@dataclass
class DartInfo:
    binary_fmt: str = "unknown"
    arch: str = "unknown"
    build_id: str | None = None
    regions: list[Region] = field(default_factory=list)
    vm: SnapshotHeader | None = None
    isolate: SnapshotHeader | None = None
    located_by: str = "none"
    layout: str = "unknown"
    has_aot_code: bool = False
    errors: list[str] = field(default_factory=list)

    @property
    def snapshot_hash(self) -> str | None:
        h = self.isolate or self.vm
        return h.hash if h else None

    @property
    def features(self) -> list[str]:
        h = self.isolate or self.vm
        return h.features if h else []

    def region(self, name: str) -> Region | None:
        for r in self.regions:
            if r.name == name:
                return r
        return None


def parse_header(data: bytes, off: int) -> SnapshotHeader | None:
    if data[off:off + 4] != SNAPSHOT_MAGIC:
        return None
    try:
        length, kind = struct.unpack_from("<qq", data, off + 4)
    except struct.error:
        return None
    h = data[off + 20:off + 52]
    if not re.fullmatch(rb"[0-9a-f]{32}", h):
        return None
    end = data.find(b"\0", off + 52, off + 52 + 1024)
    feats = data[off + 52:end if end != -1 else off + 52].decode("latin-1", "replace").split()
    return SnapshotHeader(off, length, kind, h.decode(), feats)


def analyze_app_binary(data: bytes) -> DartInfo:
    info = DartInfo()
    b = binfmt.parse(data)
    info.binary_fmt, info.arch, info.build_id = b.fmt, b.arch, b.build_id
    info.errors.extend(b.errors)

    for short in SNAPSHOT_SYMBOLS:
        s = b.dart_symbol(short)
        if s is not None:
            info.regions.append(Region(short, s.offset, s.size))

    info.has_aot_code = any(info.region(c) for c in CODE_SYMBOLS)
    vm_r, iso_r = info.region("kDartVmSnapshotData"), info.region("kDartIsolateSnapshotData")
    merged = info.region("kDartSnapshotData")
    if merged and merged.offset is not None:
        info.layout = "merged"
        info.isolate = parse_header(data, merged.offset)
    if vm_r and vm_r.offset is not None:
        info.layout = "split"
        info.vm = parse_header(data, vm_r.offset)
    if iso_r and iso_r.offset is not None:
        info.isolate = parse_header(data, iso_r.offset)
    if info.vm or info.isolate:
        info.located_by = "symbols"
    else:
        found = []
        pos = data.find(SNAPSHOT_MAGIC)
        while pos != -1 and len(found) < 4:
            hdr = parse_header(data, pos)
            if hdr:
                found.append(hdr)
            pos = data.find(SNAPSHOT_MAGIC, pos + 4)
        if found:
            info.located_by = "magic-scan"
            found.sort(key=lambda x: x.length)
            if len(found) == 1:
                info.layout = "merged"
                info.isolate = found[0]
                info.regions.append(Region("kDartSnapshotData", found[0].offset, found[0].length + 4))
            else:
                info.layout = "split"
                info.vm, info.isolate = found[0], found[-1]
                for name, h in (("kDartVmSnapshotData", info.vm), ("kDartIsolateSnapshotData", info.isolate)):
                    if not info.region(name):
                        info.regions.append(Region(name, h.offset, h.length + 4))
            info.has_aot_code = True

    for r in info.regions:
        if r.size == 0:
            hdr = info.vm if r.name == "kDartVmSnapshotData" else (
                info.isolate if r.name in DATA_SYMBOLS else None)
            if hdr:
                r.size = hdr.length + 4
    return info


def isolate_data(data: bytes, info: DartInfo) -> bytes:
    for name in DATA_SYMBOLS:
        r = info.region(name)
        if r and r.offset is not None and r.size:
            return data[r.offset:r.offset + r.size]
    return data


@dataclass
class EngineInfo:
    dart_version: str | None = None
    channel: str | None = None
    build_date: str | None = None
    target: str | None = None
    flutter_candidates: list[str] = field(default_factory=list)
    engine_binary: str | None = None


def analyze_engine(data: bytes, name: str) -> EngineInfo:
    ei = EngineInfo(engine_binary=name)
    for m in DART_VERSION_RX.finditer(data):
        if m.group(3) or ei.dart_version is None:
            ei.dart_version = m.group(1).decode()
            ei.channel = m.group(2).decode()
            ei.build_date = m.group(3).decode() if m.group(3) else None
            ei.target = m.group(4).decode() if m.group(4) else None
            if m.group(3):
                break
    if ei.dart_version:
        ei.flutter_candidates = flutter_for_dart(ei.dart_version)
    return ei


_RELEASES: list[dict] | None = None


def releases() -> list[dict]:
    global _RELEASES
    if _RELEASES is None:
        try:
            raw = resources.files("flutter_archaeologist.data").joinpath("flutter_releases.json").read_text()
            _RELEASES = json.loads(raw)["releases"]
        except (FileNotFoundError, KeyError, json.JSONDecodeError):
            _RELEASES = []
    return _RELEASES


def flutter_for_dart(dart_version: str) -> list[str]:
    out = [r["flutter"] for r in releases() if r.get("dart") == dart_version]
    seen, res = set(), []
    for v in sorted(out, key=lambda v: ("-" in v, v)):
        if v not in seen:
            seen.add(v)
            res.append(v)
    return res


def build_mode(info: DartInfo | None, has_kernel_blob: bool) -> str:
    if info is None or not (info.vm or info.isolate):
        return "debug" if has_kernel_blob else "unknown"
    h = info.isolate or info.vm
    if info.has_aot_code:
        return "release" if h.product else "profile"
    return "debug" if has_kernel_blob else "unknown"
