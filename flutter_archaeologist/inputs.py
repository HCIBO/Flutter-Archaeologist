from __future__ import annotations

import io
import os
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

ANDROID_ARCHIVES = (".apk", ".xapk", ".apks", ".apkm", ".aab")
MAX_NESTED = 512 * 1024 * 1024


@dataclass
class Entry:
    path: str
    origin: str
    size: int
    _read: Callable[[], bytes]

    def read(self) -> bytes:
        return self._read()


@dataclass
class Bundle:
    sources: list[str]
    platform: str
    container: str
    entries: dict[str, Entry] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)

    def add(self, entry: Entry) -> None:
        self.entries.setdefault(entry.path, entry)

    def get(self, path: str) -> Entry | None:
        return self.entries.get(path)

    def glob(self, pattern: str) -> list[Entry]:
        rx = re.compile(pattern)
        return [e for p, e in sorted(self.entries.items()) if rx.search(p)]


class InputError(Exception):
    pass


def load(paths: list[str]) -> Bundle:
    if not paths:
        raise InputError("no input given")
    files: list[Path] = []
    for p in paths:
        pp = Path(p)
        if not pp.exists():
            raise InputError(f"not found: {p}")
        if pp.is_dir():
            found = sorted(x for x in pp.iterdir() if x.suffix.lower() in ANDROID_ARCHIVES + (".ipa",))
            if not found:
                raise InputError(f"directory contains no .apk/.xapk/.aab/.ipa files: {p}")
            files.extend(found)
        else:
            files.append(pp)

    files.sort(key=lambda f: (0 if f.name == "base.apk" else 1, f.name))
    srcs = [str(f) for f in files]
    exts = {f.suffix.lower() for f in files}

    if exts == {".ipa"} and len(files) == 1:
        return _load_ipa(files[0])
    if len(files) == 1 and not zipfile.is_zipfile(files[0]):
        return _load_binary(files[0])
    if ".ipa" in exts:
        raise InputError("mixing .ipa with other inputs is not supported")

    container = "apk"
    if len(files) > 1:
        container = "split-apks"
    elif exts & {".xapk", ".apks", ".apkm"}:
        container = "xapk"
    elif ".aab" in exts:
        container = "aab"
    bundle = Bundle(sources=srcs, platform="android", container=container)
    for f in files:
        _add_android_zip(bundle, _open_zip(f), f.name, depth=0)
    if not bundle.entries:
        raise InputError("no readable entries in input")
    return bundle


def _open_zip(f: Path) -> zipfile.ZipFile:
    try:
        return zipfile.ZipFile(f)
    except zipfile.BadZipFile as exc:
        raise InputError(f"{f.name}: not a valid zip/APK ({exc})") from exc


def _reader(zf: zipfile.ZipFile, name: str) -> Callable[[], bytes]:
    return lambda: zf.read(name)


def _add_android_zip(bundle: Bundle, zf: zipfile.ZipFile, label: str, depth: int) -> None:
    names = zf.namelist()
    is_aab = any(n.startswith("base/manifest/") for n in names)
    if is_aab:
        bundle.container = "aab"
        bundle.notes.append("AAB manifest is protobuf-encoded; manifest analysis is skipped "
                            "(build an APK set with bundletool for full coverage).")
    for info in zf.infolist():
        name = info.filename
        if info.is_dir():
            continue
        low = name.lower()
        if low.endswith(".apk") and depth == 0:
            if info.file_size > MAX_NESTED:
                bundle.notes.append(f"skipped oversized nested APK {name}")
                continue
            try:
                inner = zipfile.ZipFile(io.BytesIO(zf.read(name)))
            except zipfile.BadZipFile:
                bundle.notes.append(f"nested {name} is not a valid APK")
                continue
            _add_android_zip(bundle, inner, f"{label}!{name}", depth + 1)
            continue
        logical = name
        if is_aab:
            m = re.match(r"^[^/]+/(.*)$", name)
            if not m:
                continue
            rest = m.group(1)
            if rest.startswith("manifest/"):
                logical = "aab-manifest/" + rest[len("manifest/"):]
            elif rest.startswith("root/"):
                logical = rest[len("root/"):]
            else:
                logical = rest
        bundle.add(Entry(logical, f"{label}!{name}", info.file_size, _reader(zf, name)))


def _load_ipa(f: Path) -> Bundle:
    zf = _open_zip(f)
    bundle = Bundle(sources=[str(f)], platform="ios", container="ipa")
    app_rx = re.compile(r"^Payload/[^/]+\.app/(.*)$")
    for info in zf.infolist():
        if info.is_dir():
            continue
        m = app_rx.match(info.filename)
        if not m:
            continue
        rest = m.group(1)
        bundle.add(Entry(rest, f"{f.name}!{info.filename}", info.file_size, _reader(zf, info.filename)))
    if not bundle.entries:
        raise InputError("IPA has no Payload/*.app directory")
    return bundle


def _load_binary(f: Path) -> Bundle:
    data = f.read_bytes()
    platform = "android" if data[:4] == b"\x7fELF" else ("ios" if data[:4] in (
        b"\xcf\xfa\xed\xfe", b"\xca\xfe\xba\xbe") else "unknown")
    bundle = Bundle(sources=[str(f)], platform=platform, container="binary")
    name = os.path.basename(f)
    bundle.add(Entry(f"binary/{name}", name, len(data), lambda: data))
    return bundle
