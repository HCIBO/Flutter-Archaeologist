from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

CLASS_RX = re.compile(r"^\s*(?:abstract\s+|sealed\s+|final\s+|base\s+|mixin\s+|interface\s+)*"
                      r"(?:class|mixin|extension|enum)\s+([A-Za-z_$][\w$@]*)")
ADDR_RX = re.compile(r"//\s*\*\*\s*addr:\s*(0x[0-9a-f]+),\s*size:\s*(0x[0-9a-f]+)")
INTERESTING = re.compile(r"(?i)(login|logout|auth|token|passw|secret|otp|pin|biometric|encrypt|decrypt|"
                         r"cipher|sign|verify|hmac|hash|root|jailbr|tamper|frida|debugger|emulator|"
                         r"pay|purchase|premium|license|subscri|wallet|transfer|admin|role|permission|"
                         r"certificate|ssl|tls|trust)")


@dataclass
class Fn:
    file: str
    cls: str
    signature: str
    name: str
    addr: int
    size: int


def load(out_dir: str, app_package: str | None) -> dict:
    root = Path(out_dir)
    asm = root / "asm"
    if not asm.is_dir():
        raise FileNotFoundError(f"{out_dir}: no asm/ directory (is this a Blutter output folder?)")
    pkgs = sorted(p.name for p in asm.iterdir() if p.is_dir())
    if app_package is None:
        cands = [p for p in pkgs if (asm / p / "main.dart").exists()]
        app_package = cands[0] if cands else None
    fns: list[Fn] = []
    if app_package and (asm / app_package).is_dir():
        for f in sorted((asm / app_package).rglob("*.dart")):
            fns.extend(_parse_file(f, f.relative_to(asm).as_posix()))
    pp = root / "pp.txt"
    pool_lines = pp.read_text("utf-8", "replace").splitlines() if pp.exists() else []
    return {
        "dir": str(root),
        "packages": pkgs,
        "app_package": app_package,
        "functions": fns,
        "interesting": [f for f in fns if INTERESTING.search(f.name) or INTERESTING.search(f.cls)],
        "pool_strings": _pool_strings(pool_lines),
        "frida_template": str(root / "blutter_frida.js") if (root / "blutter_frida.js").exists() else None,
    }


def _parse_file(path: Path, rel: str) -> list[Fn]:
    out = []
    cls = "::"
    prev = ""
    for line in path.read_text("utf-8", "replace").splitlines():
        m = CLASS_RX.match(line)
        if m and line.rstrip().endswith(("{", ";")):
            cls = m.group(1)
        m = ADDR_RX.search(line)
        if m and prev:
            sig = prev.strip().rstrip("{").strip()
            nm = re.search(r"([A-Za-z_$][\w$@]*)\s*(?:<[^>]*>)?\s*\(", sig)
            out.append(Fn(rel, cls, sig, nm.group(1) if nm else sig, int(m.group(1), 16), int(m.group(2), 16)))
        if line.strip():
            prev = line
    return out


def _pool_strings(lines: list[str]) -> list[str]:
    out = []
    for ln in lines:
        m = re.search(r'String:\s*"(.*)"\s*$', ln)
        if m:
            out.append(m.group(1).encode("latin-1", "replace").decode("unicode_escape", "replace"))
    return out
