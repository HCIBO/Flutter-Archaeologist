from __future__ import annotations

import argparse
import os
import sys

from . import __version__, analyzer, inputs, report

SEV_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class C:
    on = (sys.stdout.isatty() or bool(os.environ.get("FORCE_COLOR"))) and not os.environ.get("NO_COLOR")
    @staticmethod
    def c(code: str, s: str) -> str:
        return f"\033[{code}m{s}\033[0m" if C.on else s


SEV_CODE = {"critical": "1;41;97", "high": "1;31", "medium": "1;33", "low": "1;34", "info": "2"}


VERDICT_CODE = {"enforcement-candidate": "1;31", "weak-signal": "1;33", "telemetry-only": "2"}


def _print_anti(items: list[dict], brief: bool) -> None:
    for c in items:
        verdict = c["verdict"]
        print(f"  {C.c(VERDICT_CODE.get(verdict, '0'), verdict.ljust(22))} {c['title']}")
        ev = c["evidence"]
        own = [e for e in ev if not e["owner"]]
        show = own[:3] if brief else own
        for e in show:
            src = C.c("2", e["source"].ljust(10))
            val = repr(e["value"][:42]).ljust(44)
            print(f"      {src} {e['label'][:38]:<38} {val} {C.c('2', e['where'][:70])}")
        if brief and len(own) > 3:
            print(C.c("2", f"      … +{len(own) - 3} more"))
        sdks = sorted({e["owner"] for e in ev if e["owner"]})
        if sdks:
            print(C.c("2", "      also collected by: " + ", ".join(sdks)))
        if not brief:
            print(C.c("2", "      bypass: " + c["hint"]))


def _print_summary(r: analyzer.Result, written: dict[str, str] | None, out_dir: str | None) -> None:
    b = lambda s: C.c("1", s)
    if not r.is_flutter:
        print(C.c("1;33", "Not a Flutter app") + " (no libapp.so / App.framework / flutter_assets)")
        if r.anti_analysis:
            print("\n" + b("Anti-analysis / RASP"))
            _print_anti(r.anti_analysis, brief=True)
        return
    for k, v in report._summary_rows(r):
        print(f"  {C.c('2', f'{k:<18}')} {v}")
    if r.findings:
        print("\n" + b("Findings"))
        for f in r.findings:
            print(f"  {C.c(SEV_CODE[f.severity], f'{f.severity.upper():<8}')} {f.title}")
            for e in f.evidence[:3]:
                print(f"           {C.c('2', e)}")
    if r.anti_analysis:
        print("\n" + b("Anti-analysis / RASP"))
        _print_anti(r.anti_analysis, brief=True)
    if r.protections:
        print("\n" + b("Protections"))
        for p in r.protections:
            print(f"  {p['kind']:<8} {p['name']}  {C.c('2', p['source'])}")
    if r.next_steps:
        print("\n" + b("Next steps"))
        for i, s in enumerate(r.next_steps, 1):
            print(f"  {i}. {s['title']}")
    if written and out_dir:
        print("\n" + b("Output") + f"  {out_dir}")
        for key in ("report.html", "report.md", "report.json", "endpoints.txt", "secrets.json",
                    "app_source_tree.txt"):
            if key in written:
                print(f"  {written[key]}")
        extra = len(written) - sum(1 for k in written if "/" not in k)
        if extra:
            print(C.c("2", f"  + {extra} exported files (assets/, sources/, libs/, frida/)"))


def cmd_scan(a) -> int:
    try:
        bundle = inputs.load(a.input)
    except inputs.InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    if not a.quiet:
        print(C.c("1", "Flutter Archaeologist ") + __version__ + "  " + C.c("2", ", ".join(a.input)))
    r = analyzer.analyze(bundle)
    bl = None
    if a.blutter_out:
        from . import blutter, textscan
        try:
            bl = blutter.load(a.blutter_out, r.app_package)
        except FileNotFoundError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        extra = textscan.scan_secrets(bl["pool_strings"], "Blutter object pool")
        known = {(s["rule"], s["value"]) for s in r.secrets}
        for s in extra:
            if (s.rule, s.value) not in known:
                r.secrets.append({"rule": s.rule, "title": s.title, "severity": s.severity, "value": s.value,
                                  "masked": textscan.mask(s.value), "where": [s.where], "note": s.note,
                                  "extra": s.extra})
        r.notes.append(f"Blutter: {len(bl['functions'])} app functions indexed, "
                       f"{len(bl['interesting'])} security-relevant.")
    if a.json_stdout:
        import json
        d = r.to_dict()
        if not a.show_secrets:
            for s in d["secrets"]:
                s["value"] = s["masked"]
        print(json.dumps(d, indent=2, ensure_ascii=False, default=str))
    written, out_dir = None, None
    if not a.no_report:
        name = report.safe_name((r.app or {}).get("id") or os.path.splitext(os.path.basename(a.input[0]))[0])
        out_dir = a.output or os.path.join("fa-out", name)
        written = report.write_all(r, out_dir, show_secrets=a.show_secrets, export_libs=not a.no_libs,
                                   blutter=bl)
    if not a.quiet and not a.json_stdout:
        _print_summary(r, written, out_dir)
    if not r.is_flutter:
        return 2
    if a.fail_on:
        lim = SEV_RANK[a.fail_on]
        if any(SEV_RANK.get(f.severity, 9) <= lim for f in r.findings):
            return 3
    return 0


def cmd_info(a) -> int:
    try:
        bundle = inputs.load(a.input)
    except inputs.InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    r = analyzer.analyze(bundle, deep=False)
    eng = r.engine or {}
    print(f"flutter: {'yes' if r.is_flutter else 'no'}")
    if r.is_flutter:
        print(f"app: {(r.app or {}).get('id')} {(r.app or {}).get('version') or ''}")
        print(f"dart: {eng.get('dart_version')}  flutter: {', '.join(eng.get('flutter_candidates') or []) or '?'}")
        print(f"build: {r.build_mode}  obfuscation: {r.obfuscation.get('verdict')}")
        print(f"abis: {', '.join(b['abi'] for b in r.binaries) or '-'}")
    return 0 if r.is_flutter else 2


def cmd_tls(a) -> int:
    from . import frida, tlsfind
    targets = []
    if len(a.input) == 1 and os.path.isfile(a.input[0]) and open(a.input[0], "rb").read(4) == b"\x7fELF":
        targets.append(("binary", tlsfind.find(open(a.input[0], "rb").read())))
    else:
        try:
            bundle = inputs.load(a.input)
        except inputs.InputError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        for path, e in sorted(bundle.entries.items()):
            if path.endswith("/libflutter.so"):
                targets.append((path.split("/")[1], tlsfind.find(e.read())))
    if not targets:
        print("no libflutter.so found", file=sys.stderr)
        return 2
    js = {}
    for abi, t in targets:
        d = t.as_dict()
        print(f"{abi:<12} {d['arch']:<7} {d['status']:<10} offset={d['offset'] or '-':<10} size={d['size'] or '-'}  "
              f"prologue={(d['prologue'] or '-')[:24]}")
        if a.verbose:
            for c in d["candidates"]:
                print(f"{'':12} candidate {c['offset']} size={c['size']} refs={','.join(c['refs'])} -> {c['role']}")
            print(f"{'':12} {d['detail']}")
        fa = {"arm64": "arm64", "x86_64": "x64"}.get(d["arch"])
        if d["status"] == "found" and fa:
            js[fa] = {"offset": d["offset"], "prologue": d["prologue"]}
    if a.output and js:
        with open(a.output, "w", encoding="utf-8") as fh:
            fh.write(frida.tls_bypass_script(js))
        print(f"wrote {a.output}")
    return 0 if js else 2


def cmd_rasp(a) -> int:
    from . import frida
    try:
        bundle = inputs.load(a.input)
    except inputs.InputError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    r = analyzer.analyze(bundle, deep=False)
    if a.json_stdout:
        import json
        print(json.dumps(r.anti_analysis, indent=2, ensure_ascii=False))
    else:
        if not r.anti_analysis:
            print("no anti-analysis checks found")
        _print_anti(r.anti_analysis, brief=False)
    if a.output:
        with open(a.output, "w", encoding="utf-8") as fh:
            fh.write(frida.anti_detection_script({c["category"]: c["verdict"] for c in r.anti_analysis}))
        print(f"wrote {a.output}")
    return 0


def cmd_update(a) -> int:
    from . import versions
    try:
        n = versions.update()
    except OSError as exc:
        print(f"error: could not fetch release index: {exc}", file=sys.stderr)
        return 1
    print(f"updated: {n} Flutter releases -> {versions.DATA_FILE}")
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        prog="flutter-arch",
        description="Recon and attack-surface mapping for Flutter mobile apps (APK/XAPK/AAB/IPA).")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="full analysis + report")
    s.add_argument("input", nargs="+", help="APK / XAPK / APKS / AAB / IPA / directory of split APKs / libapp.so")
    s.add_argument("-o", "--output", help="output directory (default: fa-out/<app id>)")
    s.add_argument("--show-secrets", action="store_true", help="print full secret values in reports")
    s.add_argument("--no-libs", action="store_true", help="do not export arm64 libapp/libflutter for Blutter")
    s.add_argument("--no-report", action="store_true", help="do not write any files")
    s.add_argument("--json", dest="json_stdout", action="store_true", help="print the JSON result to stdout")
    s.add_argument("--blutter-out", metavar="DIR", help="merge an existing Blutter output directory")
    s.add_argument("--fail-on", choices=list(SEV_RANK), help="exit 3 if a finding at/above this severity exists")
    s.add_argument("-q", "--quiet", action="store_true")
    s.set_defaults(fn=cmd_scan)

    i = sub.add_parser("info", help="quick: is it Flutter, which versions, build mode")
    i.add_argument("input", nargs="+")
    i.set_defaults(fn=cmd_info)

    t = sub.add_parser("tls", help="locate BoringSSL's cert-chain verification function (+ Frida hook)")
    t.add_argument("input", nargs="+", help="libflutter.so, APK, XAPK, AAB or split APKs")
    t.add_argument("-o", "--output", help="write the Frida bypass script here")
    t.add_argument("-v", "--verbose", action="store_true", help="show all candidate functions")
    t.set_defaults(fn=cmd_tls)

    ra = sub.add_parser("rasp", help="root/frida/adb/emulator/... detection checks (any APK/IPA) + hooks")
    ra.add_argument("input", nargs="+")
    ra.add_argument("-o", "--output", help="write anti_detection.js here")
    ra.add_argument("--json", dest="json_stdout", action="store_true")
    ra.set_defaults(fn=cmd_rasp)

    u = sub.add_parser("update-versions", help="refresh the Dart -> Flutter version table (network)")
    u.set_defaults(fn=cmd_update)

    a = p.parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
