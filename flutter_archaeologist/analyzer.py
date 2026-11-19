from __future__ import annotations

import os
import re
import time
from dataclasses import asdict, dataclass, field

from . import __version__, antianalysis, dart, kernel, knowledge, platform, textscan, tlsfind
from .inputs import Bundle, Entry

ABI_PREFERENCE = ["arm64-v8a", "arm64", "x86_64", "armeabi-v7a", "x86"]
TEXT_ASSET_EXT = {".json", ".yaml", ".yml", ".txt", ".properties", ".xml", ".js", ".html", ".htm",
                  ".graphql", ".gql", ".cfg", ".conf", ".ini", ".toml", ".csv", ".plist", ".env"}
CERT_EXT = {".pem", ".crt", ".cer", ".der", ".p12", ".pfx", ".bks", ".jks", ".key", ".keystore"}
MAX_TEXT_ASSET = 4 * 1024 * 1024
FRAMEWORK_MARKERS = ["StatelessWidget", "StatefulWidget", "BuildContext", "RenderObject", "WidgetsBinding",
                     "Navigator", "MediaQuery", "GestureDetector", "TextEditingController", "ChangeNotifier"]

SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    detail: str
    evidence: list[str] = field(default_factory=list)


@dataclass
class Result:
    tool_version: str = __version__
    scanned_at: str = ""
    sources: list[str] = field(default_factory=list)
    container: str = ""
    platform: str = ""
    notes: list[str] = field(default_factory=list)
    is_flutter: bool = False
    flutter_evidence: list[str] = field(default_factory=list)
    app: dict = field(default_factory=dict)
    binaries: list[dict] = field(default_factory=list)
    primary_abi: str | None = None
    engine: dict = field(default_factory=dict)
    build_mode: str = "unknown"
    obfuscation: dict = field(default_factory=dict)
    app_package: str | None = None
    app_files: list[str] = field(default_factory=list)
    dependencies: list[dict] = field(default_factory=list)
    hosts: list[dict] = field(default_factory=list)
    api_paths: list[str] = field(default_factory=list)
    secrets: list[dict] = field(default_factory=list)
    channels: list[str] = field(default_factory=list)
    class_names: list[str] = field(default_factory=list)
    ui_strings: list[str] = field(default_factory=list)
    assets: list[dict] = field(default_factory=list)
    kernel_blob: dict = field(default_factory=dict)
    android: dict = field(default_factory=dict)
    ios: dict = field(default_factory=dict)
    native_libs: list[str] = field(default_factory=list)
    protections: list[dict] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    next_steps: list[dict] = field(default_factory=list)
    string_method: str = ""
    tls_targets: list[dict] = field(default_factory=list)
    anti_analysis: list[dict] = field(default_factory=list)
    timings: dict = field(default_factory=dict)
    _all_strings: list[str] = field(default_factory=list, repr=False)
    _lib_entries: dict = field(default_factory=dict, repr=False)
    _kernel_sources: dict = field(default_factory=dict, repr=False)
    _asset_dump: dict = field(default_factory=dict, repr=False)

    def to_dict(self) -> dict:
        d = asdict(self)
        for k in list(d):
            if k.startswith("_"):
                del d[k]
        return d


def analyze(bundle: Bundle, deep: bool = True) -> Result:
    t0 = time.time()
    r = Result(scanned_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"), sources=bundle.sources,
               container=bundle.container, platform=bundle.platform, notes=list(bundle.notes))
    hosts: dict[str, textscan.UrlInfo] = {}
    secrets: list[textscan.Secret] = []

    app_bins, engine_bins = _locate_binaries(bundle)
    assets = _flutter_assets(bundle)
    has_kernel = any(p.endswith("kernel_blob.bin") for p in assets)

    if app_bins:
        r.flutter_evidence.append("Dart AOT snapshot binary: " + ", ".join(e.path for e in app_bins.values()))
    if engine_bins:
        r.flutter_evidence.append("Flutter engine: " + ", ".join(e.path for e in engine_bins.values()))
    if assets:
        r.flutter_evidence.append(f"flutter_assets directory ({len(assets)} files)")
    r.is_flutter = bool(app_bins or engine_bins or assets)

    _platform_meta(bundle, r, hosts, secrets)
    if not r.is_flutter:
        _native(bundle, r, hosts, secrets)
        r.anti_analysis = antianalysis.analyze(bundle, [], set(), r.native_libs, r.android)
        r.secrets = _dedupe_secrets(secrets)
        r.timings["total_s"] = round(time.time() - t0, 2)
        return r

    primary_info, primary_data = None, None
    order = sorted(app_bins, key=lambda a: ABI_PREFERENCE.index(a) if a in ABI_PREFERENCE else 99)
    for abi in order:
        e = app_bins[abi]
        data = e.read()
        info = dart.analyze_app_binary(data)
        r.binaries.append({
            "abi": abi, "path": e.path, "size": e.size, "format": info.binary_fmt, "arch": info.arch,
            "build_id": info.build_id, "snapshot_hash": info.snapshot_hash, "features": info.features,
            "located_by": info.located_by,
            "regions": [{"name": x.name, "offset": x.offset, "size": x.size} for x in info.regions],
            "errors": info.errors,
        })
        r._lib_entries[abi] = {"app": e, "engine": engine_bins.get(abi)}
        if primary_info is None:
            primary_info, primary_data, r.primary_abi = info, data, abi
    for abi, e in engine_bins.items():
        r._lib_entries.setdefault(abi, {"app": None, "engine": e})

    for abi in [r.primary_abi] + list(engine_bins):
        e = engine_bins.get(abi) if abi else None
        if e:
            ei = dart.analyze_engine(e.read(), e.path)
            if ei.dart_version:
                r.engine = asdict(ei)
                break
    if not r.engine:
        r.engine = {"dart_version": None, "note": "engine binary not present or version string not found"}

    t_tls = time.time()
    for abi, e in sorted(engine_bins.items()):
        if bundle.platform == "ios":
            break
        res = tlsfind.find(e.read()).as_dict()
        res["abi"] = abi
        r.tls_targets.append(res)
    r.timings["tls_s"] = round(time.time() - t_tls, 2)

    r.build_mode = dart.build_mode(primary_info, has_kernel)

    t1 = time.time()
    strings: list[str] = []
    if primary_data is not None:
        region = dart.isolate_data(primary_data, primary_info)
        strings = textscan.snapshot_strings(region)
        r.string_method = "snapshot-stream"
        runs = textscan.extract_strings(region) if len(strings) < 2000 else []
        if not strings or (runs and len(strings) < 0.2 * len(runs)):
            strings = runs
            r.string_method = "printable-runs"
            r.notes.append("Dart string stream not recognised; fell back to printable-run extraction "
                           "(expect more noise).")
    if has_kernel:
        kb = assets["kernel_blob.bin"].read()
        ks, ncomp = kernel.strings(kb)
        r._kernel_sources = kernel.sources(kb)
        r.kernel_blob = {"size": len(kb), "components": ncomp, "strings": len(ks),
                         "sources_recovered": len(r._kernel_sources)}
        have = set(strings)
        strings += [x for x in ks if x not in have]
        if not r.string_method:
            r.string_method = "kernel-string-table"
    r.timings["strings_s"] = round(time.time() - t1, 2)
    r._all_strings = strings

    packages = textscan.find_packages(strings)
    if has_kernel:
        for uri in r._kernel_sources:
            m = textscan.PKG_RX.match(uri)
            if m:
                packages.setdefault(m.group(1), [])
                if m.group(2) not in packages[m.group(1)]:
                    packages[m.group(1)].append(m.group(2))
    r.app_package = textscan.guess_app_package(packages, knowledge.FRAMEWORK_PACKAGES)
    if r._kernel_sources:
        _rename_file_sources(r, packages)
    r.app_files = sorted(packages.get(r.app_package, [])) if r.app_package else []
    for name, files in packages.items():
        if name == r.app_package:
            continue
        cat, note = knowledge.PACKAGES.get(name, ("", ""))
        r.dependencies.append({"name": name, "files": len(files), "category": cat, "note": note})

    r.obfuscation = _obfuscation(strings, packages, r.app_package)

    textscan.find_urls(strings, "dart", hosts)
    r.api_paths = textscan.find_api_paths(strings)
    secrets += textscan.scan_secrets(strings, "Dart snapshot" if not has_kernel else "Dart snapshot / kernel")
    r.channels = textscan.find_channels(strings)
    r.class_names = textscan.class_like(strings) if deep else []
    r.ui_strings = [s for s in strings if any(ord(c) > 0xFF for c in s)][:500]

    _scan_assets(assets, r, hosts, secrets)

    _native(bundle, r, hosts, secrets)

    t_aa = time.time()
    r.anti_analysis = antianalysis.analyze(bundle, strings, set(packages), r.native_libs, r.android)
    r.timings["anti_analysis_s"] = round(time.time() - t_aa, 2)

    r.hosts = [asdict(h) for h in textscan.sort_hosts(hosts).values()]
    r.secrets = _dedupe_secrets(secrets)
    _protections(r, packages)
    _findings(r)
    _next_steps(r)
    r.timings["total_s"] = round(time.time() - t0, 2)
    return r


def _locate_binaries(bundle: Bundle) -> tuple[dict[str, Entry], dict[str, Entry]]:
    app, eng = {}, {}
    if bundle.platform == "ios":
        for p, e in bundle.entries.items():
            if re.fullmatch(r"Frameworks/App\.framework/App", p):
                app["ios"] = e
            elif re.fullmatch(r"Frameworks/Flutter\.framework/Flutter", p):
                eng["ios"] = e
        return app, eng
    for p, e in bundle.entries.items():
        m = re.fullmatch(r"lib/([^/]+)/(lib[^/]+\.so)", p)
        if m:
            abi, so = m.groups()
            if so == "libapp.so":
                app[abi] = e
            elif so == "libflutter.so":
                eng[abi] = e
        elif p.startswith("binary/"):
            data = e.read()
            if b"kDartIsolateSnapshotData" in data or dart.SNAPSHOT_MAGIC in data:
                app["binary"] = e
            elif dart.DART_VERSION_RX.search(data):
                eng["binary"] = e
    if not app and bundle.platform == "android":
        for p, e in bundle.entries.items():
            m = re.fullmatch(r"lib/([^/]+)/([^/]+\.so)", p)
            if m and e.size < 300 * 1024 * 1024 and m.group(2) != "libflutter.so":
                head = e.read()
                if b"_kDartIsolateSnapshotData" in head:
                    app[m.group(1)] = e
                    bundle.notes.append(f"Dart snapshot found in renamed library {p}")
    return app, eng


def _flutter_assets(bundle: Bundle) -> dict[str, Entry]:
    out = {}
    for p, e in bundle.entries.items():
        m = re.match(r"^(?:assets/|Frameworks/App\.framework/)flutter_assets/(.+)$", p)
        if m:
            out[m.group(1)] = e
    return out


def _platform_meta(bundle: Bundle, r: Result, hosts, secrets) -> None:
    if bundle.platform == "android":
        man = bundle.get("AndroidManifest.xml")
        if man:
            try:
                ai = platform.android_manifest(man.read())
                r.android = asdict(ai)
                r.app = {"id": ai.package, "version": ai.version_name, "build": ai.version_code,
                         "min_sdk": ai.min_sdk, "target_sdk": ai.target_sdk}
            except (platform.AxmlError, Exception) as exc:
                r.notes.append(f"AndroidManifest.xml could not be parsed: {exc}")
        nscs = []
        for p, e in bundle.entries.items():
            if p.startswith("res/") and p.endswith(".xml") and e.size < 256 * 1024:
                n = platform.network_security_config(e.read(), p)
                if n:
                    nscs.append(asdict(n))
        if r.android is not None:
            r.android["network_security_configs"] = nscs
        arsc = bundle.get("resources.arsc")
        if arsc and arsc.size < 64 * 1024 * 1024:
            rs = textscan.extract_strings(arsc.read())
            textscan.find_urls(rs, "android-resources", hosts)
            secrets += textscan.scan_secrets(rs, "resources.arsc")
    elif bundle.platform == "ios":
        pl = bundle.get("Info.plist")
        if pl:
            try:
                ii = platform.ios_info_plist(pl.read())
                r.ios = asdict(ii)
                r.app = {"id": ii.bundle_id, "version": ii.version, "build": ii.build, "min_os": ii.min_os}
            except Exception as exc:
                r.notes.append(f"Info.plist could not be parsed: {exc}")
        gs = bundle.get("GoogleService-Info.plist")
        if gs:
            try:
                import plistlib
                d = plistlib.loads(gs.read())
                vals = [f"{k}={v}" for k, v in d.items() if isinstance(v, str)]
                textscan.find_urls(vals, "GoogleService-Info.plist", hosts)
                secrets += textscan.scan_secrets(vals, "GoogleService-Info.plist")
            except Exception:
                pass


def _obfuscation(strings: list[str], packages: dict, app_pkg: str | None) -> dict:
    sset = set(strings)
    present = [m for m in FRAMEWORK_MARKERS if m in sset]
    ratio = len(present) / len(FRAMEWORK_MARKERS)
    if ratio >= 0.5:
        verdict = "not obfuscated"
    elif ratio <= 0.2:
        verdict = "obfuscated"
    else:
        verdict = "likely obfuscated"
    return {"verdict": verdict, "framework_markers_found": f"{len(present)}/{len(FRAMEWORK_MARKERS)}",
            "explanation": ("Built with --obfuscate: class/method/field names are renamed. String literals, "
                            "URLs and library URIs are still readable." if verdict != "not obfuscated" else
                            "Class/method/field names are present in the snapshot.")}


def _scan_assets(assets: dict[str, Entry], r: Result, hosts, secrets) -> None:
    for rel, e in sorted(assets.items()):
        name = os.path.basename(rel)
        ext = os.path.splitext(name)[1].lower()
        kind = "other"
        if name.startswith(".env") or ext == ".env" or name in ("env", "dotenv"):
            kind = "env"
        elif ext in CERT_EXT:
            kind = "certificate"
        elif ext in TEXT_ASSET_EXT:
            kind = "text"
        elif rel in ("kernel_blob.bin", "isolate_snapshot_data", "vm_snapshot_data"):
            kind = "jit-snapshot"
        elif rel.startswith(("fonts/", "packages/cupertino_icons/", "shaders/")) or ext in (
                ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ttf", ".otf", ".mp3", ".mp4", ".wav",
                ".riv", ".frag", ".bin"):
            kind = "media"
        item = {"path": rel, "size": e.size, "kind": kind}
        if kind in ("env", "text", "certificate") and e.size <= MAX_TEXT_ASSET:
            raw = e.read()
            if kind == "certificate":
                if b"PRIVATE KEY" in raw:
                    item["private_key"] = True
                    secrets.append(textscan.Secret("private-key", "Private key in asset", "critical",
                                                   rel, f"flutter_assets/{rel}",
                                                   "Private key material shipped inside the app."))
                r._asset_dump[rel] = raw
            else:
                text = raw.decode("utf-8", "replace")
                found = (textscan.scan_env_text(text, f"flutter_assets/{rel}") if kind == "env"
                         else textscan.scan_secrets(text.splitlines(), f"flutter_assets/{rel}"))
                secrets += found
                textscan.find_urls(text.splitlines(), f"asset:{rel}", hosts)
                if kind == "env" or found or rel.startswith(("assets/config", "config")) or ext in (".env",):
                    r._asset_dump[rel] = raw
                if kind == "env":
                    item["keys"] = [ln.split("=", 1)[0].strip() for ln in text.splitlines()
                                    if "=" in ln and not ln.lstrip().startswith("#")]
        r.assets.append(item)


def _native(bundle: Bundle, r: Result, hosts, secrets) -> None:
    libs = set()
    for p in bundle.entries:
        m = re.fullmatch(r"lib/[^/]+/([^/]+\.so)", p)
        if m:
            libs.add(m.group(1))
        m = re.fullmatch(r"Frameworks/([^/]+)\.framework/[^/]+", p)
        if m:
            libs.add(m.group(1) + ".framework")
    r.native_libs = sorted(libs)
    for p, e in bundle.entries.items():
        if re.fullmatch(r"classes\d*\.dex", p) and e.size < 80 * 1024 * 1024:
            ds = textscan.extract_strings(e.read())
            secrets += textscan.scan_secrets(ds, p)
            textscan.find_urls(ds, "dex", hosts)


def _dedupe_secrets(secrets: list[textscan.Secret]) -> list[dict]:
    seen: dict[tuple, dict] = {}
    for s in secrets:
        key = (s.rule, s.value)
        if key in seen:
            if s.where not in seen[key]["where"]:
                seen[key]["where"].append(s.where)
            continue
        seen[key] = {"rule": s.rule, "title": s.title, "severity": s.severity, "value": s.value,
                     "masked": textscan.mask(s.value), "where": [s.where], "note": s.note, "extra": s.extra}
    return sorted(seen.values(), key=lambda x: (SEV_ORDER.get(x["severity"], 9), x["rule"]))


def _protections(r: Result, packages: dict) -> None:
    prot = []
    for name in packages:
        cat, note = knowledge.PACKAGES.get(name, ("", ""))
        if cat in (knowledge.PINNING, knowledge.RASP):
            prot.append({"kind": cat, "name": name, "source": "Dart package", "note": note})
    for lib in r.native_libs:
        low = lib.lower()
        for needle, label in knowledge.NATIVE_HARDENING.items():
            if needle in low:
                prot.append({"kind": "rasp", "name": label, "source": f"native: {lib}", "note": ""})
    certs = [a["path"] for a in r.assets if a["kind"] == "certificate"]
    if certs:
        prot.append({"kind": "pinning", "name": "Bundled certificate(s)", "source": ", ".join(certs[:5]),
                     "note": "Certificates shipped as assets are usually loaded into a SecurityContext "
                             "(Dart-level pinning). The BoringSSL verify hook defeats this too."})
    pins = sorted({m.group(0) for s in r._all_strings for m in re.finditer(r"sha256/[A-Za-z0-9+/]{43}=", s)})
    if pins:
        prot.append({"kind": "pinning", "name": "SPKI pin hashes", "source": ", ".join(pins[:3]),
                     "note": f"{len(pins)} sha256/ pin(s) in strings."})
    for n in (r.android or {}).get("network_security_configs", []):
        if n.get("pin_domains"):
            prot.append({"kind": "pinning", "name": "network_security_config pin-set",
                         "source": n["file"], "note": "Applies to the Java/WebView stack only, NOT to dart:io."})
    r.protections = prot


def _findings(r: Result) -> None:
    F = r.findings
    for s in r.secrets:
        if s["severity"] == "info":
            continue
        F.append(Finding(f"secret:{s['rule']}", s["severity"], s["title"],
                         s["note"] or "Hard-coded credential shipped in the application package.",
                         [f"{s['masked']}  ({', '.join(s['where'])})"]))
    if r.build_mode == "debug":
        F.append(Finding("debug-build", "high", "Debug (JIT) Flutter build shipped",
                         "kernel_blob.bin is present: the Dart kernel of the whole app ships in the package. "
                         f"{len(r._kernel_sources)} source files were recovered (sources/).",
                         ["flutter_assets/kernel_blob.bin"]))
        if r.kernel_blob.get("build_paths"):
            F.append(Finding("build-path-leak", "info", "Build machine path disclosed",
                             "The kernel records absolute source paths of the developer/CI machine.",
                             r.kernel_blob["build_paths"]))
    elif r.build_mode == "profile":
        F.append(Finding("profile-build", "low", "Profile build shipped",
                         "Snapshot lacks the 'product' feature: profile builds keep the VM service/observatory "
                         "code paths and more symbol information.", []))
    a = r.android or {}
    if a.get("debuggable"):
        F.append(Finding("android-debuggable", "high", "android:debuggable=\"true\"",
                         "Any app with run-as/JDWP access can attach a debugger and read app data.",
                         ["AndroidManifest.xml <application android:debuggable=\"true\">"]))
    if a.get("cleartext") is True:
        F.append(Finding("android-cleartext", "low", "Cleartext traffic allowed (usesCleartextTraffic)",
                         "Affects the Java/WebView stack. Note that dart:io ignores this flag entirely.",
                         ["AndroidManifest.xml usesCleartextTraffic=true"]))
    for n in a.get("network_security_configs", []):
        if n.get("cleartext_base"):
            F.append(Finding("nsc-cleartext", "low", "network_security_config permits cleartext globally",
                             "base-config cleartextTrafficPermitted=true (Java/WebView stack).", [n["file"]]))
    if a.get("allow_backup") is True:
        F.append(Finding("android-backup", "low", "android:allowBackup=\"true\"",
                         "App data may be extractable via adb backup on Android ≤ 11 / device-transfer "
                         "backups. Verify what is actually in the backup.", []))
    ios = r.ios or {}
    if ios.get("ats_arbitrary_loads"):
        F.append(Finding("ios-ats", "low", "ATS disabled (NSAllowsArbitraryLoads)",
                         "Cleartext HTTP is permitted for URLSession/WebView traffic.", []))
    exported = [c for c in a.get("components", []) if c["exported"] and not c["launcher"]
                and not c["permission"]]
    if exported:
        F.append(Finding("android-exported", "info", f"{len(exported)} exported component(s) without permission",
                         "Attack surface for intent-based testing, not a vulnerability by itself.",
                         [f"{c['kind']}: {c['name']}" for c in exported[:15]]))
    if r.obfuscation.get("verdict") == "not obfuscated":
        F.append(Finding("no-obfuscation", "info", "Dart code not obfuscated",
                         "Class and method names are readable; Blutter output will be fully named.", []))
    F.sort(key=lambda f: SEV_ORDER.get(f.severity, 9))


def _next_steps(r: Result) -> None:
    S = r.next_steps
    pk = {d["name"] for d in r.dependencies}
    prot_kinds = {p["kind"] for p in r.protections}
    pkg_id = (r.app or {}).get("id") or "<package>"

    tls = ("Flutter's dart:io ignores the system proxy and does not trust user-installed CAs, so a normal "
           "Burp setup sees nothing. Redirect traffic at the network layer (iptables DNAT / transparent "
           "proxy, Burp 'invisible proxying' on) and hook BoringSSL's certificate verification in "
           "libflutter.so.")
    found = [t for t in r.tls_targets if t["status"] == "found"]
    if found:
        tls += (" The verification function was located in this engine (" +
                ", ".join(f"{t['abi']} {t['offset']}" for t in found) +
                "): use frida/flutter_tls_bypass.js.")
    native = sorted(pk & knowledge.NATIVE_STACK_PACKAGES)
    if native:
        tls += (" Part of the traffic does NOT go through dart:io: " + ", ".join(native) +
                " use the platform's native SDK/TLS stack (on Android: Java/Conscrypt). The generated "
                "script also hooks that layer; alternatively install your CA in the system store.")
    if "rasp" in prot_kinds:
        tls += " RASP detected: expect Frida/root detection; start with the anti-detection hooks."
    if any("approov" in p["name"].lower() for p in r.protections):
        tls += " Approov detected: requests need a valid attestation token, so TLS bypass alone will not work."
    S.append({"title": "Intercept traffic", "detail": tls, "commands": []})

    if r.primary_abi in ("arm64-v8a", "arm64", "ios"):
        S.append({"title": "Recover function names and offsets with Blutter",
                  "detail": f"Dart {r.engine.get('dart_version') or '?'} detected. The ARM64 libraries are "
                            "exported to libs/ in this report directory.",
                  "commands": [f"python3 blutter.py libs/{r.primary_abi} blutter_out",
                               "flutter-arch scan <input> --blutter-out blutter_out   # merge results"]})
    elif r.binaries:
        S.append({"title": "Function-level decompilation",
                  "detail": f"Only {r.primary_abi} snapshots are present. Blutter supports ARM64 only: fetch "
                            "the arm64-v8a split (e.g. from a real device or an ARM64 APK variant).",
                  "commands": []})

    hosts = {h["host"]: h for h in r.hosts}
    for h in hosts.values():
        svc = h.get("service")
        if svc == "Firebase RTDB":
            S.append({"title": f"Test Firebase Realtime Database rules ({h['host']})",
                      "detail": "An unauthenticated read of the root must be denied.",
                      "commands": [f"curl -s 'https://{h['host']}/.json?shallow=true'"]})
        elif svc == "Supabase":
            S.append({"title": f"Test Supabase RLS ({h['host']})",
                      "detail": "With the bundled anon key, list exposed tables and try reading/writing each.",
                      "commands": [f"curl -s 'https://{h['host']}/rest/v1/' -H 'apikey: <ANON_KEY>'"]})
    for s in r.secrets:
        if s["rule"] == "google-api-key":
            S.append({"title": "Check Google API key restrictions",
                      "detail": "Unrestricted keys can be abused for paid APIs; Firebase keys allow sign-up "
                                "if the Identity Toolkit is enabled.",
                      "commands": ["curl -s 'https://www.googleapis.com/identitytoolkit/v3/relyingparty/"
                                   "signupNewUser?key=<KEY>' -H 'Content-Type: application/json' "
                                   "-d '{\"returnSecureToken\":true}'"]})
            break
    for s in r.secrets:
        if s["rule"] == "aws-access-key":
            S.append({"title": "Check whether the AWS key is live",
                      "detail": "Needs the matching secret (look for it next to the key ID).",
                      "commands": ["AWS_ACCESS_KEY_ID=<ID> AWS_SECRET_ACCESS_KEY=<SECRET> aws sts get-caller-identity"]})
            break

    a = r.android or {}
    links = sorted({d for c in a.get("components", []) for d in c.get("deeplinks", [])})
    if links:
        S.append({"title": "Fuzz deep links",
                  "detail": "Each handled URI is untrusted input into the app (routing, webviews, auth flows).",
                  "commands": [f"adb shell am start -a android.intent.action.VIEW -d '{u}' {pkg_id}"
                               for u in links[:8]]})
    app_channels = [c for c in r.channels if not textscan.FRAMEWORK_CHANNEL.match(c)]
    if app_channels:
        S.append({"title": "Trace platform channels",
                  "detail": "Platform channels are the bridge between Dart and native code (root checks, "
                            "crypto, biometric gates). Log them at runtime.",
                  "commands": [f"frida -U -n <process> -l frida/trace_method_channels.js"]})
    if r.api_paths:
        S.append({"title": "Map the API",
                  "detail": f"{len(r.api_paths)} API-looking paths recovered (endpoints.txt). Test each for "
                            "authorization (IDOR/BOLA) once traffic is intercepted.", "commands": []})


def _rename_file_sources(r: Result, packages: dict) -> None:
    roots = {m.group(1) for uri in r._kernel_sources
             if (m := re.match(r"^file://(/.*?)/lib/main\.dart$", uri))}
    leaked: set[str] = set(roots)
    renamed = {}
    for uri, src in r._kernel_sources.items():
        new = uri
        m = re.match(r"^file://(/.*?)/lib/(.+\.dart)$", uri)
        if m:
            root, rel = m.groups()
            pub = re.search(r"^(.*?)/\.pub-cache/(?:hosted/[^/]+|git/[^/]+)/([a-z0-9_]+)-[^/]+$", root)
            sdk = re.search(r"/packages/([a-z0-9_]+)$", root)
            if root in roots and r.app_package:
                new = f"package:{r.app_package}/{rel}"
                files = packages.setdefault(r.app_package, [])
                if rel not in files:
                    files.append(rel)
            elif pub:
                leaked.add(pub.group(1))
                new = f"package:{pub.group(2)}/{rel}"
            elif sdk:
                new = f"package:{sdk.group(1)}/{rel}"
        renamed.setdefault(new, src)
    r._kernel_sources = renamed
    if leaked:
        r.kernel_blob["build_paths"] = sorted(leaked)
