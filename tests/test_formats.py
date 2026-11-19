import io
import zipfile

from flutter_archaeologist import analyzer, binfmt, dart, inputs
from synth import elf_libapp, ipa, macho_app, string_stream

STRS = ["StatelessWidget", "StatefulWidget", "BuildContext", "RenderObject", "WidgetsBinding",
        "Navigator", "MediaQuery", "package:acme_bank/main.dart", "package:acme_bank/login.dart",
        "https://api.acme-bank.io/v1", "/v1/transfer", "com.acme.bank/root"]
ENGINE = b"\0junk\x003.5.4 (stable) (Tue Jan 1 00:00:00 2025 +0000) on \"android_arm64\"\0"


def test_elf_merged_layout():
    elf = elf_libapp(string_stream(STRS), merged=True)
    b = binfmt.parse(elf)
    assert b.arch == "arm64" and b.dart_symbol("kDartSnapshotData")
    info = dart.analyze_app_binary(elf)
    assert info.layout == "merged" and info.located_by == "symbols"
    assert info.snapshot_hash == "0123456789abcdef0123456789abcdef"
    assert dart.build_mode(info, False) == "release"


def test_elf_split_layout():
    info = dart.analyze_app_binary(elf_libapp(string_stream(STRS), merged=False))
    assert info.layout == "split" and info.vm and info.isolate


def test_magic_scan_fallback_on_stripped_binary():
    data = b"\0" * 100 + elf_libapp(string_stream(STRS))[0x200:]
    info = dart.analyze_app_binary(data)
    assert info.located_by == "magic-scan" and info.snapshot_hash


def test_engine_version():
    ei = dart.analyze_engine(ENGINE, "libflutter.so")
    assert ei.dart_version == "3.5.4" and ei.channel == "stable" and ei.target == "android_arm64"
    assert "3.24.4" in ei.flutter_candidates or ei.flutter_candidates


def test_macho():
    m = macho_app(string_stream(STRS))
    b = binfmt.parse(m)
    assert b.fmt == "macho" and b.arch == "arm64"
    info = dart.analyze_app_binary(m)
    assert info.layout == "split" and info.isolate and info.has_aot_code


def _apk(tmp_path, files):
    p = tmp_path / "x.apk"
    with zipfile.ZipFile(p, "w") as z:
        for k, v in files.items():
            z.writestr(k, v)
    return p


def test_apk_end_to_end(tmp_path):
    apk = _apk(tmp_path, {
        "lib/arm64-v8a/libapp.so": elf_libapp(string_stream(STRS)),
        "lib/arm64-v8a/libflutter.so": ENGINE,
        "assets/flutter_assets/assets/prod.env": "API_SECRET=abcd1234efgh\nDEBUG=false\n",
        "assets/flutter_assets/assets/certs/pin.pem": "-----BEGIN CERTIFICATE-----\nMII\n",
    })
    r = analyzer.analyze(inputs.load([str(apk)]))
    assert r.is_flutter and r.build_mode == "release"
    assert r.app_package == "acme_bank" and r.app_files == ["login.dart", "main.dart"]
    assert r.engine["dart_version"] == "3.5.4"
    assert any(h["host"] == "api.acme-bank.io" for h in r.hosts)
    assert "/v1/transfer" in r.api_paths
    assert "com.acme.bank/root" in r.channels
    assert any(s["rule"] == "env-secret" for s in r.secrets)
    assert any(p["kind"] == "pinning" for p in r.protections)
    assert r.obfuscation["verdict"] == "not obfuscated"


def test_split_apks_and_xapk(tmp_path):
    base = _apk(tmp_path, {"assets/flutter_assets/AssetManifest.bin": b"x"})
    split = tmp_path / "split_config.arm64_v8a.apk"
    with zipfile.ZipFile(split, "w") as z:
        z.writestr("lib/arm64-v8a/libapp.so", elf_libapp(string_stream(STRS)))
    r = analyzer.analyze(inputs.load([str(base), str(split)]))
    assert r.binaries and r.binaries[0]["abi"] == "arm64-v8a"
    xapk = tmp_path / "x.xapk"
    with zipfile.ZipFile(xapk, "w") as z:
        z.write(base, "base.apk")
        z.write(split, "split_config.arm64_v8a.apk")
    b = inputs.load([str(xapk)])
    assert b.container == "xapk" and b.get("lib/arm64-v8a/libapp.so")


def test_ipa(tmp_path):
    data = ipa(macho_app(string_stream(STRS)), ENGINE.replace(b"android_arm64", b"ios_arm64"),
               {"assets/config.json": b'{"k":"https://cfg.acme-bank.io/x"}'},
               {"CFBundleIdentifier": "io.acme.bank", "CFBundleShortVersionString": "2.0",
                "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
                "CFBundleURLTypes": [{"CFBundleURLSchemes": ["acmebank"]}]})
    p = tmp_path / "a.ipa"
    p.write_bytes(data)
    r = analyzer.analyze(inputs.load([str(p)]))
    assert r.platform == "ios" and r.is_flutter
    assert r.app["id"] == "io.acme.bank" and r.ios["url_schemes"] == ["acmebank"]
    assert r.build_mode == "release" and r.app_package == "acme_bank"
    assert any(f.id == "ios-ats" for f in r.findings)
    assert any(h["host"] == "cfg.acme-bank.io" for h in r.hosts)


def test_not_flutter(tmp_path):
    r = analyzer.analyze(inputs.load([str(_apk(tmp_path, {"classes.dex": b"dex\n035"}))]))
    assert not r.is_flutter
