import shutil
import subprocess

import pytest

from conftest import FIXTURES
from flutter_archaeologist import analyzer, antianalysis as aa, frida, inputs

EXAMPLES = [
    "/system/xbin/su", "/system/app/Superuser.apk", "com.topjohnwu.magisk", "test-keys", "/sbin/.magisk",
    "which su", "ro.debuggable", "busybox", "/system/xbin",
    "/Applications/Cydia.app", "/var/jb", "cydia://package/com.example", "IOSSecuritySuite",
    "frida-server", "re.frida.server", "27042", "de.robv.android.xposed.XposedBridge", "MobileSubstrate",
    "/proc/self/maps", "DYLD_INSERT_LIBRARIES",
    "TracerPid", "/proc/self/status", "isDebuggerConnected",
    "adb_enabled", "isUsbDebuggingEnabled",
    "development_settings_enabled", "developerMode",
    "goldfish", "sdk_gphone64_x86_64", "/dev/qemu_pipe", "ro.kernel.qemu", "com.bluestacks.home",
    "15555215554", "isPhysicalDevice",
    "filterTouchesWhenObscured",
    "FLAG_SECURE",
    "isFromMockProvider", "com.lexa.fakegps",
    "tun0", "http.proxyHost",
    "com.android.vending", "com.google.android.play.core.integrity.IntegrityManager",
    "enabled_accessibility_services",
]

NEGATIVES = ["AudioVolumeMute", "MicrophoneVolumeMute", "Friday", "superb", "subscription", "result",
             "sudo", "issue", "Memuat ulang", "status", "/system/fonts"]


def test_every_indicator_has_a_matching_example():
    assert len(EXAMPLES) == len(aa.STRING_INDICATORS)
    for ex, (cat, _rx, label, _st) in zip(EXAMPLES, aa.STRING_INDICATORS):
        m = aa._match_string(ex)
        assert m is not None, f"{ex!r} should match {label}"
        assert m[0] == cat, f"{ex!r}: {m} != {cat}"


@pytest.mark.parametrize("s", NEGATIVES)
def test_no_false_positive(s):
    assert aa._match_string(s) is None


def test_crashlytics_style_attribution():
    assert aa._owner_from_class("com.google.firebase.crashlytics.internal.common.CommonUtils") == "Firebase Crashlytics"
    assert aa._owner_from_class("com.example.app.security.RootCheck") is None


def test_demo_app_checks_are_attributed():
    p = FIXTURES / "demo-release.apk"
    if not p.exists():
        pytest.skip("fixtures not built")
    r = analyzer.analyze(inputs.load([str(p)]))
    enforced = {c["category"] for c in r.anti_analysis if c["verdict"] == "enforcement-candidate"}
    assert {"root", "debugger", "adb", "developer", "emulator"} <= enforced


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
def test_anti_detection_js_parses(tmp_path):
    p = tmp_path / "a.js"
    p.write_text(frida.anti_detection_script({k: "enforcement-candidate" for k in frida.ANTI_KEYS}))
    r = subprocess.run(["node", "--check", str(p)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_anti_detection_enables_only_detected():
    js = frida.anti_detection_script({"adb": "enforcement-candidate", "debugger": "telemetry-only"})
    assert '"adb": true' in js and '"debugger": false' in js
