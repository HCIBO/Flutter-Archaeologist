import shutil
import subprocess

import pytest

from flutter_archaeologist import blutter, frida

ASM = """// lib: , url: package:acme_bank/login.dart

// class id: 1234, size: 0x10, field offset: 0x8
class _LoginPageState extends State<LoginPage> {

  _ _submit(/* No info */) async {
    // ** addr: 0x2a1b3c, size: 0x1f4
    // 0x2a1b3c: EnterFrame
  }

  Widget build(_LoginPageState, BuildContext) {
    // ** addr: 0x2a2000, size: 0x80
  }
}

// class id: 1240, size: 0x8
class RootChecker extends Object {

  static Future<bool> isJailbroken() async {
    // ** addr: 0x300000, size: 0x40
  }
}
"""


def test_blutter_output(tmp_path):
    (tmp_path / "asm" / "acme_bank").mkdir(parents=True)
    (tmp_path / "asm" / "acme_bank" / "main.dart").write_text("// empty\n")
    (tmp_path / "asm" / "acme_bank" / "login.dart").write_text(ASM)
    (tmp_path / "asm" / "flutter").mkdir()
    (tmp_path / "pp.txt").write_text('[pp+0x10] String: "https://api.acme-bank.io/v1"\n[pp+0x18] IMM: 0x1\n')
    (tmp_path / "blutter_frida.js").write_text("//")
    b = blutter.load(str(tmp_path), None)
    assert b["app_package"] == "acme_bank"
    names = {(f.cls, f.name, f.addr) for f in b["functions"]}
    assert ("_LoginPageState", "_submit", 0x2a1b3c) in names
    assert ("RootChecker", "isJailbroken", 0x300000) in names
    inter = {f.name for f in b["interesting"]}
    assert {"_submit", "isJailbroken"} <= inter
    assert b["pool_strings"] == ["https://api.acme-bank.io/v1"]
    js = frida.blutter_hooks(b["interesting"])
    assert "0x300000" in js and "RootChecker.isJailbroken" in js


@pytest.mark.skipif(not shutil.which("node"), reason="node not installed")
@pytest.mark.parametrize("src", [
    lambda: frida.method_channel_script(["com.acme/x"]),
    frida.net_recon_script,
    lambda: frida.blutter_hooks([]),
    lambda: frida.tls_bypass_script({"x64": {"offset": "0x10", "prologue": "55"}}),
])
def test_generated_js_parses(tmp_path, src):
    p = tmp_path / "s.js"
    p.write_text(src())
    r = subprocess.run(["node", "--check", str(p)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
