import pytest

from conftest import FIXTURES
from flutter_archaeologist import analyzer, inputs, report


def scan(name):
    p = FIXTURES / name
    if not p.exists():
        pytest.skip(f"{name} not built (run tools/build_fixtures.sh)")
    return analyzer.analyze(inputs.load([str(p)]))


def rules(r):
    return {s["rule"] for s in r.secrets}


def test_release():
    r = scan("demo-release.apk")
    assert r.build_mode == "release" and r.obfuscation["verdict"] == "not obfuscated"
    assert r.app_package == "archaeologist_demo"
    assert {"main.dart", "services/api_client.dart", "pages/login_page.dart"} <= set(r.app_files)
    assert {"aws-access-key", "stripe-secret", "google-api-key", "jwt", "env-secret"} <= rules(r)
    assert any(s["title"] == "Supabase service_role key" for s in r.secrets)
    hosts = {h["host"] for h in r.hosts}
    assert {"api.archaeologist-demo.example", "archaeologist-demo-default-rtdb.firebaseio.com",
            "abcdefghijklmnopqrst.supabase.co"} <= hosts
    assert "com.archaeologist.demo/vault" in r.channels
    assert "Enter your password · Введите пароль" in r.ui_strings
    a = r.android
    assert a["cleartext"] is True and a["allow_backup"] is True
    links = [d for c in a["components"] for d in c["deeplinks"]]
    assert "archdemo://pay" in links


def test_obfuscated():
    r = scan("demo-obfuscated.apk")
    assert r.obfuscation["verdict"] != "not obfuscated"
    assert "stripe-secret" in rules(r) and "jwt" in rules(r)


def test_debug():
    r = scan("demo-debug.apk")
    assert r.build_mode == "debug"
    assert r.kernel_blob["sources_recovered"] > 0
    assert "package:archaeologist_demo/main.dart" in r._kernel_sources
    assert any(f.id == "android-debuggable" for f in r.findings)


def test_aab():
    r = scan("demo-release.aab")
    assert r.container == "aab" and r.build_mode == "release" and r.app_package == "archaeologist_demo"


def test_report_escapes_html(tmp_path):
    r = scan("demo-release.apk")
    r.app_files.append("<script>alert(1)</script>.dart")
    out = report.write_all(r, str(tmp_path), export_libs=False)
    html = (tmp_path / "report.html").read_text()
    assert "<script>alert(1)" not in html
    assert "sk_live_" not in html.replace("sk_live_…", "")
    assert "report.json" in out
