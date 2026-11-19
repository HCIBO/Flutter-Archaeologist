import base64
import json

from flutter_archaeologist import textscan as t
from synth import string_stream


def _jwt(payload):
    b = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
    return b({"alg": "HS256"}) + "." + b(payload) + ".c2lnbmF0dXJlLXNpZ25hdHVyZQ"


def test_snapshot_stream_exact_boundaries():
    strs = ["StatelessWidget", "/v1/auth/login", "Zaloguj się do konta",
            "https://example-backend.io/" + "a" * 80, "ok", "LoginPage"]
    data = b"\x00\x13\x37" + string_stream(strs) + b"\x00\x00"
    got = t.snapshot_strings(data)
    for s in strs:
        assert s in got
    assert not any(g.endswith("StatelessWidget") and g != "StatelessWidget" for g in got)


def test_snapshot_stream_ignores_noise():
    assert t.snapshot_strings(bytes(range(256)) * 50) == []


def test_plausible_text():
    assert t.plausible_text("Logowanie zakończone")
    assert t.plausible_text("Огноо сонгох")
    assert t.plausible_text("مسح النص ضوئيًا")
    assert not t.plausible_text("䀸㟃썀䀵㋃썀")


def test_supabase_service_role_is_critical():
    tok = _jwt({"iss": "supabase", "ref": "abcdefghijklmnopqrst", "role": "service_role"})
    [s] = t.scan_secrets([f"key={tok}"], "x")
    assert s.severity == "critical" and "service_role" in s.title


def test_supabase_anon_is_info():
    tok = _jwt({"iss": "supabase", "ref": "abcdefghijklmnopqrst", "role": "anon"})
    [s] = t.scan_secrets([tok], "x")
    assert s.severity == "info"


def test_secret_rules():
    aws = "AK" + "IA" + "ABCDEFGHIJKLMNOP"
    stripe = "sk_" + "live_" + "abcdefghijklmnop1234"
    gkey = "AI" + "za" + "Sy" + "A" * 33
    found = {s.rule for s in t.scan_secrets([aws, stripe, gkey, "nothing here"], "x")}
    assert {"aws-access-key", "stripe-secret", "google-api-key"} <= found


def test_env_file_no_false_positives():
    text = "API_URL=https://api.example.io\nAUTH_ENABLED=false\nTIMEOUT=30\nADMIN_PASSWORD=s3cr3t-value\n"
    found = t.scan_env_text(text, ".env")
    assert [s.title for s in found] == ["Secret-looking value `ADMIN_PASSWORD`"]


def test_urls_and_noise_filter():
    hosts = t.find_urls(["https://api.shop.io/v2/cart", "see https://flutter.dev/docs",
                         "https://x.firebaseio.com/a.json"])
    assert "api.shop.io" in hosts and "flutter.dev" not in hosts
    assert hosts["x.firebaseio.com"].service == "Firebase RTDB"


def test_api_paths():
    got = t.find_api_paths(["/v1/auth/login", "/system/bin/sh", "/api/orders/", "/foo"])
    assert got == ["/api/orders/", "/v1/auth/login"]


def test_packages_and_app_guess():
    pk = t.find_packages(["package:my_shop/main.dart", "package:my_shop/pages/cart.dart",
                          "package:dio/src/dio.dart", "package:flutter/src/widgets/basic.dart"])
    assert pk["my_shop"] == ["main.dart", "pages/cart.dart"]
    assert t.guess_app_package(pk, {"dio", "flutter"}) == "my_shop"


def test_channels():
    ch = t.find_channels(["com.acme.app/security", "plugins.flutter.io/path_provider", "hello world",
                          "dev.flutter.pigeon.local_auth_android.LocalAuthApi.authenticate"])
    assert ch == ["com.acme.app/security", "dev.flutter.pigeon.local_auth_android.LocalAuthApi.authenticate",
                  "plugins.flutter.io/path_provider"]
