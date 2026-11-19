from __future__ import annotations

import base64
import json
import math
import re
import unicodedata
from collections import Counter, defaultdict
from dataclasses import dataclass, field

ASCII_RX = re.compile(rb"[\x20-\x7e\xa0-\xff]{4,}")
U16_RX = re.compile(rb"(?:[\x20-\x7e\xa0-\xff]\x00|[\x00-\xff][\x01-\x24]){4,}")


def extract_strings(data: bytes, min_len: int = 4) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for m in ASCII_RX.finditer(data):
        s = m.group().decode("latin-1")
        if s not in seen:
            seen.add(s)
            out.append(s)
    for s in _utf16(data, min_len):
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


def _utf16(data: bytes, min_len: int) -> list[str]:
    res = []
    for m in U16_RX.finditer(data):
        s = m.group().decode("utf-16-le", "ignore").strip()
        if len(s) >= min_len and plausible_text(s):
            res.append(s)
    return res


def _script(c: str) -> str | None:
    try:
        name = unicodedata.name(c)
    except ValueError:
        return "?"
    if name.startswith("CJK UNIFIED IDEOGRAPH"):
        return "EXTA" if 0x3400 <= ord(c) <= 0x4DBF else "CJK"
    return name.split(" ", 1)[0]


def plausible_text(s: str) -> bool:
    scripts: set[str] = set()
    letters = 0
    for c in s:
        o = ord(c)
        if o < 0x80:
            if not (c.isprintable() or c in "\n\t"):
                return False
            letters += c.isalpha()
            continue
        if not c.isprintable() or 0xE000 <= o <= 0xF8FF or 0xD800 <= o <= 0xDFFF:
            return False
        if not c.isalpha():
            continue
        letters += 1
        if o <= 0x24F:
            continue
        sc = _script(c)
        if sc in ("?", "EXTA"):
            return False
        scripts.add(sc)
    if len(scripts) > 3 or {"CJK", "HANGUL"} <= scripts:
        return False
    return letters >= max(2, int(len(s.replace(" ", "")) * 0.5))


_ONEBYTE_OK = re.compile(rb"[\x09\x0a\x0d\x20-\x7e\xa0-\xff]+")
_ANCHOR = re.compile(rb"[\x80-\xff][\x20-\x7e]{2}")


def _walk(data: bytes, pos: int, n: int) -> tuple[list[str], int]:
    chain: list[str] = []
    while pos < n:
        val, shift, p = 0, 0, pos
        ok = False
        while p < n and p - pos < 4:
            b = data[p]
            p += 1
            if b & 0x80:
                val |= (b & 0x7F) << shift
                ok = True
                break
            val |= b << shift
            shift += 7
        if not ok:
            break
        length, two = val >> 1, val & 1
        if length == 0 or length > 200_000:
            break
        size = length * 2 if two else length
        end = p + size
        if end > n:
            break
        if two:
            try:
                if not plausible_text(data[p:min(end, p + 64)].decode("utf-16-le", "ignore")):
                    break
                s = data[p:end].decode("utf-16-le")
            except UnicodeDecodeError:
                break
            if not plausible_text(s):
                break
        else:
            if not _ONEBYTE_OK.fullmatch(data, p, end):
                break
            s = data[p:end].decode("latin-1")
        chain.append(s)
        pos = end
    return chain, pos


def snapshot_strings(data: bytes, min_chain: int = 3) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    n = len(data)
    covered = 0
    for m in _ANCHOR.finditer(data):
        start = m.start()
        if start < covered:
            continue
        chain, pos = _walk(data, start, n)
        if len(chain) < min_chain:
            for back in (1, 2, 3):
                st = start - back
                if st < 0 or data[st] >= 0x80:
                    break
                c2, p2 = _walk(data, st, n)
                if len(c2) >= min_chain:
                    chain, pos = c2, p2
                    break
        if len(chain) >= min_chain:
            covered = pos
            for s in chain:
                if s not in seen:
                    seen.add(s)
                    out.append(s)
    return out


URL_RX = re.compile(r"(?:https?|wss?)://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%{}]+")
NOISE_HOSTS = re.compile(
    r"(^|\.)(flutter\.dev|dart\.dev|dartlang\.org|pub\.dev|github\.com|githubusercontent\.com|"
    r"w3\.org|ietf\.org|schemas\.android\.com|schemas\.microsoft\.com|apple\.com|xmlsoap\.org|"
    r"purl\.org|adobe\.com|example\.com|example\.org|localhost|unicode\.org|mozilla\.org|"
    r"wikipedia\.org|json-schema\.org|ns\.adobe\.com|xml\.org|opengis\.net|android\.com|"
    r"googlesource\.com|chromium\.org|fonts\.gstatic\.com|stackoverflow\.com|dart-lang\.github\.io|"
    r"material\.io|creativecommons\.org|openid\.net|iana\.org|tools\.ietf\.org)$")
THIRD_PARTY = {
    "googleapis.com": "Google APIs", "firebaseio.com": "Firebase RTDB", "firebasedatabase.app": "Firebase RTDB",
    "firebaseapp.com": "Firebase Hosting", "appspot.com": "Google Cloud / Firebase Storage",
    "cloudfunctions.net": "Firebase Functions", "supabase.co": "Supabase", "supabase.in": "Supabase",
    "sentry.io": "Sentry", "amazonaws.com": "AWS", "azurewebsites.net": "Azure", "windows.net": "Azure",
    "onesignal.com": "OneSignal", "branch.io": "Branch", "app.link": "Branch", "appsflyer.com": "AppsFlyer",
    "adjust.com": "Adjust", "facebook.com": "Facebook", "graph.facebook.com": "Facebook Graph",
    "stripe.com": "Stripe", "paypal.com": "PayPal", "algolia.net": "Algolia", "mapbox.com": "Mapbox",
    "crashlytics.com": "Crashlytics", "doubleclick.net": "Google Ads", "google-analytics.com": "Google Analytics",
    "revenuecat.com": "RevenueCat", "intercom.io": "Intercom", "mixpanel.com": "Mixpanel",
    "amplitude.com": "Amplitude", "segment.io": "Segment", "pusher.com": "Pusher", "agora.io": "Agora",
}


@dataclass
class UrlInfo:
    host: str
    urls: list[str] = field(default_factory=list)
    service: str | None = None
    sources: list[str] = field(default_factory=list)


def find_urls(strings: list[str], origin: str = "dart",
              hosts: dict[str, UrlInfo] | None = None) -> dict[str, UrlInfo]:
    hosts = {} if hosts is None else hosts
    for s in strings:
        for m in URL_RX.finditer(s):
            url = m.group().rstrip(".,;)'\"")
            hm = re.match(r"^[a-z]+://([^/:?#@]+@)?([^/:?#]+)", url)
            if not hm:
                continue
            host = hm.group(2).lower().strip(".")
            if "." not in host or "{" in host or "$" in host or not re.fullmatch(r"[a-z0-9.\-]+", host):
                continue
            if NOISE_HOSTS.search(host):
                continue
            if re.search(r"\.(dtd|xsd|ent)$", url, re.I):
                continue
            ui = hosts.setdefault(host, UrlInfo(host))
            if origin not in ui.sources:
                ui.sources.append(origin)
            if url not in ui.urls:
                ui.urls.append(url)
            for suffix, svc in THIRD_PARTY.items():
                if host == suffix or host.endswith("." + suffix):
                    ui.service = svc
    return hosts


def sort_hosts(hosts: dict[str, UrlInfo]) -> dict[str, UrlInfo]:
    return dict(sorted(hosts.items(), key=lambda kv: (kv[1].service is not None,
                                                      "dart" not in kv[1].sources, kv[0])))


API_PATH_RX = re.compile(r"^/(?:[A-Za-z0-9_\-.{}$:]+/)*[A-Za-z0-9_\-.{}$:]+/?(?:\?[\w=&{}$.\-]*)?$")
API_HINT = re.compile(r"(^|/)(api|v\d+|rest|graphql|auth|oauth|login|logout|token|users?|accounts?|admin|"
                      r"payments?|orders?|profile|register|signup|otp|verify|upload|internal|debug|"
                      r"customers?|cart|checkout|wallet|transfer|cards?)(/|$|\?)", re.I)


def find_api_paths(strings: list[str]) -> list[str]:
    out = []
    for s in strings:
        if 3 < len(s) < 160 and s.startswith("/") and API_PATH_RX.match(s) and API_HINT.search(s):
            if not s.startswith(("/system/", "/proc/", "/data/", "/dev/", "/sys/", "/usr/", "/etc/", "/var/")):
                out.append(s)
    return sorted(set(out))


@dataclass
class Rule:
    id: str
    title: str
    rx: re.Pattern
    severity: str
    note: str = ""
    group: int = 0


RULES = [
    Rule("private-key", "Private key", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
         "critical", "Private key material shipped inside the app."),
    Rule("aws-access-key", "AWS access key ID", re.compile(r"\b((?:AKIA|ASIA)[0-9A-Z]{16})\b"), "high",
         "Check whether the key is live (`aws sts get-caller-identity`) and what it can reach.", 1),
    Rule("stripe-secret", "Stripe secret key", re.compile(r"\b((?:sk|rk)_live_[0-9A-Za-z]{16,})"), "critical",
         "Secret/restricted Stripe keys must never ship in a client.", 1),
    Rule("stripe-publishable", "Stripe publishable key", re.compile(r"\b(pk_live_[0-9A-Za-z]{16,})"), "info",
         "Publishable keys are public by design.", 1),
    Rule("google-api-key", "Google API key", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"), "low",
         "Often public by design (Firebase/Maps). Test whether it is restricted (package/SHA-1, API list) "
         "before reporting.", 1),
    Rule("github-token", "GitHub token", re.compile(r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})"),
         "critical", "", 1),
    Rule("slack-token", "Slack token", re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,})"), "high", "", 1),
    Rule("slack-webhook", "Slack incoming webhook", re.compile(r"(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)"),
         "medium", "Anyone can post into the channel.", 1),
    Rule("sendgrid", "SendGrid API key", re.compile(r"\b(SG\.[\w\-]{22}\.[\w\-]{43})\b"), "high", "", 1),
    Rule("mailgun", "Mailgun API key", re.compile(r"\b(key-[0-9a-f]{32})\b"), "high", "", 1),
    Rule("twilio-key", "Twilio API key SID", re.compile(r"\b(SK[0-9a-f]{32})\b"), "medium", "", 1),
    Rule("openai", "OpenAI API key", re.compile(r"\b(sk-(?:proj-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,})"), "critical", "", 1),
    Rule("anthropic", "Anthropic API key", re.compile(r"\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,})"), "critical", "", 1),
    Rule("mapbox-secret", "Mapbox secret token", re.compile(r"\b(sk\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{10,})"), "high", "", 1),
    Rule("azure-conn", "Azure storage connection string",
         re.compile(r"(DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{40,})"), "critical", "", 1),
    Rule("basic-auth-url", "Credentials in URL", re.compile(r"(https?://[^/\s:@'\"]{1,64}:[^/\s@'\"]{1,64}@[A-Za-z0-9.\-]+)"),
         "high", "", 1),
    Rule("jwt", "Hard-coded JWT", re.compile(r"\b(eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,})"),
         "medium", "", 1),
    Rule("google-oauth-client", "Google OAuth client ID",
         re.compile(r"\b(\d{6,}-[0-9a-z]{32}\.apps\.googleusercontent\.com)"), "info", "Public identifier.", 1),
    Rule("sentry-dsn", "Sentry DSN", re.compile(r"(https://[0-9a-f]{32}@[a-z0-9.\-]*sentry\.io/\d+)"), "info",
         "DSNs are semi-public; they allow sending fake events only.", 1),
]

ENV_SECRET_NAME = re.compile(r"(secret|passw|pwd|token|api[_-]?key|private|credential|auth|access[_-]?key)", re.I)


@dataclass
class Secret:
    rule: str
    title: str
    severity: str
    value: str
    where: str
    note: str = ""
    extra: dict = field(default_factory=dict)


def decode_jwt(tok: str) -> dict | None:
    try:
        p = tok.split(".")[1]
        p += "=" * (-len(p) % 4)
        return json.loads(base64.urlsafe_b64decode(p))
    except (ValueError, IndexError, UnicodeDecodeError):
        return None


def scan_secrets(strings: list[str], where: str) -> list[Secret]:
    found: dict[tuple, Secret] = {}
    for s in strings:
        if len(s) > 20000:
            continue
        for r in RULES:
            for m in r.rx.finditer(s):
                val = m.group(r.group)
                key = (r.id, val)
                if key in found:
                    continue
                sec = Secret(r.id, r.title, r.severity, val, where, r.note)
                if r.id == "jwt":
                    claims = decode_jwt(val)
                    if claims is None:
                        continue
                    sec.extra["claims"] = claims
                    role = str(claims.get("role", ""))
                    if claims.get("iss") == "supabase" or "ref" in claims:
                        if role == "service_role":
                            sec.title, sec.severity = "Supabase service_role key", "critical"
                            sec.note = "service_role bypasses Row Level Security: full database access."
                        else:
                            sec.title, sec.severity = f"Supabase {role or 'anon'} key", "info"
                            sec.note = ("anon keys are public by design; security depends on RLS policies. "
                                        "Test table access with this key.")
                found[key] = sec
    return list(found.values())


def scan_env_text(text: str, where: str) -> list[Secret]:
    out = scan_secrets(text.splitlines(), where)
    known = {s.value for s in out}
    for line in text.splitlines():
        m = re.match(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.\-]*)\s*[=:]\s*['\"]?(.*?)['\"]?\s*$", line)
        if not m:
            continue
        k, v = m.group(1), m.group(2)
        if not v or v in known or len(v) < 4:
            continue
        if re.fullmatch(r"(?i)(true|false|yes|no|on|off|null|none|enabled?|disabled?|\d+(\.\d+)?)", v):
            continue
        if re.match(r"^[a-z]+://", v) and not re.match(r"^[a-z]+://[^/\s:@]+:[^/\s@]+@", v):
            continue
        if ENV_SECRET_NAME.search(k):
            out.append(Secret("env-secret", f"Secret-looking value `{k}`", "high", v, where,
                              "Value of a secret-named variable in a bundled config file."))
    return out


def mask(value: str) -> str:
    if len(value) <= 12:
        return value[:2] + "…" + value[-2:]
    return value[:8] + "…" + value[-4:]


def entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return -sum(n / len(s) * math.log2(n / len(s)) for n in c.values())


PKG_RX = re.compile(r"package:([a-z][a-z0-9_]*)/([A-Za-z0-9_/\-.]+\.dart)")


def find_packages(strings: list[str]) -> dict[str, list[str]]:
    pk: dict[str, set] = defaultdict(set)
    for s in strings:
        for m in PKG_RX.finditer(s):
            pk[m.group(1)].add(m.group(2))
    return {k: sorted(v) for k, v in sorted(pk.items())}


def guess_app_package(packages: dict[str, list[str]], known: set[str]) -> str | None:
    with_main = [p for p, files in packages.items() if "main.dart" in files and p not in known]
    if len(with_main) == 1:
        return with_main[0]
    cands = [(len(f), p) for p, f in packages.items() if p not in known and not p.startswith("flutter")]
    if with_main:
        cands = [(len(packages[p]), p) for p in with_main]
    return max(cands)[1] if cands else None


CHANNEL_RX = re.compile(r"^[a-z][a-z0-9_\-]*(?:\.[a-z0-9_\-]+)+/[A-Za-z0-9_./\-]+$")
FRAMEWORK_CHANNEL = re.compile(r"^(flutter/|plugins\.flutter\.io/|dev\.flutter\.|io\.flutter\.)")


PIGEON_RX = re.compile(r"^dev\.flutter\.pigeon\.[A-Za-z0-9_.$]+$")


def find_channels(strings: list[str]) -> list[str]:
    out = []
    for s in strings:
        if PIGEON_RX.match(s):
            out.append(s)
            continue
        if 6 < len(s) < 120 and CHANNEL_RX.match(s) and not s.endswith(".dart") and "://" not in s:
            host = s.split("/", 1)[0]
            if re.search(r"\.(com|net|org|io|dev|app|co|de|fr|tr|uk)$", host) and s.count("/") == 1 \
                    and "." in s.split("/", 1)[1] and not re.search(r"[A-Z_]", s.split("/", 1)[1][:1]):
                if re.search(r"\.(png|jpg|svg|json|js|html|css)$", s):
                    continue
            out.append(s)
    return sorted(set(out))


IDENT_RX = re.compile(r"^_?[A-Z][A-Za-z0-9]{2,60}$")


def class_like(strings: list[str]) -> list[str]:
    res = []
    for s in strings:
        if IDENT_RX.match(s) and re.search(r"[a-z]", s) and not re.search(r"(.)\1\1\1", s):
            if len(re.findall(r"[A-Z][a-z0-9]+", s)) >= 2:
                res.append(s)
    return sorted(set(res))
