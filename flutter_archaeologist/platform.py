from __future__ import annotations

import plistlib
import struct
from dataclasses import dataclass, field

ANDROID_NS = "http://schemas.android.com/apk/res/android"
ATTR_IDS = {
    0x01010003: "name", 0x01010010: "exported", 0x0101000F: "debuggable", 0x01010280: "allowBackup",
    0x010104EC: "usesCleartextTraffic", 0x01010527: "networkSecurityConfig", 0x01010006: "permission",
    0x01010027: "scheme", 0x01010028: "host", 0x01010029: "port", 0x0101002A: "path",
    0x0101002B: "pathPrefix", 0x0101002C: "pathPattern", 0x0101000E: "enabled",
    0x0101021B: "versionCode", 0x0101021C: "versionName", 0x0101020C: "minSdkVersion",
    0x01010270: "targetSdkVersion", 0x01010001: "label", 0x01010018: "authorities",
    0x0101001B: "grantUriPermissions", 0x01010007: "readPermission", 0x01010008: "writePermission",
}


@dataclass
class XmlNode:
    tag: str
    attrs: dict[str, object] = field(default_factory=dict)
    children: list["XmlNode"] = field(default_factory=list)
    text: str = ""

    def iter(self, tag: str | None = None):
        if tag is None or self.tag == tag:
            yield self
        for c in self.children:
            yield from c.iter(tag)

    def get(self, name: str, default=None):
        return self.attrs.get(name, default)


class AxmlError(Exception):
    pass


def parse_axml(data: bytes) -> XmlNode:
    if len(data) < 8 or struct.unpack_from("<H", data, 0)[0] != 0x0003:
        raise AxmlError("not a binary XML document")
    strings: list[str] = []
    res_ids: list[int] = []
    root: XmlNode | None = None
    stack: list[XmlNode] = []
    pos = struct.unpack_from("<H", data, 2)[0]
    end = len(data)
    while pos + 8 <= end:
        ctype, hsize, csize = struct.unpack_from("<HHI", data, pos)
        if csize < 8 or pos + csize > end:
            break
        if ctype == 0x0001:
            strings = _string_pool(data, pos)
        elif ctype == 0x0180:
            n = (csize - hsize) // 4
            res_ids = list(struct.unpack_from(f"<{n}I", data, pos + hsize))
        elif ctype == 0x0102:
            _ns, name, astart, asize, acount = struct.unpack_from("<IIHHH", data, pos + 16)
            node = XmlNode(_s(strings, name))
            apos = pos + 16 + astart
            for i in range(acount):
                ans, aname, araw, _sz, _r, dtype, dval = struct.unpack_from("<IIIHBBI", data, apos + i * (asize or 20))
                key = _s(strings, aname)
                if aname < len(res_ids) and res_ids[aname] in ATTR_IDS:
                    key = ATTR_IDS[res_ids[aname]]
                elif not key:
                    key = f"attr{aname:#x}"
                node.attrs[key] = _value(strings, araw, dtype, dval)
            if stack:
                stack[-1].children.append(node)
            else:
                root = node
            stack.append(node)
        elif ctype == 0x0103:
            if stack:
                stack.pop()
        elif ctype == 0x0104 and stack:
            idx = struct.unpack_from("<I", data, pos + 16)[0]
            stack[-1].text += _s(strings, idx)
        pos += csize
    if root is None:
        raise AxmlError("no root element")
    return root


def _s(strings: list[str], i: int) -> str:
    return strings[i] if 0 <= i < len(strings) else ""


def _value(strings, raw, dtype, dval):
    if raw != 0xFFFFFFFF and raw < len(strings):
        return strings[raw]
    if dtype == 0x12:
        return dval != 0
    if dtype in (0x10, 0x11):
        return dval if dval < 0x80000000 else dval - 0x100000000
    if dtype == 0x01:
        return f"@{dval:#010x}"
    if dtype == 0x03:
        return _s(strings, dval)
    return dval


def _string_pool(data: bytes, pos: int) -> list[str]:
    _t, hsize, _size, count, _styles, flags, sstart, _st = struct.unpack_from("<HHIIIIII", data, pos)
    utf8 = bool(flags & 0x100)
    offs = struct.unpack_from(f"<{count}I", data, pos + hsize)
    base = pos + sstart
    out = []
    for o in offs:
        p = base + o
        try:
            if utf8:
                _n, p = _len8(data, p)
                n, p = _len8(data, p)
                out.append(data[p:p + n].decode("utf-8", "replace"))
            else:
                n = struct.unpack_from("<H", data, p)[0]
                p += 2
                if n & 0x8000:
                    n = ((n & 0x7FFF) << 16) | struct.unpack_from("<H", data, p)[0]
                    p += 2
                out.append(data[p:p + n * 2].decode("utf-16-le", "replace"))
        except (struct.error, IndexError):
            out.append("")
    return out


def _len8(data: bytes, p: int) -> tuple[int, int]:
    n = data[p]
    if n & 0x80:
        return ((n & 0x7F) << 8) | data[p + 1], p + 2
    return n, p + 1


@dataclass
class Component:
    kind: str
    name: str
    exported: bool
    explicit: bool
    permission: str | None
    actions: list[str] = field(default_factory=list)
    deeplinks: list[str] = field(default_factory=list)
    launcher: bool = False
    authorities: str | None = None


@dataclass
class AndroidInfo:
    package: str | None = None
    version_name: str | None = None
    version_code: object = None
    min_sdk: object = None
    target_sdk: object = None
    debuggable: bool = False
    allow_backup: bool | None = None
    cleartext: bool | None = None
    nsc_ref: str | None = None
    permissions: list[str] = field(default_factory=list)
    queries: list[str] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)


def android_manifest(data: bytes) -> AndroidInfo:
    root = parse_axml(data)
    ai = AndroidInfo(package=root.get("package"), version_name=root.get("versionName"),
                     version_code=root.get("versionCode"))
    for us in root.iter("uses-sdk"):
        ai.min_sdk, ai.target_sdk = us.get("minSdkVersion"), us.get("targetSdkVersion")
    for p in root.iter("uses-permission"):
        if p.get("name"):
            ai.permissions.append(str(p.get("name")))
    for q in root.iter("queries"):
        for pk in q.iter("package"):
            if pk.get("name"):
                ai.queries.append(str(pk.get("name")))
    app = next(root.iter("application"), None)
    if app is None:
        return ai
    ai.debuggable = app.get("debuggable") is True
    ai.allow_backup = app.get("allowBackup") if isinstance(app.get("allowBackup"), bool) else None
    ai.cleartext = app.get("usesCleartextTraffic") if isinstance(app.get("usesCleartextTraffic"), bool) else None
    nsc = app.get("networkSecurityConfig")
    ai.nsc_ref = str(nsc) if nsc is not None else None
    tsdk = ai.target_sdk if isinstance(ai.target_sdk, int) else 0
    for kind in ("activity", "activity-alias", "service", "receiver", "provider"):
        for c in app.children:
            if c.tag != kind:
                continue
            filters = [f for f in c.children if f.tag == "intent-filter"]
            exp = c.get("exported")
            explicit = isinstance(exp, bool)
            if explicit:
                exported = exp
            elif kind == "provider":
                exported = tsdk < 17
            else:
                exported = bool(filters) and tsdk < 31
            comp = Component(kind, str(c.get("name") or c.get("targetActivity") or "?"), exported, explicit,
                             c.get("permission"), authorities=c.get("authorities"))
            if c.get("enabled") is False:
                continue
            for f in filters:
                acts = [str(a.get("name")) for a in f.children if a.tag == "action"]
                cats = [str(a.get("name")) for a in f.children if a.tag == "category"]
                comp.actions.extend(acts)
                if "android.intent.action.MAIN" in acts and "android.intent.category.LAUNCHER" in cats:
                    comp.launcher = True
                if "android.intent.action.VIEW" in acts and "android.intent.category.BROWSABLE" in cats:
                    schemes = [d.get("scheme") for d in f.children if d.tag == "data" and d.get("scheme")]
                    hosts = [d.get("host") for d in f.children if d.tag == "data" and d.get("host")] or [""]
                    paths = [d.get("path") or d.get("pathPrefix") or d.get("pathPattern")
                             for d in f.children if d.tag == "data"]
                    paths = [p for p in paths if p] or [""]
                    for s in schemes:
                        for h in hosts:
                            for p in paths:
                                comp.deeplinks.append(f"{s}://{h}{p}")
            ai.components.append(comp)
    return ai


@dataclass
class NetSecConfig:
    file: str
    cleartext_base: bool | None = None
    cleartext_domains: list[str] = field(default_factory=list)
    user_ca_trusted: bool = False
    user_ca_debug_only: bool = False
    pin_domains: list[str] = field(default_factory=list)


def network_security_config(data: bytes, name: str) -> NetSecConfig | None:
    try:
        root = parse_axml(data)
    except AxmlError:
        return None
    if root.tag != "network-security-config":
        return None
    n = NetSecConfig(name)
    for bc in root.iter("base-config"):
        v = bc.get("cleartextTrafficPermitted")
        if isinstance(v, bool):
            n.cleartext_base = v
        if any(c.get("src") == "user" for c in bc.iter("certificates")):
            n.user_ca_trusted = True
    for dc in root.iter("domain-config"):
        doms = [d.text.strip() for d in dc.children if d.tag == "domain" and d.text.strip()]
        if dc.get("cleartextTrafficPermitted") is True:
            n.cleartext_domains.extend(doms)
        if any(c.tag == "pin-set" for c in dc.children):
            n.pin_domains.extend(doms)
        if any(c.get("src") == "user" for c in dc.iter("certificates")):
            n.user_ca_trusted = True
    for do in root.iter("debug-overrides"):
        if any(c.get("src") == "user" for c in do.iter("certificates")):
            n.user_ca_debug_only = True
    return n


@dataclass
class IosInfo:
    bundle_id: str | None = None
    version: str | None = None
    build: str | None = None
    min_os: str | None = None
    ats_arbitrary_loads: bool = False
    ats_exceptions: list[str] = field(default_factory=list)
    url_schemes: list[str] = field(default_factory=list)
    queried_schemes: list[str] = field(default_factory=list)
    associated_domains_hint: bool = False
    usage_descriptions: list[str] = field(default_factory=list)


def ios_info_plist(data: bytes) -> IosInfo:
    p = plistlib.loads(data)
    ii = IosInfo(bundle_id=p.get("CFBundleIdentifier"), version=p.get("CFBundleShortVersionString"),
                 build=p.get("CFBundleVersion"), min_os=p.get("MinimumOSVersion"))
    ats = p.get("NSAppTransportSecurity") or {}
    ii.ats_arbitrary_loads = bool(ats.get("NSAllowsArbitraryLoads"))
    for dom, cfg in (ats.get("NSExceptionDomains") or {}).items():
        if isinstance(cfg, dict) and (cfg.get("NSExceptionAllowsInsecureHTTPLoads") or
                                      cfg.get("NSTemporaryExceptionAllowsInsecureHTTPLoads")):
            ii.ats_exceptions.append(dom)
    for t in p.get("CFBundleURLTypes") or []:
        ii.url_schemes.extend(t.get("CFBundleURLSchemes") or [])
    ii.queried_schemes = list(p.get("LSApplicationQueriesSchemes") or [])
    ii.usage_descriptions = sorted(k for k in p if k.startswith("NS") and k.endswith("UsageDescription"))
    return ii
