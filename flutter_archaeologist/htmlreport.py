from __future__ import annotations

import html
import json
import os

from . import knowledge

LOGO_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128" role="img" aria-label="Flutter Archaeologist">
<defs>
<linearGradient id="fa-body" x1="0" y1="0" x2="1" y2="1">
<stop offset="0" stop-color="#E07A3F"/><stop offset="1" stop-color="#A9441E"/>
</linearGradient>
<clipPath id="fa-clip"><path d="M54 21h20v10c18 4 28 18 26 35-2 18-15 31-28 38H56c-13-7-26-20-28-38-2-17 8-31 26-35z"/></clipPath>
</defs>
<path d="M53 26c-17-5-26 9-16 21" fill="none" stroke="#7A2F14" stroke-width="6" stroke-linecap="round"/>
<path d="M75 26c17-5 26 9 16 21" fill="none" stroke="#7A2F14" stroke-width="6" stroke-linecap="round"/>
<rect x="45" y="11" width="38" height="10" rx="4" fill="#7A2F14"/>
<path d="M54 21h20v10c18 4 28 18 26 35-2 18-15 31-28 38H56c-13-7-26-20-28-38-2-17 8-31 26-35z" fill="url(#fa-body)"/>
<g clip-path="url(#fa-clip)">
<rect x="20" y="52" width="90" height="14" fill="#3A2418"/>
<path d="M28 63l6-8 6 8 6-8 6 8 6-8 6 8 6-8 6 8 6-8 6 8 6-8 6 8" fill="none" stroke="#F4DFC0" stroke-width="2.4" stroke-linejoin="round"/>
<rect x="20" y="72" width="90" height="3" fill="#F4DFC0" opacity=".85"/>
<rect x="20" y="80" width="90" height="5" fill="#3A2418"/>
<path d="M40 50c3-9 10-14 18-16-6 6-9 12-10 18z" fill="#FFF3E6" opacity=".35"/>
</g>
<rect x="53" y="104" width="22" height="6" rx="2" fill="#7A2F14"/>
<rect x="45" y="109" width="38" height="7" rx="3.5" fill="#5C2410"/>
</svg>"""

SEVERITIES = ["critical", "high", "medium", "low", "info"]
VERDICT_LABEL = {"enforcement-candidate": "Enforced", "weak-signal": "Weak signal", "telemetry-only": "Telemetry only"}


def e(x) -> str:
    return html.escape(str(x), quote=True)


def _badge(text: str, kind: str) -> str:
    return f'<span class="badge b-{e(kind)}">{e(text)}</span>'


def _copy(cmd: str) -> str:
    return (f'<div class="cmd"><code>{e(cmd)}</code>'
            f'<button class="copy" type="button" data-copy="{e(cmd)}" aria-label="Copy command">Copy</button></div>')


def _table(head: list[str], rows: list[list[str]], widths: list[str] | None = None, raw: set[int] = frozenset(),
           mono: set[int] = frozenset()) -> str:
    cols = "".join(f'<col style="width:{w}">' for w in (widths or []))
    th = "".join(f"<th>{e(h)}</th>" for h in head)
    body = []
    for row in rows:
        tds = []
        for i, c in enumerate(row):
            v = c if i in raw else e(c)
            cls = ' class="mono"' if i in mono else ""
            tds.append(f"<td{cls}>{v}</td>")
        body.append("<tr>" + "".join(tds) + "</tr>")
    return (f'<div class="tbl"><table><colgroup>{cols}</colgroup><thead><tr>{th}</tr></thead>'
            f'<tbody>{"".join(body)}</tbody></table></div>')


def _section(sid: str, title: str, body: str, count=None, lead: str = "") -> str:
    c = f'<span class="count">{e(count)}</span>' if count is not None else ""
    ld = f'<p class="lead">{lead}</p>' if lead else ""
    return f'<section id="{sid}" class="card"><h2>{e(title)}{c}</h2>{ld}{body}</section>'


def render(r, d: dict, show_secrets: bool) -> str:
    from .report import _deps_by_cat, _tree

    app = r.app or {}
    eng = r.engine or {}
    title = app.get("id") or os.path.basename(r.sources[0])
    nav: list[tuple[str, str, object]] = []
    parts: list[str] = []

    fl = (eng.get("flutter_candidates") or [])
    flutter_v = fl[0] + (f" – {fl[-1]}" if len(fl) > 1 else "") if fl else "unknown"
    chips = [r.platform, r.container]
    if app.get("version"):
        chips.append("v" + str(app["version"]))
    if r.is_flutter:
        chips += [f"Flutter {flutter_v}", f"Dart {eng.get('dart_version') or '?'}", r.build_mode]
    chip_html = "".join(f'<span class="chip">{e(c)}</span>' for c in chips if c)

    if not r.is_flutter:
        parts.append('<section class="card" id="overview"><h2>Not a Flutter application</h2><p class="lead">'
                     'No libapp.so, App.framework or flutter_assets were found. Platform checks below still apply.'
                     '</p></section>')
        nav.append(("overview", "Overview", None))
    else:
        parts.append(_overview(r))
        nav.append(("overview", "Overview", None))

    if r.findings:
        nav.append(("findings", "Findings", len(r.findings)))
        parts.append(_section("findings", "Findings", _findings(r), len(r.findings),
                              "Issues with evidence. Info items are context, not vulnerabilities."))
    if r.next_steps:
        nav.append(("next", "Next steps", len(r.next_steps)))
        parts.append(_section("next", "Next steps", _steps(r), len(r.next_steps),
                              "A test plan derived from what was found in this app."))
    if r.tls_targets:
        nav.append(("tls", "TLS pinning", len(r.tls_targets)))
        parts.append(_section("tls", "TLS certificate verification", _tls(r), len(r.tls_targets),
                              "BoringSSL <code>ssl_crypto_x509_session_verify_cert_chain</code>, located statically "
                              "in this app's engine. Hook: <code>frida/flutter_tls_bypass.js</code>."))
    if r.anti_analysis:
        enforced = sum(1 for c in r.anti_analysis if c["verdict"] == "enforcement-candidate")
        nav.append(("rasp", "Anti-analysis", len(r.anti_analysis)))
        parts.append(_section("rasp", "Anti-analysis / RASP checks", _rasp(r.anti_analysis), len(r.anti_analysis),
                              f"{enforced} enforced in app or RASP code. Checks only collected by crash, analytics "
                              "or fraud SDKs are marked as telemetry. Hooks: <code>frida/anti_detection.js</code>."))
    if r.secrets:
        nav.append(("secrets", "Secrets", len(r.secrets)))
        rows = [[_badge(s["severity"], s["severity"]), s["title"], s["value"] if show_secrets else s["masked"],
                 ", ".join(s["where"]), s["note"]] for s in r.secrets]
        parts.append(_section("secrets", "Secrets", _filter("secrets") + _table(
            ["Severity", "Type", "Value", "Found in", "Note"], rows, ["10%", "18%", "22%", "22%", "28%"],
            raw={0}, mono={2, 3}), len(r.secrets),
            "Values are masked" + ("" if not show_secrets else " (disabled)") + "; full values are in "
            "<code>secrets.json</code>."))
    if r.hosts:
        nav.append(("hosts", "Hosts", len(r.hosts)))
        parts.append(_section("hosts", "Hosts and URLs", _filter("hosts") + _hosts(r), len(r.hosts)))
    if r.api_paths:
        nav.append(("api", "API paths", len(r.api_paths)))
        items = "".join(f"<li><code>{e(p)}</code></li>" for p in r.api_paths)
        parts.append(_section("api", "API paths", _filter("api") + f'<ul class="plist">{items}</ul>',
                              len(r.api_paths), "Relative endpoints recovered from Dart string literals."))
    if r.app_files:
        nav.append(("source", "Source tree", len(r.app_files)))
        parts.append(_section("source", "App source tree", f"<pre class='tree'>{e(_tree(r.app_package, r.app_files))}</pre>",
                              len(r.app_files), f"Library layout of <code>package:{e(r.app_package)}</code>."))
    deps = _deps_by_cat(r)
    if deps:
        nav.append(("deps", "Dependencies", len(r.dependencies)))
        parts.append(_section("deps", "Dependencies", _deps(deps), len(r.dependencies)))
    if r.android:
        nav.append(("android", "Android", None))
        parts.append(_section("android", "Android manifest", _android(r.android)))
    if r.ios:
        nav.append(("ios", "iOS", None))
        rows = [[k, json.dumps(v, ensure_ascii=False)] for k, v in r.ios.items()]
        parts.append(_section("ios", "iOS Info.plist", _table(["Key", "Value"], rows, ["30%", "70%"], mono={1})))
    if r.channels:
        nav.append(("channels", "Channels", len(r.channels)))
        items = "".join(f"<li><code>{e(c)}</code></li>" for c in r.channels)
        parts.append(_section("channels", "Platform channels", f'<ul class="plist">{items}</ul>', len(r.channels),
                              "Dart ↔ native bridges. Trace them with <code>frida/trace_method_channels.js</code>."))
    assets = [a for a in r.assets if a["kind"] != "media"]
    if assets:
        nav.append(("assets", "Assets", len(assets)))
        rows = [[a["path"], a["kind"], f"{a['size']:,}"] for a in assets]
        parts.append(_section("assets", "Bundled assets", _table(["Path", "Kind", "Bytes"], rows,
                                                                 ["64%", "18%", "18%"], mono={0}), len(assets)))
    if r.binaries:
        nav.append(("binaries", "Binaries", len(r.binaries)))
        rows = [[b["abi"], b["format"], b["snapshot_hash"] or "-", " ".join(b["features"]), b["located_by"]]
                for b in r.binaries]
        parts.append(_section("binaries", "Dart snapshots", _table(
            ["ABI", "Format", "Snapshot hash", "Features", "Located by"], rows, ["12%", "8%", "26%", "40%", "14%"],
            mono={2, 3}), len(rows)))
    if r.notes:
        nav.append(("notes", "Notes", len(r.notes)))
        parts.append(_section("notes", "Notes", "<ul class='notes'>" + "".join(f"<li>{e(n)}</li>" for n in r.notes)
                              + "</ul>", len(r.notes)))

    nav_html = "".join(
        f'<a href="#{sid}">{e(lbl)}' + (f'<span>{e(cnt)}</span>' if cnt is not None else "") + "</a>"
        for sid, lbl, cnt in nav)
    foot = (f"Flutter Archaeologist {e(r.tool_version)} · {e(r.scanned_at)} · {e(r.timings.get('total_s'))} s · "
            + e(", ".join(os.path.basename(s) for s in r.sources)))
    return (TEMPLATE.replace("{{TITLE}}", e(title)).replace("{{LOGO}}", LOGO_SVG).replace("{{CHIPS}}", chip_html)
            .replace("{{NAV}}", nav_html).replace("{{BODY}}", "\n".join(parts)).replace("{{FOOT}}", foot))


def _filter(target: str) -> str:
    return (f'<input class="filter" type="search" placeholder="Filter…" data-target="{e(target)}" '
            f'aria-label="Filter {e(target)}">')


def _overview(r) -> str:
    counts = {s: 0 for s in SEVERITIES}
    for f in r.findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    enforced = [c["category"] for c in r.anti_analysis if c["verdict"] == "enforcement-candidate"]
    tls = [t for t in r.tls_targets if t["status"] == "found"]
    tiles = "".join(
        f'<div class="tile t-{s}"><div class="n">{counts[s]}</div><div class="l">{s}</div></div>' for s in SEVERITIES)
    stats = [
        ("Source files", len(r.app_files)), ("Hosts", len(r.hosts)), ("API paths", len(r.api_paths)),
        ("Secrets", len(r.secrets)), ("RASP enforced", len(enforced)), ("TLS hook ready", "yes" if tls else "no"),
    ]
    stat_html = "".join(f'<div class="stat"><div class="n">{e(v)}</div><div class="l">{e(k)}</div></div>'
                        for k, v in stats)
    eng = r.engine or {}
    facts = [
        ("Package", (r.app or {}).get("id") or "-"),
        ("Flutter", ", ".join(eng.get("flutter_candidates") or []) or "unknown"),
        ("Dart", f"{eng.get('dart_version') or '?'} ({eng.get('channel') or '?'})"),
        ("Build mode", r.build_mode),
        ("Obfuscation", f"{r.obfuscation.get('verdict', '?')} · {r.obfuscation.get('framework_markers_found', '?')} "
                        f"framework markers"),
        ("App package", f"{r.app_package or '?'}"),
        ("TLS verify function", ", ".join(f"{t['abi']} @ {t['offset']}" for t in tls) or "not located"),
        ("Anti-analysis", ", ".join(enforced) or "nothing enforced"),
    ]
    dl = "".join(f"<dt>{e(k)}</dt><dd>{e(v)}</dd>" for k, v in facts)
    return (f'<section id="overview" class="card overview"><h2>Overview</h2>'
            f'<div class="tiles">{tiles}</div><div class="stats">{stat_html}</div><dl class="facts">{dl}</dl></section>')


def _findings(r) -> str:
    out = []
    for f in r.findings:
        ev = "".join(f"<li><code>{e(x)}</code></li>" for x in f.evidence)
        out.append(f'<article class="finding f-{e(f.severity)}"><div class="fh">{_badge(f.severity, f.severity)}'
                   f'<h3>{e(f.title)}</h3></div><p>{e(f.detail)}</p>'
                   + (f'<ul class="ev">{ev}</ul>' if ev else "") + "</article>")
    return "".join(out)


def _steps(r) -> str:
    out = []
    for i, s in enumerate(r.next_steps, 1):
        cmds = "".join(_copy(c) for c in s["commands"])
        out.append(f'<li class="step"><div class="num">{i}</div><div class="sb"><h3>{e(s["title"])}</h3>'
                   f'<p>{e(s["detail"])}</p>{cmds}</div></li>')
    return f'<ol class="steps">{"".join(out)}</ol>'


def _tls(r) -> str:
    out = []
    pkg = (r.app or {}).get("id") or "<package>"
    for t in r.tls_targets:
        ok = t["status"] == "found"
        out.append(f'<div class="tls"><div class="tls-h">{_badge(t["status"], "ok" if ok else "warn")}'
                   f'<span class="abi">{e(t["abi"])}</span><span class="arch">{e(t["arch"])}</span></div>'
                   + (f'<div class="tls-o"><div><div class="l">Offset</div><div class="big">{e(t["offset"])}</div></div>'
                      f'<div><div class="l">Size</div><div class="big">{e(t["size"])} B</div></div>'
                      f'<div class="grow"><div class="l">Prologue</div><code>{e((t["prologue"] or "")[:48])}</code></div></div>'
                      if ok else "")
                   + f'<p class="muted">{e(t["detail"])}</p></div>')
    if any(t["status"] == "found" for t in r.tls_targets):
        out.append(_copy(f"frida -U -f {pkg} -l frida/flutter_tls_bypass.js"))
    return "".join(out)


def _rasp(items: list[dict]) -> str:
    out = []
    for c in items:
        rows = [[x["strength"], x["label"], x["value"][:160], x["where"][:200], x["source"], x["owner"] or "app / unknown"]
                for x in c["evidence"][:60]]
        more = len(c["evidence"]) - len(rows)
        out.append(
            f'<details class="rasp v-{e(c["verdict"])}" {"open" if c["verdict"] == "enforcement-candidate" else ""}>'
            f'<summary>{_badge(VERDICT_LABEL.get(c["verdict"], c["verdict"]), c["verdict"])}'
            f'<span class="rt">{e(c["title"])}</span><span class="count">{len(c["evidence"])}</span></summary>'
            + _table(["Strength", "Indicator", "Value", "Where", "Source", "Owner"], rows,
                     ["8%", "18%", "27%", "24%", "7%", "16%"], mono={2, 3})
            + (f'<p class="muted">+ {more} more in report.json</p>' if more > 0 else "")
            + f'<p class="hint"><b>Bypass</b> {e(c["hint"])}</p></details>')
    return "".join(out)


def _hosts(r) -> str:
    rows = []
    for h in r.hosts:
        urls = h["urls"][:6]
        more = len(h["urls"]) - len(urls)
        ul = "<br>".join(e(u) for u in urls) + (f'<br><span class="muted">+ {more} more</span>' if more > 0 else "")
        svc = _badge(h["service"], "svc") if h.get("service") else ""
        rows.append([f"<code>{e(h['host'])}</code>", svc, e(", ".join(h["sources"])), ul])
    return _table(["Host", "Service", "Found in", "URLs"], rows, ["26%", "14%", "16%", "44%"], raw={0, 1, 2, 3},
                  mono={3})


def _deps(deps: dict) -> str:
    out = []
    for cat, items in deps.items():
        label = knowledge.CATEGORY_LABELS.get(cat, "Other packages")
        chips = []
        notes = []
        for x in items:
            chips.append(f'<span class="pkg{" has-note" if x["note"] else ""}">{e(x["name"])}</span>')
            if x["note"]:
                notes.append(f"<li><code>{e(x['name'])}</code> {e(x['note'])}</li>")
        out.append(f'<div class="dep"><h3>{e(label)}</h3><div class="pkgs">{"".join(chips)}</div>'
                   + (f'<ul class="dnotes">{"".join(notes)}</ul>' if notes else "") + "</div>")
    return "".join(out)


def _android(a: dict) -> str:
    facts = [("Package", a.get("package")), ("Version", f"{a.get('version_name')} ({a.get('version_code')})"),
             ("SDK", f"min {a.get('min_sdk')} · target {a.get('target_sdk')}"), ("Debuggable", a.get("debuggable")),
             ("Allow backup", a.get("allow_backup")), ("Cleartext traffic", a.get("cleartext")),
             ("Permissions", len(a.get("permissions", [])))]
    dl = "".join(f"<dt>{e(k)}</dt><dd>{e(v)}</dd>" for k, v in facts)
    comps = [c for c in a.get("components", []) if c["exported"]]
    rows = [[c["kind"], c["name"], ("launcher " if c["launcher"] else "") + (c["permission"] or "-"),
             "\n".join(c["deeplinks"]) or "-"] for c in comps]
    tbl = _table(["Kind", "Exported component", "Launcher / permission", "Deep links"], rows,
                 ["12%", "44%", "18%", "26%"], mono={1, 3}) if rows else ""
    return f'<dl class="facts">{dl}</dl>' + (f"<h3>Exported components ({len(rows)})</h3>{tbl}" if rows else "")


TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{TITLE}} · Flutter Archaeologist</title>
<style>
:root{--bg:#f5f3f0;--fg:#1f1b18;--muted:#6b625a;--card:#fff;--line:#e7e1da;--soft:#f3eee8;--code:#f1ece6;
--accent:#b4501f;--accent-2:#e07a3f;--critical:#b42318;--high:#d4561b;--medium:#b7791f;--low:#2e6db4;--info:#6b7280;
--ok:#2f855a;--warn:#b7791f;--shadow:0 1px 2px rgba(31,27,24,.06),0 4px 16px rgba(31,27,24,.05)}
@media (prefers-color-scheme:dark){:root{--bg:#141110;--fg:#ece6e0;--muted:#a39a91;--card:#1c1816;--line:#2e2824;
--soft:#231e1b;--code:#26201c;--accent:#f08a50;--accent-2:#f5a271;--shadow:none}}
*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:16px}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;overflow-x:hidden}
code,pre,.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace;font-size:12.5px}
a{color:var(--accent)}
header.top{background:linear-gradient(135deg,#2a1a12,#4a2616 60%,#6b3018);color:#fbefe4}
.top-in{max-width:1320px;margin:0 auto;padding:22px 20px;display:flex;gap:16px;align-items:center}
.top-in svg{width:56px;height:56px;flex:none}
.top-in h1{margin:0;font-size:20px;line-height:1.2;word-break:break-all}
.top-in .sub{font-size:12px;opacity:.75;letter-spacing:.08em;text-transform:uppercase;margin-bottom:4px}
.chips{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px}
.chip{background:rgba(255,255,255,.12);border:1px solid rgba(255,255,255,.18);padding:2px 9px;border-radius:999px;font-size:12px}
.layout{max-width:1320px;margin:0 auto;padding:20px;display:grid;grid-template-columns:210px minmax(0,1fr);gap:20px}
nav.side{position:sticky;top:16px;align-self:start;display:flex;flex-direction:column;gap:2px}
nav.side a{display:flex;justify-content:space-between;align-items:center;padding:7px 10px;border-radius:8px;color:var(--fg);text-decoration:none;font-size:13px}
nav.side a:hover{background:var(--soft)}
nav.side a span{font-size:11px;color:var(--muted);background:var(--soft);border-radius:999px;padding:0 7px}
main{min-width:0}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px 20px;margin-bottom:18px;box-shadow:var(--shadow);min-width:0}
.card h2{margin:0 0 4px;font-size:17px;display:flex;align-items:center;gap:8px}
.card h3{font-size:14px;margin:0}
.lead{margin:0 0 14px;color:var(--muted)}
.count{font-size:11px;font-weight:600;color:var(--muted);background:var(--soft);border-radius:999px;padding:1px 8px}
.tiles{display:grid;grid-template-columns:repeat(5,minmax(0,1fr));gap:10px;margin:14px 0}
.tile{border-radius:12px;padding:12px;background:var(--soft);border-left:4px solid var(--info)}
.tile .n{font-size:26px;font-weight:700;line-height:1}.tile .l{font-size:12px;color:var(--muted);text-transform:capitalize;margin-top:4px}
.t-critical{border-color:var(--critical)}.t-high{border-color:var(--high)}.t-medium{border-color:var(--medium)}.t-low{border-color:var(--low)}
.stats{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:10px;margin-bottom:16px}
.stat{border:1px solid var(--line);border-radius:12px;padding:10px 12px}.stat .n{font-size:20px;font-weight:700}.stat .l{font-size:12px;color:var(--muted)}
dl.facts{display:grid;grid-template-columns:180px minmax(0,1fr);gap:6px 16px;margin:0}
dl.facts dt{color:var(--muted)}dl.facts dd{margin:0;overflow-wrap:anywhere}
.badge{display:inline-block;font-size:11px;font-weight:700;letter-spacing:.03em;text-transform:uppercase;padding:2px 8px;border-radius:6px;color:#fff;background:var(--info);white-space:nowrap}
.b-critical{background:var(--critical)}.b-high{background:var(--high)}.b-medium{background:var(--medium)}.b-low{background:var(--low)}
.b-ok{background:var(--ok)}.b-warn{background:var(--warn)}.b-svc{background:var(--soft);color:var(--fg);text-transform:none;font-weight:600}
.b-enforcement-candidate{background:var(--high)}.b-weak-signal{background:var(--medium)}.b-telemetry-only{background:var(--info)}
.finding{border:1px solid var(--line);border-left:4px solid var(--info);border-radius:10px;padding:12px 14px;margin-bottom:10px}
.f-critical{border-left-color:var(--critical)}.f-high{border-left-color:var(--high)}.f-medium{border-left-color:var(--medium)}.f-low{border-left-color:var(--low)}
.fh{display:flex;gap:10px;align-items:center;flex-wrap:wrap}.finding p{margin:6px 0;color:var(--muted)}
ul.ev{margin:4px 0 0;padding-left:18px}ul.ev code,dd code{overflow-wrap:anywhere}
code{background:var(--code);padding:1px 5px;border-radius:5px;overflow-wrap:anywhere}
.steps{list-style:none;margin:0;padding:0}.step{display:flex;gap:14px;padding:12px 0;border-top:1px solid var(--line)}.step:first-child{border-top:0}
.num{flex:none;width:28px;height:28px;border-radius:50%;background:var(--accent);color:#fff;display:grid;place-items:center;font-weight:700;font-size:13px}
.sb{min-width:0;flex:1}.sb p{margin:4px 0 8px;color:var(--muted)}
.cmd{display:flex;gap:8px;align-items:flex-start;background:var(--code);border-radius:8px;padding:8px 10px;margin:6px 0}
.cmd code{background:none;padding:0;flex:1;min-width:0;white-space:pre-wrap;overflow-wrap:anywhere}
.copy{flex:none;border:1px solid var(--line);background:var(--card);color:var(--fg);border-radius:6px;font-size:12px;padding:3px 9px;cursor:pointer}
.copy.done{background:var(--ok);color:#fff;border-color:var(--ok)}
.tls{border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin-bottom:10px}
.tls-h{display:flex;gap:10px;align-items:center}.abi{font-weight:700}.arch{color:var(--muted)}
.tls-o{display:flex;gap:24px;flex-wrap:wrap;margin-top:10px}.tls-o .l{font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em}
.tls-o .big{font:700 20px ui-monospace,Menlo,Consolas,monospace}.grow{flex:1;min-width:200px}
.muted{color:var(--muted)}
details.rasp{border:1px solid var(--line);border-radius:10px;margin-bottom:10px;overflow:hidden}
details.rasp>summary{list-style:none;cursor:pointer;display:flex;gap:10px;align-items:center;padding:10px 14px;background:var(--soft)}
details.rasp>summary::-webkit-details-marker{display:none}
details.rasp>summary::after{content:"▸";margin-left:auto;color:var(--muted);transition:transform .15s}
details.rasp[open]>summary::after{transform:rotate(90deg)}
.rt{font-weight:600}details.rasp .tbl{margin:0 14px}.hint{margin:10px 14px 12px;color:var(--muted)}.hint b{color:var(--fg);margin-right:6px}
details.rasp>p.muted{margin:6px 14px}
.tbl{overflow-x:auto;border:1px solid var(--line);border-radius:10px}
table{width:100%;border-collapse:collapse;table-layout:fixed}
th,td{text-align:left;vertical-align:top;padding:7px 10px;border-top:1px solid var(--line);overflow-wrap:anywhere;word-break:break-word;white-space:pre-line}
thead th{border-top:0;background:var(--soft);font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted);position:sticky;top:0}
tbody tr:hover{background:var(--soft)}
td.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
.filter{width:100%;max-width:340px;padding:7px 10px;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--fg);margin-bottom:10px;font:inherit}
ul.plist{list-style:none;padding:0;margin:0;display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:6px}
ul.plist li code{display:block;padding:5px 8px}
pre.tree{background:var(--code);border-radius:10px;padding:12px 14px;margin:0;max-height:520px;overflow:auto;white-space:pre}
.dep{padding:10px 0;border-top:1px solid var(--line)}.dep:first-child{border-top:0}
.pkgs{display:flex;flex-wrap:wrap;gap:6px;margin:8px 0}
.pkg{font:12px ui-monospace,Menlo,Consolas,monospace;background:var(--soft);border:1px solid var(--line);border-radius:6px;padding:2px 8px}
.pkg.has-note{border-color:var(--accent-2)}
ul.dnotes{margin:4px 0 0;padding-left:18px;color:var(--muted)}ul.dnotes li{margin:3px 0}
ul.notes li{margin:4px 0}
footer{text-align:center;color:var(--muted);font-size:12px;padding:10px 20px 30px}
.hidden{display:none!important}
@media (max-width:980px){.layout{grid-template-columns:minmax(0,1fr)}
nav.side{position:static;flex-direction:row;overflow-x:auto;gap:6px;padding-bottom:4px}
nav.side a{white-space:nowrap;border:1px solid var(--line);background:var(--card)}
.tiles{grid-template-columns:repeat(5,minmax(0,1fr))}.stats{grid-template-columns:repeat(3,minmax(0,1fr))}}
@media (max-width:620px){.layout{padding:12px 16px}.top-in{padding:16px}.tiles{grid-template-columns:repeat(3,minmax(0,1fr))}
.stats{grid-template-columns:repeat(2,minmax(0,1fr))}dl.facts{grid-template-columns:minmax(0,1fr)}dl.facts dt{margin-top:6px}
.card{padding:14px}.tbl table{min-width:640px}}
@media print{nav.side{display:none}.layout{grid-template-columns:1fr}details.rasp{break-inside:avoid}}
</style></head><body>
<header class="top"><div class="top-in">{{LOGO}}<div><div class="sub">Flutter Archaeologist report</div><h1>{{TITLE}}</h1><div class="chips">{{CHIPS}}</div></div></div></header>
<div class="layout"><nav class="side" aria-label="Sections">{{NAV}}</nav><main>
{{BODY}}
</main></div>
<footer>{{FOOT}}</footer>
<script>
document.querySelectorAll('button.copy').forEach(function(b){b.addEventListener('click',function(){
var t=b.getAttribute('data-copy');var done=function(){b.textContent='Copied';b.classList.add('done');
setTimeout(function(){b.textContent='Copy';b.classList.remove('done')},1400)};
if(navigator.clipboard){navigator.clipboard.writeText(t).then(done,function(){})}else{var a=document.createElement('textarea');
a.value=t;document.body.appendChild(a);a.select();try{document.execCommand('copy');done()}catch(x){}a.remove()}})});
document.querySelectorAll('input.filter').forEach(function(inp){inp.addEventListener('input',function(){
var q=inp.value.toLowerCase();var sec=inp.closest('section');
sec.querySelectorAll('tbody tr, ul.plist li').forEach(function(row){row.classList.toggle('hidden',q&&row.textContent.toLowerCase().indexOf(q)<0)})})});
</script>
</body></html>
"""
