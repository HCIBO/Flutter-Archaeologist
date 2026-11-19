from __future__ import annotations

import html
import json
import os
import re
from collections import defaultdict
from pathlib import Path

from . import frida, knowledge, textscan
from .analyzer import Result

SEV_COLORS = {"critical": "#b3261e", "high": "#d9480f", "medium": "#c78a00", "low": "#2f6fb0", "info": "#6b7280"}


def safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("._") or "app"


def write_all(r: Result, out_dir: str, show_secrets: bool = False, export_libs: bool = True,
              blutter: dict | None = None, formats=("html", "md", "json")) -> dict[str, str]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written: dict[str, str] = {}

    def w(rel: str, data, binary=False):
        p = out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        if binary:
            p.write_bytes(data)
        else:
            p.write_text(data, encoding="utf-8")
        written[rel] = str(p)

    d = r.to_dict()
    if blutter:
        d["blutter"] = {"dir": blutter["dir"], "app_package": blutter["app_package"],
                        "functions": len(blutter["functions"]),
                        "interesting": [{"name": f"{f.cls}.{f.name}", "addr": hex(f.addr), "size": f.size,
                                         "file": f.file} for f in blutter["interesting"]]}
    if not show_secrets:
        for s in d["secrets"]:
            s["value"] = s["masked"]
    if "json" in formats:
        w("report.json", json.dumps(d, indent=2, ensure_ascii=False, default=str))
    if "md" in formats:
        w("report.md", render_md(r, d, show_secrets))
    if "html" in formats:
        w("report.html", render_html(r, d, show_secrets))

    if r.secrets:
        w("secrets.json", json.dumps(r.secrets, indent=2, ensure_ascii=False))
    if r._all_strings:
        w("strings.txt", "\n".join(s.replace("\n", "\\n") for s in r._all_strings) + "\n")
    lines = []
    for h in r.hosts:
        lines.append(f"# {h['host']}" + (f"  ({h['service']})" if h.get("service") else "") +
                     f"  [{', '.join(h['sources'])}]")
        lines += h["urls"]
    if r.api_paths:
        lines += ["", "# relative API paths"] + r.api_paths
    if lines:
        w("endpoints.txt", "\n".join(lines) + "\n")
    if r.app_files:
        w("app_source_tree.txt", _tree(r.app_package, r.app_files))
    if r.class_names:
        w("classes.txt", "\n".join(r.class_names) + "\n")
    for rel, raw in r._asset_dump.items():
        w("assets/" + _clean_rel(rel), raw, binary=True)
    for uri, src in r._kernel_sources.items():
        w("sources/" + _clean_rel(re.sub(r"^(package:|file:///)", "", uri)), src)

    if export_libs:
        for abi, ents in r._lib_entries.items():
            if abi not in ("arm64-v8a", "arm64", "ios"):
                continue
            for key, fname in (("app", "libapp.so"), ("engine", "libflutter.so")):
                e = ents.get(key)
                if e is not None:
                    w(f"libs/{abi}/{fname}" if abi != "ios" else f"libs/ios/{'App' if key == 'app' else 'Flutter'}",
                      e.read(), binary=True)

    if r.anti_analysis:
        w("frida/anti_detection.js", frida.anti_detection_script({c["category"]: c["verdict"] for c in r.anti_analysis}))
    if r.is_flutter:
        app_channels = [c for c in r.channels if not textscan.FRAMEWORK_CHANNEL.match(c)]
        native_http = sorted(dep["name"] for dep in r.dependencies if dep["name"] in knowledge.NATIVE_STACK_PACKAGES)
        w("frida/trace_method_channels.js", frida.method_channel_script(app_channels))
        w("frida/net_recon.js", frida.net_recon_script())

        arch_map = {"arm64-v8a": "arm64", "x86_64": "x64", "binary": None}
        targets = {}
        for t in r.tls_targets:
            fa = arch_map.get(t["abi"]) or {"arm64": "arm64", "x86_64": "x64"}.get(t["arch"])
            if t["status"] == "found" and fa:
                targets[fa] = {"offset": t["offset"], "prologue": t["prologue"]}
        if targets:
            w("frida/flutter_tls_bypass.js", frida.tls_bypass_script(targets))
        located = ", ".join(f"{a} @ {t['offset']}" for a, t in targets.items())
        w("frida/flutter_tls_bypass_hint.md", frida.tls_hint((r.app or {}).get("id"), r.protections, native_http,
                                                             located))
        if blutter and blutter["interesting"]:
            w("frida/blutter_hooks.js", frida.blutter_hooks(blutter["interesting"]))
    return written


def _clean_rel(rel: str) -> str:
    parts = [p for p in rel.replace("\\", "/").split("/") if p not in ("", ".", "..")]
    return "/".join(parts) or "unnamed"


def _tree(pkg: str | None, files: list[str]) -> str:
    out = [f"package:{pkg}/" if pkg else "(app)/"]
    prev: list[str] = []
    for f in sorted(files):
        parts = f.split("/")
        common = 0
        while common < min(len(prev), len(parts) - 1) and prev[common] == parts[common]:
            common += 1
        for i in range(common, len(parts) - 1):
            out.append("  " * (i + 1) + parts[i] + "/")
        out.append("  " * len(parts) + parts[-1])
        prev = parts[:-1]
    return "\n".join(out) + "\n"


def _summary_rows(r: Result) -> list[tuple[str, str]]:
    eng = r.engine or {}
    fl = ", ".join(eng.get("flutter_candidates") or []) or "unknown"
    app = r.app or {}
    rows = [
        ("App", f"{app.get('id') or '?'} {app.get('version') or ''}".strip()),
        ("Platform", f"{r.platform} ({r.container})"),
        ("Flutter", fl),
        ("Dart", f"{eng.get('dart_version') or '?'} ({eng.get('channel') or '?'})"),
        ("Build mode", r.build_mode),
        ("Obfuscation", f"{r.obfuscation.get('verdict', '?')} "
                        f"(framework markers {r.obfuscation.get('framework_markers_found', '?')})"),
        ("App package", f"{r.app_package or '?'} ({len(r.app_files)} source files)"),
        ("Snapshot", ", ".join(f"{b['abi']}: {b['snapshot_hash'] or '?'}" for b in r.binaries) or "-"),
        ("TLS verify fn", ", ".join(f"{t['abi']} {t['offset']}" if t["status"] == "found" else f"{t['abi']} {t['status']}"
                                    for t in r.tls_targets) or "-"),
        ("Anti-analysis", ", ".join(c["category"] for c in r.anti_analysis
                                    if c["verdict"] == "enforcement-candidate") or "none enforced"),
        ("Hosts / API paths", f"{len(r.hosts)} / {len(r.api_paths)}"),
        ("Secrets", ", ".join(f"{n} {k}" for k, n in _sev_counts(r.secrets).items()) or "none"),
    ]
    return rows


def _sev_counts(items) -> dict[str, int]:
    c: dict[str, int] = {}
    for s in items:
        sev = s["severity"] if isinstance(s, dict) else s.severity
        c[sev] = c.get(sev, 0) + 1
    return dict(sorted(c.items(), key=lambda kv: list(SEV_COLORS).index(kv[0])))


def _deps_by_cat(r: Result) -> dict[str, list[dict]]:
    g: dict[str, list[dict]] = defaultdict(list)
    for dep in r.dependencies:
        g[dep["category"] or "_"].append(dep)
    order = list(knowledge.CATEGORY_LABELS) + ["_"]
    return {k: sorted(g[k], key=lambda x: x["name"]) for k in order if g.get(k)}


def render_md(r: Result, d: dict, show_secrets: bool) -> str:
    L = []
    app = r.app or {}
    L.append(f"# Flutter Archaeologist report: {app.get('id') or os.path.basename(r.sources[0])}\n")
    if not r.is_flutter:
        L.append("**This is not a Flutter application** (no libapp.so / App.framework / flutter_assets).\n")
        return "\n".join(L)
    L.append("| | |\n|---|---|")
    for k, v in _summary_rows(r):
        L.append(f"| {k} | {_md(v)} |")
    L.append("")
    L.append("## Findings\n")
    if not r.findings:
        L.append("No findings.\n")
    for f in r.findings:
        L.append(f"- **[{f.severity.upper()}] {_md(f.title)}**: {_md(f.detail)}")
        for e in f.evidence:
            L.append(f"  - `{_md(e)}`")
    L.append("\n## Next steps\n")
    for i, s in enumerate(r.next_steps, 1):
        L.append(f"{i}. **{_md(s['title'])}**: {_md(s['detail'])}")
        for c in s["commands"]:
            L.append(f"   ```\n   {c}\n   ```")
    if r.tls_targets:
        L.append("\n## TLS verification function (BoringSSL)\n")
        L.append("`ssl_crypto_x509_session_verify_cert_chain` located statically:\n")
        L.append("| ABI | Status | Offset | Size | Prologue |\n|---|---|---|---|---|")
        for t in r.tls_targets:
            L.append(f"| {t['abi']} | {t['status']} | `{t['offset'] or '-'}` | {t['size'] or '-'} | "
                     f"`{(t['prologue'] or '-')[:24]}` |")
    if r.anti_analysis:
        L.append("\n## Anti-analysis / RASP checks\n")
        L.append("Verdicts: **enforcement-candidate** = app/RASP code performs the check; **weak-signal** = only "
                 "weak indicators; **telemetry-only** = only SDKs that collect the signal (crash/analytics/fraud).\n")
        for c in r.anti_analysis:
            L.append(f"### {c['title']}: {c['verdict']}\n")
            for e in c["evidence"][:25]:
                own = f" _(by {e['owner']})_" if e["owner"] else ""
                L.append(f"- [{e['strength']}] {_md(e['label'])}: `{_md(e['value'][:80])}` in `{_md(e['where'][:120])}` "
                         f"({e['source']}){own}")
            if len(c["evidence"]) > 25:
                L.append(f"- … {len(c['evidence']) - 25} more (report.json)")
            L.append(f"\n> Bypass: {_md(c['hint'])}\n")
    if r.protections:
        L.append("\n## Protections detected\n")
        for p in r.protections:
            L.append(f"- **{p['kind']}**: {_md(p['name'])} ({_md(p['source'])}). {_md(p['note'])}")
    if r.secrets:
        L.append("\n## Secrets\n")
        L.append("| Severity | Type | Value | Where |\n|---|---|---|---|")
        for s in r.secrets:
            v = s["value"] if show_secrets else s["masked"]
            L.append(f"| {s['severity']} | {_md(s['title'])} | `{_md(v)}` | {_md(', '.join(s['where']))} |")
    if r.hosts:
        L.append("\n## Hosts\n")
        for h in r.hosts:
            L.append(f"- `{h['host']}`" + (f" ({h['service']})" if h.get("service") else "") +
                     f" [{', '.join(h['sources'])}]: {len(h['urls'])} URL(s)")
    if r.api_paths:
        L.append("\n## API paths\n")
        L += [f"- `{_md(p)}`" for p in r.api_paths[:300]]
    if r.app_files:
        L.append(f"\n## App source tree ({len(r.app_files)} files)\n\n```\n{_tree(r.app_package, r.app_files)}```")
    deps = _deps_by_cat(r)
    if deps:
        L.append("\n## Dependencies\n")
        for cat, items in deps.items():
            L.append(f"**{knowledge.CATEGORY_LABELS.get(cat, 'Other packages')}**: " +
                     ", ".join(f"`{x['name']}`" for x in items))
            for x in items:
                if x["note"]:
                    L.append(f"  - `{x['name']}`: {_md(x['note'])}")
    _md_platform(r, L)
    if r.channels:
        L.append("\n## Platform channels\n")
        L += [f"- `{c}`" for c in r.channels]
    if r.notes:
        L.append("\n## Notes\n")
        L += [f"- {_md(n)}" for n in r.notes]
    L.append(f"\n---\nGenerated by Flutter Archaeologist {r.tool_version} in {r.timings.get('total_s')}s.")
    return "\n".join(L) + "\n"


def _md_platform(r: Result, L: list[str]) -> None:
    a = r.android or {}
    if a:
        L.append("\n## Android\n")
        L.append(f"- package `{a.get('package')}`, version {a.get('version_name')} ({a.get('version_code')}), "
                 f"minSdk {a.get('min_sdk')}, targetSdk {a.get('target_sdk')}")
        L.append(f"- debuggable={a.get('debuggable')}, allowBackup={a.get('allow_backup')}, "
                 f"usesCleartextTraffic={a.get('cleartext')}")
        exp = [c for c in a.get("components", []) if c["exported"]]
        if exp:
            L.append(f"- exported components ({len(exp)}):")
            for c in exp:
                tag = " (launcher)" if c["launcher"] else ""
                perm = f" perm={c['permission']}" if c["permission"] else ""
                L.append(f"  - {c['kind']} `{c['name']}`{tag}{perm}" +
                         (f" deeplinks: {', '.join(c['deeplinks'])}" if c["deeplinks"] else ""))
    i = r.ios or {}
    if i:
        L.append("\n## iOS\n")
        L.append(f"- bundle `{i.get('bundle_id')}` {i.get('version')} ({i.get('build')}), min iOS {i.get('min_os')}")
        L.append(f"- ATS arbitrary loads: {i.get('ats_arbitrary_loads')}; insecure exception domains: "
                 f"{', '.join(i.get('ats_exceptions') or []) or '-'}")
        L.append(f"- URL schemes: {', '.join(i.get('url_schemes') or []) or '-'}")


def _md(s) -> str:
    return str(s).replace("|", "\\|").replace("\n", " ")


def render_html(r: Result, d: dict, show_secrets: bool) -> str:
    from . import htmlreport
    return htmlreport.render(r, d, show_secrets)
