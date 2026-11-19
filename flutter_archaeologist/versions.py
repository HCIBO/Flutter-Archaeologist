from __future__ import annotations

import json
import re
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

INDEX_URLS = [
    "https://storage.googleapis.com/flutter_infra_release/releases/releases_linux.json",
    "https://storage.googleapis.com/flutter_infra_release/releases/releases_macos.json",
]
DATA_FILE = Path(__file__).parent / "data" / "flutter_releases.json"


def fetch() -> dict:
    rows: dict[tuple, dict] = {}
    for url in INDEX_URLS:
        req = urllib.request.Request(url, headers={"User-Agent": "flutter-archaeologist"})
        with urllib.request.urlopen(req, timeout=30) as r:
            idx = json.load(r)
        for rel in idx.get("releases", []):
            dart = rel.get("dart_sdk_version")
            ver = rel.get("version")
            if not dart or not ver:
                continue
            m = re.search(r"\(build ([^)]+)\)", dart)
            dart = m.group(1) if m else dart.split(" ")[0]
            key = (ver, dart)
            rows.setdefault(key, {"flutter": ver.lstrip("v"), "dart": dart,
                                  "channel": rel.get("channel"),
                                  "date": (rel.get("release_date") or "")[:10]})
    out = sorted(rows.values(), key=lambda r: r["date"], reverse=True)
    return {"generated": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            "source": INDEX_URLS[0], "releases": out}


def update(path: Path = DATA_FILE) -> int:
    data = fetch()
    path.write_text(json.dumps(data, indent=0, separators=(",", ":")) + "\n")
    return len(data["releases"])
