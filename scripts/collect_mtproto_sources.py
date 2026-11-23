#!/usr/bin/env python3
"""Собирает MTProto-ссылки из источников в sources.json.

Читает ключ ``mtproto`` (список URL), выкачивает их и складывает все строки,
похожие на MTProto-ссылку, в ``configs/mtproto_input.txt`` (по одной на строку).
"""
from __future__ import annotations

import json
import os
import urllib.request

MTPROTO_SCHEMES = (
    "tg://proxy",
    "tg://socks",
    "https://t.me/proxy",
    "https://t.me/socks",
    "http://t.me/proxy",
    "http://t.me/socks",
)
UA = "Mozilla/5.0 (compatible; proxy-preflight/1.0)"
SOURCES_FILE = "sources.json"
OUT_FILE = "configs/mtproto_input.txt"


def collect() -> set[str]:
    with open(SOURCES_FILE, encoding="utf-8") as f:
        sources = json.load(f)
    proxies: set[str] = set()
    for url in sources.get("mtproto", []):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=15) as r:
                content = r.read().decode("utf-8", errors="replace")
        except Exception as e:  # noqa: BLE001 — один битый источник не должен ронять сбор
            print(f"WARN {url}: {e}")
            continue
        for line in content.splitlines():
            line = line.strip()
            if line.lower().startswith(MTPROTO_SCHEMES):
                proxies.add(line)
    return proxies


def main() -> int:
    proxies = collect()
    os.makedirs(os.path.dirname(OUT_FILE) or ".", exist_ok=True)
    with open(OUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(sorted(proxies)))
    print(f"MTProto proxies collected: {len(proxies)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
