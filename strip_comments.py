#!/usr/bin/env python3
"""
Убирает комментарии из VPN-конфигов и добавляет GeoIP флаг страны.

Использование:
  python strip_comments.py proxies_live.txt -o proxies_live.txt
  python strip_comments.py proxies_live.txt --fast  # только убрать комментарии, без GeoIP
  AUTO_COMMENT=" verified · proxy-preflight" python strip_comments.py proxies_live.txt
"""
import argparse
import json
import os
import socket
import sys
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlparse

GEO_API = "http://ip-api.com/json/{ip}?fields=countryCode"
GEO_TIMEOUT = 3
GEO_DELAY = 0.2
DNS_MAX_WORKERS = 32
GEO_MAX_WORKERS = 10

DEFAULT_AUTO_COMMENT = " verified · proxy-preflight"
FAST_MODE = os.environ.get("STRIP_FAST", "").lower() in ("1", "true", "yes")


def get_auto_comment() -> str:
    return os.environ.get("AUTO_COMMENT", DEFAULT_AUTO_COMMENT).strip() or DEFAULT_AUTO_COMMENT


def country_code_to_flag(cc: str) -> str:
    if not cc or len(cc) != 2:
        return "\U0001f310"  # 🌐
    a = 0x1F1E6
    return "".join(chr(a + ord(c) - ord("A")) for c in cc.upper() if "A" <= c <= "Z")


def strip_comment(line: str) -> str:
    line = line.strip()
    if not line or line.startswith("#"):
        return line
    return line.split("#", 1)[0].strip()


def get_host(line: str) -> str | None:
    try:
        url = line.split("#")[0].strip()
        return urlparse(url).hostname
    except Exception:
        return None


def resolve_ip(host: str) -> str | None:
    if not host:
        return None
    try:
        return socket.gethostbyname(host)
    except Exception:
        return None


def fetch_country(ip: str, cache: dict) -> str:
    if ip in cache:
        return cache[ip]
    time.sleep(GEO_DELAY)
    try:
        req = urllib.request.Request(
            GEO_API.format(ip=ip),
            headers={"User-Agent": "proxy-preflight/1.0"}
        )
        with urllib.request.urlopen(req, timeout=GEO_TIMEOUT) as r:
            data = json.loads(r.read().decode())
            cc = data.get("countryCode") or ""
            cache[ip] = cc
            return cc
    except Exception:
        cache[ip] = ""
        return ""


def process_file(input_path: str, output_path: str, fast: bool = False) -> int:
    path = Path(input_path)
    if not path.is_file():
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 0

    lines_in = path.read_text(encoding="utf-8").splitlines()
    links = []
    hosts = []
    for line in lines_in:
        link = strip_comment(line)
        if not link or link.startswith("#"):
            continue
        links.append(link)
        hosts.append(get_host(link) if not fast else None)

    geo_cache: dict[str, str] = {}
    host_to_ip: dict[str, str] = {}

    if not fast:
        unique_hosts = sorted({h for h in hosts if h})

        def _resolve(h: str) -> None:
            host_to_ip[h] = resolve_ip(h) or ""

        if unique_hosts:
            with ThreadPoolExecutor(max_workers=min(DNS_MAX_WORKERS, len(unique_hosts))) as ex:
                list(ex.map(_resolve, unique_hosts))

        unique_ips = sorted({ip for ip in host_to_ip.values() if ip})

        def _fetch_cc(ip: str) -> None:
            fetch_country(ip, geo_cache)

        if unique_ips:
            with ThreadPoolExecutor(max_workers=min(GEO_MAX_WORKERS, len(unique_ips))) as ex:
                list(ex.map(_fetch_cc, unique_ips))

    result = []
    for link, host in zip(links, hosts):
        if fast:
            cc = ""
        else:
            ip = host_to_ip.get(host or "", "")
            cc = geo_cache.get(ip, "")
        flag = country_code_to_flag(cc)
        result.append(f"{link}#{flag}{get_auto_comment()}")

    out = Path(output_path)
    out.write_text("\n".join(result) + ("\n" if result else ""), encoding="utf-8")
    print(f"strip_comments: {len(lines_in)} in → {len(result)} out → {out}")
    return len(result)


def main():
    parser = argparse.ArgumentParser(description="Strip & re-add GeoIP comments to proxy configs")
    parser.add_argument("input", help="Input file")
    parser.add_argument("-o", "--output", default=None, help="Output file (default: overwrite input)")
    parser.add_argument("--fast", action="store_true", help="Skip GeoIP lookup, just strip comments")
    args = parser.parse_args()

    output = args.output or args.input
    n = process_file(args.input, output, fast=args.fast or FAST_MODE)
    sys.exit(0 if n > 0 else 1)


if __name__ == "__main__":
    main()
