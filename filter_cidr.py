#!/usr/bin/env python3
"""
Фильтрует прокси из input файла:
- Если endpoint — literal IP: проверяет попадание в CIDR из cidrlist
- Если endpoint — домен: пропускает (не DNS-резолвит, слишком долго)
- Результат записывает в output файл

Использование:
  python filter_cidr.py input_proxies.txt proxies_ru.txt --cidrlist cidrlist
"""
from __future__ import annotations

import argparse
import ipaddress
import os
import socket
import sys
from urllib.parse import urlparse


def load_cidr_networks(path: str) -> list:
    nets = []
    if not path or not os.path.isfile(path):
        print(f"[warn] cidrlist not found: {path}", file=sys.stderr)
        return nets
    with open(path, encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            try:
                nets.append(ipaddress.ip_network(s, strict=False))
            except ValueError:
                continue
    return nets


def _resolve_endpoint_ips(address: str) -> list:
    if not address:
        return []
    literal = address.strip().strip("[]")
    try:
        return [ipaddress.ip_address(literal)]
    except ValueError:
        pass
    old_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(3.0)
    try:
        infos = socket.getaddrinfo(literal, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except OSError:
        return []
    finally:
        socket.setdefaulttimeout(old_timeout)
    seen: set[str] = set()
    result = []
    for info in infos:
        ip_str = info[4][0]
        if ip_str in seen:
            continue
        try:
            result.append(ipaddress.ip_address(ip_str))
            seen.add(ip_str)
        except ValueError:
            continue
    return result


def _ip_in_networks(ip, networks: list) -> bool:
    for net in networks:
        if ip.version == net.version and ip in net:
            return True
    return False


def parse_address(line: str) -> str | None:
    try:
        url = line.split("#")[0].strip()
        return urlparse(url).hostname
    except Exception:
        return None


def filter_proxies(lines: list[str], networks: list) -> tuple[list[str], int, int]:
    kept, dropped = [], 0
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            kept.append(line)
            continue
        host = parse_address(stripped)
        if not host:
            kept.append(line)
            continue
        try:
            ipaddress.ip_address(host.strip("[]"))
            is_literal = True
        except ValueError:
            is_literal = False

        if not is_literal:
            # Доменные прокси — оставляем без фильтрации
            kept.append(line)
            continue

        ips = _resolve_endpoint_ips(host)
        if not ips:
            dropped += 1
            continue
        if any(_ip_in_networks(ip, networks) for ip in ips):
            kept.append(line)
        else:
            dropped += 1
    kept_count = len([l for l in kept if l.strip() and not l.strip().startswith("#")])
    return kept, kept_count, dropped


def main():
    parser = argparse.ArgumentParser(description="Фильтр прокси по CIDR whitelist")
    parser.add_argument("infile", help="Входной файл с прокси")
    parser.add_argument("outfile", help="Выходной файл (отфильтрованные)")
    parser.add_argument("--cidrlist", default="cidrlist", help="Файл с CIDR (по умолчанию: cidrlist)")
    args = parser.parse_args()

    networks = load_cidr_networks(args.cidrlist)
    if not networks:
        print("ERROR: no CIDR networks loaded, aborting", file=sys.stderr)
        sys.exit(1)
    print(f"Loaded {len(networks)} CIDR networks from {args.cidrlist}")

    with open(args.infile, encoding="utf-8") as f:
        lines = f.readlines()

    kept_lines, kept_count, dropped = filter_proxies(lines, networks)

    with open(args.outfile, "w", encoding="utf-8") as f:
        f.writelines(kept_lines)

    print(f"filter_cidr: kept {kept_count}, dropped {dropped} → {args.outfile}")


if __name__ == "__main__":
    main()
