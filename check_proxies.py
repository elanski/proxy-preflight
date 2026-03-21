#!/usr/bin/env python3
"""
Two-stage proxy checker:
1. xray (v2rayChecker) for ss/trojan/hysteria2/tuic — full protocol check
2. TCP ping for vless/vmess — checks if port is open (fast, 5s timeout)
"""
import asyncio, aiohttp, json, os, sys, re
from urllib.parse import urlparse, parse_qs, unquote

TIMEOUT = 15
CONCURRENCY = 50
TCP_TIMEOUT = 5
TCP_CONCURRENCY = 200

async def fetch(session, url):
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=TIMEOUT)) as r:
            if r.status == 200:
                return await r.text(errors="replace")
    except Exception as e:
        print(f"  WARN fetch {url}: {e}")
    return ""

async def collect_proxies():
    with open("sources.json") as f:
        sources = json.load(f)
    urls = []
    for cat, cat_urls in sources.items():
        if cat == "mtproto":
            continue
        for u in cat_urls:
            if u.startswith("http"):
                urls.append(u)

    print(f"Fetching {len(urls)} source URLs...")
    proxies, seen = [], set()
    connector = aiohttp.TCPConnector(limit=CONCURRENCY)
    async with aiohttp.ClientSession(connector=connector) as session:
        results = await asyncio.gather(*[fetch(session, u) for u in urls])

    SCHEMES = ("vless://","vmess://","trojan://","ss://","hysteria2://","hy2://","tuic://")
    for content in results:
        for line in content.splitlines():
            line = line.strip()
            if any(line.lower().startswith(s) for s in SCHEMES):
                base = line.split("#")[0].strip()
                if base not in seen:
                    seen.add(base)
                    proxies.append(line)

    print(f"Total unique proxies: {len(proxies)}")
    return proxies

def parse_host_port(url):
    """Extract (host, port) from proxy URL."""
    try:
        url = url.split("#")[0].strip()
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port

        if not host or not port:
            return None, None

        # Skip local/invalid addresses
        if host in ("127.0.0.1", "localhost", "0.0.0.0") or host.startswith("192.168.") or host.startswith("10."):
            return None, None

        return host, port
    except Exception:
        return None, None

async def tcp_check(host, port, sem):
    """Check if TCP port is open."""
    async with sem:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=TCP_TIMEOUT
            )
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return True
        except Exception:
            return False

async def tcp_check_proxies(proxies):
    """TCP ping check for vless/vmess proxies."""
    sem = asyncio.Semaphore(TCP_CONCURRENCY)
    tasks = []
    valid = []

    for url in proxies:
        host, port = parse_host_port(url)
        if host and port:
            tasks.append((url, asyncio.create_task(tcp_check(host, port, sem))))

    live = []
    for url, task in tasks:
        try:
            ok = await task
            if ok:
                live.append(url)
        except Exception:
            pass

    return live

async def main():
    os.makedirs("sources", exist_ok=True)
    proxies = await collect_proxies()

    if not proxies:
        print("No proxies found!")
        sys.exit(1)

    # Разделяем по протоколам
    xray_protos = ("ss://", "trojan://", "hysteria2://", "hy2://", "tuic://")
    tcp_protos = ("vless://", "vmess://")

    xray_proxies = [p for p in proxies if any(p.lower().startswith(s) for s in xray_protos)]
    tcp_proxies = [p for p in proxies if any(p.lower().startswith(s) for s in tcp_protos)]

    print(f"xray check: {len(xray_proxies)} proxies (ss/trojan/hysteria2/tuic)")
    print(f"TCP check:  {len(tcp_proxies)} proxies (vless/vmess)")

    # Записываем xray прокси в input_proxies.txt
    with open("input_proxies.txt", "w") as f:
        f.write("\n".join(xray_proxies))
    print(f"Wrote {len(xray_proxies)} proxies to input_proxies.txt (for xray checker)")

    # TCP проверка vless/vmess
    print(f"\nRunning TCP check for {len(tcp_proxies)} vless/vmess proxies...")
    tcp_live = await tcp_check_proxies(tcp_proxies)
    print(f"TCP live: {len(tcp_live)}/{len(tcp_proxies)}")

    # Сохраняем TCP-живые прокси
    with open("tcp_live_proxies.txt", "w") as f:
        f.write("\n".join(tcp_live))
    print(f"Saved {len(tcp_live)} TCP-live proxies to tcp_live_proxies.txt")

asyncio.run(main())