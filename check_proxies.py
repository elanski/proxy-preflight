#!/usr/bin/env python3
"""
Wrapper: download sources -> run v2rayChecker.py with xray -> save proxies_live.txt
"""
import asyncio, aiohttp, json, os, sys, subprocess, datetime

TIMEOUT = 15
CONCURRENCY = 50

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

async def main():
    proxies = await collect_proxies()
    if not proxies:
        print("No proxies found!")
        sys.exit(1)

    # Write input file
    with open("input_proxies.txt", "w") as f:
        f.write("\n".join(proxies))
    print(f"Wrote {len(proxies)} proxies to input_proxies.txt")

asyncio.run(main())