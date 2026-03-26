#!/usr/bin/env python3
"""
Proxy collector + pre-filter:
- Собирает прокси из sources.json (glob/ru/speed/us/mtproto категории)
- Добавляет конфиги из sources_tg/ (scraped Telegram channels)
- Все протоколы (vless/vmess/ss/trojan/hysteria2/tuic) → input_proxies.txt для xray E2E
- MTProto → mtproto_input.txt для отдельной проверки
- tcp_live_proxies.txt больше не создаётся (TCP ping убран — давал 98% ложных срабатываний)
"""
import asyncio
import base64
import glob
import json
import os
import sys

import aiohttp

TIMEOUT = 15
CONCURRENCY = 50

SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://")
MTPROTO_SCHEMES = ("tg://proxy", "tg://socks", "https://t.me/proxy", "https://t.me/socks",
                   "http://t.me/proxy", "http://t.me/socks")


def decode_subscription(text: str) -> str:
    """Декодирует base64-подписку если нужно."""
    stripped = text.strip()
    for s in SCHEMES:
        if s in stripped:
            return stripped
    try:
        decoded = base64.b64decode(stripped + "==").decode("utf-8", errors="replace")
        if any(s in decoded for s in SCHEMES):
            return decoded
    except Exception:
        pass
    return stripped


async def fetch(session, url):
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=TIMEOUT)) as r:
            if r.status == 200:
                text = await r.text(errors="replace")
                return decode_subscription(text)
    except Exception as e:
        print(f"  WARN fetch {url}: {e}")
    return ""


async def collect_proxies():
    with open("sources.json") as f:
        sources = json.load(f)

    proxy_urls = []
    mtproto_urls = []

    for cat, cat_urls in sources.items():
        for u in cat_urls:
            if not u.startswith("http"):
                continue
            if cat == "mtproto":
                mtproto_urls.append(u)
            else:
                proxy_urls.append(u)

    print(f"Fetching {len(proxy_urls)} proxy source URLs + {len(mtproto_urls)} MTProto URLs...")

    connector = aiohttp.TCPConnector(limit=CONCURRENCY)
    async with aiohttp.ClientSession(connector=connector) as session:
        proxy_results = await asyncio.gather(*[fetch(session, u) for u in proxy_urls])
        mtproto_results = await asyncio.gather(*[fetch(session, u) for u in mtproto_urls])

    proxies, seen = [], set()
    for content in proxy_results:
        for line in content.splitlines():
            line = line.strip()
            if any(line.lower().startswith(s) for s in SCHEMES):
                base = line.split("#")[0].strip()
                if base not in seen:
                    seen.add(base)
                    proxies.append(line)

    mtproto, seen_mt = [], set()
    for content in mtproto_results:
        for line in content.splitlines():
            line = line.strip()
            if any(line.lower().startswith(s) for s in MTPROTO_SCHEMES):
                if line not in seen_mt:
                    seen_mt.add(line)
                    mtproto.append(line)

    print(f"Total unique proxies: {len(proxies)}, MTProto: {len(mtproto)}")
    return proxies, mtproto


def add_tg_sources(proxies: list, seen: set) -> list:
    """Добавляет конфиги из sources_tg/*.txt (scraped Telegram channels)."""
    added = 0
    for fname in glob.glob("sources_tg/*.txt"):
        try:
            with open(fname) as f:
                for line in f:
                    line = line.strip()
                    if line and any(line.lower().startswith(s) for s in SCHEMES):
                        base = line.split("#")[0].strip()
                        if base not in seen:
                            seen.add(base)
                            proxies.append(line)
                            added += 1
        except Exception as e:
            print(f"  WARN reading {fname}: {e}")
    print(f"Added {added} proxies from TG channel files")
    return proxies


async def main():
    os.makedirs("sources", exist_ok=True)

    proxies, mtproto = await collect_proxies()

    seen_bases = {p.split("#")[0].strip() for p in proxies}
    proxies = add_tg_sources(proxies, seen_bases)

    if not proxies:
        print("No proxies found!")
        sys.exit(1)

    print("\nProtocol breakdown:")
    for proto in ["vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "tuic"]:
        count = sum(1 for p in proxies if p.lower().startswith(f"{proto}://"))
        if count:
            print(f"  {proto}: {count}")

    with open("input_proxies.txt", "w") as f:
        f.write("\n".join(proxies))
    print(f"\nWrote {len(proxies)} proxies to input_proxies.txt (all → xray E2E check)")

    if mtproto:
        with open("mtproto_input.txt", "w") as f:
            f.write("\n".join(mtproto))
        print(f"Wrote {len(mtproto)} MTProto proxies to mtproto_input.txt")

    if os.path.exists("tcp_live_proxies.txt"):
        with open("tcp_live_proxies.txt", "w") as f:
            f.write("# TCP ping removed — all proxies now checked via xray E2E\n")


asyncio.run(main())
