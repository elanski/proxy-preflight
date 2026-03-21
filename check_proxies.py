#!/usr/bin/env python3
"""
Pre-filter SS/VLESS/VMess/Trojan/Hysteria2 proxies via TCP connect check.
Downloads sources from sources.json, checks TCP connectivity, saves live proxies.
"""
import asyncio
import base64
import json
import os
import re
import sys
import urllib.parse
import datetime
import aiohttp

TIMEOUT = float(os.environ.get("CHECK_TIMEOUT", "5"))
CONCURRENCY = int(os.environ.get("CHECK_CONCURRENCY", "200"))
SOURCES_URL = os.environ.get(
    "SOURCES_URL",
    "https://raw.githubusercontent.com/elanski/proxy-preflight/main/sources.json"
)
OUTPUT_FILE = os.environ.get("OUTPUT_FILE", "proxies_live.txt")


# ── Parsers ──────────────────────────────────────────────────────────────────

def parse_host_port(url: str):
    """Extract (host, port) from proxy URL. Returns None if can't parse."""
    url = url.strip()
    if not url:
        return None
    low = url.lower()

    try:
        # VLESS, Trojan, Hysteria2, TUIC: scheme://uuid@host:port?...
        if any(low.startswith(p) for p in ["vless://", "trojan://", "hysteria2://", "hy2://", "tuic://"]):
            u = urllib.parse.urlparse(url)
            host = u.hostname
            port = u.port
            if host and port:
                return host, port

        # VMess: vmess://base64(json)
        elif low.startswith("vmess://"):
            b64 = url[8:].split("#")[0].strip()
            # pad
            b64 += "=" * (-len(b64) % 4)
            try:
                data = json.loads(base64.b64decode(b64).decode("utf-8", errors="replace"))
                host = str(data.get("add", "")).strip()
                port = int(data.get("port", 0))
                if host and port:
                    return host, port
            except Exception:
                pass

        # SS: ss://base64@host:port or ss://method:pass@host:port
        elif low.startswith("ss://"):
            body = url[5:].split("#")[0]
            # Try userinfo@host:port format
            if "@" in body:
                host_part = body.rsplit("@", 1)[1].split("?")[0]
                if ":" in host_part:
                    h, p = host_part.rsplit(":", 1)
                    h = h.strip("[]")  # IPv6
                    if h and p.isdigit():
                        return h, int(p)
            else:
                # base64 encoded
                b64 = body.split("?")[0]
                b64 += "=" * (-len(b64) % 4)
                try:
                    decoded = base64.b64decode(b64).decode("utf-8", errors="replace")
                    if "@" in decoded:
                        host_part = decoded.rsplit("@", 1)[1].split("/")[0]
                        if ":" in host_part:
                            h, p = host_part.rsplit(":", 1)
                            if h and p.isdigit():
                                return h, int(p)
                except Exception:
                    pass

    except Exception:
        pass

    return None


def clean_url(url: str) -> str:
    """Strip comments and whitespace."""
    for sep in [" #", "\t#"]:
        if sep in url:
            url = url[:url.index(sep)]
    return url.strip()


def is_proxy_url(url: str) -> bool:
    low = url.lower()
    return any(low.startswith(p) for p in [
        "vless://", "vmess://", "trojan://", "ss://",
        "hysteria2://", "hy2://", "tuic://"
    ])


# ── Source fetching ───────────────────────────────────────────────────────────

async def fetch_url(session: aiohttp.ClientSession, url: str) -> str:
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status == 200:
                return await resp.text(errors="replace")
    except Exception:
        pass
    return ""


async def load_all_sources(sources: dict) -> list:
    """Download all source URLs and collect proxy URLs."""
    all_urls = []
    for cat_urls in sources.values():
        for u in cat_urls:
            if not u.startswith("file://") and not u.startswith("http"):
                continue
            if u.startswith("file://"):
                # skip local files on GitHub Actions
                continue
            all_urls.append(u)

    print(f"Fetching {len(all_urls)} source URLs...")
    proxies = []
    seen = set()

    connector = aiohttp.TCPConnector(limit=50)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [fetch_url(session, u) for u in all_urls]
        results = await asyncio.gather(*tasks)

    for content in results:
        for line in content.splitlines():
            line = clean_url(line)
            if is_proxy_url(line) and line not in seen:
                seen.add(line)
                proxies.append(line)

    print(f"Total unique proxies found: {len(proxies)}")
    return proxies


# ── TCP checker ───────────────────────────────────────────────────────────────

async def tcp_check(host: str, port: int, timeout: float) -> float | None:
    """Try TCP connect. Returns latency in ms or None on failure."""
    try:
        t0 = asyncio.get_event_loop().time()
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout
        )
        ms = (asyncio.get_event_loop().time() - t0) * 1000
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return ms
    except Exception:
        return None


async def check_all(proxies: list) -> list:
    """Check all proxies concurrently. Returns list of (url, ping_ms)."""
    sem = asyncio.Semaphore(CONCURRENCY)
    live = []
    lock = asyncio.Lock()
    checked = [0]

    async def check_one(url):
        hp = parse_host_port(url)
        if not hp:
            return
        host, port = hp
        async with sem:
            ping = await tcp_check(host, port, TIMEOUT)
            async with lock:
                checked[0] += 1
                if checked[0] % 500 == 0:
                    print(f"  Checked {checked[0]}/{len(proxies)}, live so far: {len(live)}")
            if ping is not None:
                async with lock:
                    live.append((url, ping))

    await asyncio.gather(*[check_one(u) for u in proxies])
    return live


# ── Main ──────────────────────────────────────────────────────────────────────

async def main():
    # Load sources.json
    sources_path = "sources.json"
    if not os.path.exists(sources_path):
        print(f"ERROR: {sources_path} not found")
        sys.exit(1)

    with open(sources_path) as f:
        sources = json.load(f)

    # Filter to only non-mtproto categories
    filtered = {k: v for k, v in sources.items() if k != "mtproto"}
    print(f"Categories: {list(filtered.keys())}")

    # Fetch all proxies
    proxies = await load_all_sources(filtered)

    if not proxies:
        print("No proxies found!")
        return

    # TCP check
    print(f"\nChecking {len(proxies)} proxies (timeout={TIMEOUT}s, concurrency={CONCURRENCY})...")
    t_start = asyncio.get_event_loop().time()
    live = await check_all(proxies)
    elapsed = asyncio.get_event_loop().time() - t_start

    # Sort by ping
    live.sort(key=lambda x: x[1])
    print(f"\nDone in {elapsed:.1f}s: {len(live)}/{len(proxies)} live")

    # Save results
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    with open(OUTPUT_FILE, "w") as f:
        f.write(f"# Proxy preflight — {len(live)} live / {len(proxies)} total\n")
        f.write(f"# Updated: {now}\n")
        f.write(f"# TCP check only (timeout={TIMEOUT}s)\n")
        for url, ping in live:
            f.write(f"{url}\n")

    print(f"Saved {len(live)} proxies to {OUTPUT_FILE}")
    return live


if __name__ == "__main__":
    asyncio.run(main())
