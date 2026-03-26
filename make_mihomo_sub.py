#!/usr/bin/env python3
"""
Собирает прокси из WhitePrime/xraycheck/configs и генерирует:
1. sub.txt — base64-подписка (для mihomo/clash/v2rayNG)
2. sub_ru.txt — только RU прокси (white-list_available) в base64
3. proxies_raw.txt — сырые прокси (один на строку)
"""
import urllib.request
import base64
import datetime
import os

SOURCES_ALL = [
    # Отсортированные по скорости (приоритет)
    "https://raw.githubusercontent.com/WhitePrime/xraycheck/main/configs/available_st",
    # RU прокси
    "https://raw.githubusercontent.com/WhitePrime/xraycheck/main/configs/white-list_available",
    # Все живые
    "https://raw.githubusercontent.com/WhitePrime/xraycheck/main/configs/available",
]

SOURCES_RU = [
    "https://raw.githubusercontent.com/WhitePrime/xraycheck/main/configs/white-list_available",
]

SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "hysteria2://", "hy2://", "tuic://")


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.read().decode("utf-8", errors="replace")


def collect(sources):
    proxies, seen = [], set()
    for url in sources:
        try:
            content = fetch(url)
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                base = line.split("#")[0].strip()
                if base not in seen and any(base.lower().startswith(s) for s in SCHEMES):
                    seen.add(base)
                    proxies.append(line)
        except Exception as e:
            print(f"WARN {url}: {e}")
    return proxies


def to_base64_sub(proxies):
    content = "\n".join(proxies)
    return base64.b64encode(content.encode("utf-8")).decode("utf-8")


def main():
    now = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    os.makedirs("configs", exist_ok=True)

    # All proxies
    print("Collecting all proxies...")
    all_proxies = collect(SOURCES_ALL)
    print(f"Total: {len(all_proxies)} unique proxies")
    for proto in ["vless", "vmess", "trojan", "ss", "hysteria2", "hy2", "tuic"]:
        c = sum(1 for p in all_proxies if p.lower().startswith(f"{proto}://"))
        if c:
            print(f"  {proto}: {c}")

    # RU proxies
    print("\nCollecting RU proxies...")
    ru_proxies = collect(SOURCES_RU)
    print(f"RU: {len(ru_proxies)} proxies")

    # Write raw
    with open("configs/proxies_raw.txt", "w") as f:
        f.write(f"# xraycheck proxies — {len(all_proxies)} live | {now}\n")
        for p in all_proxies:
            f.write(p + "\n")
    print(f"\nWrote configs/proxies_raw.txt ({len(all_proxies)} proxies)")

    # Write base64 sub (all)
    sub = to_base64_sub(all_proxies)
    with open("configs/sub.txt", "w") as f:
        f.write(sub)
    print(f"Wrote configs/sub.txt (base64, {len(all_proxies)} proxies)")

    # Write base64 sub (RU)
    if ru_proxies:
        sub_ru = to_base64_sub(ru_proxies)
        with open("configs/sub_ru.txt", "w") as f:
            f.write(sub_ru)
        print(f"Wrote configs/sub_ru.txt (base64 RU, {len(ru_proxies)} proxies)")

    print(f"\nDone! Updated: {now}")
    print("\nSubscription URLs (after push to GitHub):")
    print("  All: https://raw.githubusercontent.com/elanski/proxy-preflight/main/configs/sub.txt")
    print("  RU:  https://raw.githubusercontent.com/elanski/proxy-preflight/main/configs/sub_ru.txt")
    print("  Raw: https://raw.githubusercontent.com/elanski/proxy-preflight/main/configs/proxies_raw.txt")


if __name__ == "__main__":
    main()
