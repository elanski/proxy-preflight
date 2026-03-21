#!/usr/bin/env python3
"""Send proxy preflight results to Telegram as a file."""
import os
import requests

BOT_TOKEN = os.environ["TG_BOT_TOKEN"]
CHAT_ID = os.environ["TG_CHAT_ID"]
OUTPUT_FILE = os.environ.get("OUTPUT_FILE", "proxies_live.txt")


def read_stats():
    live, total, updated = 0, 0, ""
    proto_counts = {}
    try:
        with open(OUTPUT_FILE) as f:
            for line in f:
                line = line.strip()
                if line.startswith("# Proxy preflight"):
                    import re
                    m = re.search(r"(\d+) live / (\d+) total", line)
                    if m:
                        live, total = int(m.group(1)), int(m.group(2))
                elif line.startswith("# Updated:"):
                    updated = line.replace("# Updated:", "").strip()
                elif line and not line.startswith("#"):
                    proto = line.split("://")[0].lower() if "://" in line else "unknown"
                    proto_counts[proto] = proto_counts.get(proto, 0) + 1
    except FileNotFoundError:
        pass
    return live, total, updated, proto_counts


def main():
    live, total, updated, proto_counts = read_stats()

    if live == 0:
        requests.post(
            f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
            json={"chat_id": CHAT_ID, "text": f"❌ Proxy Preflight: нет живых прокси\n🕐 {updated or 'unknown'}"}
        )
        return

    proto_str = " | ".join(f"{k}: {v}" for k, v in sorted(proto_counts.items()))
    caption = (
        f"✅ <b>Proxy Preflight — {live} live / {total} total</b>\n"
        f"🕐 {updated}\n"
        f"📊 {proto_str}"
    )

    # Отправляем файл с живыми прокси
    with open(OUTPUT_FILE, "rb") as f:
        r = requests.post(
            f"https://api.telegram.org/bot{BOT_TOKEN}/sendDocument",
            data={"chat_id": CHAT_ID, "caption": caption, "parse_mode": "HTML"},
            files={"document": ("proxies_live.txt", f, "text/plain")},
        )
    r.raise_for_status()
    print(f"Sent file with {live} live proxies")


if __name__ == "__main__":
    main()