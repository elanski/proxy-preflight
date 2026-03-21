#!/usr/bin/env python3
"""Send proxy preflight results to Telegram."""
import os
import requests
import datetime

BOT_TOKEN = os.environ["TG_BOT_TOKEN"]
CHAT_ID = os.environ["TG_CHAT_ID"]
OUTPUT_FILE = os.environ.get("OUTPUT_FILE", "proxies_live.txt")


def read_results():
    live = []
    total = 0
    updated = ""
    try:
        with open(OUTPUT_FILE) as f:
            for line in f:
                line = line.strip()
                if line.startswith("# Proxy preflight"):
                    # "# Proxy preflight — 123 live / 4567 total"
                    import re
                    m = re.search(r"(\d+) live / (\d+) total", line)
                    if m:
                        total = int(m.group(2))
                elif line.startswith("# Updated:"):
                    updated = line.replace("# Updated:", "").strip()
                elif line and not line.startswith("#"):
                    live.append(line)
    except FileNotFoundError:
        pass
    return live, total, updated


def send_message(text):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    r = requests.post(url, json={
        "chat_id": CHAT_ID,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    })
    r.raise_for_status()


def main():
    live, total, updated = read_results()
    count = len(live)

    if count == 0:
        send_message(f"❌ <b>Proxy Preflight</b>\nНет живых прокси\n🕐 {updated or 'unknown'}")
        return

    # Отправляем статистику + первые 20 для примера
    proto_counts = {}
    for url in live:
        proto = url.split("://")[0].lower() if "://" in url else "unknown"
        proto_counts[proto] = proto_counts.get(proto, 0) + 1

    proto_str = " | ".join(f"{k}: {v}" for k, v in sorted(proto_counts.items()))
    
    msg = (
        f"✅ <b>Proxy Preflight — {count} live / {total} total</b>\n"
        f"🕐 {updated}\n"
        f"📊 {proto_str}\n\n"
        f"<i>Список сохранён в репо, роутер подтянет при следующей проверке</i>"
    )
    send_message(msg)
    print(f"Sent summary: {count} live proxies")


if __name__ == "__main__":
    main()
