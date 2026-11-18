"""Геолокация exit_ip. Страна определяется ТОЛЬКО по измеренному exit_ip,
никогда по имени узла или гео сервера (cm. proxy-pool-operations §7).

ip-api.com free tier работает ТОЛЬКО по HTTP (HTTPS отдаёт status=fail).
Резерв — ipinfo.io, если ip-api недоступен/отдает fail.
"""
from __future__ import annotations

import json
from urllib.request import Request, urlopen

IPAPI_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,query"
IPINFO_URL = "https://ipinfo.io/{ip}/json"
RU_CODES = {"RU", "RF"}


def lookup(ip: str, timeout: float = 8.0) -> dict:
    # ip-api.com — HTTP only на бесплатном тарифе.
    try:
        req = Request(IPAPI_URL.format(ip=ip), headers={"User-Agent": "singbox-harvest"})
        with urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8"))
        if data.get("status") == "success":
            return {"ip": ip, "country": data.get("country", ""),
                    "code": data.get("countryCode", "")}
    except Exception:
        pass
    # Резерв: ipinfo.io (HTTPS).
    try:
        req = Request(IPINFO_URL.format(ip=ip), headers={"User-Agent": "singbox-harvest"})
        with urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode("utf-8"))
        cc = (data.get("country") or "").upper()
        if cc:
            return {"ip": ip, "country": data.get("country", ""), "code": cc}
    except Exception:
        pass
    return {"ip": ip, "country": "", "code": ""}


def is_ru(code: str) -> bool:
    return (code or "").upper() in RU_CODES
