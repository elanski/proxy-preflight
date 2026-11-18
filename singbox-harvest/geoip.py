"""Геолокация exit_ip. Страна определяется ТОЛЬКО по измеренному exit_ip,
никогда по имени узла или гео сервера (cm. proxy-pool-operations §7).

ip-api.com free tier работает ТОЛЬКО по HTTP (HTTPS отдаёт status=fail).
Резерв — ipinfo.io, если ip-api недоступен/отдает fail.
"""
from __future__ import annotations

import json
from pathlib import Path
from urllib.request import Request, urlopen

IPAPI_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,query"
IPINFO_URL = "https://ipinfo.io/{ip}/json"
RU_CODES = {"RU", "RF"}
# CIDR-лист из этого же репозитория (30k сетей) — запасной сигнал для RU,
# когда публичный GeoIP отдаёт 'null' (см. cidrlist / filter_cidr.py).
CIDR_PATH = Path(__file__).resolve().parents[1] / "cidrlist"
_cidr_cache: list | None = None


def _load_ru_cidrs() -> list:
    global _cidr_cache
    if _cidr_cache is not None:
        return _cidr_cache
    import ipaddress
    nets = []
    if CIDR_PATH.exists():
        for line in CIDR_PATH.read_text(encoding="utf-8", errors="replace").splitlines():
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            try:
                nets.append(ipaddress.ip_network(s, strict=False))
            except ValueError:
                continue
    _cidr_cache = nets
    return nets


def is_ru_ip(ip: str, code: str = "") -> bool:
    """RU по measured exit: сначала код (из xray-knife/GeoIP), потом CIDR-лист."""
    if code and is_ru(code):
        return True
    if not ip:
        return False
    # если код есть и он НЕ RU — доверяем GeoIP, CIDR не нужен
    if code and not is_ru(code):
        return False
    # кода нет (xray-knife 'null') — проверить локальный CIDR-лист репозитория
    import ipaddress
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _load_ru_cidrs())


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


def code_from_xrayknife(location: str) -> str:
    """xray-knife пишет код страны в location, но для неизвестной пишет строку 'null'.
    Без этого 'null' превращалось в 'NU' (Ниуэ) и попадало в other-списки."""
    raw = (location or "").strip()
    if not raw or raw.lower() in ("null", "none", "n/a", "-"):
        return ""
    if len(raw) == 2 and raw.isalpha():
        return raw.upper()
    return ""  # полное имя страны не считаем кодом


def is_ru(code: str) -> bool:
    return (code or "").upper() in RU_CODES
