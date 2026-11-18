"""Парсер URI прокси в формат outbound'ов sing-box.

Поддерживаемые схемы: vless://, vmess://, trojan://, ss://, ssr://,
hysteria2:// / hy2://. Возвращаемый outbound — dict для поля outbounds
конфига sing-box. Невалидные/неподдерживаемые узлы отбрасываются с причиной.
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qsl, unquote, urlsplit

SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "ssr://", "hysteria2://", "hy2://")
URI_RE = re.compile(r"(?:vless|vmess|trojan|ss|ssr|hysteria2|hy2)://[^\s\"'<>\[\]()]+", re.I)
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


@dataclass
class ParsedNode:
    uri: str
    outbound: dict[str, Any]
    name: str = ""
    category: str = "other"
    tags: list[str] = field(default_factory=list)


def find_uris(text: str) -> list[str]:
    """Достаёт все URI прокси из произвольного текста (список/подписка)."""
    return [m.group(0).rstrip(".,;|)") for m in URI_RE.finditer(text)]


def decode_subscription(content: bytes) -> str:
    """Декодирует base64-подписку или возвращает текст как есть."""
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        text = content.decode("utf-8", errors="replace")
    stripped = text.strip()
    if not stripped:
        return text
    # Если уже есть URI — это плоский список, не(base64
    if any(s in stripped for s in SCHEMES):
        return text
    # Попробовать base64 (с паддингом и без), в т.ч. urlsafe
    compact = re.sub(r"\s+", "", stripped)
    for candidate in (compact, compact + "=" * (-len(compact) % 4)):
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                decoded = decoder(candidate) if decoder is base64.urlsafe_b64decode else base64.b64decode(candidate, validate=False)
                out = decoded.decode("utf-8", errors="strict")
                if any(s in out for s in SCHEMES) or "\n" in out:
                    return out
            except (binascii.Error, ValueError, UnicodeDecodeError):
                continue
    return text


def _unescape_qs(query: str) -> dict[str, str]:
    """parse_qs, который снимает HTML-экранирование &amp; ДО разбора.

    Иначе pbk/sid у Reality-узлов теряются (cm. proxy-pool-operations §12).
    """
    fixed = query.replace("&amp;", "&").replace("&#38;", "&")
    result: dict[str, str] = {}
    for key, value in parse_qsl(fixed, keep_blank_values=True):
        # Дубликаты возможны после снятия &amp;-экранирования: держим ПЕРВЫЙ,
        # он соответствует настоящему параметру ссылки.
        result.setdefault(key, value)
    return result


def _transport(q: dict[str, str], host_header: str = "") -> dict[str, Any] | None:
    net_type = (q.get("type") or "tcp").lower()
    if net_type in ("raw", "tcp", ""):
        return None
    if net_type == "ws":
        tr: dict[str, Any] = {"type": "ws"}
        path = q.get("path", "/")
        tr["path"] = unquote(path)
        headers = {}
        host = q.get("host") or host_header
        if host:
            headers["Host"] = host
        if headers:
            tr["headers"] = headers
        return tr
    if net_type in ("grpc", "gun"):
        tr = {"type": "grpc", "service_name": unquote(q.get("serviceName", "") or q.get("path", "") or "GunService")}
        return tr
    if net_type == "httpupgrade":
        tr = {"type": "httpupgrade", "path": unquote(q.get("path", "/"))}
        host = q.get("host") or host_header
        if host:
            tr["host"] = host
        return tr
    if net_type == "h2":
        tr = {"type": "http", "path": unquote(q.get("path", "/")), "method": "GET"}
        host = q.get("host") or host_header
        if host:
            tr["headers"] = {"Host": host}
        return tr
    if net_type == "xhttp":
        # sing-box 1.14 поддерживает xhttp; stream-up — режим по умолчанию.
        tr = {"type": "xhttp", "path": unquote(q.get("path", "/"))}
        host = q.get("host") or host_header
        if host:
            tr["host"] = host
        return tr
    return None


def _tls(q: dict[str, str], server: str, sni: str = "") -> dict[str, Any] | None:
    security = (q.get("security") or "tls").lower()
    if security in ("none", ""):
        return None
    if security not in ("tls", "reality"):
        return None
    tls: dict[str, Any] = {
        "enabled": True,
        "server_name": sni or q.get("sni") or server,
        "insecure": True,
    }
    fp = q.get("fp")
    if fp:
        tls["utls"] = {"enabled": True, "fingerprint": fp}
    if security == "reality":
        pbk = q.get("pbk") or ""
        if not pbk:
            # Reality без public_key — битый узел; его нельзя отдавать ядру.
            return None
        reality: dict[str, Any] = {"enabled": True, "public_key": pbk}
        sid = q.get("sid") or ""
        # short_id может быть списком через запятую — берём первый валидный.
        if sid:
            first = sid.split(",")[0].strip()
            if re.fullmatch(r"[0-9a-fA-F]{1,16}", first) and len(first) % 2 == 0:
                reality["short_id"] = first
        tls["reality"] = reality
        if "utls" not in tls:
            # Reality требует uTLS (проверено sing-box check).
            tls["utls"] = {"enabled": True, "fingerprint": "chrome"}
    return tls


def _finalize(out: dict[str, Any], q: dict[str, str], name: str) -> dict[str, Any] | None:
    tr = _transport(q, host_header=q.get("host", "") or q.get("authority", ""))
    if tr:
        out["transport"] = tr
    return out


def parse_uri(uri: str, category: str = "other") -> ParsedNode | None:
    """Разбирает одиночный URI в ParsedNode или None, если узел не годен."""
    uri = uri.strip()
    try:
        parts = urlsplit(uri)
    except ValueError:
        return None
    scheme = parts.scheme.lower()
    if scheme not in ("vless", "vmess", "trojan", "ss", "ssr", "hysteria2", "hy2"):
        return None
    name = unquote(parts.fragment or "") or ""
    q = _unescape_qs(parts.query)
    host = parts.hostname or ""
    try:
        port = int(parts.port or 0)
    except ValueError:
        return None
    if not host or not (1 <= port <= 65535):
        return None

    out: dict[str, Any] | None = None
    if scheme == "vless":
        uuid = unquote(parts.username or "")
        if not UUID_RE.match(uuid):
            return None
        out = {"type": "vless", "server": host, "server_port": port, "uuid": uuid}
        # Reality без public_key — битый узел: _tls() вернёт None, отбраковываем.
        if (q.get("security") or "").lower() == "reality" and not (q.get("pbk") or ""):
            return None
        tls = _tls(q, host)
        if tls:
            out["tls"] = tls
        flow = (q.get("flow") or "").lower()
        if flow == "xtls-rprx-vision" and tls and "reality" not in tls:
            # VISION требует TCP transport; с ws/grpc несовместим.
            if (q.get("type") or "tcp").lower() in ("tcp", "raw", ""):
                out["flow"] = flow
        out = _finalize(out, q, name)
    elif scheme == "vmess":
        raw = parts.netloc.split("@")[0]
        try:
            padded = raw + "=" * (-len(raw) % 4)
            data = json.loads(base64.b64decode(padded, validate=False).decode("utf-8"))
        except (ValueError, json.JSONDecodeError, binascii.Error):
            return None
        uuid = data.get("id", "")
        if not UUID_RE.match(uuid):
            return None
        aid = data.get("aid", 0)
        try:
            aid = int(aid)
        except (ValueError, TypeError):
            aid = 0
        out = {"type": "vmess", "server": data.get("add") or host,
               "server_port": int(data.get("port") or port), "uuid": uuid,
               "alter_id": aid, "security": data.get("scy") or "auto"}
        net = (data.get("net") or "tcp").lower()
        fake_q = dict(q)
        if not fake_q.get("type"):
            fake_q["type"] = net
        for src, dst in (("path", "path"), ("host", "host")):
            if data.get(src) and not fake_q.get(dst):
                fake_q[dst] = data[src]
        tls_security = "none" if data.get("tls") in (None, "", "none") else "tls"
        fake_q.setdefault("security", tls_security)
        if data.get("sni"):
            fake_q["sni"] = data["sni"]
        tls = _tls(fake_q, host)
        if tls:
            out["tls"] = tls
        out = _finalize(out, fake_q, name)
    elif scheme == "trojan":
        password = unquote(parts.username or "")
        if not password:
            return None
        out = {"type": "trojan", "server": host, "server_port": port, "password": password}
        tls = _tls(q, host)
        if tls:
            out["tls"] = tls
        else:
            # Trojan без TLS бессмысленен и sing-box не примет.
            out["tls"] = {"enabled": True, "server_name": q.get("sni") or host, "insecure": True}
        out = _finalize(out, q, name)
    elif scheme == "ss":
        #要么 userinfo=base64(method:password), либо plugin.
        raw = parts.username or ""
        password = ""
        method = ""
        try:
            padded = unquote(raw) + "=" * (-len(unquote(raw)) % 4)
            decoded = base64.b64decode(padded, validate=False).decode("utf-8")
            if ":" in decoded:
                method, password = decoded.split(":", 1)
        except (ValueError, UnicodeDecodeError, binascii.Error):
            pass
        if not (method and password):
            try:
                decoded = base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8")
                if ":" in decoded:
                    method, password = decoded.split(":", 1)
            except (ValueError, UnicodeDecodeError, binascii.Error):
                pass
        if not (method and password):
            return None
        out = {"type": "shadowsocks", "server": host, "server_port": port,
               "method": method.lower(), "password": password}
        plugin = q.get("plugin", "")
        if plugin.startswith("obfs-local") or plugin.startswith("v2ray-plugin"):
            # sing-box не умеет эти плагины — такой узел не годен.
            return None
    elif scheme in ("hysteria2", "hy2"):
        password = unquote(parts.username or "")
        if not password:
            return None
        out = {"type": "hysteria2", "server": host, "server_port": port, "password": password}
        tls = _tls(q, host)
        if tls:
            out["tls"] = tls
        else:
            out["tls"] = {"enabled": True, "server_name": q.get("sni") or host, "insecure": True}
        if q.get("upmbps") or q.get("downmbps"):
            out["up_mbps"] = int(q.get("upmbps") or 0) or None
            out["down_mbps"] = int(q.get("downmbps") or 0) or None
            out = {k: v for k, v in out.items() if v is not None}
    elif scheme == "ssr":
        # SSR не поддерживается sing-box нативно — пропускаем.
        return None

    if out is None:
        return None
    return ParsedNode(uri=uri, outbound=out, name=name, category=category)
