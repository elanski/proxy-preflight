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
from urllib.parse import parse_qsl, quote, unquote, urlencode, urlsplit

SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "ssr://", "hysteria2://", "hy2://")
URI_RE = re.compile(r"(?:vless|vmess|trojan|ss|ssr|hysteria2|hy2)://[^\s\"'<>\[\]()]+", re.I)
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


@dataclass
class ParsedNode:
    uri: str
    outbound: dict[str, Any]
    name: str = ""
    category: str = "other"
    source: str = ""  # URL подписки, откуда взят узел (для статистики живых/мёртвых)
    tags: list[str] = field(default_factory=list)


def find_uris(text: str) -> list[str]:
    """Достаёт все URI прокси из произвольного текста (список/подписка)."""
    return [m.group(0).rstrip(".,;|)") for m in URI_RE.finditer(text)]


# --- Xray/v2rayN JSON-подписки (мультиконфиг Happ, Remnawave) ---------------
# Часть панелей отдаёт не список URI, а массив Xray-конфигов: в каждом
# "remarks" = название группы и "outbounds" = узлы. Без этого разбора такие
# подписки выглядят пустыми (find_uris не находит ни одной ссылки).

_DEAD_PROTOCOLS = ("freedom", "blackhole", "direct", "block", "dns",
                   "selector", "urltest", "loadbalance")


def _xray_stream(ss: dict[str, Any]) -> dict[str, str]:
    """streamSettings Xray -> параметры URI (те же имена, что в ссылках)."""
    net = (ss.get("network") or "tcp").lower()
    q: dict[str, str] = {}
    if net in ("raw", "tcp"):
        q["type"] = "tcp"
        header = (ss.get("tcpSettings") or {}).get("header") or {}
        if (header.get("type") or "").lower() == "http":
            q["type"] = "http"
            req = header.get("request") or {}
            path = req.get("path")
            if path:
                q["path"] = ",".join(path) if isinstance(path, list) else str(path)
            host = (req.get("headers") or {}).get("Host")
            if host:
                q["host"] = ",".join(host) if isinstance(host, list) else str(host)
    elif net == "ws":
        ws = ss.get("wsSettings") or {}
        q["type"] = "ws"
        q["path"] = ws.get("path") or "/"
        host = (ws.get("headers") or {}).get("Host")
        if host:
            q["host"] = str(host)
    elif net in ("grpc", "gun"):
        g = ss.get("grpcSettings") or {}
        q["type"] = "grpc"
        q["serviceName"] = str(g.get("serviceName") or "")
        if g.get("multiMode"):
            q["mode"] = "multi"
    elif net == "xhttp":
        x = ss.get("xhttpSettings") or {}
        q["type"] = "xhttp"
        q["path"] = str(x.get("path") or "/")
        if x.get("host"):
            q["host"] = str(x["host"])
        if x.get("mode"):
            q["mode"] = str(x["mode"])
    elif net == "httpupgrade":
        h = ss.get("httpupgradeSettings") or {}
        q["type"] = "httpupgrade"
        q["path"] = str(h.get("path") or "/")
        if h.get("host"):
            q["host"] = str(h["host"])
    else:
        q["type"] = net
    security = (ss.get("security") or "none").lower()
    if security == "reality":
        rs = ss.get("realitySettings") or {}
        q["security"] = "reality"
        for src, dst in (("serverName", "sni"), ("fingerprint", "fp"),
                         ("publicKey", "pbk"), ("shortId", "sid"), ("spiderX", "spx")):
            if rs.get(src):
                q[dst] = str(rs[src])
    elif security == "tls":
        ts = ss.get("tlsSettings") or {}
        q["security"] = "tls"
        if ts.get("serverName"):
            q["sni"] = str(ts["serverName"])
        if ts.get("fingerprint"):
            q["fp"] = str(ts["fingerprint"])
        if ts.get("alpn"):
            q["alpn"] = ",".join(str(a) for a in ts["alpn"])
    else:
        q["security"] = "none"
    return q


def xray_outbound_uri(ob: dict[str, Any]) -> str | None:
    """Один outbound Xray -> URI прокси (None, если узел не поддержан)."""
    proto = str(ob.get("protocol") or ob.get("type") or "").lower()
    if not proto or proto in _DEAD_PROTOCOLS:
        return None
    st = ob.get("settings") or {}
    ss = ob.get("streamSettings") or {}
    tag = str(ob.get("tag") or "")
    frag = "#" + quote(tag, safe="") if tag else ""
    if proto == "vless":
        v = (st.get("vnext") or [{}])[0] or {}
        u = (v.get("users") or [{}])[0] or {}
        uid = str(u.get("id") or "")
        addr = v.get("address")
        if not (addr and UUID_RE.match(uid)):
            return None
        q = {"encryption": str(u.get("encryption") or "none")}
        if u.get("flow"):
            q["flow"] = str(u["flow"])
        q.update(_xray_stream(ss))
        return f"vless://{uid}@{addr}:{v.get('port') or 443}?{urlencode(q)}{frag}"
    if proto == "trojan":
        s = (st.get("servers") or [{}])[0] or {}
        addr, pw = s.get("address"), s.get("password")
        if not (addr and pw):
            return None
        q = _xray_stream(ss)
        if q.get("security") == "none":
            q["security"] = "tls"  # trojan без TLS нерабочий
        return f"trojan://{quote(str(pw), safe='')}@{addr}:{s.get('port') or 443}?{urlencode(q)}{frag}"
    if proto in ("hysteria", "hysteria2"):
        hs = ss.get("hysteriaSettings") or {}
        addr = st.get("address")
        auth = hs.get("auth") or st.get("auth") or ""
        if not (addr and auth):
            return None
        ts = ss.get("tlsSettings") or {}
        q = {"sni": str(ts.get("serverName") or addr), "insecure": "1"}
        alpn = ts.get("alpn") or ["h3"]
        q["alpn"] = ",".join(str(a) for a in alpn)
        return f"hysteria2://{quote(str(auth), safe='')}@{addr}:{st.get('port') or 443}/?{urlencode(q)}{frag}"
    if proto == "shadowsocks":
        s = (st.get("servers") or [{}])[0] or {}
        addr, method, pw = s.get("address"), s.get("method"), s.get("password")
        if not (addr and method and pw):
            return None
        userinfo = base64.urlsafe_b64encode(f"{method}:{pw}".encode()).decode().rstrip("=")
        return f"ss://{userinfo}@{addr}:{s.get('port') or 443}{frag}"
    return None


def xray_json_uris(text: str) -> list[str]:
    """Xray-JSON (один конфиг или массив конфигов) -> список URI узлов."""
    stripped = text.strip()
    if not stripped or stripped[0] not in "[{":
        return []
    try:
        data = json.loads(stripped)
    except json.JSONDecodeError:
        return []
    configs = data if isinstance(data, list) else [data]
    uris: list[str] = []
    for cfg in configs:
        if not isinstance(cfg, dict):
            continue
        for ob in cfg.get("outbounds") or []:
            if isinstance(ob, dict):
                uri = xray_outbound_uri(ob)
                if uri:
                    uris.append(uri)
    return uris


def extract_uris(content: bytes) -> list[str]:
    """Универсальный разбор подписки: URI-список, base64 или Xray-JSON."""
    text = decode_subscription(content)
    uris = find_uris(text)
    if uris:
        return uris
    return xray_json_uris(text)


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


def parse_uri(uri: str, category: str = "other", source: str = "") -> ParsedNode | None:
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
        if flow == "xtls-rprx-vision" and tls:
            # VISION живёт только на TCP-транспорте, но с Reality он работает
            # штатно (самая частая современная связка) — flow сохраняем и там,
            # иначе сервер с flow=xtls-rprx-vision не пустит клиента.
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
    return ParsedNode(uri=uri, outbound=out, name=name, category=category, source=source)
