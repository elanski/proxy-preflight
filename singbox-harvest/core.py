"""Запуск реального ядра (sing-box / Xray) для одного узла и проверка выхода.

Каждый узел поднимается отдельным инстансом ядра на уникальном SOCKS-порту.
Годность подтверждается ТОЛЬКО реальным curl-запросом через поднятый туннель;
exit_ip измеряется обязательно (без него узел не жив — proxy-pool-operations §1).

Уроки из референсов (mrdevmohamed/v2ray-configs, 0xRadikal/Free-v2ray-Configs):
  * probe через curl --socks5-hostname, НЕ urllib+PySocks (последний молча падает);
  * stderr ядра → ФАЙЛ, не pipe (pipe может заполниться и заблокировать ядро);
  * REALITY и XHTTP уходят в Xray — sing-box поднимает их синтаксически, но
    на практике ломается (оба референса подтверждают);
  * порт бронируется под замком, иначе два воркера измеряют чужое ядро.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

LOCAL_HOSTS = ("127.0.0.1", "::1", "0.0.0.0")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


@dataclass
class CheckResult:
    ok: bool
    exit_ip: str = ""
    latency_ms: float = 0.0
    error: str = ""
    engine: str = ""


def resolve_binaries(singbox: str = "", xray: str = "") -> tuple[str, str]:
    def find(explicit: str, name: str, candidates: list[str]) -> str:
        if explicit:
            return explicit
        found = shutil.which(name)
        if found:
            return found
        for c in candidates:
            if os.path.isfile(c) and os.access(c, os.X_OK):
                return c
        return ""
    sb = find(singbox, "sing-box", [
        "/tmp/sing-box-1.14.2-linux-amd64/sing-box",
        "/root/DK2/app/bin/sing-box", "/usr/local/bin/sing-box", "/usr/bin/sing-box"])
    xr = find(xray, "xray", [
        "/root/mp-radar/tools/xray/xray", "/root/mp-radar/bin/xray/xray",
        "/usr/local/bin/xray", "/usr/bin/xray"])
    return sb, xr


def _needs_xray(outbound: dict[str, Any]) -> bool:
    tls = outbound.get("tls") or {}
    if "reality" in tls:
        return True
    transport = outbound.get("transport") or {}
    if transport.get("type") in ("xhttp", "http"):
        return True
    return False


def build_singbox_config(outbound: dict[str, Any], socks_port: int) -> dict[str, Any]:
    ob = dict(outbound)
    ob["tag"] = "proxy"
    return {
        "log": {"level": "error"},
        "inbounds": [{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": socks_port}],
        "outbounds": [ob, {"type": "direct", "tag": "direct"}],
        "route": {"final": "proxy"},
    }


def build_xray_config(outbound: dict[str, Any], socks_port: int) -> dict[str, Any] | None:
    """Xray-конфиг из уже распарсенного outbound (для reality/xhttp). None = не годен."""
    ob = outbound
    tls = ob.get("tls") or {}
    transport = ob.get("transport") or {}
    stream: dict[str, Any] = {"security": "reality" if "reality" in tls else ("tls" if tls else "none")}
    if "reality" in tls:
        reality = tls["reality"]
        rs: dict[str, Any] = {"show": False, "publicKey": reality.get("public_key", "")}
        if reality.get("short_id"):
            rs["shortId"] = reality["short_id"]
        if tls.get("server_name"):
            rs["serverName"] = tls["server_name"]
        stream["realitySettings"] = rs
    if tls.get("server_name"):
        stream["tlsSettings"] = {"serverName": tls["server_name"]}
    utls = tls.get("utls") or {}
    if utls.get("fingerprint"):
        stream.setdefault("tlsSettings", {})["fingerprint"] = utls["fingerprint"]

    net = transport.get("type") or "raw"
    if net == "ws":
        stream["network"] = "ws"
        settings: dict[str, Any] = {}
        if transport.get("path"):
            settings["path"] = transport["path"]
        host = (transport.get("headers") or {}).get("Host", "")
        if host:
            settings["host"] = host
        stream["wsSettings"] = settings
    elif net == "grpc":
        stream["network"] = "grpc"
        stream["grpcSettings"] = {"serviceName": transport.get("service_name", ""), "multiMode": False}
    elif net == "xhttp":
        stream["network"] = "xhttp"
        stream["xhttpSettings"] = {"path": transport.get("path", "/")}
        if transport.get("host"):
            stream["xhttpSettings"]["host"] = transport["host"]
    elif net in ("raw", "tcp", "httpupgrade", "http"):
        stream["network"] = "raw"
    else:
        return None

    typ = ob.get("type")
    if typ == "vless":
        out = {"protocol": "vless", "settings": {"vnext": [{
            "address": ob["server"], "port": ob["server_port"],
            "users": [{"id": ob["uuid"], "encryption": "none",
                       **({"flow": ob["flow"]} if ob.get("flow") else {})}]}]}}
    elif typ == "vmess":
        out = {"protocol": "vmess", "settings": {"vnext": [{
            "address": ob["server"], "port": ob["server_port"],
            "users": [{"id": ob["uuid"], "alterId": ob.get("alter_id", 0),
                       "security": ob.get("security", "auto")}]}]}}
    elif typ == "trojan":
        out = {"protocol": "trojan", "settings": {"servers": [{
            "address": ob["server"], "port": ob["server_port"], "password": ob["password"]}]}}
    else:
        return None
    out["streamSettings"] = stream
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": socks_port, "protocol": "socks",
                      "settings": {"auth": "noauth"}}],
        "outbounds": [out],
    }


def _port_is_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


def allocate_port(start: int, end: int, reserved: set[int]) -> int:
    for port in range(start, end + 1):
        if port not in reserved and _port_is_free(port):
            reserved.add(port)
            return port
    raise RuntimeError(f"no free port in {start}-{end}")


def _curl(port: int, url: str, timeout: float, capture: bool = False, fail: bool = True):
    cmd = ["curl", "--silent", "--show-error"]
    if fail:
        cmd.append("--fail")
    cmd += ["--socks5-hostname", f"127.0.0.1:{port}",
            "--connect-timeout", str(int(timeout)), "--max-time", str(int(timeout))]
    if capture:
        # код ответа отдельной строкой в конце, тело — в stdout
        cmd += ["-w", "\n%{http_code}"]
    cmd.append(url)
    return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, timeout=timeout + 2, check=False)


def _first_ip(text: str) -> str:
    for candidate in IP_RE.findall(text):
        try:
            ipaddress.ip_address(candidate)
            if candidate not in LOCAL_HOSTS:
                return candidate
        except ValueError:
            continue
    return ""


def check_node(
    outbound: dict[str, Any],
    *,
    singbox: str,
    xray: str,
    socks_port: int,
    ip_urls: tuple[str, ...] = ("https://api.ipify.org", "https://ifconfig.me/ip"),
    probe_urls: tuple[str, ...] = ("https://www.gstatic.com/generate_204",
                                   "https://api.ipify.org", "https://www.google.com/generate_204"),
    startup_wait: float = 0.7,
    timeout: float = 6.0,
    local_ip: str = "",
) -> CheckResult:
    """Поднимает ядро, проверяет HTTPS-трафик и замеряет exit_ip."""
    use_xray = _needs_xray(outbound)
    binary = xray if use_xray else singbox
    engine = "xray" if use_xray else "sing-box"
    if not binary:
        return CheckResult(False, error=f"{engine} binary missing", engine=engine)

    cfg = build_xray_config(outbound, socks_port) if use_xray else build_singbox_config(outbound, socks_port)
    if cfg is None:
        return CheckResult(False, error="cannot build engine config", engine=engine)

    with tempfile.TemporaryDirectory(prefix="sbh-") as td:
        cfg_path = Path(td) / "config.json"
        cfg_path.write_text(json.dumps(cfg, ensure_ascii=False), encoding="utf-8")
        stderr_path = Path(td) / "engine.stderr"
        with open(stderr_path, "wb") as stderr_file:
            proc = subprocess.Popen([binary, "run", "-c", str(cfg_path)], cwd=td,
                                    stdout=subprocess.DEVNULL, stderr=stderr_file,
                                    start_new_session=True)
        try:
            deadline = time.monotonic() + startup_wait + 3.0
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    tail = stderr_path.read_text(encoding="utf-8", errors="replace")[-300:]
                    return CheckResult(False, error=f"core exited: {tail.strip()[:200]}", engine=engine)
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(0.2)
                    if s.connect_ex(("127.0.0.1", socks_port)) == 0:
                        break
                time.sleep(0.05)
            else:
                return CheckResult(False, error="core did not open socks port", engine=engine)

            # 1) exit_ip — обязателен. Echo-сервисы часто блокируются апстримом,
            # поэтому пробуем несколько и не требуем HTTP 2xx (тело важнее кода).
            t0 = time.monotonic()
            exit_ip = ""
            for url in ip_urls:
                try:
                    er = _curl(socks_port, url, timeout, fail=False, capture=True)
                    found = _first_ip(er.stdout.strip() + " " + (er.stderr or ""))
                    if found:
                        exit_ip = found
                        break
                except subprocess.TimeoutExpired:
                    continue
            if not exit_ip:
                return CheckResult(False, error="exit ip not measured", engine=engine)
            if local_ip and exit_ip == local_ip:
                return CheckResult(False, exit_ip=exit_ip,
                                   error="exit equals local ip (proxy not applied)", engine=engine)

            # 2) Общая доступность: пробуем несколько целей (широкий контроль).
            latency = 0.0
            for url in probe_urls:
                try:
                    r = _curl(socks_port, url, timeout, capture=True)
                except subprocess.TimeoutExpired:
                    continue
                if r.returncode != 0:
                    continue
                try:
                    status = int(r.stdout.strip().rsplit("\n", 1)[-1].strip())
                except ValueError:
                    continue
                if 200 <= status < 400:
                    latency = (time.monotonic() - t0) * 1000.0 if t0 else 0.0
                    break
            if not latency:
                return CheckResult(False, exit_ip=exit_ip, error="no probe target reachable", engine=engine)
            return CheckResult(True, exit_ip=exit_ip, latency_ms=round(latency, 1), engine=engine)
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=1)
