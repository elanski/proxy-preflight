#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Собирает прокси из списка подписок (urls) и валидирует их через vless_checker.
Выход: файл с проверенными рабочими ссылками, пригодный для run_multi_socks.py

Пример:
  python proxy-preflight/run_from_subs.py --subs-file proxy-preflight/configs/sub.txt --validated-out proxy-preflight/configs/available_from_subs.txt

Логика:
- Загружает по HTTP(S) каждый url из subs-file
- Если контент — base64 подписка: декодирует, извлекает строки с протоколами
- Если контент — yaml (clash): пытается извлечь из раздела proxies
- Если контент — плоский список ссылок: берёт строки по префиксам
- Склеивает все найденные ссылки в temp-файл
- Вызывает vless_checker.py, чтобы получить проверенный файл (--output)
"""
from __future__ import annotations

import argparse
import base64
import io
import os
import re
import sys
from pathlib import Path
from typing import Iterable, List

import subprocess

try:
    import requests
    import yaml  # type: ignore
except Exception:
    # В случае отсутствия модулей — попытаемся установить на лету
    subprocess.run([sys.executable, "-m", "pip", "install", "requests", "pyyaml"], check=False)
    import requests  # type: ignore
    import yaml  # type: ignore

SUPPORTED_PREFIXES = (
    "vless://",
    "hysteria2://",
    "hy2://",
)


def _iter_lines(text: str) -> Iterable[str]:
    for raw in text.splitlines():
        s = raw.strip()
        if not s:
            continue
        # обрезаем комменты и хвосты
        s = s.split(" ", 1)[0]
        s = s.split("#", 1)[0].strip() or s
        yield s


def _maybe_b64_decode(content: bytes) -> str | None:
    # Пытаемся декодировать как base64 без падения
    b = content.strip()
    if not b:
        return None
    # base64 часто без паддинга
    pad = len(b) % 4
    if pad:
        b += b"=" * (4 - pad)
    try:
        dec = base64.b64decode(b, validate=False)
        # простая эвристика: в тексте после декодирования должны быть видимые протоколы или yaml ключи
        t = dec.decode("utf-8", errors="ignore")
        if any(p in t for p in ("vless://", "vmess://", "proxies:", "trojan://", "ss://", "hysteria")):
            return t
    except Exception:
        pass
    return None


def _extract_from_yaml(text: str) -> List[str]:
    try:
        data = yaml.safe_load(text)
    except Exception:
        return []
    res: List[str] = []
    if isinstance(data, dict) and "proxies" in data and isinstance(data["proxies"], list):
        for it in data["proxies"]:
            if not isinstance(it, dict):
                continue
            # Попробуем восстановить ссылку через тип/поля — минимально: name/server/port/protocol
            t = (it.get("type") or "").lower()
            server = it.get("server") or it.get("address")
            port = it.get("port")
            if not (t and server and port):
                continue
            if t in ("vless", "vmess", "trojan", "ss"):
                # Нормальная сборка из yaml потребует полного набора полей. Здесь проще пропускаем —
                # большинство подписок в итоге base64/плоский список, yaml реже.
                # В таком случае не извлекаем из yaml, чтобы не ошибиться.
                pass
    return res


def _extract_links(text: str) -> List[str]:
    # Прямая выдача
    out: List[str] = []
    for s in _iter_lines(text):
        if any(s.startswith(p) for p in SUPPORTED_PREFIXES):
            out.append(s)
    if out:
        return out
    # Попробуем yaml
    out = _extract_from_yaml(text)
    if out:
        return out
    return []


def _download(url: str, timeout: int = 15) -> bytes:
    try:
        r = requests.get(url, timeout=timeout, allow_redirects=True)
        r.raise_for_status()
        return r.content
    except Exception as e:
        sys.stderr.write(f"[warn] fetch fail {url}: {e}\n")
        return b""


def build_from_subs(subs_file: str, temp_out: Path) -> int:
    links: List[str] = []
    for raw in Path(subs_file).read_text(encoding="utf-8").splitlines():
        u = raw.strip()
        if not u or u.startswith("#"):
            continue
        b = _download(u)
        if not b:
            continue
        t = _maybe_b64_decode(b)
        if t is None:
            try:
                t = b.decode("utf-8", errors="ignore")
            except Exception:
                t = ""
        if not t:
            continue
        links.extend(_extract_links(t))
    # dedup
    uniq = []
    seen = set()
    for s in links:
        if s in seen:
            continue
        seen.add(s)
        uniq.append(s)
    temp_out.write_text("\n".join(uniq) + ("\n" if uniq else ""), encoding="utf-8")
    return len(uniq)


def run_checker(input_file: str, validated_out: str) -> int:
    env = os.environ.copy()
    env["PYTHONPATH"] = os.pathsep.join([env.get("PYTHONPATH", ""), str(Path(__file__).parent)])
    env["OUTPUT_DIR"] = str(Path(validated_out).parent)
    env["OUTPUT_FILE"] = str(Path(validated_out).name)
    cmd = [sys.executable, str(Path(__file__).parent / "lib" / "vless_checker.py"), input_file]
    p = subprocess.run(cmd, env=env)
    return p.returncode


def main() -> int:
    ap = argparse.ArgumentParser(description="Build proxies from subscriptions and validate them")
    ap.add_argument("--subs-file", default="proxy-preflight/configs/sub.txt")
    ap.add_argument("--validated-out", default="proxy-preflight/configs/available_from_subs.txt")
    args = ap.parse_args()

    tmp = Path(args.validated_out).with_suffix(".raw.txt")
    tmp.parent.mkdir(parents=True, exist_ok=True)

    n = build_from_subs(args.subs_file, tmp)
    print(f"Collected {n} candidates from subscriptions -> {tmp}")
    if n <= 0:
        print("No candidates, abort.", file=sys.stderr)
        return 2
    rc = run_checker(str(tmp), args.validated_out)
    if rc != 0:
        print(f"Checker exited with code {rc}", file=sys.stderr)
        return rc
    print(f"Validated proxies -> {args.validated_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
