"""Быстрая проверка узлов через xray-knife (практика топ-проектов
0xRadikal/Free-v2ray-Configs, Au1rxx/free-vpn-subscriptions).

Вместо подъёма отдельного ядра на каждый узел (медленно) xray-knife
проверяет ТЫСЯЧИ узлов одним процессом с TCP prescan + параллельными
HTTP-пробами через core (singbox/xray), выдавая CSV:
  link,status,ip,delay,location,success,total,rtt_min/avg/max,...

Наш старый core.py остаётся fallback'ом (и для точной проверки RU exit).
"""
from __future__ import annotations

import csv
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from core import CheckResult

XK_BIN = "xray-knife"
DEFAULT_TEST_URL = "https://www.gstatic.com/generate_204"


def resolve_xrayknife(explicit: str = "") -> str:
    if explicit:
        return explicit
    found = shutil.which(XK_BIN)
    if found:
        return found
    for c in ("/tmp/xray-knife", "/usr/local/bin/xray-knife", "/usr/bin/xray-knife"):
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return ""


@dataclass
class FastResult:
    ok: bool
    exit_ip: str = ""
    latency_ms: float = 0.0
    country: str = ""
    error: str = ""
    success: int = 0
    total: int = 0


def check_batch(uri_lines: list[str], *, binary: str,
                workers: int = 32, timeout_ms: int = 6000,
                delay_ms: int = 5000, test_url: str = DEFAULT_TEST_URL,
                prescan: bool = True, retries: int = 1,
                max_passed: int = 0) -> list[FastResult]:
    """Проверяет пачку URI одним процессом xray-knife. Возвращает по URI."""
    if not binary:
        raise RuntimeError("xray-knife недоступен")
    with tempfile.TemporaryDirectory(prefix="xk-") as td:
        in_path = Path(td) / "in.txt"
        out_path = Path(td) / "out.csv"
        in_path.write_text("\n".join(uri_lines) + "\n", encoding="utf-8")
        argv = [binary, "http", "-f", str(in_path), "-x", "csv", "-o", str(out_path),
                "-t", str(workers), "-d", str(delay_ms), "--timeout", str(timeout_ms),
                "-u", test_url, "--diagnose=false"]
        if prescan:
            argv.append("--prescan")
        if retries:
            argv += ["--retries", str(retries)]
        if max_passed:
            argv += ["--max-passed", str(max_passed)]
        try:
            subprocess.run(argv, stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=max(60, len(uri_lines) // 2 + 60), check=False)
        except subprocess.TimeoutExpired:
            pass
        if not out_path.exists():
            return [FastResult(False, error="xray-knife не записал CSV") for _ in uri_lines]

        # CSV → результат по ссылке (.key без фрагмента, как в parsers)
        rows: dict[str, FastResult] = {}
        with open(out_path, encoding="utf-8", errors="replace") as f:
            for row in csv.DictReader(f):
                link = (row.get("link") or "").strip()
                key = link.split("#", 1)[0]
                status = (row.get("status") or "").strip()
                try:
                    ip = (row.get("ip") or "").strip()
                    latency = float(row.get("delay") or 0)
                    success = int(row.get("success") or 0)
                    total = int(row.get("total") or 0)
                except ValueError:
                    ip, latency, success, total = "", 0.0, 0, 0
                rows[key] = FastResult(
                    ok=status == "passed" and bool(ip),
                    exit_ip=ip,
                    latency_ms=latency,
                    country=(row.get("location") or "").strip(),
                    error="" if status == "passed" else (row.get("reason") or status),
                    success=success, total=total,
                )
    return [rows.get(u.split("#", 1)[0], FastResult(False, error="нет в отчёте"))
            for u in uri_lines]
