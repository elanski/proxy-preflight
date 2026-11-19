"""Проверка свежести источников через GitHub API.

Автономный отбор: источник, чей ФАЙЛ не обновлялся дольше порога,
пропускается без скачивания. Это можно включить в CI: репозиторий может быть
активным, а конкретный файл подписки — застаревшим.

Работает без токена (60 запросов/час), с GITHUB_TOKEN — 5000/час.
Результат кэшируется на диске, чтобы не долбить API каждый запуск.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
import urllib.parse
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from urllib.request import Request, urlopen

API = "https://api.github.com"
CACHE_TTL = 6 * 3600  # 6 часов


def parse_github_path(url: str) -> tuple[str, str, str] | None:
    """Возвращает (owner, repo, path) для raw.githubusercontent URL."""
    m = re.search(r"raw\.githubusercontent\.com/([^/]+)/([^/]+)/([^/]+)/(.+)", url)
    if not m:
        m = re.search(r"github\.com/([^/]+)/([^/]+)/raw/([^/]+)/(.+)", url)
    if not m:
        return None
    owner, repo, ref, path = m.group(1), m.group(2), m.group(3), m.group(4)
    # refs/heads/main/... → обычный путь без префикса ref
    if ref.startswith("refs/heads/"):
        path = ref[len("refs/heads/"):] + "/" + path
    return owner, repo, path


def _api_get(path: str, timeout: float = 8.0):
    req = Request(API + path, headers={
        "User-Agent": "singbox-harvest",
        "Accept": "application/vnd.github+json",
    })
    token = os.environ.get("GITHUB_TOKEN") or ""
    if token:
        req.add_header("Authorization", "Bearer " + token)
    with urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def last_commit_age_days(url: str, timeout: float = 8.0) -> int | None:
    """Сколько дней назад файл последний раз менялся. None = неизвестно."""
    parsed = parse_github_path(url)
    if not parsed:
        return None  # gist и др. — свежесть не проверяем, доверимся загрузке
    owner, repo, path = parsed
    q = urllib.parse.urlencode({"path": path, "per_page": 1})
    try:
        data = _api_get(f"/repos/{owner}/{repo}/commits?{q}", timeout)
        date = data[0]["commit"]["committer"]["date"]
        dt = datetime.fromisoformat(date.replace("Z", "+00:00"))
        return max(0, (datetime.now(timezone.utc) - dt).days)
    except Exception:
        return None  # сетевая ошибка НЕ должна убивать источник


class FreshnessGate:
    def __init__(self, max_age_days: int = 3, cache_path: str = "", enabled: bool = True):
        self.max_age = max_age_days
        self.enabled = enabled
        self.cache_path = Path(cache_path) if cache_path else None
        self.cache: dict[str, dict] = {}
        if self.cache_path and self.cache_path.exists():
            try:
                self.cache = json.loads(self.cache_path.read_text(encoding="utf-8"))
            except Exception:
                self.cache = {}

    def check(self, url: str) -> tuple[bool, int | None, str]:
        """(пропустить?, возраст дней, причина). Также кэширует наш коммит."""
        if not self.enabled:
            return False, None, ""
        cached = self.cache.get(url)
        if cached and time.time() - cached.get("ts", 0) < CACHE_TTL:
            age = cached.get("age")
            if age is not None and age > self.max_age:
                return True, age, f"источник не обновлялся {age} дн."
            return False, age, ""

        age = url_last_modified_days(url)
        self.cache[url] = {"age": age, "ts": time.time()}
        # None (неизвестно) — НЕ отсекаем: лучше проверить, чем потерять источник
        if age is not None and age > self.max_age:
            return True, age, f"источник не обновлялся {age} дн. (порог {self.max_age})"
        return False, age, ""

    def save(self):
        if self.cache_path:
            try:
                self.cache_path.parent.mkdir(parents=True, exist_ok=True)
                self.cache_path.write_text(json.dumps(self.cache, indent=2), encoding="utf-8")
            except Exception:
                pass


def url_last_modified_days(url: str, timeout: float = 8.0) -> int | None:
    """Возраст не-GitHub источника по HTTP Last-Modified / Age.

    Для raw.githubusercontent используем commits API (точно). Для остальных
    хостингов сервер часто отдаёт Last-Modified — используем его как сигнал.
    None = неизвестно (не отсекать).
    """
    if parse_github_path(url):
        return last_commit_age_days(url, timeout)
    try:
        req = Request(url, headers={"User-Agent": "singbox-harvest"}, method="HEAD")
        with urlopen(req, timeout=timeout) as r:
            lm = r.headers.get("Last-Modified")
        if not lm:
            return None
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(lm)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - dt).days)
    except Exception:
        return None


def url_is_dead(url: str, timeout: float = 10.0) -> bool:
    """True, если URL точно мёртв (404/410/ домен не найден). Сетевые ошибки — не мёртв."""
    try:
        req = Request(url, headers={"User-Agent": "singbox-harvest"}, method="GET")
        with urlopen(req, timeout=timeout) as r:
            return False
    except urllib.error.HTTPError as e:
        return e.code in (404, 410)
    except Exception:
        return False  # таймаут/DNS — не доказательство смерти


def prune_sources(sources_path: str, max_age_days: int = 3,
                  remove_dead: bool = True) -> tuple[list[str], list[str]]:
    """УДАЛЯЕТ устаревшие и 404-источники из sources.yaml навсегда.

    Возвращает (удалённые, оставшиеся). Работает без AI — чисто по дате
    последнего коммита файла и HTTP-коду. Вызывается в CI перед сбором.
    """
    import yaml  # type: ignore
    path = Path(sources_path)
    text = path.read_text(encoding="utf-8")
    data = yaml.safe_load(text) or {}
    cats = data.get("categories") or {}
    gate = FreshnessGate(max_age_days=max_age_days, enabled=max_age_days > 0)
    removed: list[str] = []
    kept: list[str] = []
    for category, urls in list(cats.items()):
        good = []
        for url in urls:
            skip, age, reason = gate.check(url)
            if skip:
                removed.append(url)
                print(f"[prune] REMOVE stale ({reason}): {url[:80]}", file=sys.stderr)
                continue
            if remove_dead and url_is_dead(url):
                removed.append(url)
                print(f"[prune] REMOVE dead 404/410: {url[:80]}", file=sys.stderr)
                continue
            good.append(url)
            kept.append(url)
        cats[category] = good
    data["categories"] = cats
    path.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")
    print(f"[prune] удалено {len(removed)}, осталось {len(kept)} источников", file=sys.stderr)
    return removed, kept
