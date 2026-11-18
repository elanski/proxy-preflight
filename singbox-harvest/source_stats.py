"""Статистика живых/мёртвых по каждому источнику и автоудаление балласта.

Идея: если источник за N прогонов дал мало живых относительно проверенных,
он не стоит времени проверки — удаляем его из sources.yaml. Статистика
накапливается в out/source_stats.json (в git), чтобы решение принималось
не по одному шумному прогону.

Пороги по умолчанию:
  MIN_CHECKED = 8      — минимум проверенных узлов, прежде чем судить;
  MIN_ALIVE_RATE = 0.05 — меньше 5% живых → кандидат на удаление;
  FAIL_RUNS = 2        — столько прогонов подряд ниже порога → удалить.
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

MIN_CHECKED = 10       # минимум уникальных проверенных узлов, прежде чем судить
MIN_ALIVE_RATE = 0.03  # меньше 3% живых → провальный прогон
FAIL_RUNS = 3          # подряд 3 провальных прогона → удалить (не 2)


def load(path: str) -> dict:
    p = Path(path)
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


def update_from_records(stats: dict, records: list[dict]) -> dict:
    """Добавить результаты текущего прогона к накопленной статистике."""
    per = defaultdict(lambda: {"checked": 0, "alive": 0})
    for r in records:
        src = r.get("source") or ""
        if not src:
            continue
        per[src]["checked"] += 1
        if r.get("ok"):
            per[src]["alive"] += 1

    now = datetime.now(timezone.utc).isoformat()
    for src, v in per.items():
        entry = stats.setdefault(src, {"checked": 0, "alive": 0, "fail_runs": 0,
                                       "history": [], "updated": now})
        entry["checked"] += v["checked"]
        entry["alive"] += v["alive"]
        entry["updated"] = now
        rate = v["alive"] / v["checked"] if v["checked"] else 0.0
        entry["history"].append({"checked": v["checked"], "alive": v["alive"], "date": now})
        entry["history"] = entry["history"][-10:]

        # провальный прогон: достаточно данных И живых меньше порога
        if v["checked"] >= MIN_CHECKED and rate < MIN_ALIVE_RATE:
            entry["fail_runs"] += 1
        else:
            entry["fail_runs"] = 0
    return stats


def bad_sources(stats: dict) -> list[str]:
    """Источники, которые пора удалить."""
    return [src for src, e in stats.items()
            if e.get("fail_runs", 0) >= FAIL_RUNS]


def prune_dead_sources(sources_path: str, stats: dict,
                       min_checked: int = MIN_CHECKED,
                       min_rate: float = MIN_ALIVE_RATE,
                       fail_runs: int = FAIL_RUNS) -> tuple[list[str], dict]:
    """УДАЛЯЕТ из sources.yaml источники с устойчиво низкой долей живых."""
    import yaml  # type: ignore
    path = Path(sources_path)
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    cats = data.get("categories") or {}
    to_remove = set()
    for src, e in stats.items():
        checked = e.get("checked", 0)
        alive = e.get("alive", 0)
        rate = alive / checked if checked else 0.0
        # только устойчиво мёртвые:fail_runs подряд. Отдельного «накопительного»
        # правила больше нет — оно удаляло живые источники по шумной выборке.
        if e.get("fail_runs", 0) >= fail_runs:
            to_remove.add(src)

    removed = []
    for category, urls in list(cats.items()):
        good = []
        for u in urls:
            # сравнить с нормализацией HEAD/main
            norm = u.replace("/HEAD/", "/main/")
            if u in to_remove or norm in to_remove:
                removed.append(u)
                rate = 0.0
                e = stats.get(u) or stats.get(norm) or {}
                if e.get("checked"):
                    rate = e["alive"] / e["checked"]
                print(f"[source-stats] REMOVE {u[:75]} "
                      f"(alive {e.get('alive', 0)}/{e.get('checked', 0)} = {rate:.1%}, "
                      f"fails {e.get('fail_runs', 0)})", file=sys.stderr)
                continue
            good.append(u)
        cats[category] = good
    data["categories"] = cats
    path.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")
    print(f"[source-stats] удалено {len(removed)} неэффективных источников", file=sys.stderr)
    return removed, stats
