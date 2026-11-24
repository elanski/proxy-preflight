#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sing-box harvester — свежие подписки → проверка ядром → списки RU / остальные.

Что делает:
  1. Читает источники из sources.yaml (категории ru / other).
  2. Скачивает каждый URL (GitHub raw, gist, plain, base64, clash yaml),
     декодирует, извлекает URI прокси (vless/vmess/trojan/ss/hy2), дедуплирует.
  3. Для каждого узла поднимает РЕАЛЬНОЕ sing-box ядро на отдельном SOCKS-порту
     и проверяет: трафик идёт и exit_ip измерен. Несколько раундов отсекают
     «мигающие» узлы; задержка — медиана; дубли по exit_ip убираются.
  4. Гео exit_ip (ip-api.com) решает категорию RU / other. Имя/флаг — только
     подсказка приоритета, не доказательство.
  5. Пишет списки и отчёт.

Пример:
  python singbox-harvest/harvest.py --max-nodes 60 --workers 6 \\
      --out-dir singbox-harvest/out

CI: см. .github/workflows/singbox-harvest.yml
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import core  # noqa: E402
import fastcheck  # noqa: E402
import freshness  # noqa: E402
import geoip  # noqa: E402
import parsers  # noqa: E402
import source_stats  # noqa: E402

UA = "Mozilla/5.0 (compatible; singbox-harvest/1.0)"
ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def expand_env(value: str) -> str:
    """${VAR} -> значение из окружения; незаполненный плейсхолдер -> пусто.

    Так токен личной подписки не попадает в публичный sources.yaml: в файле
    лежит только имя переменной, значение приходит из окружения (локально —
    export, в CI — secrets).
    """
    return ENV_RE.sub(lambda m: os.environ.get(m.group(1), ""), str(value))


def load_sources(path: Path, extra_path: Path | None = None
                 ) -> tuple[dict[str, list[str]], list[str], dict[str, dict[str, str]]]:
    """sources.yaml (+ личный sources.local.yaml) → категории, подсказки, заголовки.

    ``source_headers``: ключ — хост или префикс URL, значение — заголовки
    запроса. Нужно подпискам, которые отдают данные только «своему» клиенту:
    Remnawave без ``x-hwid`` возвращает заглушку «Скачивайте Happ».
    """
    try:
        import yaml  # type: ignore
    except ImportError:
        print("[harvest] PyYAML не найден: pip install pyyaml", file=sys.stderr)
        raise
    files = [Path(path)]
    if extra_path and Path(extra_path).exists():
        files.append(Path(extra_path))
    cats: dict[str, list[str]] = {}
    hints: list[str] = []
    headers: dict[str, dict[str, str]] = {}
    for file in files:
        data = yaml.safe_load(file.read_text(encoding="utf-8")) or {}
        for cat, urls in (data.get("categories") or {}).items():
            cats.setdefault(str(cat), []).extend(str(u) for u in (urls or []))
        hints.extend(str(h) for h in (data.get("ru_hint_words") or []))
        for host, hdrs in (data.get("source_headers") or {}).items():
            expanded = {str(k): expand_env(v) for k, v in (hdrs or {}).items()}
            headers[str(host)] = {k: v for k, v in expanded.items() if v}
    # плейсхолдер без значения (нет переменной окружения) — источник пропускаем
    cleaned: dict[str, list[str]] = {}
    for cat, urls in cats.items():
        keep: list[str] = []
        for url in urls:
            resolved = expand_env(url)
            if resolved:
                keep.append(resolved)
            elif "${" in url:
                print(f"[harvest] skip source (env не задан): {url}", file=sys.stderr)
        cleaned[cat] = keep
    return cleaned, hints, headers


def headers_for(url: str, headers: dict[str, dict[str, str]] | None) -> dict[str, str]:
    """Заголовки для конкретного источника: по префиксу URL или по хосту."""
    if not headers:
        return {}
    host = (urlsplit(url).hostname or "").lower()
    merged: dict[str, str] = {}
    for key, hdrs in headers.items():
        key_l = key.lower()
        if url.startswith(key) or (host and (host == key_l or host.endswith("." + key_l))):
            merged.update(hdrs)
    return merged


def fetch_url(url: str, timeout: float = 12.0, headers: dict[str, str] | None = None) -> bytes:
    req_headers = {"User-Agent": UA}
    if headers:
        req_headers.update(headers)
    req = Request(url, headers=req_headers)
    with urlopen(req, timeout=timeout) as r:
        return r.read(8_000_000)


def collect(categories: dict[str, list[str]], timeout: float,
            max_sources: int = 0, per_category: int = 0,
            gate: "freshness.FreshnessGate | None" = None,
            headers: dict[str, dict[str, str]] | None = None) -> list[parsers.ParsedNode]:
    """Скачивает источники ПАРАЛЛЕЛЬНО и возвращает дедуплированные узлы.

    Последовательная загрузка 200+ источников упиралась в таймаут CI
    (один висящий URL = 12с × 200). Топ-проекты грузят источники пулом.
    """
    # 1) собрать задания (отсеяв застаревшие)
    jobs: list[tuple[str, str]] = []
    stale: list[str] = []
    for category, urls in categories.items():
        if per_category:
            urls = list(urls)[:per_category]
        if max_sources:
            urls = list(urls)[:max_sources]
        for url in urls:
            if gate is not None:
                skip, age, reason = gate.check(url)
                if skip:
                    stale.append(f"{url[:60]} ({reason})")
                    continue
            jobs.append((category, url))

    # 2) параллельно скачать и распарсить
    def fetch_one(job: tuple[str, str]) -> tuple[str, str, list[str]]:
        category, url = job
        try:
            content = fetch_url(url, timeout, headers_for(url, headers))
            return category, url, parsers.extract_uris(content)
        except Exception as e:
            print(f"[warn] fetch {url[:70]}: {type(e).__name__}", file=sys.stderr)
            return category, url, []

    fetched: list[tuple[str, str, list[str]]] = []
    with ThreadPoolExecutor(max_workers=16) as pool:
        for fut in as_completed([pool.submit(fetch_one, j) for j in jobs]):
            try:
                fetched.append(fut.result())
            except Exception:
                pass

    # 3) дедуп в детерминированном порядке (RU-источники первыми)
    nodes: list[parsers.ParsedNode] = []
    seen: set[str] = set()
    stats: dict[str, dict[str, int]] = {}
    for category, url in jobs:
        stats.setdefault(category, {"sources_ok": 0, "sources_bad": 0})
    for category, url, uris in fetched:
        if uris:
            stats[category]["sources_ok"] += 1
        else:
            stats[category]["sources_bad"] += 1
        for uri in uris:
            base = uri.split("#", 1)[0]
            if base in seen:
                continue
            try:
                node = parsers.parse_uri(uri, category=category, source=url)
            except Exception:
                continue
            if node is None:
                continue
            seen.add(base)
            nodes.append(node)
    print(f"[harvest] sources: {stats}; parsed unique nodes: {len(nodes)}", file=sys.stderr)
    if stale:
        print(f"[harvest] stale sources skipped: {len(stale)}", file=sys.stderr)
        for s in stale[:10]:
            print(f"  - {s}", file=sys.stderr)
    if gate is not None:
        gate.save()
    return nodes


def local_ip() -> str:
    """Наш собственный публичный IP — чтобы отличить 'прокси не применился'."""
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            with urlopen(Request(url, headers={"User-Agent": UA}), timeout=6) as r:
                ip = r.read(256).decode("utf-8", errors="replace").strip()
                socket.inet_aton(ip)
                return ip
        except Exception:
            continue
    return ""


def node_key(node: parsers.ParsedNode) -> str:
    o = node.outbound
    return f"{o.get('type')}:{o.get('server')}:{o.get('server_port')}:{o.get('uuid') or o.get('password','')}"


def verify_batch_fast(nodes: list[parsers.ParsedNode], binary: str, args) -> list[dict]:
    """Быстрая проверка пачки через xray-knife (один процесс на все узлы)."""
    results = fastcheck.check_batch(
        [n.uri for n in nodes], binary=binary,
        workers=args.workers, timeout_ms=int(args.timeout * 1000),
        delay_ms=int(args.timeout * 1000), test_url=args.probe_urls[0],
        prescan=args.prescan, retries=args.retries,
    )
    out: list[dict] = []
    for n, r in zip(nodes, results):
        # xray-knife уже выдал exit_ip и страну; перепроверять страну не нужно
        out.append({
            "uri": n.uri, "source": n.source, "source_category": n.category,
            "name": n.name, "proto": n.outbound.get("type", ""),
            "server": n.outbound.get("server", ""),
            "port": n.outbound.get("server_port", 0),
            "ok": r.ok, "exit_ip": r.exit_ip, "latency_ms": r.latency_ms,
            "country": r.country if r.country.lower() not in ("null", "none", "") else "",
            "country_code": geoip.code_from_xrayknife(r.country),
            "rounds_ok": r.success if r.total > 1 else (1 if r.ok else 0),
            "success_rate": (r.success / r.total) if r.total else (1.0 if r.ok else 0.0),
            "error": r.error, "engine": "xray-knife",
        })
    return out


def verify_one(node: parsers.ParsedNode, singbox: str, xray: str, base_port: int, idx: int,
               local: str, args: argparse.Namespace, port_lock) -> dict:
    """Проверяет один узел: поднимает ядро, меряет выход, rho."""
    with port_lock:
        port = core.allocate_port(base_port, base_port + 4000, args._reserved)
    try:
        result = core.check_node(
            node.outbound, singbox=singbox, xray=xray, socks_port=port,
            ip_urls=tuple(args.ip_urls), probe_urls=tuple(args.probe_urls),
            timeout=args.timeout, local_ip=local,
            rounds=args.rounds, round_gap=args.round_gap, latency_samples=args.latency_samples,
        )
    except Exception as e:
        result = core.CheckResult(False, error=f"{type(e).__name__}: {e}", engine="unknown")
    finally:
        with port_lock:
            args._reserved.discard(port)

    record = {
        "uri": node.uri,
        "source": node.source,
        "source_category": node.category,
        "name": node.name,
        "proto": node.outbound.get("type", ""),
        "server": node.outbound.get("server", ""),
        "port": node.outbound.get("server_port", 0),
        "ok": result.ok,
        "exit_ip": result.exit_ip,
        "latency_ms": result.latency_ms,
        "error": result.error,
    }
    if result.ok:
        geo = geoip.lookup(result.exit_ip)
        record["country"] = geo.get("country", "")
        record["country_code"] = geo.get("code", "")
    else:
        record["country"] = ""
        record["country_code"] = ""
    return record


def unique_records_for_stats(records: list[dict]) -> list[dict]:
    """Дедуп по exit_ip везде (живые и мёртвые), чтобы один канал
    с 8 конфигами не голосовал 8 раз за источник."""
    seen: set[str] = set()
    out: list[dict] = []
    for r in records:
        # живые: по exit_ip; мёртвые (exit неизмерен): по URI без фрагмента
        key = r.get("exit_ip") or "__uri__:" + (r.get("uri") or "").split("#", 1)[0]
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def unique_live_records(records: list[dict]) -> list[dict]:
    """Живые узлы, дедуплированные по exit_ip (быстрый сначала)."""
    seen_exit: set[str] = set()
    deduped: list[dict] = []
    for r in sorted([x for x in records if x.get("ok")], key=lambda x: x["latency_ms"]):
        ip = r.get("exit_ip") or ""
        if ip and ip in seen_exit:
            continue
        if ip:
            seen_exit.add(ip)
        deduped.append(r)
    return deduped


def write_outputs(records: list[dict], out_dir: Path, top: int,
                  meta: dict | None = None) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    live = unique_live_records(records)
    ru = [r for r in live if geoip.is_ru_ip(r.get("exit_ip", ""), r.get("country_code", ""))]
    other = [r for r in live if not geoip.is_ru_ip(r.get("exit_ip", ""), r.get("country_code", ""))]
    # Пустой прогон НЕ перезаписывает рабочие списки: это «неизвестно», а не «всё мертво».
    if not live:
        print("[harvest] WARNING: нет живых узлов — списки НЕ перезаписаны", file=sys.stderr)
        return {"tested": len(records), "live": 0, "ru": 0, "other": 0, "skipped_write": True}

    def dump(name: str, rows: list[dict]) -> str:
        p = out_dir / name
        lines = [r["uri"] for r in rows]
        p.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        return str(p)

    ru_path = dump("subscriptions_ru.txt", ru)
    other_path = dump("subscriptions_other.txt", other)
    top_path = dump("subscriptions_top.txt", sorted(live, key=lambda r: r["latency_ms"])[:top])
    all_path = dump("subscriptions_live.txt", live)
    report = {
        "generated_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "tested": len(records),
        "live": len(live),
        "ru": len(ru),
        "other": len(other),
        "geo_unknown": sum(1 for r in live if not r.get("country_code")),
        **(meta or {}),
        "files": {"ru": ru_path, "other": other_path, "top": top_path, "all": all_path},
        "nodes": [{k: r.get(k) for k in ("uri", "source", "source_category", "proto", "server", "exit_ip",
                                     "country", "country_code", "latency_ms", "ok", "rounds_ok",
                                     "success_rate", "error")} for r in records],
    }
    source_stats.atomic_write_text(out_dir / "report.json", json.dumps(report, ensure_ascii=False, indent=2))
    return report


def parse_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=" sing-box harvester: RU / other subscription lists")
    ap.add_argument("--sources", default=str(HERE / "sources.yaml"))
    ap.add_argument("--sources-extra", default=str(HERE / "sources.local.yaml"),
                    help="личные источники (в .gitignore); формат как у sources.yaml: "
                         "categories + source_headers, значения могут быть ${ENV_VAR}")
    ap.add_argument("--out-dir", default=str(HERE / "out"))
    ap.add_argument("--max-nodes", type=int, default=80, help="максимум узлов к проверке (0 = все)")
    ap.add_argument("--per-category", type=int, default=0, help="лимит источников на категорию (0 = все)")
    ap.add_argument("--max-sources", type=int, default=0, help="лимит источников всего (0 = все), для быстрой отладки")
    ap.add_argument("--workers", type=int, default=6, help="параллельных инстансов sing-box")
    ap.add_argument("--base-port", type=int, default=24100, help="начало диапазона SOCKS-портов пробника")
    ap.add_argument("--timeout", type=float, default=6.0)
    ap.add_argument("--probe-urls", nargs="+", default=["https://www.gstatic.com/generate_204",
                     "https://api.ipify.org", "https://www.google.com/generate_204"])
    ap.add_argument("--ip-urls", nargs="+", default=["https://api.ipify.org", "https://icanhazip.com",
                     "https://ifconfig.me/ip"])
    ap.add_argument("--top", type=int, default=50)
    ap.add_argument("--singbox", default="", help="путь к бинарнику sing-box (по умолчанию авто)")
    ap.add_argument("--xray", default="", help="путь к бинарнику xray (для reality/xhttp, по умолчанию авто)")
    ap.add_argument("--max-source-age", type=int, default=3,
                    help="отсекать источники старше N дней (0 = не отсекать)")
    ap.add_argument("--freshness-cache", default=str(HERE / "out" / "freshness.json"))
    ap.add_argument("--prune", action="store_true",
                    help="УДАЛЯТЬ устаревшие/404 источники из sources.yaml навсегда")
    ap.add_argument("--prune-dead", action="store_true",
                    help="УДАЛЯТЬ источники с устойчиво низкой долей живых узлов")
    ap.add_argument("--per-source", type=int, default=8,
                    help="максимум узлов от одного источника (round-robin, чтобы все источники проверялись)")
    ap.add_argument("--rounds", type=int, default=2, help="число раундов проверки узла (фильтр мигающих)")
    ap.add_argument("--round-gap", type=float, default=0.5, help="пауза между раундами, сек")
    ap.add_argument("--latency-samples", type=int, default=1, help="замеров latency на раунд (медиана)")
    ap.add_argument("--backend", choices=["fast", "core"], default="fast",
                    help="fast = xray-knife (быстро, топ-проекты), core = своё ядро на узел")
    ap.add_argument("--xrayknife", default="", help="путь к xray-knife (по умолчанию авто)")
    ap.add_argument("--prescan", action="store_true", help="TCP-предфильтр xray-knife")
    ap.add_argument("--retries", type=int, default=1, help="повторы xray-knife при ошибке")
    ap.add_argument("--stats-file", default=str(HERE / "out" / "source_stats.json"))
    return ap.parse_args(argv)


def main(argv=None) -> int:
    t_start = time.monotonic()
    args = parse_args(argv)
    args._reserved = set()
    singbox, xray = core.resolve_binaries(args.singbox, args.xray)
    xk = fastcheck.resolve_xrayknife(args.xrayknife)
    if args.backend == "fast" and xk:
        print(f"[harvest] backend: xray-knife ({xk})", file=sys.stderr)
    elif not singbox and not xray:
        # fast без xray-knife всё равно требует своё ядро как fallback
        print("[harvest] ни xray-knife, ни sing-box/xray не найдены", file=sys.stderr)
        return 2
    print(f"[harvest] sing-box: {singbox or '-'} | xray: {xray or '-'}", file=sys.stderr)

    if args.prune:
        freshness.prune_sources(args.sources, max_age_days=args.max_source_age)

    # Накопленная статистика по источникам: какой источник даёт живые узлы.
    stats = source_stats.load(args.stats_file)
    if args.prune_dead:
        source_stats.prune_dead_sources(args.sources, stats)

    categories, hints, source_headers = load_sources(
        Path(args.sources),
        Path(args.sources_extra) if args.sources_extra else None,
    )
    if source_headers:
        print(f"[harvest] источникам с заголовками: {len(source_headers)}", file=sys.stderr)
    gate = freshness.FreshnessGate(
        max_age_days=args.max_source_age,
        cache_path=args.freshness_cache,
        enabled=args.max_source_age > 0,
    )
    nodes = collect(categories, timeout=12.0, per_category=args.per_category,
                    max_sources=args.max_sources, gate=gate, headers=source_headers)

    # Приоритет: RU-источники, затем источники с высокой долей живых.
    # Мёртвые источники не должны съедать лимит --max-nodes.
    def alive_rate(src: str) -> float:
        e = stats.get(src) or stats.get(src.replace("/HEAD/", "/main/")) or {}
        checked = e.get("checked", 0)
        return (e.get("alive", 0) / checked) if checked else -1.0

    def priority(n: parsers.ParsedNode) -> tuple[int, float, int]:
        hint = any(h.lower() in n.name.lower() for h in hints)
        return ((0 if n.category == "ru" else 1), -alive_rate(n.source), 0 if hint else 1)

    nodes.sort(key=priority)
    # Не давать одному источнику съесть весь лимит: берём по --per-source
    # от каждого, проходим несколько кругов, пока не наберём max_nodes.
    if args.per_source and args.max_nodes:
        by_src: dict[str, list[parsers.ParsedNode]] = defaultdict(list)
        for n in nodes:
            by_src[n.source].append(n)
        picked: list[parsers.ParsedNode] = []
        for offset in range(0, args.per_source):
            for src in sorted(by_src):
                group = by_src[src]
                if offset < len(group):
                    picked.append(group[offset])
                    if args.max_nodes and len(picked) >= args.max_nodes:
                        break
            if args.max_nodes and len(picked) >= args.max_nodes:
                break
        nodes = picked
    if args.max_nodes:
        nodes = nodes[:args.max_nodes]
    print(f"[harvest] checking {len(nodes)} nodes from "
          f"{len(set(n.source for n in nodes))} sources with {args.workers} workers", file=sys.stderr)

    local = local_ip()
    print(f"[harvest] local ip: {local or 'unknown'}", file=sys.stderr)

    import threading
    port_lock = threading.Lock()
    records: list[dict] = []
    # xk уже определён при выборе backend
    if args.backend == "fast" and xk:
        print(f"[harvest] backend: xray-knife ({xk})", file=sys.stderr)
        # разбиваем на батчи, чтобы один процесс не съедал весь список
        for start in range(0, len(nodes), 400):
            batch = nodes[start:start + 400]
            try:
                records.extend(verify_batch_fast(batch, xk, args))
            except Exception as e:
                print(f"[warn] fast batch {start} пропущен: {e}", file=sys.stderr)
    elif args.backend == "fast":
        print("[harvest] xray-knife не найден — fallback на своё ядро", file=sys.stderr)
    if args.backend == "core" or (args.backend == "fast" and not xk):
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = [pool.submit(verify_one, n, singbox, xray, args.base_port, i, local, args, port_lock)
                       for i, n in enumerate(nodes)]
            for fut in as_completed(futures):
                try:
                    records.append(fut.result())
                except Exception as e:
                    print(f"[warn] verify: {type(e).__name__}: {e}", file=sys.stderr)

    # Накопить статистику ТОЛЬКО по уникальным exit_ip — иначе один канал,
    # выданный 8 конфигами, 8 раз «голосует» за источник.
    stats = source_stats.update_from_records(stats, unique_records_for_stats(records))
    source_stats.atomic_write_text(args.stats_file, json.dumps(stats, indent=2, ensure_ascii=False))
    if args.prune_dead:
        source_stats.prune_dead_sources(args.sources, stats)

    report = write_outputs(records, Path(args.out_dir), args.top, meta={
        "backend": "xray-knife" if (args.backend == "fast" and xk) else "core",
        "sources_count": sum(len(v) for v in categories.values()),
        "duration_sec": round(time.monotonic() - t_start, 1),
    })
    summary = {"generated_utc": report.get("generated_utc", ""),
               "tested": report["tested"], "live": report["live"],
               "ru": report["ru"], "other": report["other"]}
    if report.get("skipped_write"):
        summary["warning"] = "списки не перезаписаны: живых узлов нет"
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
