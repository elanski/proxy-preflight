#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""sing-box harvester — свежие подписки → проверка ядром → списки RU / остальные.

Что делает:
  1. Читает источники из sources.yaml (категории ru / other).
  2. Скачивает каждый URL (GitHub raw, gist, plain, base64, clash yaml),
     декодирует, извлекает URI прокси (vless/vmess/trojan/ss/hy2), дедуплирует.
  3. Для каждого узла поднимает РЕАЛЬНОЕ sing-box ядро на отдельном SOCKS-порту
     и проверяет: трафик идёт иexit_ip измерен. Без exit_ip узел мёртв.
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
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.request import Request, urlopen

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import core  # noqa: E402
import freshness  # noqa: E402
import geoip  # noqa: E402
import parsers  # noqa: E402

UA = "Mozilla/5.0 (compatible; singbox-harvest/1.0)"


def load_sources(path: Path) -> tuple[dict[str, list[str]], list[str]]:
    try:
        import yaml  # type: ignore
    except ImportError:
        print("[harvest] PyYAML не найден: pip install pyyaml", file=sys.stderr)
        raise
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    cats = data.get("categories") or {}
    hints = data.get("ru_hint_words") or []
    return {k: list(v) for k, v in cats.items()}, [str(h) for h in hints]


def fetch_url(url: str, timeout: float = 12.0) -> bytes:
    req = Request(url, headers={"User-Agent": UA})
    with urlopen(req, timeout=timeout) as r:
        return r.read(8_000_000)


def collect(categories: dict[str, list[str]], timeout: float,
            max_sources: int = 0, per_category: int = 0,
            gate: "freshness.FreshnessGate | None" = None) -> list[parsers.ParsedNode]:
    """Скачивает источники и возвращает дедуплированные узлы с категорией."""
    nodes: list[parsers.ParsedNode] = []
    seen: set[str] = set()
    stats: dict[str, dict[str, int]] = {}
    stale: list[str] = []
    for category, urls in categories.items():
        if per_category:
            urls = list(urls)[:per_category]
        if max_sources:
            urls = list(urls)[:max_sources]
        sources_ok = sources_bad = 0
        for url in urls:
            # Автономный отсев застаревших источников (по дате коммита файла).
            if gate is not None:
                skip, age, reason = gate.check(url)
                if skip:
                    stale.append(f"{url[:60]} ({reason})")
                    continue
            try:
                content = fetch_url(url, timeout)
                text = parsers.decode_subscription(content)
                uris = parsers.find_uris(text)
                sources_ok += 1
            except Exception as e:
                sources_bad += 1
                print(f"[warn] fetch {url[:70]}: {type(e).__name__}", file=sys.stderr)
                continue
            for uri in uris:
                base = uri.split("#", 1)[0]
                if base in seen:
                    continue
                try:
                    node = parsers.parse_uri(uri, category=category)
                except Exception:
                    continue
                if node is None:
                    continue
                seen.add(base)
                nodes.append(node)
        stats[category] = {"sources_ok": sources_ok, "sources_bad": sources_bad}
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
        )
    except Exception as e:
        result = core.CheckResult(False, error=f"{type(e).__name__}: {e}", engine="unknown")
    finally:
        with port_lock:
            args._reserved.discard(port)

    record = {
        "uri": node.uri,
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


def write_outputs(records: list[dict], out_dir: Path, top: int) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    live = [r for r in records if r["ok"]]
    ru = [r for r in live if geoip.is_ru(r.get("country_code", ""))]
    other = [r for r in live if not geoip.is_ru(r.get("country_code", ""))]
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
        "files": {"ru": ru_path, "other": other_path, "top": top_path, "all": all_path},
        "nodes": [{k: r[k] for k in ("uri", "source_category", "proto", "server", "exit_ip",
                                     "country", "country_code", "latency_ms", "ok", "error")} for r in records],
    }
    (out_dir / "report.json").write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    return report


def parse_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=" sing-box harvester: RU / other subscription lists")
    ap.add_argument("--sources", default=str(HERE / "sources.yaml"))
    ap.add_argument("--out-dir", default=str(HERE / "out"))
    ap.add_argument("--max-nodes", type=int, default=80, help="максимум узлов к проверке (0 = все)")
    ap.add_argument("--per-category", type=int, default=0, help="лимит источников на категорию (0 = все)")
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
    return ap.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    args._reserved = set()
    singbox, xray = core.resolve_binaries(args.singbox, args.xray)
    if not singbox and not xray:
        print("[harvest] ни sing-box, ни xray не найдены", file=sys.stderr)
        return 2
    print(f"[harvest] sing-box: {singbox or '-'} | xray: {xray or '-'}", file=sys.stderr)

    if args.prune:
        freshness.prune_sources(args.sources, max_age_days=args.max_source_age)

    categories, hints = load_sources(Path(args.sources))
    gate = freshness.FreshnessGate(
        max_age_days=args.max_source_age,
        cache_path=args.freshness_cache,
        enabled=args.max_source_age > 0,
    )
    nodes = collect(categories, timeout=12.0, per_category=args.per_category, gate=gate)

    # Приоритет: RU-источники и узлы с RU-подсказкой в имени идут первыми,
    # чтобы лимит --max-nodes не съедали глобальные узлы.
    def priority(n: parsers.ParsedNode) -> int:
        hint = any(h.lower() in n.name.lower() for h in hints)
        return (0 if n.category == "ru" else 1) + (0 if hint else 1)

    nodes.sort(key=priority)
    if args.max_nodes:
        nodes = nodes[:args.max_nodes]
    print(f"[harvest] checking {len(nodes)} nodes with {args.workers} workers", file=sys.stderr)

    local = local_ip()
    print(f"[harvest] local ip: {local or 'unknown'}", file=sys.stderr)

    import threading
    port_lock = threading.Lock()
    records: list[dict] = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(verify_one, n, singbox, xray, args.base_port, i, local, args, port_lock)
                   for i, n in enumerate(nodes)]
        for fut in as_completed(futures):
            try:
                records.append(fut.result())
            except Exception as e:
                print(f"[warn] verify: {type(e).__name__}: {e}", file=sys.stderr)

    report = write_outputs(records, Path(args.out_dir), args.top)
    summary = {"generated_utc": report.get("generated_utc", ""),
               "tested": report["tested"], "live": report["live"],
               "ru": report["ru"], "other": report["other"]}
    if report.get("skipped_write"):
        summary["warning"] = "списки не перезаписаны: живых узлов нет"
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
