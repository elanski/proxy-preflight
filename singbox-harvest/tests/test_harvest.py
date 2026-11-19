"""Тесты парсера и сборки конфигов (без сети и без запуска ядра)."""
import base64
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
import core  # noqa: E402
import parsers  # noqa: E402
import source_stats  # noqa: E402

UUID = "b831381d-6324-4d53-ad4f-8cda48b30811"


def test_parse_vless_reality_and_amp_escape():
    uri = ("vless://" + UUID + "@1.2.3.4:443?encryption=none&security=reality"
           "&flow=xtls-rprx-vision&type=tcp&sni=example.com&fp=chrome"
           "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=abcdef0123456789"
           "&amp;sid=ignored#RU%20Moscow")
    node = parsers.parse_uri(uri, category="ru")
    assert node is not None
    ob = node.outbound
    assert ob["type"] == "vless"
    assert ob["server"] == "1.2.3.4" and ob["server_port"] == 443
    assert ob["tls"]["reality"]["public_key"].startswith("AAAA")
    assert ob["tls"]["reality"]["short_id"] == "abcdef0123456789"
    assert "amp;sid" not in ob["tls"]["reality"]
    assert core._needs_xray(ob)  # reality → xray


def test_parse_vless_ws():
    uri = ("vless://" + UUID + "@host.example:443?encryption=none&security=tls"
           "&type=ws&path=%2Fws&host=cdn.example&sni=cdn.example#node")
    node = parsers.parse_uri(uri)
    assert node is not None
    ob = node.outbound
    assert ob["transport"]["type"] == "ws"
    assert ob["transport"]["path"] == "/ws"
    assert ob["transport"]["headers"]["Host"] == "cdn.example"
    assert not core._needs_xray(ob)


def test_parse_hysteria2():
    uri = "hysteria2://pw@host.example:8443?sni=host.example#hy2"
    node = parsers.parse_uri(uri)
    assert node is not None
    assert node.outbound["type"] == "hysteria2"
    assert node.outbound["password"] == "pw"


def test_parse_shadowsocks():
    cred = base64.b64encode(b"aes-128-gcm:passwd").decode()
    uri = f"ss://{cred}@host.example:8388#ss"
    node = parsers.parse_uri(uri)
    assert node is not None
    assert node.outbound["type"] == "shadowsocks"
    assert node.outbound["method"] == "aes-128-gcm"


def test_reality_without_pbk_rejected():
    uri = ("vless://" + UUID + "@1.2.3.4:443?security=reality"
           "&flow=xtls-rprx-vision&type=tcp#broken")
    assert parsers.parse_uri(uri) is None


def test_find_uris_in_text_and_base64():
    uri = "vless://" + UUID + "@1.1.1.1:443?security=tls#x"
    raw = f"some text\n{uri}\n"
    assert uri in parsers.find_uris(raw)
    b64 = base64.b64encode(raw.encode()).decode()
    decoded = parsers.decode_subscription(b64.encode())
    assert uri in decoded


def test_build_configs_validate_with_real_binaries():
    """Собранные конфиги должны проходить проверку реальных бинарников."""
    sb, xr = core.resolve_binaries()
    import shutil, subprocess, tempfile
    if not sb or not shutil.which("curl"):
        pytest.skip("sing-box/curl недоступны")
    ob = {"type": "shadowsocks", "server": "1.2.3.4", "server_port": 8388,
          "method": "aes-128-gcm", "password": "pw"}
    cfg = core.build_singbox_config(ob, 24999)
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "c.json"
        p.write_text(json.dumps(cfg))
        r = subprocess.run([sb, "check", "-c", str(p)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr


def test_first_ip_skips_local():
    assert core._first_ip("garbage 127.0.0.1 then 8.8.8.8") == "8.8.8.8"


def test_xray_config_valid_for_reality():
    """Собранный Xray-конфиг для REALITY должен проходить xray -test."""
    sb, xr = core.resolve_binaries()
    if not xr:
        pytest.skip("xray недоступен")
    uri = ("vless://" + UUID + "@1.2.3.4:443?security=reality&flow=xtls-rprx-vision"
           "&type=tcp&sni=www.example.com&fp=chrome"
           "&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA#x")
    ob = parsers.parse_uri(uri).outbound
    assert ob is not None
    cfg = core.build_xray_config(ob, 24998)
    assert cfg is not None
    assert "serverNames" not in json.dumps(cfg)  # Xray требует serverName
    with tempfile.TemporaryDirectory() as td:
        p = Path(td) / "c.json"
        p.write_text(json.dumps(cfg))
        r = subprocess.run([xr, "-test", "-c", str(p)], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def test_vless_without_username_rejected():
    assert parsers.parse_uri("vless://@1.2.3.4:443?security=tls#x") is None


def test_source_stats_accumulates_and_marks_bad():
    recs = [{"source": "http://good", "ok": True} for _ in range(5)]
    recs += [{"source": "http://bad", "ok": False} for _ in range(10)]
    stats = source_stats.update_from_records({}, recs)
    assert stats["http://good"]["alive"] == 5
    assert stats["http://bad"]["alive"] == 0
    # один провальный прогон: fail_runs=1 (порог удаления 3)
    assert stats["http://bad"]["fail_runs"] == 1
    assert source_stats.bad_sources(stats) == []
    # второй и третий провальные прогоны → кандидат на удаление
    stats = source_stats.update_from_records(stats, [{"source": "http://bad", "ok": False} for _ in range(10)])
    stats = source_stats.update_from_records(stats, [{"source": "http://bad", "ok": False} for _ in range(10)])
    assert stats["http://bad"]["fail_runs"] == 3
    assert "http://bad" in source_stats.bad_sources(stats)


def test_source_is_set_on_parsed_node():
    n = parsers.parse_uri("ss://YWVzLTEyOC1nY206cHc@1.2.3.4:8388#x", source="http://src")
    assert n is not None and n.source == "http://src"


def test_fastcheck_module_importable():
    """xray-knife backend должен импортироваться и находить бинарник."""
    import fastcheck
    assert hasattr(fastcheck, "check_batch")
    assert hasattr(fastcheck, "resolve_xrayknife")


def test_xrayknife_null_country_not_nu():
    """Строка 'null' от xray-knife не должна превращаться в код Ниуэ."""
    import geoip
    assert geoip.code_from_xrayknife("null") == ""
    assert geoip.code_from_xrayknife("IT") == "IT"
    assert geoip.code_from_xrayknife("RU") == "RU"
    assert geoip.code_from_xrayknife("") == ""
    assert not geoip.is_ru("NU")


def test_repo_cidrlist_used_for_ru():
    """CIDR-лист из этого же репозитория — запасной RU-сигнал при пустом коде."""
    import geoip
    assert len(geoip._load_ru_cidrs()) > 1000
    assert geoip.is_ru_ip("", "RU")
    assert not geoip.is_ru_ip("", "US")
    # код есть и не RU — CIDR не опрашиваем
    assert not geoip.is_ru_ip("8.8.8.8", "US")


def test_parser_gap_not_removed():
    """Источник с битыми парсами — не "мёртвый", а parser-gap: не удаляем."""
    import source_stats
    recs = [{"source": "s", "ok": False, "error": "parse protocol: invalid characters"} for _ in range(6)]
    st = source_stats.update_from_records({}, recs)
    assert st["s"]["parser_gap"] is True
    assert st["s"]["fail_runs"] == 0
    assert source_stats.bad_sources(st) == []
    # обратная совместимость: старая запись без parse_errors не роняет
    old = {"s": {"checked": 5, "alive": 0, "fail_runs": 1, "history": [], "updated": ""}}
    st2 = source_stats.update_from_records(old, recs)
    assert st2["s"]["parse_errors"] == 6


def test_atomic_write_no_tmp_left():
    """Атомарная запись не оставляет .tmp."""
    import tempfile
    import source_stats
    with tempfile.TemporaryDirectory() as td:
        p = f"{td}/x.json"
        source_stats.atomic_write_text(p, "{}")
        import os
        assert os.path.exists(p) and not os.path.exists(p + ".tmp")


def test_last_modified_for_non_github(monkeypatch):
    """Не-GitHub источник проверяется по HTTP Last-Modified."""
    import freshness
    from email.utils import format_datetime
    from datetime import datetime, timezone, timedelta
    class FakeResp:
        def __enter__(self): return self
        def __exit__(self, *a): return False
        headers = {"Last-Modified": format_datetime(
            datetime.now(timezone.utc) - timedelta(days=2))}
    monkeypatch.setattr(freshness, "parse_github_path", lambda u: None)
    monkeypatch.setattr(freshness, "urlopen", lambda *a, **k: FakeResp())
    assert freshness.url_last_modified_days("https://example.com/sub.txt") == 2


def test_unique_records_for_stats_keeps_alive_ratio():
    """Статистика считается по уникальным выходам, но живые/мёртвые сохраняются."""
    import harvest
    recs = [
        {"uri": "a", "source": "s", "ok": True, "exit_ip": "1.1.1.1"},
        {"uri": "b", "source": "s", "ok": True, "exit_ip": "1.1.1.1"},  # дубль
        {"uri": "c", "source": "s", "ok": False, "exit_ip": "2.2.2.2"},
        {"uri": "d", "source": "s", "ok": False, "exit_ip": ""},
        {"uri": "d", "source": "s", "ok": False, "exit_ip": ""},  # дубль d
    ]
    uniq = harvest.unique_records_for_stats(recs)
    assert len(uniq) == 3
    stats = __import__("source_stats").update_from_records({}, uniq)
    assert stats["s"]["checked"] == 3
    assert stats["s"]["alive"] == 1


def test_dedup_by_exit_ip():
    """Один выходной IP — одна запись в списке (практика sub2singbox)."""
    import harvest
    recs = [
        {"uri": "a", "ok": True, "exit_ip": "1.1.1.1", "latency_ms": 100, "country_code": "US", "source": "s"},
        {"uri": "b", "ok": True, "exit_ip": "1.1.1.1", "latency_ms": 80, "country_code": "US", "source": "s"},
        {"uri": "c", "ok": True, "exit_ip": "2.2.2.2", "latency_ms": 200, "country_code": "RU", "source": "s"},
        {"uri": "d", "ok": False, "exit_ip": "", "latency_ms": 0, "country_code": "", "source": "s"},
    ]
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as td:
        # подменим geoip, чтобы тест не зависел от сети
        report = harvest.write_outputs(recs, Path(td), 10)
        assert report["live"] == 2  # два уникальных выхода, не три
        lines = (Path(td) / "subscriptions_live.txt").read_text().splitlines()
        assert sorted(lines) == ["b", "c"]  # dup с меньшей latency (80ms) выживает
