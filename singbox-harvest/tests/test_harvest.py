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
