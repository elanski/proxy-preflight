# sing-box harvester

Парсер и валидатор свежих VPN-подписок через **реальное ядро** sing-box / Xray.
Собирает подписки с GitHub (raw), gist и др. источников, проверяет каждый узел
реальным подключением, замеряет exit_ip и раскладывает рабочие узлы на списки:

| Файл | Что внутри |
|---|---|
| `out/subscriptions_ru.txt` | рабочие узлы с **выходом в RU** (по exit_ip) |
| `out/subscriptions_other.txt` | все остальные рабочие узлы |
| `out/subscriptions_top.txt` | топ по задержке (быстрые) |
| `out/subscriptions_live.txt` | все рабочие узлы |
| `out/report.json` | полный отчёт: страна, exit_ip, задержка, ошибки |

## Ключевой принцип

Страна определяется **только по измеренному exit_ip** через поднятое ядро
(`ip-api.com`). Флаг 🇷🇺 в имени узла или гео сервера — лишь подсказка
приоритета, не доказательство. Узел без измеренного exit_ip считается мёртвым.

Проверка идёт через `curl --socks5-hostname` (не `urllib`+PySocks — тот молча
падает на SOCKS). REALITY и XHTTP валидируются Xray, остальное — sing-box.

## Запуск локально

```bash
pip install -r requirements.txt
python singbox-harvest/harvest.py --max-nodes 60 --workers 6 \
    --out-dir singbox-harvest/out
```

## GitHub Actions — полностью автономно

Workflow `.github/workflows/singbox-harvest.yml` работает **на серверах GitHub**
без твоего участия:

* запускается каждые 6 часов по `schedule` (+ кнопка `workflow_dispatch`);
* **сам удаляет** устаревшие (старше 3 дней) и мёртвые (404) источники из
  `sources.yaml` (`--prune`) — по дате последнего коммита файла и HTTP-коду,
  без ИИ;
* коммитит обновлённые `sources.yaml` и списки обратно в репозиторий;
* нет триггера `push`, поэтому собственный коммит не вызывает бесконечный цикл;
* если живых узлов нет — списки НЕ перезаписываются.

Списки доступны по прямым ссылкам:

```
https://raw.githubusercontent.com/elanski/proxy-preflight/main/singbox-harvest/out/subscriptions_ru.txt
https://raw.githubusercontent.com/elanski/proxy-preflight/main/singbox-harvest/out/subscriptions_other.txt
```

## Источники

Правятся в `singbox-harvest/sources.yaml`, категории `ru` и `other`. Источники
должны отдавать plain/base64/clash-подписки с URI прокси.
