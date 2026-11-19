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
* **не тратит время на мёртвые подписки** (`--prune-dead`): статистика по источникам
  накапливается в `out/source_stats.json`; после двух прогонов с долей живых
  <5% источник удаляется; `--per-source 8` даёт каждому источнику квоту,
  чтобы он проверялся, а не съедал лимит целиком;
* коммитит обновлённые `sources.yaml` и списки обратно в репозиторий;
* нет триггера `push`, поэтому собственный коммит не вызывает бесконечный цикл;
* если живых узлов нет — списки НЕ перезаписываются.

## Docker (локально)

```bash
cd singbox-harvest
docker compose up --build
```

Контейнер содержит зафиксированный xray-knife v11.5.1 и Python-deps,
списки пишутся в `singbox-harvest/out` через volume.

## Источники: 829 (98 RU + 731 other)

Подписки собраны из каталогов `mehdirzfx/v2ray-sub`, `morpheusadam/subs/all.txt`,
DK2 и прямого поиска по GitHub. Крупнейшие свежие (обновляются ежедневно):
`pie-with-jam/5ubscrpt10n-Reborn` (360k URI), `rtwo2/FastNodes`,
`Delta-Kronecker/V2ray-Config`, `mani-moh/navaroute`, `happ-tmn`,
`0xRadikal/Free-v2ray-Configs`, `nikita29a/FreeProxyList`.

## Перенесённое из похожих проектов

* **rtwo2/FastNodes** (`track_source_health.py`): атомарная запись JSON/CSV
  (tmp + replace), классификация `parser-gap` — источник с битыми парсами
  не удаляется как «мёртвый», а помечается.
* **xray-knife** (`--check-preset`, `--max-passed`, `--prescan`) — удобная
  multi-endpoint проверка и быстрый TCP-предфильтр.
* **Au1rxx / 0xRadikal** — CSV с exit_ip/страной/задержкой, дедуп по exit_ip.

## Аудит (ноябрь 2026) — исправленные дефекты

1. `country='null'` от xray-knife превращалось в код `NU` (Ниуэ) — добавлен
   `geoip.code_from_xrayknife`.
2. Статистика источников считалась по всем дублям exit_ip —
   один канал с 8 конфигами голосовал 8 раз; теперь `unique_records_for_stats`.
3. Недостоверный батч xray-knife (>50% без отчёта) мог обнулить списки —
   теперь батч пропускается с предупреждением.
4. `--prune-dead` удалял живые источники по 2 шумным прогонам — порог поднят
   до 10 уникальных проверок и 3 провальных прогонов подряд.
5. `--max-sources` не передавался в `collect()` — исправлено.
6. Требовались sing-box/xray даже при fast backend — исправлено.
7. Добавлены метрики прогона: `duration_sec`, `backend`, `sources_count`,
   `geo_unknown`.
8. Переиспользован `cidrlist` этого репозитория (30k сетей) как запасной
   RU-сигнал, когда GeoIP отдаёт пустой код.

## Внедрённые практики (из похожих решений на GitHub)

* **xray-knife как быстрый backend** (0xRadikal/Free-v2ray-Configs,
  Au1rxx/free-vpn-subscriptions): один процесс проверяет тысячи узлов с
  TCP prescan + параллельными HTTP-пробами и пишет CSV с exit_ip, задержкой
  и страной. В 10–20 раз быстрее подъёма ядра на каждый узел.
  `--backend core` оставляет старый точный путь как fallback.
* **Параллельная загрузка источников** пулом 16 потоков.
* **Дедуп по exit_ip** (dmsh-public-contact/sub2singbox) и по URI.

Списки доступны по прямым ссылкам:

```
https://raw.githubusercontent.com/elanski/proxy-preflight/main/singbox-harvest/out/subscriptions_ru.txt
https://raw.githubusercontent.com/elanski/proxy-preflight/main/singbox-harvest/out/subscriptions_other.txt
```

## Источники

Правятся в `singbox-harvest/sources.yaml`, категории `ru` и `other`. Источники
должны отдавать plain/base64/clash-подписки с URI прокси.
