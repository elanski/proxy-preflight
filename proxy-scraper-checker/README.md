# HTTP/SOCKS scrape & check (`http-socks-scrape.yml`)

Отдельный конвейер для HTTP/SOCKS4/SOCKS5 прокси, не пересекающийся с
xray-проверкой VLESS/VMess/Hysteria подписок (`check-proxies.yml`,
`nightly-check.yml`, `singbox-harvest.yml`).

## Как работает

1. В CI собирается vendored-копия `monosans/proxy-scraper-checker`
   (исходники в `proxy-scraper-checker/`, катом в `UPSTREAM.md`).
2. Бинарник читает `proxy-scraper-checker/config.toml` (~50 публичных источников)
   и проверяет каждый прокси полной загрузкой `https://ipv4.icanhazip.com`.
   Прокси, который conectится, но не отдаёт весь ответ в timeout, отбрасывается.
3. Результат — `http_socks_verified.txt` в корне репо (строки вида
   `http://host:port`, `socks5://user:pass@host:port`), коммитится ботом.
4. Оттуда список вручную грузится на Deca2.

## Расписание и изоляция

- `cron: "42 */6 * * *"` — каждые 6 часов в :42.
- Своя `concurrency`-группа `proxy-preflight-http-socks`: не блокирует
  серийные xray-прогоны.
- Перед запуском `out/` удаляется принудительно: бинарник намеренно не
  затирает прошлый результат, если не нашёл ни одного живого прокси, —
  без очистки в репо ушёл бы устаревший список.

## Обновление апстрима

Исходники скопированы с `main` репозитория `monosans/proxy-scraper-checker`.
Чтобы обновить: заменить содержимое `proxy-scraper-checker/src`, `Cargo.toml`,
`Cargo.lock`, сохранив наш `config.toml` и `.gitignore`.
