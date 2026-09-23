# B3. Маршруты через AdGuard Home («какие домены в какой туннель»)

## Схема сети gw
```
клиент LAN ---> DNS 10.10.1X.1 ---> nft redirect :53 ---> AdGuard Home (:53)
   AdGuard: домены из правил ---> upstream 127.0.0.1:1053 (sing-box dns-in, fakeip 198.18.0.0/15)
            остальные         ---> Cloudflare DoH/DoT
клиент ---> 198.18.x.x ---> маршрут в singbox-tun ---> sing-box: fakeip -> домен -> route rules:
            domain_suffix [список A] -> mieruNeth ; [список B] -> Finland ; иначе proxy-out
```
Панель должна держать одно место правды: правила «списки доменов → outbound», и из
них раскладывать (а) route rules в конфиг sing-box, (б) upstream-строки в AdGuard.
Сам sing-box конфиг собирается B2 (режим external), этот модуль его дополняет.

## Настройки (`core/config_manager.DEFAULT_CONFIG`, секция `agh_routes`)
```python
"agh_routes": {
    "enabled": False,
    "agh_url": "http://127.0.0.1:3000",   # AdGuard Home API
    "agh_user": "",
    "agh_password": "",                    # хранится как gui.auth_password (маскировать в /api/config)
    "dns_target": "127.0.0.1:1053",        # куда AdGuard шлёт домены из правил
    "singbox_config": "",                  # имя конфига sing-box в /etc/sing-box (без .json)
    "clients": [],                         # [] = глобально; иначе список IP/CIDR клиентов AdGuard,
                                           #   для которых ставится per-client upstream (поэтапное включение)
    "rules": [                             # порядок = приоритет (первое совпадение в sing-box)
        # {"id": "ai", "name": "AI-сервисы", "enabled": True, "outbound": "mieruNeth",
        #  "lists": ["hl:claude", "geosite:openai", "<named list id>"], "domains": ["example.org"]}
    ],
}
```
Источники доменов в `lists`: как в `core/unified/model.Destination.resolve`:
`hl:<name>` (hostlist nfqws2), `ipl:` не поддерживать (только домены), id из
`core/named_lists`, `geosite:<name>` через `core/routing/alias_resolver.expand_domains`
(кэш есть). Итог правила: множество суффиксов доменов, нормализация как
`singbox_config._norm_suffix_domains` (нижний регистр, без `*.`/`www.`, без IP).

## Модуль `core/agh_routes.py`
- `collect(rule) -> list[str]` домены правила (dedup, отсортированы).
- `render_agh_lines(domains, target) -> list[str]`: строки вида
  `[/a.com/b.org/…/]127.0.0.1:1053`, не больше 40 доменов в строке (AdGuard принимает
  длинные, но так читаемо в его UI). Домены всех правил объединяются.
- `plan() -> dict`: без записи. Содержит: `agh: {mode: global|clients, current: [...],
  desired: [...], add: [...], remove: [...]}`, `singbox: {config, rules_desired: [...],
  rules_current: [...]}`, `errors: [...]` (нет связи с AGH, нет конфига sing-box,
  outbound не найден в конфиге, домен в нескольких правилах: предупреждение, берётся первое).
- `apply() -> dict`: (1) sing-box: в `route.rules` конфига удалить ранее поставленные
  нами правила и вставить новые `{"domain_suffix":[...],"outbound":"<tag>"}` сразу
  после `hijack-dns` и до `{"inbound":["tun-in"],...}`; свои правила помечать полем
  `"_zg": "agh_routes"`? Нет: sing-box отвергает неизвестные поля. Хранить список
  поставленных правил в `settings.json` (`agh_routes._applied.singbox`) и удалять по
  точному совпадению; сохранить через `SingboxManager.save_config` после
  `check_text`; если инстанс запущен, перезапустить через штатный restart панели.
  (2) AdGuard: `GET /control/dns_info` → `upstream_dns`; управляемые строки это те,
  что заканчиваются на `]<dns_target>`; заменить их на новые, остальные строки
  оставить как есть; `POST /control/dns_config` с полным телом (обязательные поля
  взять из dns_info). Режим `clients`: вместо глобальных upstream'ов у каждого клиента
  из списка `POST /control/clients/add|update` с `use_global_settings: false`,
  `upstreams: <текущие глобальные не-управляемые> + <наши строки>`; клиента искать
  по `ids` (IP), имя `zg-<ip>` если создаём; при пустом `clients` наши строки у
  таких клиентов снимаются. Basic auth из настроек, таймауты 10 с, ошибки в лог
  панели (`core/log_buffer.log`, source `agh_routes`).
- `test_connection() -> dict`: `GET /control/status` → версия AdGuard.
- Идемпотентность: повторный `apply` без изменений ничего не пишет (сравнить plan).

## API `api/agh_routes.py`
`GET /api/agh-routes` (настройки, пароль замаскирован), `PUT /api/agh-routes`
(частичное обновление; пустой пароль = не менять), `GET /api/agh-routes/sources`
(доступные списки: hostlists, named lists с названиями, известные geosite-алиасы),
`GET /api/agh-routes/plan`, `POST /api/agh-routes/apply`, `POST /api/agh-routes/test`.
Зарегистрировать в `api/__init__.py` как остальные.

## UI
Страница `agh-routes` («Туннель: домены → outbound») в `web/js/pages/agh_routes.js`,
пункт в сайдбаре в группе «Обход DPI (nfqws2)» после «Стратегии» (тогда `gui.hidden_pages`
владельца её не задевает). Блоки: подключение к AdGuard (url, логин, пароль,
кнопка «Проверить» → версия), цель DNS, конфиг sing-box (select из
`/api/singbox/configs`), клиенты (textarea IP по одному), таблица правил
(имя, outbound select из outbounds выбранного конфига, списки multiselect из
`/sources`, свои домены textarea, вкл/выкл, порядок стрелками), кнопки «План»
(показать diff: сколько доменов, какие строки добавятся/уйдут в AdGuard, какие
правила в sing-box) и «Применить». Стиль как у соседних страниц (см.
`web/js/pages/hostlists.js`, `singbox.js`), без новых зависимостей.

## Тесты
`tests/test_agh_routes.py`: рендер строк и чанки, сбор доменов из hl/named/geosite
(мок alias_resolver), plan/apply с моком HTTP (`urllib`), замена только управляемых
строк, режим clients (создание/обновление клиента, снятие), вставка правил в конфиг
sing-box в нужное место и удаление старых, идемпотентность, маскировка пароля в
`/api/config` и `/api/agh-routes`.

## Не делать
Не использовать dnsmasq/ipset/ip rule (`core/routing`). Не включать `dns_intercept`.
Не переписывать `core/unified`.
