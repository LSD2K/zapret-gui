# B2. FakeIP с внешним фронт-DNS (AdGuard Home)

## Контекст
`core/singbox_fakeip.build_and_save` → `singbox_config.build_fakeip_config`
собирает конфиг «podkop-стиля»: TUN с `auto_route=true`, `strict_route=true`, на
nft ещё `auto_redirect=true`, sing-box сам становится DNS всей LAN. На gw фронт-DNS
это AdGuard Home на :53 (логи по клиентам, фильтры, только Cloudflare DoH). Нужен
режим, где AdGuard остаётся впереди и шлёт sing-box только домены из списка.

Целевой конфиг (проверен `sing-box check` на extended 1.14.1):
```json
{
  "log": {"level": "info"},
  "dns": {
    "servers": [
      {"type": "https", "tag": "dns-direct", "server": "1.1.1.1", "detour": "direct"},
      {"type": "fakeip", "tag": "dns-fakeip", "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18"}
    ],
    "rules": [
      {"query_type": ["AAAA"], "action": "predefined", "rcode": "NOERROR"},
      {"query_type": ["A"], "server": "dns-fakeip"}
    ],
    "final": "dns-direct"
  },
  "inbounds": [
    {"type": "direct", "tag": "dns-in", "listen": "127.0.0.1", "listen_port": 1053, "network": "udp"},
    {"type": "tun", "tag": "tun-in", "interface_name": "singbox-tun", "address": ["172.19.0.1/30"],
     "auto_route": false, "strict_route": false, "stack": "system"}
  ],
  "outbounds": [ ...прокси..., {"type": "selector", "tag": "proxy-out", ...}, {"type": "direct", "tag": "direct"} ],
  "route": {
    "rules": [
      {"action": "sniff"},
      {"protocol": "dns", "action": "hijack-dns"},
      {"inbound": ["tun-in"], "outbound": "proxy-out"}
    ],
    "final": "direct",
    "auto_detect_interface": true,
    "default_domain_resolver": "dns-direct"
  },
  "experimental": {"cache_file": {"enabled": true, "path": "/var/lib/sing-box/cache.db", "store_fakeip": true}}
}
```
Смысл: AdGuard для доменов из списка использует upstream `127.0.0.1:1053`; sing-box
отдаёт fakeip (A) и пустой ответ на AAAA (IPv6 в сети нет); маршрут `198.18.0.0/15`
ведёт в `singbox-tun` (ставится снаружи, networkd); всё, что пришло из TUN, идёт в
`proxy-out`; реальные имена sing-box резолвит сам через DoH 1.1.1.1. Доменные правила
`domain_suffix → <outbound>` внутрь route добавляет отдельный модуль (B3), сборщик
их не генерирует, но не должен ломать (правила вставляются перед `inbound tun-in`).

## Что сделать
1. `build_and_save` и `build_fakeip_config`: новые параметры
   `front_dns: str = "engine"` (`engine` = как сейчас; `external` = схема выше),
   `dns_listen: str = "127.0.0.1"`, `dns_port` уже есть (дефолт 1153 оставить для
   engine, для external дефолт 1053 в UI). В режиме `external`:
   - TUN: `auto_route=false`, `strict_route=false`, без `auto_redirect`, адрес
     параметром `tun_address` (дефолт `172.19.0.1/30`), `stack` параметром (дефолт `system`)
   - inbound `dns-in` типа `direct` на `dns_listen:dns_port`, `network: udp`, всегда,
     независимо от nft/iptables; никакого перехвата :53 (`capture_dns` игнорируется,
     `_apply_dns_capture` не вызывать для таких конфигов: признак режима хранить в
     `settings.json` рядом с конфигом, см. п.4)
   - dns rules: AAAA → `predefined NOERROR`, A → fakeip; `domain_suffix`-правила для
     fakeip НЕ нужны (в sing-box приходят только домены, которые прислал AdGuard);
     `route.rules`: `sniff`, `hijack-dns`, `{"inbound":["tun-in"],"outbound":"proxy-out"}`;
     `ip_is_private → direct` не добавлять (fakeip-диапазон приватный, правило
     утянуло бы всё в direct)
   - `default_domain_resolver` = тег direct-DNS, всегда (1.14 без него падает)
   - `cache_file.path` абсолютный: `<platform.run_dir или /var/lib/sing-box>/cache-<name>.db`,
     каталог создавать при сохранении
2. `direct_dns` (обе ветки, typed): принимать `https://host/path`, `tls://host`,
   `ip:port`, `udp://ip:port`; typed-серверы соответственно `https`/`tls`/`udp` с
   `detour: direct`. Сейчас всё, кроме `local` и голого IPv4, молча превращается в
   `local`, это баг.
3. Несколько прокси: в режиме `external` `proxy_config` может содержать несколько
   outbounds и группы (`selector`/`urltest`). Брать все outbounds/endpoints как есть;
   если среди них нет тега `proxy-out`, создать `selector` с тегом `proxy-out` из всех
   прокси-outbound'ов (первый по умолчанию). `proxy_link` по-прежнему один прокси.
4. Хранение режима: `settings.json` → `singbox.fakeip_front[<name>] = {"front_dns":
   "external", "dns_listen": ..., "dns_port": ...}` (или аналогичный существующий
   механизм sidecar, если есть). `SingboxManager._do_up/_do_down`: для конфигов с
   `front_dns=external` не трогать transparent/dns-capture. `_config_dns_in_port`
   сейчас распознаёт `dns-in` и тянет за собой iptables-REDIRECT на LAN :53, в
   режиме external это запрещено.
5. UI (`web/js/pages/singbox.js`, карточка FakeIP): переключатель «Фронт-DNS:
   sing-box (перехват LAN) / внешний (AdGuard Home, слушать 127.0.0.1:1053)», поля
   адрес/порт, `direct_dns` с подсказкой `https://1.1.1.1/dns-query`. Показывать в
   результате сборки строку-подсказку: «в AdGuard добавьте upstream
   `[/домен/]127.0.0.1:1053`» (B3 сделает это сам, подсказка для ручного режима).
6. `api/singbox.py`: пробросить новые параметры в `/api/singbox/fakeip/build` и
   отдать дефолты в `/api/singbox/fakeip/options`.
7. Мелочь: `/api/singbox/version` для бинаря, чья версия содержит `extended`
   (или не совпадает с форматом релизов панели), отдавать `has_update: false` и
   `external_build: true`; UI кнопку «обновить» для такого бинаря не показывать.
8. Тесты: `tests/test_singbox_fakeip_front.py`: сборка external-конфига (точная форма
   JSON выше, с учётом п.1-3), `direct_dns` варианты, несколько прокси, режим engine
   не изменился (снапшот существующего поведения), `_do_up` не вызывает capture.

## Не делать
Не менять поведение режима `engine` (Keenetic/OpenWrt пользователи апстрима).
Не трогать `core/routing`, `dns_intercept`, `dnsmasq_integration`.
