# B1. Outbound `mieru` и ссылки `mierus://`

## Контекст
На gw стоит `sing-box-extended 1.14.1-extended-2.7.2` (форк shtorm-7), у него есть
outbound `type: mieru`. Апстримный sing-box его не знает. Панель сейчас не умеет
ни собрать такой outbound, ни разобрать ссылку `mierus://`.

Формат outbound, проверен `sing-box check` на gw (лишние поля декодер отвергает,
`json: unknown field`, поэтому схема точная):
```json
{"type": "mieru", "tag": "mieruNeth",
 "server": "203.0.113.10", "server_ports": ["9000-9010"],
 "transport": "TCP", "username": "user1", "password": "pass1",
 "multiplexing": "MULTIPLEXING_LOW"}
```
`server_ports` это список строк, элемент либо `"9000"`, либо диапазон `"9000-9010"`.
`multiplexing` необязателен (значения по протоколу mieru: `MULTIPLEXING_OFF`,
`MULTIPLEXING_LOW`, `MULTIPLEXING_MIDDLE`, `MULTIPLEXING_HIGH`). `transport`:
`TCP` или `UDP`.

Формат ссылки (значения выдуманные):
```
mierus://user1:pass1@203.0.113.10?multiplexing=MULTIPLEXING_LOW&port=9000-9010&profile=mieruNeth&protocol=TCP
mierus://user2:pass2@203.0.113.20?port=9010-9020&profile=Finland&protocol=TCP
```
`user:pass@host`, query: `port` (один или диапазон, может повторяться или быть
через запятую), `profile` (имя, идёт в `tag`), `protocol` (`TCP`/`UDP`, дефолт TCP),
`multiplexing` (опционально), возможно `mtu` (пропускать в поле `mtu`, если
указан). Схема `mieru://` считать синонимом.

## Что сделать
1. `core/singbox_config.py`: `make_mieru_outbound(tag, server, ports, username,
   password, transport="TCP", multiplexing=None, mtu=None)`; `ports` принимает
   список строк/чисел/диапазонов, нормализует в `server_ports`. Добавить `mieru` во
   все места, где перечислены известные прокси-типы (валидация, `_PLAIN_TYPES`,
   выбор `pick_proxy_outbound`, UI-списки типов, если такие есть: найти grep-ом по
   `hysteria2`/`tuic`).
2. `core/singbox_subscription.py` (или где живёт `uri_to_outbound`): разбор
   `mierus://` и `mieru://` → `make_mieru_outbound`. Ошибки разбора в том же стиле,
   что у других схем.
3. Тесты: `tests/test_singbox_mieru.py` (сборка outbound, нормализация портов,
   разбор ссылки с профилем/без, UDP, несколько портов, ошибочные ссылки).
   Существующие тесты не ломать.
4. В `docs/gw/README.md` ничего не менять. В `.claude/skills/singbox/SKILL.md`
   раздел 5.1 дополнить одной строкой про `mieru` (только extended-сборка).

## Не делать
Не трогать установщик sing-box (панель ставит апстримную сборку без mieru, это
известно; бинарь extended кладётся руками в `/usr/local/bin`).
