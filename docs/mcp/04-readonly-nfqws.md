# S4 — Read-only: nfqws2

> Вход: [`00-contract.md`](00-contract.md) + этот файл + `HANDOFF.md` + скил `mcp`.
> Однотипная сессия: берём эталон из S2 и **копируем форму** на десяток
> инструментов. Рассуждать тут почти не о чем — ценность в единообразии.
> Независима от S5, можно вести параллельно.

## Что прочитать (≈28K)

- Эталонные инструменты из S2 (`core/mcp/tools/status.py`, `config.py`) —
  целиком. Это главный вход.
- По `grep -n "def "` (и только нужные диапазоны!):
  `core/strategy_builder.py`, `core/catalog_loader.py`, `core/lua_manager.py`,
  `core/blob_registry.py`, `core/hostlist_manager.py`, `core/ipset_manager.py`,
  `core/named_lists.py`, `core/strategy_state.py`, `core/block_detector.py`.
- `core/firewall.py` — **только** `grep -n "def get_status\|def status\|backend\|conflict"`.
- **Не открывать целиком:** `strategy_scanner.py`, `firewall.py`,
  `blockcheck.py`, `web/js/pages/strategies.js`.
- Полезный приём: спросить `Explore`-субагента «какой менеджер отдаёт список
  стратегий с признаком активной и как выглядит его результат» — вернётся
  абзац вместо файлов.

## Что написать

```
core/mcp/tools/strategies.py  — strategy_list, strategy_get, catalog_search,
                                strategy_state_list, nfqws_command_preview
core/mcp/tools/lists.py       — hostlists_list, hostlist_get, ipsets_list,
                                lists_list, blobs_list, lua_functions_list
core/mcp/tools/firewall.py    — firewall_status
core/mcp/tools/traffic.py     — traffic_recent
```

| Инструмент | Возвращает |
|---|---|
| `strategy_list` | стратегии (builtin+user): `id/name/protocol/level/featured/is_active`, фильтры + пагинация |
| `strategy_get` | одна стратегия целиком (профили, args) |
| `catalog_search` | поиск по INI-каталогам: протокол, уровень, подстрока, приём (`fake`, `split`, `disorder`, `oob`, …) |
| `nfqws_command_preview` | итоговый argv/командная строка для текущей или указанной стратегии (`strategy_builder.build_preview_command`) |
| `lua_functions_list` | доступные `--lua-desync` функции с параметрами и требованиями — **ключевой инструмент против «тихого 0%»** |
| `blobs_list`, `hostlists_list`, `hostlist_get`, `ipsets_list`, `lists_list` | ассеты и списки, с пагинацией |
| `firewall_status` | применённые правила, backend, конфликты |
| `strategy_state_list` | выученные circular-стратегии из `state.tsv` |
| `traffic_recent` | см. ниже |

### `traffic_recent` — почему он отдельно и почему важен

Отвечает на вопрос **«дошёл ли трафик до движка»**, который **не равен**
вопросу «настроен ли домен» (`hostlists_list`/`strategy_get`). У b4 это
разделение `b4_recent_connections` vs `b4_check_domain`, и оно ровно отличает
ошибку в целях от ошибки в маршрутизации — без него модель будет чинить
стратегию там, где сломан перехват.

Что отдавать: домен/SNI, сработавший профиль, вердикт, время — за последние
N минут. Источники: лог nfqws2 (при `nfqws.debug`), `core/block_detector.py`,
conntrack. Если `nfqws.debug` выключен — сказать об этом прямо и подсказать,
какую настройку включить (она writable, см. `logging.*`/`nfqws.*`).

## Правила этой сессии

1. **Никакой новой логики в `core/mcp/tools/*`.** Не хватает функции —
   добавь в соответствующий `core/*.py` (она станет доступна и UI/CLI).
2. **Все списки — с пагинацией и лимитами**, `truncated: true`, стабильная
   сортировка. Ответ модели, а не дамп: `hostlist_get` на списке из 50 тысяч
   доменов должен отдать окно и общее число, а не 2 МБ.
3. **Единые имена полей** во всех инструментах: `items`, `total`, `offset`,
   `limit`, `truncated`. Разнобой здесь — это разнобой в контексте модели.
4. Данные из внешнего мира (домены, SNI, строки лога) — помечать
   `untrusted data` в описании поля.
5. Обновить `tests/test_mcp_tool_counts.py` — числа изменятся, это ожидаемо.
6. Обновить скил `mcp`: строка на инструмент в таблице реестра.

## Тесты

| Файл | Что фиксирует |
|---|---|
| `tests/test_mcp_tools_nfqws.py` | каждый инструмент на monkeypatch'нутых менеджерах: форма ответа, пагинация, фильтры, поведение при «менеджера нет / бинаря нет» (честный ответ, не исключение) |
| `tests/test_mcp_tool_counts.py` | обновить ожидаемые числа |
| `tests/test_mcp_redaction.py` | проходит автоматически (сторож перебирает реестр) — убедиться, что новые инструменты в него попали |

## Приёмка

- Модель read-only может ответить: что сейчас применено, какие есть
  стратегии и списки, какие lua-функции доступны, дошёл ли трафик до движка.
- Ни один ответ не превышает `mcp.limits.response_kb`.
- На dev-машине без nfqws2 все инструменты отвечают корректно («бинарь
  недоступен»), а не падают.

## Грабли

- **`is_active` вычисляется, а не хранится.** Проверь, как это делает UI
  (`api/strategies.py`), и переиспользуй — иначе модель будет уверена, что
  применена не та стратегия.
- **`catalog_search` без фильтров** способен вернуть тысячи записей: лимит по
  умолчанию обязателен.
- **Не дублируй `lua_functions_list` из скила.** Источник — `lua_manager` и
  карта расширений: в Lua неизвестное имя не ошибка загрузки, а тихо
  неработающая стратегия.

## Оставить следующим

`HANDOFF.md` + скил: таблица добавленных инструментов, куда какие поля
пришли из менеджеров, что пришлось добавить в `core/*.py` (S7 будет
дописывать туда же write-операции).
