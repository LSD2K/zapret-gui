# S7 — Управление движком и правка стратегий

> Вход: [`00-contract.md`](00-contract.md) + этот файл + `HANDOFF.md` + скил `mcp`.
> После этой сессии модель умеет **менять обход**: запускать движок,
> применять стратегии, править user-стратегии, hostlist'ы, blob'ы и lua.
> `strategy_compose`/`strategy_validate` — **не здесь**, они в S11.

## Что прочитать (≈28K)

- Инструменты из S4 (`tools/strategies.py`, `tools/lists.py`) — целиком:
  дописываем write-часть рядом с уже работающей read-частью.
- `core/mcp/audit.py` из S6 — формат снимка (сюда лягут стратегии и списки).
- `core/nfqws_manager.py` — **точечно**: `grep -n "def start\|def stop\|def restart\|def reload\|def get_status\|SIGHUP"`.
- `core/nfqws_reload.py` — целиком (небольшой).
- `core/strategy_builder.py` — `grep -n "def "`: CRUD user-стратегий,
  `autowrap_bare_trick`, `build_nfqws_args`.
- `core/hostlist_manager.py`, `core/ipset_manager.py`, `core/blob_registry.py`,
  `core/lua_manager.py` — по `grep -n "def "` и только write-методы.
- Скил nfqws2 — **только §2 (инварианты)**: что делает стратегию тихо
  неработающей. ~1.5K токенов, не больше.

## Что написать

```
core/mcp/tools/nfqws.py       — nfqws_start/stop/restart/reload_lists, strategy_apply
core/mcp/tools/strategies.py  — дополнить: strategy_save, strategy_delete
core/mcp/tools/lists.py       — дополнить: hostlist_edit, ipset_edit,
                                blob_add, lua_script_save
core/mcp/tools/firewall.py    — дополнить: firewall_apply, firewall_remove
```

### Управление (`control`)

`nfqws_start`, `nfqws_stop`, `nfqws_restart`, `nfqws_reload_lists` (SIGHUP),
`strategy_apply` (по `id`), `firewall_apply`, `firewall_remove`.

`tunnel_up`/`tunnel_down` объявляются здесь же, но требуют **`tunnels_write`**,
а не `control`: «разрешить править стратегии» не должно означать «разрешить
поднять туннель». Остальные туннельные write-инструменты (`*_config_save`,
`subscription_refresh`, `pool_refresh`, `unified_rule_*`) — по остаточному
принципу: если контекст на исходе, вынести в отдельный PR и записать в
HANDOFF, это честнее, чем сделать их наспех.

### Правка (`strategies_write`)

| Инструмент | Смысл |
|---|---|
| `strategy_save` | сохранить/обновить user-стратегию |
| `strategy_delete` | удалить user-стратегию |
| `hostlist_edit` | правка списка доменов (режимы `replace`/`add`/`remove`, лимит размера) |
| `ipset_edit` | то же для ipset'ов |
| `blob_add` | добавить blob (с проверкой размера и формата) |
| `lua_script_save` | сохранить lua-скрипт (с проверкой синтаксиса, если есть чем) |

**Важно про `strategy_save`:** в S7 он сохраняет то, что дали, проверив
базовую форму. Полноценная валидация (`dry_run` через `--intercept=0`) —
инструмент `strategy_validate` из S11. Не дублируй её здесь; но **если
`nfqws_manager.dry_run()` уже есть — вызови его перед сохранением** и положи
результат в ответ полем `validation` (не блокируя сохранение). Это дёшево и
сильно помогает модели.

## Правила безопасности этой сессии

1. **Каждый мутирующий вызов пишет снимок** в аудит (S6) — иначе
   `mcp_undo_last` для стратегий и списков не заработает.
2. **`firewall_apply`/`firewall_remove` не должны рвать управление.** Порт
   GUI и SSH исключаются. Проверить, что `core/firewall.py` это уже делает
   (`grep -n "gui.port\|22\|ssh\|exclude"`); **если нет — добавить и покрыть
   тестом**. Это прямое требование плана, не опция.
3. **Списки заменяются целиком** — та же логика, что у `config_set` (S6):
   в описании инструмента явно сказать модели, что `replace` затирает всё,
   и предложить `add`/`remove` для точечных правок.
4. Лимиты размера на всё, что пишется: hostlist, ipset, blob, lua. Роутер со
   128 МБ RAM не должен получить файл на 200 МБ через MCP.
5. Имена файлов и списков — валидировать по белому списку символов, никакой
   подстановки пути (`../`, абсолютные пути, слеши внутри имени).

## Тесты

| Файл | Что фиксирует |
|---|---|
| `tests/test_mcp_control.py` | `nfqws_start/stop/restart/reload_lists` и `strategy_apply` на monkeypatch'нутом менеджере; без `control` инструмент не в `tools/list` и не вызывается по имени; движок не установлен → честный `isError`, а не исключение |
| `tests/test_mcp_strategies_write.py` | CRUD user-стратегии; снимок в аудите; `mcp_undo_last` откатывает сохранение и удаление; имя с `../` отклоняется; лимит размера |
| `tests/test_mcp_lists_write.py` | режимы `replace/add/remove`; лимиты; откат через `mcp_undo_last` |
| `tests/test_mcp_firewall.py` | порт GUI и SSH исключены из правил, применяемых из MCP (сторож: правило с ними ломает тест) |
| `tests/test_mcp_tool_counts.py` | обновить числа |

## Приёмка

- Модель с `control` + `strategies_write` проходит цикл: собрать список →
  сохранить стратегию → применить → перезапустить движок → откатить всё
  через `mcp_undo_last`.
- Без `control` ни один из этих инструментов не виден и не вызывается.
- `python3 -m pytest tests/ -q` зелёный: поведение существующего UI и
  сканера не изменилось.

## Грабли

- **`strategy_apply` и сканер дерутся за nfqws2.** Полноценный общий мьютекс
  — это S9. Здесь: если сканер занят, вернуть `isError` с понятным текстом
  («идёт скан, остановите его или дождитесь»), а не применять поверх.
  Проверку сделать так, чтобы S9 мог её заменить одной строкой.
- **SIGHUP ≠ рестарт.** `nfqws_reload_lists` перечитывает списки без
  перезапуска; не подменяй одно другим — модель будет считать, что «перезапуск
  не помог», хотя перезапуска не было.
- **Пустой hostlist — это выключенный фильтр, а не «ничего не изменилось».**
  Предупреждать в ответе.

## Оставить следующим

`HANDOFF.md` + скил: как берётся защита от конкуренции со сканером (S9
заменит её на общий мьютекс), какие снимки пишутся для стратегий и списков,
что осталось из туннельных write-инструментов, если их вынесли.
