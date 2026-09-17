# S12 — Shell и система

> Вход: [`00-contract.md`](00-contract.md) + этот файл + `HANDOFF.md` + скил `mcp`.
> Контекста проекта почти не нужно (~20K): это самостоятельный модуль.
> Независима от волн C и D — можно вести параллельно после S2.
>
> **Порядок по риску.** Shell стоит в конце намеренно: включать его разумно
> на сервере, который уже проверен в бою. Технически сессия независима, но
> разрешения по умолчанию — `false`, и это не обсуждается.

## Зачем

Из LM Studio пользователь должен управлять **роутером целиком**, а не только
нашим GUI: «поставь пакет», «покажи, что жрёт память», «перезапусти dnsmasq»,
«почему не резолвится домен». Логика — в `core/shell_exec.py` (пригодится и
диагностике, и будущему терминалу в GUI), MCP — обёртка.

## Что прочитать (≈20K)

- `core/blockcheck2.py` — **образец async-задачи** (`grep -n "def \|offset\|Popen"`).
- `core/ext_binary_installer.py` — `grep -n "opkg\|apk\|def _detect"`: как
  детектится пакетный менеджер.
- `core/system_control.py` — целиком: как уже делается отвязанный процесс и
  рестарт (нужно для `system_reboot`).
- `core/safe_io.py` — `atomic_write_*` для `file_write`.
- `core/mcp/redact.py` (S2) и `core/mcp/audit.py` (S6).

## Что написать

```
core/shell_exec.py             — исполнение: argv/sh -c, таймаут, лимиты, guard'ы, async
core/mcp/tools/shell.py        — shell_exec, shell_exec_async, shell_job_*, shell_confirm
core/mcp/tools/files.py        — file_read, file_list, file_write
core/mcp/tools/packages.py     — package_list/install/remove
core/mcp/tools/services.py     — service_list, service_control
core/mcp/tools/system.py       — system_reboot
```

| Инструмент | Разрешение | Что делает |
|---|---|---|
| `shell_exec` | `shell_readonly`/`shell_full` | При `shell_readonly` — только safe-список и **только argv-режим** (без `sh -c`, пайпов, редиректов, подстановок). При `shell_full` — произвольная строка через `sh -c` |
| `shell_exec_async`, `shell_job_status/output/stop` | те же | долгие команды: `job_id`, инкрементальный вывод по `offset` |
| `shell_confirm` | те же | второй шаг для `confirm_patterns`; принимает `confirm_token` или `run_id` (для guard) |
| `file_read` | `shell_readonly` | `path`, `offset`, `limit_kb`, `tail`. Безопаснее `cat`: лимиты + редактирование секретов |
| `file_list` | `shell_readonly` | имя, размер, права, mtime |
| `file_write` | `shell_full` | только внутри `shell.allow_write_paths`, атомарно, с бэкапом прежней версии в аудит |
| `package_list/install/remove` | `shell_readonly`/`shell_full` | обёртки над `opkg`/`apk`; `remove` требует подтверждения |
| `service_list/control` | `shell_readonly`/`shell_full` | `/opt/etc/init.d/*` и `/etc/init.d/*`: `start\|stop\|restart\|status`. Имя валидируется **по списку найденных скриптов** — никакой подстановки в команду |
| `system_reboot` | `dangerous` | только через `shell_confirm`, через `core/system_control.py` (на Keenetic — `ndmc`), отложенным запуском в отвязанном процессе, чтобы успел уйти ответ |

## Правила исполнения (`core/shell_exec.py`) — это и есть спека модуля

1. `stdin=/dev/null` — команда не может уйти в интерактивный запрос и повиснуть.
2. `env` минимальный (`PATH`, `HOME`, `LANG=C`), **без переменных процесса GUI**.
3. Таймаут обязателен (`timeout_sec` ≤ `shell.max_timeout_sec`): `SIGTERM`,
   затем `SIGKILL`; в ответе `timed_out: true`.
4. Вывод: `stdout`+`stderr` слиты, обрезка до `shell.output_kb`
   (`truncated: true`, **сохраняется хвост** — он информативнее), к тексту
   применяется `redact()`: `cat` конфига с паролем не должен утечь в
   облачную модель.
5. Ответ: `{ok, returncode, output, truncated, timed_out, duration_ms, command}`.
6. **`deny_patterns`** — жёсткий отказ, **не обходится подтверждением**:
   запись в `/dev/mtd*`, `mkfs`, `sysupgrade`, `firstboot`, `dd of=/dev/…`,
   `rm -rf /` и `rm -rf /opt` без уточнения, смена пароля root,
   `chmod -R 777 /`. Список — константа модуля, покрытая тестом.
7. **`confirm_patterns`** — двухшаговое подтверждение: `reboot`, `halt`,
   `opkg remove`/`apk del`, `rm -rf`, `iptables -F`/`nft flush ruleset`,
   `ifconfig … down`/`ip link set … down`, правка `/etc/passwd`, остановка
   `dropbear`/`sshd`. Первый вызов → `isError: true` + `confirm_token`
   (живёт 60 с, одноразовый) + человеческое описание последствий.
8. **`guard` (дедмен-свитч)**: `{revert_cmd: "…", ttl_sec: 120}` — после
   команды заводится таймер, который выполнит `revert_cmd`, если не пришёл
   `shell_confirm` с `run_id`. **Обязателен проверкой в коде** для команд,
   матчащих сетевые `confirm_patterns`: именно так модель не отрежет себе и
   пользователю доступ к роутеру.
9. Параллелизм: одна синхронная команда за раз, ≤ `shell.max_jobs` async.
10. **Никаких `shell=True` с f-строками.** `shell_full` передаёт строку
    **одним аргументом** в `["sh", "-c", command]`; остальные инструменты
    собирают `argv` из валидированных частей.

Полные примеры обмена (подтверждение и guard) — Приложение C плана:
`grep -n "Приложение C" -A 35 docs/mcp-server-plan.md`.

### Safe-список для `shell_readonly`

`uname, uptime, free, df, ls, cat, head, tail, ps, top -n1, netstat, ss, ip,
ifconfig, route, arp, iptables -L/-S, nft list, conntrack -L, dmesg, logread,
nslookup, dig, ping -c, traceroute, opkg list-installed, apk info, wg show,
awg show, curl -sI, date, mount, lsmod, cat /proc/*`. Для каждого —
разрешённые флаги; всё, что не в списке, — отказ с подсказкой «нужен
`shell_full`». Список расширяется в скиле `mcp`, а не в коде наспех.

## Тесты

| Файл | Что фиксирует |
|---|---|
| `tests/test_mcp_shell.py` | разрешённая команда выполняется; `sh -c` при `shell_readonly` отклоняется; таймаут → `timed_out`; обрезка сохраняет хвост; `env` не содержит переменных процесса GUI; `stdin` закрыт |
| `tests/test_mcp_shell_guards.py` | `deny_patterns` отклоняются **всегда** — в т.ч. с лишними пробелами, кавычками и `env`-префиксом; `confirm_patterns` требуют `confirm_token`, токен одноразовый и протухает; сетевая команда без `guard` отклоняется; дедмен выполняет `revert_cmd` по TTL |
| `tests/test_mcp_shell_redaction.py` | вывод `cat` конфига с паролем/ключом приходит замаскированным |
| `tests/test_mcp_files.py` | `file_write` вне `allow_write_paths` отклоняется; запись атомарна; прежняя версия попадает в аудит и откатывается `mcp_undo_last` |
| `tests/test_mcp_no_dangerous.py` | нет инструмента `teardown`; `system_reboot` существует только под `dangerous` и не выполняется без подтверждения |

## Приёмка

- При `shell_readonly` модель диагностирует роутер (`ps`/`df`/`logread`/`ip`/
  `nslookup`), но **не может ничего изменить**.
- При `shell_full` ставит пакет и перезапускает службу.
- Команда из `deny_patterns` отклоняется; `reboot` требует подтверждения.
- Команда, гасящая интерфейс, без `guard` не выполняется, а с `guard`
  откатывается по TTL — **проверить на устройстве с секундомером**.
- Всё видно в журнале аудита с кодом возврата и первыми строками вывода.

## Грабли

- **Обход `deny_patterns` тривиален**, если сравнивать строки наивно:
  `env  rm   -rf /`, `"rm" -rf /`, `/bin/rm -rf /`. Нормализуй команду
  (пробелы, кавычки, префиксы `env`/абсолютные пути) **до** матчинга и
  покрой это тестом — иначе защита декоративная.
- **`shell_full` = root для всякого, у кого есть токен** — и для модели,
  которая читает логи и файлы, а значит потенциально исполняет то, что
  кто-то в эти логи записал. Предупреждение в UI и README — не формальность.
- **Дедмен должен пережить рестарт GUI.** Таймер в памяти процесса,
  который сам же и падает, ничего не откатит: писать guard на диск.
- `/tmp` на роутере — tmpfs: ни журнал, ни guard туда не класть.

## Оставить следующим

`HANDOFF.md` + скил: safe-список, `deny_patterns`, `confirm_patterns`, формат
guard'а и где он хранится, контракт async-задачи shell (S15 показывает список
команд и кнопку «запретить shell немедленно»).
