# MCP: эстафета между сессиями

> Одна страница, которую **каждая сессия перезаписывает в конце**. Следующая
> сессия читает её вместо того, чтобы реконструировать состояние по диффам.
> Держать в пределах ~120 строк: это не журнал, а снимок «где мы сейчас».
>
> Шаблон записи — в конце файла.

---

## Состояние: после S8 (активные пробы, сканер, blockcheck)

**Дата:** 2026-09-18 · **Ветка/PR:** `claude/zen-fermi-1188qf`

### Сделано

- `core/probe_runner.py` (405) — **не в пакете MCP**: `probe_many`,
  `probe_target`, `fold`, `compare`, `clean_targets`, `limits`,
  `VERDICTS`. Пробы по списку целей и сравнение «с обходом и без»
  одним кодом для MCP, CLI и UI.
- `core/mcp/tools/_jobs.py` (190) — асинхронная задача: `job_id`,
  `resolve`, `is_current`, `update`, `describe`, `running_id`. Записи
  переживают конец прогона (`KEEP` на вид).
- `core/mcp/tools/probes.py` (320) — `probe_targets`, `probe_compare`
  (`probes`), `connectivity_matrix` (чтение + `refresh` по `probes`).
- `core/mcp/tools/scan.py` (490) — `scan_start`, `scan_stop`
  (`probes`), `scan_status`, `scan_results` (чтение), `scan_apply`
  (`control` + внутренняя проверка `strategies_write`).
- `core/mcp/tools/blockcheck.py` (520) — `blockcheck_start`,
  `blockcheck2_start`, `blockcheck2_stop`, `healthcheck_run`
  (`probes`); `blockcheck_status`, `blockcheck2_status`,
  `blockcheck2_output`, `healthcheck_status` (чтение).
- `core/nfqws_control.py` — `running()` (состояние движка без побочных
  действий) и `_is_running()` (см. «что оказалось не так», п. 3).
- `core/config_manager.py` — секция `mcp.probes` (`max_targets`,
  `max_repeats`, `timeout_sec`, `budget_sec`, `parallel`,
  `settle_sec`).
- `core/mcp/redact.py` — у `pass` в `SECRET_KEY_RE` появилась оглядка
  назад: `with_bypass`/`without_bypass` уезжали как `"***"`.
- тесты: `test_mcp_probes.py` (22), `test_mcp_jobs.py` (20),
  дополнен `test_mcp_permissions.py` (+5, класс `TestProbesBoundary`),
  правлен `test_mcp_tool_counts.py` (`read: 32`, `probes: 8`,
  `control: 8` + поимённые списки). По `test_mcp_*` — **565 зелёных**;
  весь `tests/` — 3395 passed, 1 skipped; `make lint` чист.

### Зафиксированные контракты

**`probe_compare` — то, на чём S10 строит baseline.** `with_bypass` /
`without_bypass` / `verdict`; вердикт только из
`probe_runner.VERDICTS` (`bypass_helps`, `no_difference`,
`target_down`, `bypass_hurts`, `unknown`), код только из
`PROBE_CODES`. Неизмеренная сторона — `measured: false` + `reason`, и
тогда вердикт `unknown`: выдуманная половина хуже отсутствующей.

**Переключение движка в `compare` требует `control` вдобавок к
`probes`** и возвращает исходное состояние в `finally` (`restored`,
`restore_error` в ответе). Без `control` инструмент не отказывает, а
отдаёт одну сторону и называет переключатель.

**Асинхронный контракт**: `*_start` → `job_id` + `async: true` сразу;
`*_status` → живой статус либо сохранённый снимок (`live`, `done`,
`job_note`); `*_output` → инкремент по `offset` → `next_offset`;
второй старт при занятом движке → `isError` с активным `job_id`.
Задача переживает конец прогона; ярлык старой задачи живым статусом
не отвечает (`_jobs.is_current`).

**Своё пояснение — в `job_note`, а не в `note`.** `note` в этих
ответах занят пометкой «untrusted data».

**Лимиты проб — `mcp.probes`**, схема режет вдобавок на уровне
протокола. Лишние цели уезжают в `rejected` с причиной, не влезшие в
бюджет — в `skipped`. Повторы сворачиваются по СТРОГОМУ большинству
(`fold`).

**Опрос — чтение, прогон — проба.** `scan_status`/`scan_results`,
`*_status`, `blockcheck2_output`, `healthcheck_status` и снимок
`connectivity_matrix` пакетов не выпускают и живут в read-наборе;
`*_start`/`*_stop`/`healthcheck_run`/`refresh` — под `probes`.

### Следующий шаг

**S9** — [`09-nfqws-session.md`](09-nfqws-session.md): общий мьютекс на
движок. Подключаться к `nfqws_control.busy()`: заменить её тело
опросом сессии, вызывающих (`tools/nfqws.py`, `tools/scan.py`,
`tools/blockcheck.py` — все зовут `_busy_refusal`) не трогать. Сканер
переводится на ту же сессию. Учесть: `probe_compare` тоже трогает
движок (`nfqws_control.stop/start`) и обязан брать ту же сессию, иначе
скан и сравнение подерутся.

**S10** — [`10-experiments.md`](10-experiments.md): движок
экспериментов. Baseline — `probe_runner.compare()` и
`probe_runner.probe_many()` (не писать свои пробы), применение
варианта — `nfqws_control.apply_strategy`, авто-откат — снимок вида
`strategy_active`. Лимиты эксперимента уже лежат в `mcp.experiment`,
лимиты проб — в `mcp.probes`.

**S15** — [`15-ui.md`](15-ui.md): на странице MCP у `probes` теперь 8
инструментов, у чтения 32; `any_write` — не переключатель.

### Что оказалось не так, как написано в задании

1. **`connectivity_matrix` — чтение, а не `probes`.** Задание
   перечисляет его среди инструментов проб, но у матрицы есть
   сохранённый снимок, и прятать его целиком значило бы повторить
   ошибку, от которой S5 отказался на `updates_check`. Сделано так же:
   инструмент в read-наборе, `refresh=true` — по `probes`.
2. **`scan_apply` — `control`, и этого мало.** Он не только поднимает
   движок, но и сохраняет найденное как USER-стратегию
   (`scanner._apply_probe_result`). Scope один, поэтому
   `strategies_write` спрашивается внутри обработчика; иначе `control`
   в одиночку открыл бы запись стратегий.
3. **`busy()` не видела наш blockcheck.** У `Blockcheck2Runner`
   `is_running` — метод, у `BlockcheckRunner` — `@property`;
   безусловный вызов бросал `TypeError`, который съедался общим
   `except`. То есть стратегия применялась прямо поверх идущих проб
   (наследство S7, найдено при подключении `blockcheck_start`).
   Починено в `nfqws_control._is_running()`.
4. **`with_bypass` маскировался как секрет.** `SECRET_KEY_RE` ловил
   `pass` внутри `bypass`. Имена полей заданы контрактом задания и
   нужны S10, поэтому переименовать было нельзя — сужен регексп
   (`(?<![a-z])pass`). Побочно перестал маскироваться
   `opera_proxy.proxy_bypass` (список доменов, не секрет).
5. **`blockcheck_status` в задании не назван.** Без него асинхронный
   контракт для нашего blockcheck неполон: `dpi_report` отдаёт
   готовый отчёт, но не прогресс идущего прогона.
6. **Свободный `params` для blockcheck2 не отдан модели.** Вместо
   произвольного env — фиксированные аргументы (`ipv`, `repeats`,
   `http`, `tls12`, `tls13`, `http3`), которые `_env_params`
   раскладывает в `IPVS`/`REPEATS`/`ENABLE_*`. Произвольный env — это
   `PATH` и `LD_PRELOAD` в руках модели.

### Грабли

- **Пустой `active_strategy_args()` ≠ «запусти как есть».** Поднять
  голый nfqws2 и назвать это «с обходом» — прямая ложь в baseline;
  `compare` в этом случае отдаёт неизмеренную сторону с причиной.
- **Бюджет времени режет ЗАПУСК проб, а не их длительность.** Задачи,
  уже отправленные в пул, доработают: `budget_sec` проверяется между
  порциями.
- **`limits()` поднимает всё до 1, кроме `settle_sec`.** Иначе
  `settle_sec=0` превращается в секунду — и восемь тестов сравнения
  стоят восемь секунд.
- **Runner помнит один прогон.** `_jobs` помнит несколько ярлыков, и
  живой статус можно отдавать только под последним. Для
  `blockcheck2_output` это прямой отказ: чужих строк у нас нет.
- **`healthcheck.run_now(blocking=True)` — это до ~30 секунд.**
  Инструмент зовёт `blocking=False` и отправляет модель за
  результатом в `healthcheck_status`.
- **Сканер применяет стратегию своим кодом**, не через
  `nfqws_control`. Оборачивать его новой логикой нельзя (S8 не меняет
  поведение сканера), поэтому снимок для отката снимается снаружи:
  `strategy.current_id` читается до и после вызова.
- **`_paging.unavailable()` отдаёт `ok: true`.** «Сканера на
  устройстве нет» — это ответ, а не сбой вызова; тест на это
  опирается.

---

## Шаблон записи (перезаписывать, не дописывать)

```markdown
## Состояние: после SNN (<название сессии>)

**Дата:** YYYY-MM-DD · **Ветка/PR:** <ссылка>

### Сделано
- <файл> — <что в нём теперь есть> (<строк>)
- тесты: <какие файлы, что фиксируют>, прогон зелёный

### Зафиксированные контракты
- <имя> — <сигнатура/формат, который следующие сессии обязаны соблюдать>

### Следующий шаг
**SNN+1** — <файл задания>: <первое, за что браться>, <где подключиться к
написанному>.

### Что оказалось не так, как написано в задании
- <расхождение> → <принятое решение и где оно записано>

### Грабли
- <то, на что потрачено время и что не видно из кода>
```
