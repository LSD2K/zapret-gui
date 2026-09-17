# S8 — Активные пробы

> Вход: [`00-contract.md`](00-contract.md) + этот файл + `HANDOFF.md` + скил `mcp`.
> Здесь модель начинает **выпускать трафик с роутера**. Это отдельное
> разрешение `probes`, а не часть чтения: выпустить трафик — не то же самое,
> что записать настройку (и это нагрузка на роутер, и следы в сети
> провайдера).

## Что прочитать (≈30K)

- `core/testers/probe.py` — целиком: `PROBE_CODES` (единый словарь кодов,
  на нём же построен S10).
- `core/testers/tls_tester.py`, `body_tester.py` — по `grep -n "def "`.
- `core/blockcheck2.py` — **образец асинхронной задачи**: старт, `job_id`,
  инкрементальный вывод по `offset`, стоп. Читать целенаправленно:
  `grep -n "def \|offset\|job"`.
- `core/blockcheck.py` — **только** `grep -n "def start\|def status\|def stop\|classif"`.
- `core/strategy_scanner.py` — **только** `grep -n "def start\|def stop\|def get_status\|def get_results\|def apply"`. Целиком не открывать ни при каких условиях.
- `core/healthcheck.py`, `core/scan_targets.py`, `core/targets.py` — по
  `grep -n "def "`.

## Что написать

```
core/mcp/tools/probes.py     — probe_targets, probe_compare, connectivity_matrix
core/mcp/tools/scan.py       — scan_start/stop/status/results/apply
core/mcp/tools/blockcheck.py — blockcheck_start, blockcheck2_start/stop/
                               status/output, healthcheck_run
```

| Инструмент | Смысл |
|---|---|
| `probe_targets` | быстрая проба DNS→TCP→TLS→HTTP(+QUIC/STUN) по списку доменов **без изменения состояния** |
| `probe_compare` | тот же домен **через nfqws2 и мимо него**: ответ «что из двух работает». Аналог `b4_test_domain_now`; **на нём же строится baseline эксперимента в S10** |
| `scan_start/stop/status/results/apply` | наш сканер стратегий (target, protocol, mode, resume) |
| `blockcheck_start` | наши пробы + классификация DPI |
| `blockcheck2_start/stop/status/output` | оригинальный скрипт bol-van с параметрами `DOMAINS/IPVS/SCANLEVEL/REPEATS/…` |
| `healthcheck_run` | прогон healthcheck |
| `connectivity_matrix` | сводная матрица доступности |

### Два правила, которые определяют форму всей сессии

1. **Всё тяжёлое — асинхронное.** `*_start` возвращает `job_id` и **сразу**
   отдаёт управление; модель опрашивает `*_status`/`*_output`. Синхронных
   вызовов дольше `mcp.limits.tool_timeout_sec` быть не должно. Образец —
   `core/blockcheck2.py`.
2. **Разделение «читает / пробует» внутри одного инструмента.** У
   `healthcheck_*`: `status` — чтение, `run` — проба. Инструмент публикуется
   **всегда**, но его действия проверяются по отдельности (так у b4 с
   `b4_watchdog`, и это лучше, чем прятать инструмент целиком). Тот же приём
   уже применён к `diagnostics_run` в S5 — соблюсти единообразие.

### `probe_compare` — самый важный инструмент сессии

Он отвечает на вопрос, который модель задаёт первым: «дело в обходе или
домен и так лежит?». Контракт (S10 будет на него опираться):

```json
{"target": "rutracker.org",
 "with_bypass":    {"ok": true,  "code": "OK",       "latency_ms": 310},
 "without_bypass": {"ok": false, "code": "TLS_RST",  "latency_ms": 0},
 "verdict": "bypass_helps"}
```

`verdict` — из фиксированного набора: `bypass_helps`, `no_difference`,
`target_down` (не работает ни так, ни так), `bypass_hurts`. Никаких
свободных строк: коды — из `PROBE_CODES`.

## Правила

1. Пробы не меняют состояние. Если для `probe_compare` нужно на секунду
   остановить обход — **это уже изменение состояния**: требовать `control`
   вдобавок к `probes` и обязательно восстанавливать в `finally`.
2. Лимиты: число целей, число повторов, суммарное время. Модель не должна
   уметь запустить пробу по 500 доменам.
3. Вывод blockcheck и домены — `untrusted data`, пометить в описании.
4. Один тяжёлый прогон за раз (скан/blockcheck2): второй старт → `isError`
   с указанием активного `job_id`.
5. Обновить `test_mcp_tool_counts.py` и скил.

## Тесты

| Файл | Что фиксирует |
|---|---|
| `tests/test_mcp_probes.py` | `probe_targets` и `probe_compare` на замоканных тестерах: коды только из `PROBE_CODES`, все четыре `verdict` воспроизводятся, лимит целей соблюдается |
| `tests/test_mcp_jobs.py` | асинхронный контракт: `*_start` → `job_id` мгновенно; `*_output` отдаёт инкремент по `offset`; `*_stop` останавливает; второй старт при занятом слоте → `isError` |
| `tests/test_mcp_permissions.py` (дополнить) | без `probes` пробы недоступны; `healthcheck_status` доступен, `healthcheck_run` — нет; `diagnostics_run` ведёт себя так же, как в S5 |

## Приёмка

- Во время идущего скана GUI остаётся отзывчивым (проверка: параллельный
  запрос `/api/status` не ждёт).
- Модель без `probes` видит `healthcheck`/`diagnostics`, но не может ими
  что-либо запустить — и понимает из текста отказа, что включить.
- На dev-машине без nfqws2 `probe_compare` честно говорит, что обхода нет.

## Грабли

- **Не оборачивай сканер новой логикой.** `scan_*` — обёртки над
  `strategy_scanner`; его поведение менять нельзя (это S9, и то без смены
  поведения).
- **`job_id` должен переживать опрос после завершения**: модель спросит
  `*_status` через 30 секунд после конца — хранить последний результат, а не
  «задачи нет».
- **Таймауты клиента.** LM Studio рвёт запрос раньше, чем роутер закончит
  blockcheck2 — это ровно то, ради чего всё асинхронно; не «оптимизируй»
  обратно в синхронный вызов.

## Оставить следующим

`HANDOFF.md` + скил: контракт `probe_compare` (S10 строит на нём baseline),
контракт асинхронной задачи (`job_id`, `offset`, хранение результата),
какие лимиты выставлены и где они настраиваются.
