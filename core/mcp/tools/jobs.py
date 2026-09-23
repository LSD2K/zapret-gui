# core/mcp/tools/jobs.py
"""
Дождаться конца долгой операции — одним вызовом вместо череды опросов.

## Зачем

Асинхронный контракт (``*_start`` отдаёт ``job_id``, дальше опрашивай
``*_status``) писался под таймаут клиента: скан идёт минутами, а HTTP-
запрос столько не живёт. Но у него есть обратная сторона, и её видно на
любом живом клиенте: модель не умеет ждать. Она опрашивает статус
подряд, в цикле, по нескольку раз в секунду — каждый опрос это вызов,
контекст, запись в журнале и такт рейт-лимита. Скан на три минуты
превращается в полторы сотни вызовов, из которых сто сорок девять
говорят «ещё идёт».

``job_wait`` — это таймер на стороне сервера. Один вызов блокируется до
тех пор, пока операция не кончится ИЛИ не истечёт бюджет ожидания
(``mcp.limits.wait_sec``, потолок ``max_wait_sec``), и возвращает
ровно то, что вернул бы соответствующий ``*_status``. Не кончилась —
``done: false`` и «позовите ещё раз»: три вызова вместо ста пятидесяти.

## Чего он не делает

* **не ждёт дольше клиента.** Бюджет заведомо меньше
  ``tool_timeout_sec``: ожидание, которое само отваливается по
  таймауту, хуже опроса — модель не узнает ни результата, ни того, что
  операция ещё идёт;
* **не обходит разрешения.** У каждого вида своё: ждать скан — это
  ``probes``, эксперимент — ``experiments``, shell-задачу —
  ``shell_readonly``. Иначе ``job_wait`` стал бы дырой, через которую
  чтение без разрешений видит чужие результаты;
* **не заводит своей очереди задач.** Он спрашивает те же источники,
  что и ``*_status``, — и отвечает их же ответом (см. :data:`KINDS`).
  Вторая реализация статуса разошлась бы с первой в первый же месяц;
* **не занимает GUI.** Веб-сервер многопоточный (``app.py``,
  ``_ThreadingWSGIServer``): ожидание держит свой поток запроса и
  больше ничего.
"""

import time

from core.mcp import permissions as perms_mod
from core.mcp.registry import tool


# Как часто заглядывать в состояние. Полсекунды — компромисс: реже
# значит «дождался и ещё две секунды не заметил», чаще незачем, все
# источники здесь дешёвые (поле в памяти процесса).
POLL_SEC = 0.5

# Сколько ждём по умолчанию и максимум, если настройка не прочиталась.
DEFAULT_WAIT_SEC = 45
DEFAULT_MAX_WAIT_SEC = 90

# Запас до таймаута инструмента: ответ ещё надо собрать и отдать.
TIMEOUT_MARGIN_SEC = 10


def _scan():
    from core.mcp.tools import scan
    return scan.scan_status


def _blockcheck():
    from core.mcp.tools import blockcheck
    return blockcheck.blockcheck_status


def _blockcheck2():
    from core.mcp.tools import blockcheck
    return blockcheck.blockcheck2_status


def _healthcheck():
    from core.mcp.tools import blockcheck
    return blockcheck.healthcheck_status


def _shell():
    from core.mcp.tools import shell
    return shell.shell_job_status


def _experiment():
    from core.mcp.tools import experiments
    return experiments.strategy_experiment_status


def _capture():
    from core.mcp.tools import traffic
    return traffic.traffic_capture_status


def _pool():
    from core.mcp.tools import tunnels

    def status(args):
        return tunnels.pool_refresh({"status_only": True})
    return status


def _running(payload: dict) -> bool:
    """Общий признак «ещё идёт» — у всех наших статусов это ``running``."""
    return bool(payload.get("running"))


def _experiment_running(payload: dict) -> bool:
    """У эксперимента фазой служит ``state``, а не флаг.

    ``awaiting_commit`` — это ТОЖЕ конец ожидания: прогон отработал и
    ждёт решения человека (или модели), а не продолжается. Ждать его
    дальше значит проспать дедмен-свитч, по которому всё откатится.
    """
    from core.strategy_experiment import STATE_RUNNING

    return (payload.get("state") == STATE_RUNNING
            and not payload.get("awaiting_commit"))


# Вид операции → чем её опросить, чем она разрешена и как понять, что
# она кончилась. Один источник правды: сам статус берётся у того же
# инструмента, которым модель опрашивала бы вручную.
KINDS = {
    "scan":        (_scan, "probes", _running,
                    "подбор стратегий (scan_start)"),
    "blockcheck":  (_blockcheck, "probes", _running,
                    "наш blockcheck (blockcheck_start)"),
    "blockcheck2": (_blockcheck2, "probes", _running,
                    "скрипт bol-van (blockcheck2_start)"),
    "healthcheck": (_healthcheck, "probes", _running,
                    "прогон healthcheck (healthcheck_run)"),
    "shell":       (_shell, "shell_readonly", _running,
                    "фоновая команда (shell_exec_async), нужен job_id"),
    "experiment":  (_experiment, "experiments", _experiment_running,
                    "эксперимент со стратегиями "
                    "(strategy_experiment_start)"),
    "capture":     (_capture, "probes", _running,
                    "снифер трафика (traffic_capture_start)"),
    "pool":        (_pool, "tunnels_write", _running,
                    "пересборка пула серверов (pool_refresh)"),
}


@tool(
    name="job_wait",
    scope="read",
    mutating=False,
    title="Wait for a long operation",
    description=("Block until a long operation finishes (scan, "
                 "blockcheck, blockcheck2, healthcheck, shell job, "
                 "experiment, capture, pool) and return its status. One "
                 "call instead of polling. / Дождаться конца долгой "
                 "операции одним вызовом."),
    schema={
        "type": "object",
        "properties": {
            "kind": {
                "type": "string",
                "enum": sorted(KINDS),
                "description": "Which operation to wait for. / Какую "
                               "операцию ждём.",
            },
            "job_id": {
                "type": "string",
                "maxLength": 64,
                "description": "Job id (required for kind=shell, "
                               "optional elsewhere). / Ярлык задачи.",
            },
            "timeout_sec": {
                "type": "integer",
                "minimum": 1,
                "maximum": 300,
                "description": "How long to wait (capped by "
                               "mcp.limits.max_wait_sec). / Сколько "
                               "ждать.",
            },
        },
        "required": ["kind"],
        "additionalProperties": False,
    },
)
def job_wait(args: dict) -> dict:
    """Ждать конца операции и отдать статус того инструмента, что её ведёт."""
    kind = (args.get("kind") or "").strip()
    entry = KINDS.get(kind)
    if entry is None:
        return {
            "ok": False,
            "error": "неизвестный вид операции «%s»" % kind,
            "known": sorted(KINDS),
            "hint": "ждать можно: %s" % ", ".join(sorted(KINDS)),
        }
    getter, permission, running_of, title = entry

    # Разрешение — то же, что у опроса вручную. Без этой проверки
    # job_wait отдавал бы под scope чтения то, что закрыто разрешением.
    if not perms_mod.granted(permission):
        denial = perms_mod.denial(permission, perms_mod.current())
        denial["kind"] = kind
        denial["hint"] = ("ждать «%s» можно с тем же разрешением, что и "
                          "опрашивать его: %s" % (title, permission))
        return denial

    try:
        status_of = getter()
    except Exception as e:                      # noqa: BLE001 — граница
        return {"ok": False, "kind": kind,
                "error": "вид «%s» недоступен: %s: %s"
                         % (kind, type(e).__name__, e)}

    budget = _budget(args.get("timeout_sec"))
    call_args = {"job_id": args["job_id"]} if args.get("job_id") else {}
    started = time.time()
    polls = 0
    payload = {}

    while True:
        payload = status_of(dict(call_args)) or {}
        polls += 1
        if not payload.get("ok", True):
            # Ошибку статуса возвращаем как есть: ждать нечего, и
            # молчать о причине — худшее, что можно сделать.
            payload["kind"] = kind
            payload["waited_sec"] = round(time.time() - started, 2)
            payload["hint"] = "; ".join(x for x in (
                payload.get("hint"),
                "ожидание прервано: статус прочитать не удалось") if x)
            return payload
        if not running_of(payload):
            break
        if time.time() - started >= budget:
            break
        time.sleep(POLL_SEC)

    done = not running_of(payload)
    waited = round(time.time() - started, 2)
    result = dict(payload)
    result.update({
        "ok": True,
        "kind": kind,
        "done": done,
        "waited_sec": waited,
        "budget_sec": budget,
        "polls": polls,
    })
    result["hint"] = "; ".join(x for x in (
        payload.get("hint"),
        ("операция завершилась — результат забирайте её собственным "
         "инструментом (*_result / *_results)" if done else
         "бюджет ожидания (%d с) вышел, операция ЕЩЁ ИДЁТ: позовите "
         "job_wait ещё раз — это дешевле, чем опрашивать статус в "
         "цикле. Нужен живой прогресс, а не конец — подпишитесь на "
         "zapret://state/jobs (resources/subscribe)" % budget)) if x)
    return result


# ───────────────────────────── частности ────────────────────────────

def _budget(requested) -> int:
    """Сколько ждём: запрошенное, ужатое настройкой и таймаутом вызова.

    Потолок считается ещё и от ``tool_timeout_sec``: ожидание, которое
    само упирается в таймаут инструмента, возвращает клиенту ошибку
    транспорта вместо ответа — то есть хуже, чем не ждать вовсе.
    """
    from core.mcp import auth

    try:
        limits = auth.settings().get("limits") or {}
    except Exception:                           # noqa: BLE001 — граница
        limits = {}
    default = _int(limits.get("wait_sec"), DEFAULT_WAIT_SEC)
    maximum = _int(limits.get("max_wait_sec"), DEFAULT_MAX_WAIT_SEC)
    tool_timeout = _int(limits.get("tool_timeout_sec"), 120)
    maximum = min(maximum, max(1, tool_timeout - TIMEOUT_MARGIN_SEC))

    wanted = _int(requested, 0) or default
    return max(1, min(wanted, maximum))


def _int(value, fallback: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return fallback
    return number if number > 0 else fallback
