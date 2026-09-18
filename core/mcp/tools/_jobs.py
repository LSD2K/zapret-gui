# core/mcp/tools/_jobs.py
"""
Асинхронная задача в одной форме: ``job_id``, опрос, инкремент вывода.

Модуль с подчёркиванием — реестр такие пропускает (``load_tools``): это
не инструмент, а общая упаковка, как ``_paging``.

**Зачем он нужен.** Скан стратегий и blockcheck идут минутами, а клиент
(LM Studio, Cline) рвёт HTTP-запрос через десятки секунд. Поэтому
тяжёлое запускается и сразу отдаёт управление: ``*_start`` возвращает
``job_id``, дальше модель опрашивает ``*_status`` и ``*_output``.
Синхронных вызовов длиннее ``mcp.limits.tool_timeout_sec`` в MCP быть
не должно — и «оптимизировать» это обратно в синхронный вызов нельзя,
именно от него всё и уезжает по таймауту.

**Почему запись переживает конец прогона.** Модель спрашивает
``*_status`` и через полминуты после завершения — ответ «задачи нет»
она прочитает как «прогон потерян» и запустит ещё один. Поэтому у
каждого вида держим небольшую очередь записей и кладём в запись
последний увиденный статус: завершённая задача отвечает своим
результатом, а не молчанием.

**Что здесь НЕ живёт.** Сам прогон: скан — ``core/strategy_scanner.py``,
blockcheck — ``core/blockcheck.py`` и ``core/blockcheck2.py``. Они
singleton'ы и держат ровно один (последний) прогон каждого вида;
``job_id`` — это наш ярлык поверх них, а не вторая реализация очереди
задач.
"""

import threading
import time
import uuid


KIND_SCAN = "scan"
KIND_BLOCKCHECK = "blockcheck"
KIND_BLOCKCHECK2 = "blockcheck2"

# Сколько записей на вид помним. Больше не нужно: данными отвечает
# сам runner, а он держит только последний прогон.
KEEP = 8

_lock = threading.Lock()
_jobs = []                       # новые в конце


def start(kind: str, params: dict = None) -> dict:
    """Завести запись о новом прогоне и вернуть её."""
    record = {
        "job_id": "%s-%s" % (kind, uuid.uuid4().hex[:8]),
        "kind": kind,
        "params": dict(params or {}),
        "started_at": round(time.time(), 3),
        "finished_at": 0.0,
        "done": False,
        "status": {},
    }
    with _lock:
        _jobs.append(record)
        _trim(kind)
    return record


def get(job_id: str):
    """Запись по ``job_id`` или ``None``."""
    with _lock:
        for record in _jobs:
            if record["job_id"] == job_id:
                return record
    return None


def latest(kind: str):
    """Последняя заведённая запись вида или ``None``."""
    with _lock:
        for record in reversed(_jobs):
            if record["kind"] == kind:
                return record
    return None


def is_current(record, kind: str) -> bool:
    """Та ли это задача, о которой сейчас рассказывает runner.

    Runner помнит один прогон. Если запись не последняя, живой статус
    описывает уже ДРУГУЮ задачу, и отдавать его под её ``job_id``
    нельзя: модель решит, что её скан всё ещё идёт.
    """
    current = latest(kind)
    return bool(record and current and
                record["job_id"] == current["job_id"])


def update(record, status: dict, running: bool) -> dict:
    """Запомнить последний статус прогона и отметить его конец."""
    if not record:
        return {}
    with _lock:
        record["status"] = dict(status or {})
        if not running and not record["done"]:
            record["done"] = True
            record["finished_at"] = round(time.time(), 3)
    return record


def running_id(kind: str) -> str:
    """``job_id`` незавершённой задачи вида (для отказа второму старту)."""
    record = latest(kind)
    if record and not record["done"]:
        return record["job_id"]
    return ""


def resolve(kind: str, job_id: str = ""):
    """``(запись, отказ)`` по ``job_id``; пустой id — последняя задача.

    Отказ — готовый ответ инструмента: неизвестный ``job_id`` это не
    «ничего не найдено», а опечатка или чужая задача, и модель должна
    увидеть, какие ярлыки существуют.
    """
    job_id = (job_id or "").strip()
    if not job_id:
        return latest(kind), None
    record = get(job_id)
    if record is None:
        known = [r["job_id"] for r in _by_kind(kind)]
        return None, {
            "ok": False,
            "error": "задачи %s нет" % job_id,
            "kind": kind,
            "known_job_ids": known,
            "hint": ("известные задачи этого вида: %s"
                     % (", ".join(known) or "ни одной — возможно, GUI "
                        "перезапускался: ярлыки живут в памяти процесса")),
        }
    if record["kind"] != kind:
        return None, {
            "ok": False,
            "error": "задача %s другого вида (%s)" % (job_id, record["kind"]),
            "kind": kind,
            "hint": "опрашивайте её инструментом своего вида",
        }
    return record, None


def describe(record, live: bool) -> dict:
    """Общие поля ответа о задаче — одинаковые у всех видов.

    Своё пояснение кладём в ``job_note``, а не в ``note``: у ``note``
    в этих ответах уже есть хозяин (пометка «untrusted data»), и
    затирание оставило бы модель без одного из двух объяснений.
    """
    if not record:
        return {"job_id": "", "job_known": False,
                "job_note": "прогон запущен не через MCP (или не "
                            "запускался): ярлыка задачи у него нет"}
    out = {
        "job_id": record["job_id"],
        "job_known": True,
        "started_at": record["started_at"],
        "finished_at": record["finished_at"],
        "done": record["done"],
        "params": dict(record["params"]),
        "live": live,
    }
    if not live:
        out["job_note"] = ("это ЗАВЕРШЁННАЯ задача: показан последний "
                           "сохранённый статус, а не то, что выполняется "
                           "сейчас")
    return out


def reset():
    """Забыть все задачи (нужно тестам, чтобы не тянуть чужие)."""
    with _lock:
        _jobs.clear()


def _by_kind(kind: str) -> list:
    with _lock:
        return [r for r in _jobs if r["kind"] == kind]


def _trim(kind: str):
    """Оставить последние ``KEEP`` записей вида (вызывать под ``_lock``)."""
    same = [r for r in _jobs if r["kind"] == kind]
    for old in same[:-KEEP]:
        _jobs.remove(old)
