# core/mcp/tools/nfqws.py
"""
Управление движком nfqws2: старт, стоп, перезапуск, SIGHUP, применение
стратегии. Всё под разрешением ``control``.

Первое место, где модель не читает устройство, а меняет его. Три вещи,
которые здесь важнее кода:

* **Логика не живёт в MCP.** Последовательность «правила firewall →
  движок → конфиг → автозапуск» лежит в ``core/nfqws_control.py`` и
  одинакова для веб-интерфейса, CLI и модели. Инструмент — обёртка,
  которая переводит её результат на язык ответа MCP;
* **SIGHUP — не перезапуск.** ``nfqws_reload_lists`` заставляет живой
  движок перечитать хостлисты и ipset'ы, не роняя соединений и не
  меняя аргументов. Подменять им ``nfqws_restart`` нельзя: модель
  запомнит «перезапуск не помог», хотя перезапуска не было;
* **За движок дерутся.** Сканер стратегий и blockcheck поднимают nfqws2
  сами. Применить стратегию поверх работающего скана — испортить оба,
  поэтому каждый мутирующий инструмент здесь сначала спрашивает
  ``nfqws_control.busy()`` — у неё текст отказа человечнее. Сама же
  защита от гонки стоит глубже: ``core/nfqws_control`` берёт общий
  мьютекс (``core/nfqws_session``) на время последовательности и
  возвращает ``error_code="busy"``, если движок успели занять между
  вопросом и делом.

Отката у старта и остановки нет намеренно: «было запущено» — это не
значение, которое можно вернуть снимком, а состояние процесса. Обратная
операция здесь — соседний инструмент (``nfqws_stop`` для ``nfqws_start``
и наоборот), и в ответе она названа явно. Снимок делает только
``strategy_apply``: он меняет ``strategy.current_id`` в настройках,
а это уже значение.
"""

from core.mcp import audit
from core.mcp.registry import tool


# Что уехало в движок — это длинные строки; в ответе их режем.
MAX_ARGS = 60


@tool(
    name="nfqws_start",
    scope="control",
    mutating=True,
    title="Start the nfqws2 engine",
    description=("Apply firewall NFQUEUE rules and start nfqws2 with the "
                 "currently applied strategy (rebuilt from config). "
                 "Reverse: nfqws_stop. / Поднять обход: правила перехвата "
                 "и движок с активной стратегией."),
    schema={"type": "object", "properties": {},
            "additionalProperties": False},
)
def nfqws_start(args: dict) -> dict:
    """Поднять движок с активной стратегией (и правила перехвата)."""
    from core import nfqws_control

    blocked = _busy_refusal("nfqws_start")
    if blocked:
        return blocked
    return _engine_result(nfqws_control.start(source="mcp"),
                          action="start", reverse="nfqws_stop")


@tool(
    name="nfqws_stop",
    scope="control",
    mutating=True,
    title="Stop the nfqws2 engine",
    description=("Stop nfqws2 and remove the NFQUEUE firewall rules. "
                 "Traffic goes direct afterwards — blocked sites stop "
                 "working. Reverse: nfqws_start. / Остановить обход и "
                 "снять правила перехвата."),
    schema={"type": "object", "properties": {},
            "additionalProperties": False},
)
def nfqws_stop(args: dict) -> dict:
    """Остановить движок и снять правила перехвата."""
    from core import nfqws_control

    blocked = _busy_refusal("nfqws_stop")
    if blocked:
        return blocked
    return _engine_result(nfqws_control.stop(source="mcp"),
                          action="stop", reverse="nfqws_start")


@tool(
    name="nfqws_restart",
    scope="control",
    mutating=True,
    title="Restart the nfqws2 engine",
    description=("Restart nfqws2 with freshly rebuilt args of the applied "
                 "strategy and re-apply firewall rules. Use after editing "
                 "the applied strategy. / Перезапустить движок со свежими "
                 "аргументами активной стратегии."),
    schema={"type": "object", "properties": {},
            "additionalProperties": False},
)
def nfqws_restart(args: dict) -> dict:
    """Перезапустить движок, пересобрав аргументы активной стратегии."""
    from core import nfqws_control

    blocked = _busy_refusal("nfqws_restart")
    if blocked:
        return blocked
    return _engine_result(nfqws_control.restart(source="mcp"),
                          action="restart", reverse="nfqws_stop")


@tool(
    name="nfqws_reload_lists",
    scope="control",
    mutating=True,
    title="Reload hostlists (SIGHUP)",
    description=("SIGHUP the running nfqws2 so it re-reads hostlists and "
                 "ipsets. NOT a restart: args stay, connections survive. "
                 "Needed after editing any list. / Перечитать списки без "
                 "перезапуска."),
    schema={
        "type": "object",
        "properties": {
            "reason": {
                "type": "string",
                "description": "What changed — goes to the log. / Что "
                               "поменялось (уходит в журнал).",
                "maxLength": 120,
            },
        },
        "additionalProperties": False,
    },
)
def nfqws_reload_lists(args: dict) -> dict:
    """SIGHUP движку: перечитать хостлисты и ipset'ы без перезапуска."""
    from core import nfqws_control

    reason = (args.get("reason") or "").strip() or "mcp"
    result = nfqws_control.reload_lists(reason)
    pids = result.get("pids") or []
    if not pids:
        # Движок не запущен — это не сбой: списки подхватятся при
        # старте. Но `ok: true` без объяснения модель прочитает как
        # «списки перечитаны», а они не перечитаны.
        return {
            "ok": True,
            "signalled": False,
            "pids": [],
            "reason": result.get("error") or "nfqws2 не запущен",
            "hint": "правка списков сохранена; движок прочитает её при "
                    "старте — nfqws_start()",
        }
    return {
        "ok": True,
        "signalled": True,
        "pids": pids,
        "note": "SIGHUP — это перечитывание списков, а НЕ перезапуск: "
                "аргументы движка и соединения остались прежними",
        "hint": "если изменились сами аргументы стратегии, нужен "
                "strategy_apply() или nfqws_restart()",
    }


@tool(
    name="strategy_apply",
    scope="control",
    mutating=True,
    title="Apply a strategy",
    description=("Apply an existing strategy by id: build args, re-apply "
                 "firewall rules, (re)start nfqws2 and remember it in "
                 "config. Undoable via mcp_undo_last. / Применить "
                 "существующую стратегию по id."),
    schema={
        "type": "object",
        "properties": {
            "id": {
                "type": "string",
                "description": "Strategy id from strategy_list. / ID "
                               "стратегии из strategy_list.",
                "maxLength": 120,
            },
        },
        "required": ["id"],
        "additionalProperties": False,
    },
)
def strategy_apply(args: dict) -> dict:
    """Применить стратегию по id — тем же кодом, что и веб-интерфейс."""
    from core import nfqws_control

    wanted = (args.get("id") or "").strip()
    if not wanted:
        return {"ok": False, "error": "не передан id стратегии",
                "hint": "список — strategy_list()"}

    blocked = _busy_refusal("strategy_apply")
    if blocked:
        return blocked

    result = nfqws_control.apply_strategy(wanted, source="mcp")
    # Прежний id отдаёт сам `apply_strategy`: прочитать его здесь уже
    # нельзя — к этому моменту в конфиге стоит новый.
    before = result.get("previous_id")
    if not result.get("ok"):
        out = _engine_result(result, action="apply", reverse="")
        out["strategy_id"] = wanted
        if result.get("error_code") == "not_found":
            out["hint"] = "такого id нет; список — strategy_list(query=…)"
        elif result.get("error_code") == "no_profiles":
            out["hint"] = ("в стратегии нет включённых профилей — "
                           "запускать нечего; посмотрите "
                           "strategy_get(id=\"%s\")" % wanted)
        return out

    # Снимок делается ПОСЛЕ удачного применения и только по тому, что
    # действительно является значением: активная стратегия в конфиге.
    # Откат вернёт её и переподнимет движок (см. `_undo_strategy_apply`).
    undo = audit.snapshot(audit.KIND_STRATEGY_ACTIVE, "strategy.current_id",
                          before, wanted, tool="strategy_apply")

    out = _engine_result(result, action="apply", reverse="")
    out.update({
        "strategy": result.get("strategy") or {},
        "strategy_id": wanted,
        "before": before,
        "after": wanted,
        "changed": before != wanted,
        "undo": undo or None,
        "hint": "стратегия применена и записана в конфиг; откат — "
                "mcp_undo_last. Трафик появится не мгновенно: проверьте "
                "traffic_recent() через минуту",
    })
    if not undo:
        out["hint"] += " (журнал MCP выключен — снимка для отката нет)"
    return out


# ───────────────────────────── откат ────────────────────────────────

def _undo_strategy_apply(snapshot: dict) -> dict:
    """Вернуть прежнюю активную стратегию и переподнять с ней движок.

    Вернуть только запись в конфиге мало: движок продолжал бы работать с
    аргументами откаченной стратегии, и `strategy_list` показывал бы одну
    стратегию, а обход делал бы другую.
    """
    from core import nfqws_control

    before = snapshot.get("before")
    if not before:
        # Стратегии не было вовсе — возвращаем ровно это: пустой
        # current_id и остановленный движок.
        stopped = nfqws_control.clear_strategy(source="mcp")
        return {"ok": bool(stopped.get("ok")),
                "error": stopped.get("error", ""),
                "undone_to": None,
                "nfqws": stopped.get("nfqws") or {}}

    result = nfqws_control.apply_strategy(str(before), source="mcp")
    return {
        "ok": bool(result.get("ok")),
        "error": result.get("error", ""),
        "undone_to": before,
        "nfqws": result.get("nfqws") or {},
    }


# ───────────────────────────── частности ────────────────────────────

def _busy_refusal(tool_name: str):
    """Отказ, если движком сейчас управляет кто-то другой (S9 заменит).

    Возвращает готовый ответ инструмента или ``None``, если свободно.
    """
    from core import nfqws_control

    holder = nfqws_control.busy()
    if not holder:
        return None
    return {
        "ok": False,
        "error": "движок занят: %s" % holder.get("reason", holder.get("who")),
        "busy": holder.get("who", ""),
        "tool": tool_name,
        "hint": holder.get("hint", "дождитесь окончания и повторите"),
    }


def _engine_result(result: dict, action: str, reverse: str) -> dict:
    """Ответ инструмента из результата ``core/nfqws_control``.

    Состояние движка и правил кладём и в успех, и в отказ одинаково:
    «не удалось запустить» без `running`/`exit_code` не даёт модели ни
    одного способа понять, почему.
    """
    nfqws = result.get("nfqws") or {}
    firewall = result.get("firewall") or {}
    out = {
        "ok": bool(result.get("ok")),
        "action": action,
        "running": bool(nfqws.get("running")),
        "pid": nfqws.get("pid"),
        "uptime_sec": nfqws.get("uptime"),
        "exit_code": nfqws.get("exit_code"),
        "binary": nfqws.get("binary") or "",
        "firewall_applied": bool(firewall.get("applied")),
        "firewall_backend": firewall.get("type") or "",
        "firewall_rules": firewall.get("rules_count", 0),
    }
    argv = result.get("strategy_args") or nfqws.get("last_args") or []
    if argv:
        out["strategy_args"] = [str(a) for a in argv[:MAX_ARGS]]
        out["strategy_args_truncated"] = len(argv) > MAX_ARGS
    if reverse:
        out["reverse"] = reverse
    if not out["ok"]:
        out["error"] = result.get("error") or "движок не поддался"
        out["hint"] = ("подробности — logs_tail(source=\"nfqws\"); "
                       "проверить бинарник и правила — nfqws_status(), "
                       "firewall_status()")
    if result.get("error_code") == "busy":
        # Отказ пришёл от общего мьютекса (`core/nfqws_session`), а не
        # от движка: искать причину в логах nfqws2 бесполезно — там
        # ничего не происходило. Отвечаем тем же полем `busy`, что и
        # проверка перед вызовом, чтобы модель не разбирала два формата.
        out["busy"] = result.get("busy", "")
        out["hint"] = result.get("hint") or (
            "дождитесь окончания операции и повторите")
    return out


# Откат применения стратегии объявляется на импорте — так же, как откат
# настроек в tools/config.py: `mcp_undo_last` находит обработчик готовым.
audit.register_undo(audit.KIND_STRATEGY_ACTIVE, _undo_strategy_apply)
