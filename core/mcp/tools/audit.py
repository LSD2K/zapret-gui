# core/mcp/tools/audit.py
"""
Журнал вызовов MCP и откат последнего изменения.

Два инструмента поверх ``core/mcp/audit.py``:

* ``audit_list`` (чтение) — что вообще делалось через MCP. Нужен и
  человеку («кто поменял порты»), и самой модели: после перезапуска
  клиента она не помнит своих прошлых вызовов, а журнал помнит;
* ``mcp_undo_last`` (``config_write``) — вернуть как было по снимку.
  Снимки лежат на диске, поэтому откат переживает перезагрузку роутера
  — в отличие от истории «в оперативке», которая обнуляется ровно
  тогда, когда откат нужнее всего.

Логики здесь нет: выбор последнего снимка, вызов обработчика по виду и
пометка «откачено» — в ``core/mcp/audit.py``, потому что тем же
механизмом будут пользоваться S12 (файлы) и S13 (правки кода).
"""

from core.mcp import permissions as perms_mod
from core.mcp.registry import tool
from core.mcp.tools import _paging


# Что показываем в записи журнала. Полные значения «было/стало» живут в
# закреплённых снимках, а не в журнале: строка на вызов должна
# оставаться строкой, а не дампом конфига.
_FIELDS = ("ts", "time", "tool", "scope", "mutating", "status", "ok",
           "elapsed_ms", "args", "subject", "remote", "error")


@tool(
    name="audit_list",
    scope="read",
    mutating=False,
    title="List MCP calls",
    description=("Recent MCP tool calls from the on-disk journal: tool, "
                 "status, redacted arguments, errors and which of them can "
                 "still be undone. Newest first. / Последние вызовы MCP из "
                 "журнала на диске, новые первыми."),
    schema={
        "type": "object",
        "properties": {
            "tool": {
                "type": "string",
                "description": "Only calls of this tool. / Только этот "
                               "инструмент.",
                "maxLength": 60,
                "default": "",
            },
            "status": {
                "type": "string",
                "description": "ok | error | denied | invalid | unknown. "
                               "/ Чем кончился вызов.",
                "enum": ["", "ok", "error", "denied", "invalid", "unknown"],
                "default": "",
            },
            "mutating_only": {
                "type": "boolean",
                "description": "Only calls that changed something. / Только "
                               "менявшие состояние.",
                "default": False,
            },
            "offset": {"type": "integer", "minimum": 0, "default": 0},
            "limit": {"type": "integer", "minimum": 1,
                      "maximum": _paging.MAX_LIMIT, "default": 25},
        },
        "additionalProperties": False,
    },
)
def audit_list(args: dict) -> dict:
    """Последние вызовы MCP — новые первыми, с пагинацией."""
    from core.mcp import audit

    wanted_tool = (args.get("tool") or "").strip()
    wanted_status = (args.get("status") or "").strip()
    mutating_only = bool(args.get("mutating_only"))
    offset, limit = _paging.limits(args)

    records, stats = audit.read_records()
    if not stats["exists"]:
        return _paging.empty(
            "журнала ещё нет: через MCP пока ничего не вызывали"
            if stats["enabled"] else
            "журнал MCP выключен (mcp.audit.enabled=false)",
            hint="журнал лежит рядом с settings.json: %s" % stats["path"],
            enabled=stats["enabled"], path=stats["path"])

    snapshots = audit.snapshot_index()
    items = []
    for record in records:
        if wanted_tool and record.get("tool") != wanted_tool:
            continue
        if wanted_status and record.get("status") != wanted_status:
            continue
        if mutating_only and not record.get("mutating"):
            continue
        items.append(_entry(record, snapshots))

    if not items:
        return _paging.empty(
            "в журнале нет записей под этот фильтр",
            hint="всего записей: %d — уберите фильтры tool/status/"
                 "mutating_only" % len(records),
            enabled=stats["enabled"], path=stats["path"],
            total_in_journal=len(records))

    result = _paging.page(items, offset, limit,
                          enabled=stats["enabled"],
                          path=stats["path"],
                          total_in_journal=len(records))
    if stats["skipped_lines"]:
        # Битая строка — это оборванная запись (роутер выключили
        # розеткой). Молчать о ней нельзя: иначе «пропал мой вызов»
        # выглядит как «вызова не было».
        result["skipped_lines"] = stats["skipped_lines"]
    note = ("аргументы записаны после маскировки секретов; undo.available "
            "= снимок ещё можно откатить через mcp_undo_last")
    result["hint"] = ("%s; %s" % (result["hint"], note)) if \
        result.get("hint") else note
    return result


@tool(
    # Откат публикуется при ЛЮБОМ разрешении на запись, а не под
    # config_write: снимки бывают видов config, strategy, hostlist,
    # ipset, blob, lua (дальше — файлы и код). Модель с
    # `strategies_write` без `config_write` иначе получила бы право
    # менять стратегии без права их вернуть — §5.4 контракта.
    name="mcp_undo_last",
    scope=perms_mod.ANY_WRITE_SCOPE,
    mutating=True,
    title="Undo last change",
    description=("Revert the last change made through MCP using its "
                 "on-disk snapshot (survives a GUI restart). Kinds: "
                 "config, strategy, hostlist, ipset, blob, lua. / "
                 "Откатить последнее изменение, сделанное через MCP."),
    schema={
        "type": "object",
        "properties": {
            "kind": {
                "type": "string",
                "description": "Snapshot kind: config, strategy, "
                               "strategy_active, hostlist, ipset, blob, "
                               "lua. Empty = the most recent one. / Вид "
                               "снимка; пусто — самый последний.",
                "maxLength": 40,
                "default": "",
            },
        },
        "additionalProperties": False,
    },
)
def mcp_undo_last(args: dict) -> dict:
    """Откатить последний мутирующий вызов по снимку из журнала."""
    from core.mcp import audit

    return audit.undo_last((args.get("kind") or "").strip())


# ───────────────────────────── частности ────────────────────────────

def _entry(record: dict, snapshots: dict) -> dict:
    """Запись журнала в виде, пригодном для чтения моделью."""
    item = {key: record[key] for key in _FIELDS if key in record}
    refs = record.get("undo")
    if isinstance(refs, list) and refs:
        item["undo"] = [_undo_ref(ref, snapshots) for ref in refs
                        if isinstance(ref, dict)]
    return item


def _undo_ref(ref: dict, snapshots: dict) -> dict:
    """Ссылка на снимок + можно ли его ещё откатить.

    «Снимок был» и «снимок ещё действует» — разные ответы: второй
    отвечает на вопрос «могу ли я это вернуть», а первый — только на
    «что произошло».
    """
    out = {"kind": ref.get("kind"), "target": ref.get("target"),
           "id": ref.get("id")}
    pinned = snapshots.get(ref.get("id"))
    if pinned is None:
        out["available"] = False
        out["reason"] = "снимок вытеснен более новыми"
    elif pinned.get("undone"):
        out["available"] = False
        out["reason"] = "уже откачено"
    else:
        out["available"] = True
    return out
