# core/mcp/tools/firewall.py
"""
Правила перехвата: стоят ли они и сходятся ли с движком.

Половина жалоб «обход не работает» живёт здесь, а не в стратегии.
Правила могут быть не применены вовсе; могут стоять, пока движок лежит;
могут уводить в очередь 300, когда движок слушает 301. Снаружи все три
случая выглядят одинаково — и все три невидимы, если смотреть на статус
движка и на статус firewall по отдельности.

Поэтому инструмент отдаёт не только правила, но и **расхождения**
(``core/firewall.py:get_conflicts``) — тем же кодом, каким их считает
UI. Ни одного вывода здесь не делается заново.
"""

from core.mcp.registry import tool
from core.mcp.tools import _paging


# Правила — длинные строки, и их бывает полтора десятка на семью
# цепочек. Окно обязательно, иначе ответ съедает лимит.
RULES_MAX = 100
RULES_DEFAULT = 30

# Одна строка правила в выводе iptables-save бывает длинной.
MAX_RULE = 400


@tool(
    name="firewall_status",
    scope="read",
    mutating=False,
    title="Firewall status",
    description=("NFQUEUE rules: backend (iptables/nftables), whether "
                 "they are applied, the queue numbers they point at, and "
                 "conflicts with the engine's settings. / Правила "
                 "перехвата, бэкенд и расхождения с движком."),
    schema={
        "type": "object",
        "properties": {
            "rules": {
                "type": "boolean",
                "description": "Include the rule lines themselves. / "
                               "Вернуть сами строки правил.",
                "default": True,
            },
            "offset": {"type": "integer", "minimum": 0, "default": 0,
                       "description": "Window start in rules. / Начало "
                                      "окна по правилам."},
            "limit": {"type": "integer", "minimum": 1, "maximum": RULES_MAX,
                      "default": RULES_DEFAULT,
                      "description": "How many rule lines (1-100). / "
                                     "Сколько строк правил вернуть."},
        },
        "additionalProperties": False,
    },
)
def firewall_status(args: dict) -> dict:
    """Правила NFQUEUE, бэкенд, номера очередей и расхождения."""
    from core.firewall import get_firewall_manager

    manager = get_firewall_manager()
    try:
        status = manager.get_status()
    except Exception as e:                      # noqa: BLE001 — граница
        return {
            "ok": False,
            "error": "правила не прочитаны: %s: %s" % (type(e).__name__, e),
            "hint": "обычно это отсутствие прав (нужен root) или самих "
                    "iptables/nft на устройстве",
        }

    rules = status.get("rules") or []
    conflicts = _safe(lambda: manager.get_conflicts(rules), [])
    queues = _safe(lambda: manager.queue_numbers(rules), [])

    offset, limit = _paging.limits(args, default=RULES_DEFAULT,
                                   maximum=RULES_MAX)
    want_rules = args.get("rules", True)
    lines = [str(r)[:MAX_RULE] for r in rules] if want_rules else []

    result = _paging.page(lines, offset, limit,
                          total=len(rules) if want_rules else 0)
    result.update({
        "backend": status.get("type") or "",
        "applied": bool(status.get("applied")),
        "rules_count": status.get("rules_count", len(rules)),
        "queue_numbers": queues,
        "conflicts": conflicts,
        "conflicts_count": len(conflicts),
    })

    if not status.get("type"):
        result["hint"] = ("ни iptables, ни nft не найдены — перехват "
                          "невозможен")
    elif not status.get("applied"):
        result["hint"] = ("правила не применены: в NFQUEUE не приходит "
                          "ничего, и стратегия не срабатывает ни на одном "
                          "пакете")
    elif conflicts:
        # Расхождение важнее всего остального в ответе: с ним «правила
        # применены» ничего не значит.
        result["hint"] = "; ".join("%s: %s" % (c["title"], c["hint"])
                                   for c in conflicts[:3])
    return result


# ───────────────────────────── частности ────────────────────────────

def _safe(getter, default):
    try:
        return getter()
    except Exception:                           # noqa: BLE001 — граница
        return default
