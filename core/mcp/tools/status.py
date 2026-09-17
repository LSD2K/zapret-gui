# core/mcp/tools/status.py
"""
Состояние устройства и движка nfqws2.

Два инструмента, с которых начинается любой разговор модели с роутером:
«что это за железка и что на ней запущено» и «жив ли движок обхода».
Оба — чтение, доступны без разрешений.
"""

import time

from core.mcp.registry import tool
from core.version import GUI_VERSION


@tool(
    name="system_status",
    scope="read",
    mutating=False,
    title="System status",
    description=("Router summary: platform, uptime, RAM, GUI version, "
                 "current strategy and which engines are running. / "
                 "Сводка по устройству и запущенным движкам."),
    schema={"type": "object", "properties": {},
            "additionalProperties": False},
)
def system_status(args: dict) -> dict:
    """Сводка по устройству: платформа, аптайм, память, что запущено."""
    from core.config_manager import get_config_manager
    from core.system_info import get_system_info

    cfg = get_config_manager()
    return {
        "ok": True,
        "system": get_system_info(),
        "gui_version": GUI_VERSION,
        "strategy": {
            "id": cfg.get("strategy", "current_id"),
            "name": cfg.get("strategy", "current_name") or "Не выбрана",
        },
        "engines": _engines_running(),
        "timestamp": int(time.time()),
    }


@tool(
    name="nfqws_status",
    scope="read",
    mutating=False,
    title="nfqws2 status",
    description=("State of the nfqws2 DPI-bypass engine: running, pid, "
                 "uptime, binary, argv of the last start, exit code. / "
                 "Состояние движка nfqws2."),
    schema={"type": "object", "properties": {},
            "additionalProperties": False},
)
def nfqws_status(args: dict) -> dict:
    """Состояние движка nfqws2: pid, аптайм, argv последнего запуска."""
    from core.config_manager import get_config_manager

    status = dict(_nfqws_manager().get_status())
    cfg = get_config_manager()
    status["strategy"] = {
        "id": cfg.get("strategy", "current_id"),
        "name": cfg.get("strategy", "current_name") or "Не выбрана",
    }
    status["ok"] = True
    return status


# ───────────────────────────── частности ────────────────────────────

def _engines_running() -> dict:
    """Какие движки сейчас подняты. Недоступный движок — ``None``.

    Каждый опрашивается отдельно и под ``try``: на устройстве может не
    быть половины из них, и это не повод ронять сводку целиком.
    """
    engines = {}

    def probe(name, fn):
        try:
            engines[name] = fn()
        except Exception:
            engines[name] = None

    probe("nfqws", lambda: bool(
        _nfqws_manager().get_status().get("running")))
    probe("firewall", lambda: bool(
        __import__("core.firewall", fromlist=["x"])
        .get_firewall_manager().get_status().get("applied")))
    probe("awg", lambda: _count_active(
        __import__("core.awg_manager", fromlist=["x"])
        .get_awg_manager().list_configs(), "active"))
    probe("singbox", lambda: _count_active(
        __import__("core.singbox_manager", fromlist=["x"])
        .get_singbox_manager().list_configs(), "running"))
    probe("mihomo", lambda: _count_active(
        __import__("core.mihomo_manager", fromlist=["x"])
        .get_mihomo_manager().list_configs(), "running"))
    return engines


def _count_active(configs, key) -> int:
    return sum(1 for c in (configs or [])
               if isinstance(c, dict) and c.get(key))


def _nfqws_manager():
    from core.nfqws_manager import get_nfqws_manager
    return get_nfqws_manager()
