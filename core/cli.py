# core/cli.py
"""
CLI-обёртка над менеджерами zapret-gui.

Заимствовано из XKeen, где основной интерфейс — команда `xkeen` в
SSH-терминале. У нас GUI-first, но иногда нужно быстро дёрнуть из
консоли (по SSH, из скрипта, из cron) без браузера:

    zapret-gui status
    zapret-gui nfqws {start|stop|restart|status}
    zapret-gui strategy list
    zapret-gui strategy apply <id>
    zapret-gui singbox list
    zapret-gui singbox {up|down|restart} <name>
    zapret-gui mcp {status|tools|call|token|audit|code}
    zapret-gui mcp --stdio            (MCP-клиент через ssh)

Тонкий слой: только парсинг + вызов синглтон-менеджеров + печать.
Никакого Bottle — инициализируем только ядро (init_config) и работаем
напрямую с core/*. Возвращаемый код = exit-code процесса.

Вызывается из app.py main(), когда первый аргумент — известная
подкоманда (а не --host/--port и т.п. для web-сервера).
"""

import argparse
import sys


# Подкоманды верхнего уровня, по которым app.py решает «это CLI, не web».
COMMANDS = ("status", "nfqws", "strategy", "singbox", "mihomo",
            "usque", "tgproxy", "opera", "monitor", "updates", "dns-routing",
            "mcp")


def _p(msg=""):
    print(msg)


def _ok(label, result):
    """Печать результата dict {ok, error?} в человекочитаемом виде."""
    if isinstance(result, dict):
        if result.get("ok", True):
            _p("✓ %s" % label)
            return 0
        _p("✗ %s: %s" % (label, result.get("error") or "ошибка"))
        return 1
    # bool
    if result:
        _p("✓ %s" % label)
        return 0
    _p("✗ %s" % label)
    return 1


# ─────────────────────── status ──────────────────────────────────────

def _cmd_status(_args) -> int:
    _p("=== zapret-gui ===")
    # nfqws
    try:
        from core.nfqws_manager import get_nfqws_manager
        st = get_nfqws_manager().get_status()
        running = st.get("running")
        _p("nfqws2:   %s%s" % (
            "запущен" if running else "остановлен",
            " (pid %s)" % st.get("pid") if running and st.get("pid") else ""))
    except Exception as e:
        _p("nfqws2:   ? (%s)" % e)
    # current strategy
    try:
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        sid = cfg.get("strategy", "current_id", default=None)
        sname = cfg.get("strategy", "current_name", default=None)
        if sid or sname:
            _p("стратегия: %s%s" % (sname or "?",
                                    " [%s]" % sid if sid else ""))
        else:
            _p("стратегия: не выбрана")
    except Exception:
        pass
    # sing-box
    try:
        from core.singbox_manager import get_singbox_manager
        cfgs = get_singbox_manager().list_configs()
        if cfgs:
            up = [c["name"] for c in cfgs if c.get("running")]
            _p("sing-box: %d конфигов, запущено: %s"
               % (len(cfgs), ", ".join(up) if up else "—"))
    except Exception:
        pass
    # mihomo
    try:
        from core.mihomo_manager import get_mihomo_manager
        cfgs = get_mihomo_manager().list_configs()
        if cfgs:
            up = [c["name"] for c in cfgs if c.get("running")]
            _p("mihomo:   %d конфигов, запущено: %s"
               % (len(cfgs), ", ".join(up) if up else "—"))
    except Exception:
        pass
    return 0


# ─────────────────────── nfqws ───────────────────────────────────────

def _cmd_nfqws(args) -> int:
    from core.nfqws_manager import get_nfqws_manager
    mgr = get_nfqws_manager()
    action = args.action
    if action == "status":
        st = mgr.get_status()
        _p("nfqws2: %s" % ("запущен" if st.get("running")
                           else "остановлен"))
        if st.get("pid"):
            _p("pid: %s" % st["pid"])
        return 0
    if action == "start":
        return _ok("nfqws start", mgr.start())
    if action == "stop":
        return _ok("nfqws stop", mgr.stop())
    if action == "restart":
        return _ok("nfqws restart", mgr.restart())
    _p("Неизвестное действие: %s" % action)
    return 2


# ─────────────────────── strategy ────────────────────────────────────

def _cmd_strategy(args) -> int:
    from core.strategy_builder import get_strategy_manager
    sm = get_strategy_manager()
    if args.action == "list":
        for s in sm.get_strategies():
            _p("  %-24s %s" % (s.get("id", "?"),
                               s.get("name", "")))
        return 0
    if args.action == "apply":
        if not args.id:
            _p("Укажите id стратегии: zapret-gui strategy apply <id>")
            return 2
        strategy = sm.get_strategy(args.id)
        if not strategy:
            _p("✗ Стратегия не найдена: %s" % args.id)
            return 1
        nfqws_args = sm.build_nfqws_args(strategy)
        if not nfqws_args:
            _p("✗ Нет включённых профилей в стратегии")
            return 1
        from core.nfqws_manager import get_nfqws_manager
        from core.config_manager import get_config_manager
        mgr = get_nfqws_manager()
        ok = mgr.restart(nfqws_args) if mgr.is_running() \
            else mgr.start(nfqws_args)
        if ok:
            try:
                cfg = get_config_manager()
                cfg.set("strategy", "current_id", strategy.get("id"))
                cfg.set("strategy", "current_name", strategy.get("name"))
                cfg.save()
            except Exception:
                pass
        return _ok("strategy apply %s" % args.id, ok)
    _p("Неизвестное действие: %s" % args.action)
    return 2


# ─────────────────────── singbox ─────────────────────────────────────

def _cmd_singbox(args) -> int:
    from core.singbox_manager import get_singbox_manager
    mgr = get_singbox_manager()
    if args.action == "list":
        cfgs = mgr.list_configs()
        if not cfgs:
            _p("sing-box: конфигов нет")
            return 0
        for c in cfgs:
            _p("  %-24s %s" % (c["name"],
                               "запущен" if c.get("running")
                               else "остановлен"))
        return 0
    if not args.name:
        _p("Укажите имя конфига: zapret-gui singbox %s <name>" % args.action)
        return 2
    if args.action == "up":
        return _ok("singbox up %s" % args.name, mgr.up(args.name))
    if args.action == "down":
        return _ok("singbox down %s" % args.name, mgr.down(args.name))
    if args.action == "restart":
        return _ok("singbox restart %s" % args.name, mgr.restart(args.name))
    _p("Неизвестное действие: %s" % args.action)
    return 2


def _cmd_mihomo(args) -> int:
    from core.mihomo_manager import get_mihomo_manager
    mgr = get_mihomo_manager()
    if args.action == "list":
        cfgs = mgr.list_configs()
        if not cfgs:
            _p("mihomo: конфигов нет")
            return 0
        for c in cfgs:
            _p("  %-24s %s" % (c["name"],
                               "запущен" if c.get("running")
                               else "остановлен"))
        return 0
    if not args.name:
        _p("Укажите имя конфига: zapret-gui mihomo %s <name>" % args.action)
        return 2
    if args.action == "up":
        return _ok("mihomo up %s" % args.name, mgr.up(args.name))
    if args.action == "down":
        return _ok("mihomo down %s" % args.name, mgr.down(args.name))
    if args.action == "restart":
        return _ok("mihomo restart %s" % args.name, mgr.restart(args.name))
    _p("Неизвестное действие: %s" % args.action)
    return 2


# ─────────────────────── usque (WARP/MASQUE) ────────────────────────

def _cmd_usque(args) -> int:
    from core.usque_manager import get_usque_manager
    mgr = get_usque_manager()
    action = args.action
    if action == "status":
        env = mgr.detect()
        if env.get("installed"):
            _p("usque: установлен (%s, %s)" % (env.get("version", "?"), env.get("arch", "?")))
        else:
            _p("usque: не установлен")
        configs = mgr.list_configs()
        active = [c for c in configs if c.get("active")]
        _p("конфигов: %d, активных: %s" % (len(configs), ", ".join(c["iface"] for c in active) if active else "—"))
        return 0
    if action == "start":
        if not args.iface:
            _p("Укажите интерфейс: zapret-gui usque start <iface>")
            return 2
        configs = mgr.list_configs()
        target = next((c for c in configs if c.get("iface") == args.iface
                       or c.get("name") == args.iface), None)
        if not target:
            _p("✗ Интерфейс не найден: %s" % args.iface)
            return 1
        iface = mgr.iface_for_config(target["path"])
        return _ok("usque start %s" % iface,
                    mgr.start(iface, target["path"]))
    if action == "stop":
        if not args.iface:
            _p("Укажите интерфейс: zapret-gui usque stop <iface>")
            return 2
        return _ok("usque stop %s" % args.iface, mgr.stop(args.iface))
    _p("Неизвестное действие: %s" % action)
    return 2


# ─────────────────────── tgproxy (Telegram) ──────────────────────────

def _cmd_tgproxy(args) -> int:
    from core.tgproxy_manager import get_tgwsproxy_manager
    mgr = get_tgwsproxy_manager()
    action = args.action
    if action == "status":
        st = mgr.get_status()
        _p("telegram: %s" % ("запущен (%s)" % st.get("engine", "?")
                            if st.get("running") else "остановлен"))
        if st.get("pid"):
            _p("pid: %s" % st["pid"])
        return 0
    if action == "start":
        return _ok("telegram start", mgr.start())
    if action == "stop":
        return _ok("telegram stop", mgr.stop())
    _p("Неизвестное действие: %s" % action)
    return 2


# ─────────────────────── opera proxy ─────────────────────────────────

def _cmd_opera(args) -> int:
    from core.opera_proxy_manager import (get_opera_proxy_manager,
                                          start_kwargs_from_config)
    mgr = get_opera_proxy_manager()
    action = args.action
    if action == "status":
        st = mgr.status()
        _p("opera: %s" % ("запущен" if st.get("running") else "остановлен"))
        if st.get("bind"):
            _p("bind: %s%s" % (st["bind"],
                               "" if st.get("listening", True)
                               else " (порт не отвечает)"))
        if st.get("pid"):
            _p("pid: %s" % st["pid"])
        return 0
    if action == "start":
        # Настройки берём из конфига — как GUI, автозапуск и watchdog.
        # Раньше CLI стартовал с дефолтами (EU, 127.0.0.1:18080) и молча
        # игнорировал сохранённые страну, bind, SOCKS-режим и fake-SNI.
        result = mgr.start(**start_kwargs_from_config())
        if result.get("ok"):
            _set_opera_enabled(True)
        return _ok("opera start", result)
    if action == "stop":
        _set_opera_enabled(False)
        return _ok("opera stop", mgr.stop())
    _p("Неизвестное действие: %s" % action)
    return 2


def _set_opera_enabled(enabled: bool) -> None:
    """Флаг «opera должна работать» — его читают boot-автозапуск и watchdog."""
    try:
        from core.config_manager import get_config_manager
        cfg = get_config_manager()
        cfg.set("opera_proxy", "enabled", enabled)
        cfg.save()
        from core.opera_proxy_watchdog import get_opera_proxy_watchdog
        get_opera_proxy_watchdog().reconfigure()
    except Exception:
        pass


# ─────────────────────── monitor (live metrics) ──────────────────────

def _cmd_monitor(_args) -> int:
    from core.tunnel_monitor import get_tunnel_monitor
    monitor = get_tunnel_monitor()
    metrics = monitor.get_metrics()
    if not metrics:
        _p("Нет активных туннелей")
        return 0
    _p("%-20s %12s %12s %12s %12s" % ("Интерфейс", "RX", "TX", "RX/s", "TX/s"))
    _p("-" * 70)
    for m in metrics:
        rx = _fmt_bytes(m.get("rx_bytes", 0))
        tx = _fmt_bytes(m.get("tx_bytes", 0))
        rx_s = _fmt_speed(m.get("rx_speed", 0))
        tx_s = _fmt_speed(m.get("tx_speed", 0))
        _p("%-20s %12s %12s %12s %12s" % (m["iface"], rx, tx, rx_s, tx_s))
    return 0


def _fmt_bytes(b):
    if b < 1024: return "%d B" % b
    if b < 1024*1024: return "%.1f KB" % (b/1024)
    if b < 1024*1024*1024: return "%.1f MB" % (b/(1024*1024))
    return "%.2f GB" % (b/(1024*1024*1024))


def _fmt_speed(bps):
    if bps < 1024: return "%d B/s" % bps
    if bps < 1024*1024: return "%.1f KB/s" % (bps/1024)
    return "%.1f MB/s" % (bps/(1024*1024))


# ─────────────────────── updates ─────────────────────────────────────

def _cmd_updates(_args) -> int:
    from core.update_checker import check_all
    _p("Проверка обновлений...")
    result = check_all()
    results = result.get("results", [])
    updates = [r for r in results if r.get("has_update")]
    _p("")
    _p("%-20s %-15s %-15s %s" % ("Компонент", "Установлена", "Последняя", "Статус"))
    _p("-" * 70)
    for r in results:
        status = "← обновление" if r.get("has_update") else "OK"
        _p("%-20s %-15s %-15s %s" % (
            r.get("display_name", r.get("name", "?")),
            r.get("current", "-") or "-",
            r.get("latest", "-") or "-",
            status))
    _p("")
    _p("Найдено обновлений: %d" % len(updates))
    return 0 if not updates else 1


# ─────────────────────── dns-routing ─────────────────────────────────

def _cmd_dns_routing(args) -> int:
    from core.dns_routing import get_dns_routing_manager
    mgr = get_dns_routing_manager()
    action = args.action
    if action == "list":
        rules = mgr.get_rules()
        if not rules:
            _p("Нет DNS-правил")
            return 0
        _p("%-30s %-20s %s" % ("Домен", "DNS", "Описание"))
        _p("-" * 70)
        for r in rules:
            _p("%-30s %-20s %s" % (r.get("domain", "?"),
                                   r.get("dns", "?"),
                                   r.get("description", "")))
        return 0
    if action == "apply":
        result = mgr.apply()
        return _ok("dns-routing apply: %d правил" % result.get("applied", 0), result)
    _p("Неизвестное действие: %s" % action)
    return 2


# ─────────────────────── mcp (MCP-сервер) ────────────────────────────
#
# Отладка MCP по SSH: посмотреть, включён ли, что разрешено, какие
# инструменты видит модель, позвать инструмент руками — и, главное,
# поднять stdio-мост, чтобы клиент на ноутбуке ходил в роутер через
# `ssh router zapret-gui mcp --stdio`.

def _cmd_mcp(args) -> int:
    action = "stdio" if getattr(args, "stdio", False) else (args.action
                                                            or "status")
    rest = list(getattr(args, "rest", None) or [])
    handler = {
        "status": _mcp_status,
        "token": _mcp_token,
        "tools": _mcp_tools,
        "call": _mcp_call,
        "stdio": _mcp_stdio,
        "audit": _mcp_audit,
        "code": _mcp_code,
    }.get(action)
    if handler is None:
        _p("Неизвестное действие: %s" % action)
        return 2
    return handler(args, rest)


def _mcp_status(args, rest) -> int:
    from core.mcp import auth, permissions, registry, session

    cfg = auth.settings()
    perms = auth.permissions()
    effective = permissions.effective(perms)

    _p("=== MCP-сервер ===")
    _p("состояние:   %s" % ("включён" if cfg.get("enabled")
                            else "выключен (mcp.enabled=false)"))
    if cfg.get("enabled") and not auth.is_enabled():
        _p("             ВНИМАНИЕ: токен не задан и allow_gui_auth "
           "выключен — пускать некого")
    _p("токен:       %s" % ("задан" if cfg.get("token")
                            else "не задан (zapret-gui mcp token rotate)"))
    _p("адрес:       %s" % _mcp_endpoint())
    _p("bind:        %s%s" % (cfg.get("bind", "inherit"),
                              "  (только с самого роутера)"
                              if cfg.get("bind") == "local" else ""))
    transports = cfg.get("transports") or {}
    _p("транспорты:  http=%s  sse=%s%s"
       % ("вкл" if transports.get("http", True) else "выкл",
          "вкл" if transports.get("sse") else "выкл",
          ", открыто потоков: %d" % session.count()
          if transports.get("sse") else ""))
    _p("GUI-авторизация вместо токена: %s"
       % ("да" if cfg.get("allow_gui_auth") else "нет"))

    registry.load_tools()
    _p("")
    _p("инструментов: %d из %d доступны сейчас"
       % (len(registry.available_tools(perms)), len(registry.all_tools())))
    counts = registry.scope_counts(perms)
    for scope in sorted(counts):
        _p("  %-18s %d" % (scope, counts[scope]))

    _p("")
    _p("разрешения:")
    for name in permissions.PERMISSIONS:
        on = bool(perms.get(name))
        live = bool(effective.get(name))
        mark = "✓" if live else ("!" if on else "·")
        note = ""
        if on and not live:
            note = "  (не действует: нужно ещё %s)" % ", ".join(
                permissions.REQUIRES.get(name, ()))
        _p("  %s %-18s %s%s" % (mark, name, "вкл" if on else "выкл", note))
    if not any(perms.values()):
        _p("  — только чтение: ни одно разрешение на запись не включено")
    return 0


def _mcp_token(args, rest) -> int:
    from core.config_manager import get_config_manager
    from core.mcp import auth

    action = (rest[0] if rest else "show").lower()
    cfg = get_config_manager()

    if action == "show":
        token = auth.settings().get("token") or ""
        if not token:
            _p("Токен не задан. Создать: zapret-gui mcp token rotate")
            return 1
        # Печать токена в терминал — осознанное решение: иначе его не
        # скопировать по SSH. Цена — история shell и буфер терминала.
        _p("ВНИМАНИЕ: токен даёт клиенту всё, что открыто разрешениями "
           "MCP, и остаётся в истории shell и в буфере терминала.")
        _p("")
        _p(token)
        return 0

    if action == "rotate":
        token = auth.generate_token()
        cfg.set("mcp", "token", token)
        cfg.save()
        _p("ВНИМАНИЕ: старый токен больше не действует — подключённые "
           "клиенты оборвутся и их придётся перенастроить.")
        _p("")
        _p(token)
        return 0

    _p("Неизвестное действие: %s (show|rotate)" % action)
    return 2


def _mcp_tools(args, rest) -> int:
    import json as _json
    from core.mcp import auth, registry

    perms = auth.permissions()
    registry.load_tools()
    tools = registry.available_tools(perms)

    if getattr(args, "json", False):
        _p(_json.dumps([t.to_wire() for t in tools], ensure_ascii=False,
                       indent=2))
        return 0
    if not tools:
        _p("Доступных инструментов нет (проверьте mcp.permissions)")
        return 1
    for spec in tools:
        _p("  %-28s [%s] %s" % (spec.name, spec.scope or "read",
                                spec.description))
    _p("")
    _p("Итого: %d из %d (остальные закрыты разрешениями)"
       % (len(tools), len(registry.all_tools())))
    return 0


def _mcp_call(args, rest) -> int:
    import json as _json
    from core.mcp import auth, registry, schema

    if not rest:
        _p("Укажите инструмент: zapret-gui mcp call <tool> '<json>'")
        return 2
    name = rest[0]
    raw = rest[1] if len(rest) > 1 else "{}"
    try:
        arguments = _json.loads(raw or "{}")
    except ValueError as e:
        # Самая частая ошибка вызова из shell — кавычки: без одинарных
        # оболочка съедает двойные, и до нас доезжает {a:1}.
        _p("✗ Аргументы не разобраны как JSON: %s" % e)
        _p("  Получено: %s" % raw)
        _p("  Ожидается объект в одинарных кавычках, например:")
        _p("    zapret-gui mcp call %s '{\"limit\": 5}'" % name)
        return 2
    if not isinstance(arguments, dict):
        _p("✗ Аргументы должны быть объектом JSON, а не %s"
           % type(arguments).__name__)
        return 2

    registry.load_tools()
    try:
        result = registry.call(name, arguments, auth.permissions(),
                               {"subject": "cli", "transport": "cli"})
    except registry.UnknownTool as e:
        _p("✗ %s" % (e.args[0] if e.args else e))
        return 1
    except schema.SchemaError as e:
        _p("✗ %s" % e.message)
        return 2

    payload = result.get("structuredContent") or {}
    _p(_json.dumps(payload, ensure_ascii=False, indent=2))
    return 1 if result.get("isError") else 0


def _mcp_stdio(args, rest) -> int:
    from core.mcp import stdio
    return stdio.serve(url=getattr(args, "url", "") or "",
                       token=getattr(args, "token", "") or "",
                       timeout=getattr(args, "timeout", 0) or 0)


def _mcp_audit(args, rest) -> int:
    from core.mcp import audit

    limit = max(1, int(getattr(args, "limit", 50) or 50))
    records, stats = audit.read_records(limit=limit)
    if not records:
        _p("Журнал пуст%s"
           % ("" if audit.is_enabled() else " (mcp.audit.enabled=false)"))
        _p("файл: %s" % stats.get("path", audit.journal_path()))
        return 0
    _p("%-20s %-26s %-9s %s" % ("Время", "Инструмент", "Статус", "Детали"))
    _p("-" * 78)
    for rec in records:
        detail = rec.get("error") or ""
        if not detail and rec.get("result"):
            # Итог вызова (код возврата, первые строки вывода) — его
            # пишет audit.note(): для shell-команд это самое нужное.
            detail = ", ".join("%s=%s" % (k, v) for k, v in
                               sorted(rec["result"].items()))
        _p("%-20s %-26s %-9s %s" % (
            str(rec.get("time") or rec.get("ts", ""))[:19],
            str(rec.get("tool", "?"))[:26],
            str(rec.get("status", "?")),
            _cut(detail, 30)))
    _p("")
    _p("Показано записей: %d (%s)" % (len(records), stats.get(
        "path", audit.journal_path())))
    if stats.get("skipped_lines"):
        _p("Пропущено битых строк: %d" % stats["skipped_lines"])
    return 0


def _mcp_code(args, rest) -> int:
    """Снимки самоправки (S13). Нет модуля — говорим честно."""
    import importlib
    try:
        # import_module, а не `from core import …`: имя модуля,
        # которого в сборке нет, должно давать ImportError, а не
        # атрибут пакета, оставшийся от чужого импорта.
        code_editor = importlib.import_module("core.code_editor")
    except ImportError:
        _p("Самоправка кода в этой сборке недоступна: модуля "
           "core/code_editor.py нет.")
        return 1

    action = (rest[0] if rest else "list").lower()
    if action == "list":
        items = code_editor.history(limit=max(1, int(
            getattr(args, "limit", 20) or 20)))
        if not items:
            _p("Снимков нет: правок через code_apply ещё не было")
            return 0
        _p("%-22s %-20s %-10s %s" % ("Снимок", "Создан", "Состояние",
                                     "Файлы"))
        _p("-" * 78)
        for item in items:
            _p("%-22s %-20s %-10s %s" % (
                item.get("snapshot_id", "?"),
                str(item.get("created", ""))[:19],
                item.get("state", "?"),
                _cut(", ".join(item.get("files") or []), 28)))
        pending = code_editor.last_open_snapshot()
        if pending:
            _p("")
            _p("Не подтверждён: %s — подтвердить code_commit, вернуть "
               "code_rollback" % pending.get("id", "?"))
        return 0

    if action == "diff":
        snapshot_id = rest[1] if len(rest) > 1 else ""
        if snapshot_id:
            manifest = code_editor.read_manifest(snapshot_id)
            if manifest is None:
                _p("✗ Снимка «%s» нет" % snapshot_id)
                return 1
            text = code_editor.snapshot_diff(snapshot_id, manifest)
        else:
            text = code_editor.staging_diff()
            if not text:
                text = code_editor.export_patch()["patch"]
        _p(text or "(различий нет)")
        return 0

    if action in ("export-patch", "export_patch"):
        export = code_editor.export_patch()
        # Патч идёт в stdout как есть: `… > /tmp/local.patch` должен
        # давать файл, который применяется git apply, а не отчёт.
        sys.stdout.write(export.get("patch") or "")
        if not export.get("files"):
            sys.stderr.write("zapret-gui: локальных правок нет\n")
        return 0

    if action == "rollback":
        snapshot_id = rest[1] if len(rest) > 1 else ""
        result = code_editor.rollback(snapshot_id, reason="cli rollback")
        if not result.get("ok"):
            _p("✗ %s" % (result.get("error") or "откат не удался"))
            return 1
        _p("✓ Откат к снимку %s: возвращено %d, удалено %d"
           % (result.get("snapshot_id", snapshot_id or "?"),
              len(result.get("restored") or []),
              len(result.get("removed") or [])))
        if result.get("hint"):
            _p("  %s" % result["hint"])
        return 0

    _p("Неизвестное действие: %s (list|diff|rollback|export-patch)"
       % action)
    return 2


def _mcp_endpoint() -> str:
    """Адрес точки MCP, как его набирать в клиенте."""
    from core.config_manager import get_config_manager
    cfg = get_config_manager()
    host = cfg.get("gui", "host", default="127.0.0.1") or "127.0.0.1"
    port = cfg.get("gui", "port", default=8080) or 8080
    if host in ("0.0.0.0", "::"):
        host = "<адрес роутера>"
    return "http://%s:%s/api/mcp" % (host, port)


def _cut(text, limit: int) -> str:
    text = str(text or "").replace("\n", " ").replace("\r", " ")
    return text if len(text) <= limit else text[:limit - 1] + "…"


# ─────────────────────── entry ───────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="zapret-gui",
        description="CLI-управление zapret-gui (nfqws2 / sing-box / стратегии)")
    p.add_argument("--config", default=None,
                   help="Путь к директории конфигурации")
    sub = p.add_subparsers(dest="command", required=True)

    sub.add_parser("status", help="Общий статус")

    pn = sub.add_parser("nfqws", help="Управление nfqws2")
    pn.add_argument("action", choices=["start", "stop", "restart", "status"])

    ps = sub.add_parser("strategy", help="Стратегии nfqws2")
    ps.add_argument("action", choices=["list", "apply"])
    ps.add_argument("id", nargs="?", help="ID стратегии (для apply)")

    pb = sub.add_parser("singbox", help="Управление sing-box")
    pb.add_argument("action", choices=["list", "up", "down", "restart"])
    pb.add_argument("name", nargs="?", help="Имя конфига")

    pm = sub.add_parser("mihomo", help="Управление mihomo (Clash.Meta)")
    pm.add_argument("action", choices=["list", "up", "down", "restart"])
    pm.add_argument("name", nargs="?", help="Имя конфига")

    pu = sub.add_parser("usque", help="Управление WARP/MASQUE (usque)")
    pu.add_argument("action", choices=["status", "start", "stop"])
    pu.add_argument("iface", nargs="?", help="Интерфейс (opkgtun0)")

    pt = sub.add_parser("tgproxy", help="Управление Telegram MTProto Proxy")
    pt.add_argument("action", choices=["status", "start", "stop"])

    po = sub.add_parser("opera", help="Управление Opera Proxy")
    po.add_argument("action", choices=["status", "start", "stop"])

    sub.add_parser("monitor", help="Live метрики туннелей")
    sub.add_parser("updates", help="Проверка обновлений")

    pdr = sub.add_parser("dns-routing", help="Per-domain DNS routing")
    pdr.add_argument("action", choices=["list", "apply"])

    # mcp: действие необязательно (по умолчанию status), хвост свободный
    # — у разных действий разные аргументы (`token show`, `call <tool>
    # '<json>'`, `code rollback <id>`), и расписывать их отдельными
    # под-парсерами значило бы завести argparse-дерево ради одной ветки.
    pmc = sub.add_parser("mcp", help="MCP-сервер (управление через ИИ)")
    pmc.add_argument("action", nargs="?", default="status",
                     choices=["status", "token", "tools", "call", "stdio",
                              "audit", "code"],
                     help="status | token show|rotate | tools | call | "
                          "stdio | audit | code list|diff|rollback|"
                          "export-patch")
    pmc.add_argument("rest", nargs="*",
                     help="Аргументы действия (имя инструмента и JSON, "
                          "под-действие code/token, id снимка)")
    # Форма из README MCP-клиентов: `zapret-gui mcp --stdio` без слова
    # stdio. Поддерживаем обе — клиент уже настроен как настроен.
    pmc.add_argument("--stdio", action="store_true",
                     help="Поднять stdio-мост (то же, что действие stdio)")
    pmc.add_argument("--json", action="store_true",
                     help="tools: выдать список машинно-читаемо")
    pmc.add_argument("--limit", type=int, default=50,
                     help="audit/code list: сколько записей показать")
    pmc.add_argument("--url", default="",
                     help="stdio: проксировать в HTTP-точку другого "
                          "экземпляра")
    pmc.add_argument("--token", default="",
                     help="stdio: MCP-токен для --url")
    pmc.add_argument("--timeout", type=int, default=0,
                     help="stdio: таймаут запроса в режиме прокси, сек")

    return p


_DISPATCH = {
    "status":      _cmd_status,
    "nfqws":       _cmd_nfqws,
    "strategy":    _cmd_strategy,
    "singbox":     _cmd_singbox,
    "mihomo":      _cmd_mihomo,
    "usque":       _cmd_usque,
    "tgproxy":     _cmd_tgproxy,
    "opera":       _cmd_opera,
    "monitor":     _cmd_monitor,
    "updates":     _cmd_updates,
    "dns-routing": _cmd_dns_routing,
    "mcp":         _cmd_mcp,
}


def run(argv) -> int:
    """Точка входа CLI. argv — список без имени программы."""
    parser = build_parser()
    args = parser.parse_args(argv)

    # Инициализируем только ядро (без web-сервера).
    try:
        from core.config_manager import init_config
        init_config(args.config)
    except Exception as e:
        _p("Ошибка инициализации конфига: %s" % e)
        return 2

    handler = _DISPATCH.get(args.command)
    if handler is None:
        parser.print_help()
        return 2
    try:
        return handler(args)
    except Exception as e:
        _p("Ошибка: %s" % e)
        return 2


def main():
    sys.exit(run(sys.argv[1:]))
