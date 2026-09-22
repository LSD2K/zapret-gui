# core/tunnels_control.py
"""
Поднять, погасить и переписать конфиг туннеля — одним вызовом на все
шесть движков.

Пара к :mod:`core.tunnels_overview`: тот **читает** состояние шести
движков в одной форме, этот — **меняет** его в одной форме. Почему
отдельный модуль, а не шесть инструментов MCP и не код внутри
``tools/``:

* поднимают туннель шестью разными способами. У sing-box и mihomo это
  ``up(name)``; у AmneziaWG — тоже ``up(name)``, но имя конфига и имя
  интерфейса могут разойтись; usque требует **сначала выделить
  интерфейс**, а потом ``start(iface, config_path, …)`` с профилем
  транспорта из настроек; у Opera Proxy аргументы старта собираются из
  секции конфига, и после успешного старта надо выставить
  ``opera_proxy.enabled`` и перенастроить watchdog, иначе автозапуск и
  сторож остаются мёртвыми; Telegram-прокси — это вообще два
  независимых движка под одной страницей;
* всё это уже написано — в ``api/*.py``, внутри HTTP-обработчиков.
  Позвать их из MCP нельзя, а повторить по памяти значит завести
  вторую, расходящуюся реализацию: «поднял из GUI» и «поднял из MCP»
  начали бы значить разное. Поэтому логика переехала сюда, и теперь ею
  пользуются оба;
* ошибка «движок не установлен» и ошибка «конфига нет» должны звучать
  одинаково у всех шести. Отдельный слой это гарантирует, шесть
  обработчиков — нет.

Модуль ничего не знает про MCP: разрешения и форму ответа инструмента
добавляет ``core/mcp/tools/tunnels.py``.
"""

from core.log_buffer import log
from core.tunnels_overview import ENGINES, TITLES


# Движки, у которых конфиг — это файл, который можно прочитать и
# переписать целиком. У usque конфиг создаётся регистрацией устройства
# в Cloudflare (ключи и токен), у Telegram- и Opera-прокси файла нет
# вовсе — их настройки живут в settings.json.
CONFIG_ENGINES = ("singbox", "mihomo", "awg")

# Сколько байт конфига принимаем на запись. Конфиг sing-box с полусотней
# outbound'ов — это десятки килобайт; мегабайт сюда не приезжает никогда.
MAX_CONFIG_BYTES = 512 * 1024


class EngineError(ValueError):
    """Движок или конфиг назван неверно — это ответ, а не исключение."""


# ──────────────────────────── запуск ────────────────────────────────

def up(engine: str, name: str = "") -> dict:
    """Поднять инстанс движка."""
    return _dispatch(engine, name, "up")


def down(engine: str, name: str = "") -> dict:
    """Погасить инстанс движка."""
    return _dispatch(engine, name, "down")


def restart(engine: str, name: str = "") -> dict:
    """Перезапустить инстанс: движки без своего restart гасим и поднимаем."""
    return _dispatch(engine, name, "restart")


def _dispatch(engine: str, name: str, action: str) -> dict:
    engine = _engine(engine)
    handler = _ACTIONS[engine]
    result = handler(name, action)
    if not isinstance(result, dict):
        result = {"ok": bool(result)}
    result.setdefault("ok", True)
    result["engine"] = engine
    result["action"] = action
    if name:
        result.setdefault("name", name)
    level = "info" if result.get("ok") else "warning"
    getattr(log, level)(
        "tunnels_control: %s %s%s — %s"
        % (action, TITLES.get(engine, engine),
           ("/" + name) if name else "",
           "ок" if result.get("ok") else result.get("error", "ошибка")),
        source="tunnels")
    return result


# ──────────────────────────── конфиги ───────────────────────────────

def config_get(engine: str, name: str) -> dict:
    """Текст конфига движка.

    Конфиг туннеля — это ключи, пароли и адреса подписок. Маскировкой
    занимается слой MCP (``core/mcp/redact.py``), здесь текст отдаётся
    как есть: модулем пользуется и UI, которому маска не нужна.
    """
    engine = _engine(engine, allowed=CONFIG_ENGINES,
                     why="у него нет конфига-файла")
    name = _name(name)
    if engine == "singbox":
        from core.singbox_manager import get_singbox_manager
        data = get_singbox_manager().get_config(name)
    elif engine == "mihomo":
        from core.mihomo_manager import get_mihomo_manager
        data = get_mihomo_manager().get_config(name)
    else:
        from core.awg_manager import get_awg_manager
        data = get_awg_manager().get_config(name)
    if not isinstance(data, dict):
        raise EngineError("конфиг «%s» не прочитан" % name)
    if data.get("ok") is False:
        raise EngineError(str(data.get("error") or
                              "конфиг «%s» не прочитан" % name))
    text = data.get("text") or ""
    return {
        "ok": True,
        "engine": engine,
        "name": name,
        "path": data.get("path", ""),
        "text": text,
        "size": len(text.encode("utf-8")),
        "errors": data.get("errors") or [],
        "running": bool(data.get("active") or data.get("running")),
    }


def config_save(engine: str, name: str, text: str) -> dict:
    """Переписать конфиг движка целиком.

    Целиком — а не по частям: у трёх движков три разных формата (JSON,
    YAML, ini-подобный .conf), и точечная правка каждого была бы третьей
    реализацией разбора. Прежний текст возвращается в ``before`` — по
    нему делается снимок для отката.
    """
    engine = _engine(engine, allowed=CONFIG_ENGINES,
                     why="у него нет конфига-файла")
    name = _name(name)
    if not isinstance(text, str) or not text.strip():
        raise EngineError("конфиг пуст")
    size = len(text.encode("utf-8"))
    if size > MAX_CONFIG_BYTES:
        raise EngineError("конфиг великоват: %d байт при пределе %d"
                          % (size, MAX_CONFIG_BYTES))

    before = None
    try:
        before = config_get(engine, name).get("text")
    except (EngineError, Exception):            # noqa: BLE001 — граница
        # Конфига может не быть: это создание нового, а не ошибка.
        before = None

    if engine == "singbox":
        from core.singbox_manager import get_singbox_manager
        result = get_singbox_manager().save_config(name, text=text)
    elif engine == "mihomo":
        from core.mihomo_manager import get_mihomo_manager
        result = get_mihomo_manager().save_config(name, text)
    else:
        from core.awg_manager import get_awg_manager
        try:
            result = get_awg_manager().save_config(name, text=text)
        except ValueError as e:
            raise EngineError(str(e))
    if not isinstance(result, dict):
        result = {"ok": bool(result)}
    if result.get("ok") is False:
        raise EngineError(str(result.get("error") or "конфиг не сохранён"))

    out = {
        "ok": True,
        "engine": engine,
        "name": name,
        "path": result.get("path", ""),
        "size": size,
        "created": before is None,
        "changed": before != text,
        "before": before,
        "warnings": result.get("warnings") or result.get("errors") or [],
    }
    log.info("tunnels_control: сохранён конфиг %s/%s (%d байт)"
             % (engine, name, size), source="tunnels")
    return out


def instances(engine: str) -> list:
    """Имена инстансов движка — то же, что показывает ``tunnels_status``."""
    from core import tunnels_overview

    report = tunnels_overview.overview(engine=_engine(engine), logs=False)
    if not report.get("ok"):
        return []
    out = []
    for record in report.get("engines") or []:
        for item in record.get("instances") or []:
            out.append(item.get("name", ""))
    return [name for name in out if name]


# ─────────────────────── движки: по одному ──────────────────────────

def _simple(getter, has_restart=True):
    """Адаптер для движков с ``up(name)``/``down(name)``/``restart(name)``."""
    def handler(name, action):
        manager = getter()
        target = _name(name)
        if action == "up":
            return manager.up(target)
        if action == "down":
            return manager.down(target)
        if has_restart:
            return manager.restart(target)
        manager.down(target)
        return manager.up(target)
    return handler


def _singbox(name, action):
    from core.singbox_manager import get_singbox_manager
    return _simple(get_singbox_manager)(name, action)


def _mihomo(name, action):
    from core.mihomo_manager import get_mihomo_manager
    return _simple(get_mihomo_manager)(name, action)


def _awg(name, action):
    from core.awg_manager import get_awg_manager
    return _simple(get_awg_manager)(name, action)


def _usque(name, action):
    """usque: интерфейс выделяется отдельно, старт берёт профиль из настроек.

    Повтор логики ``api/usque.py``: «Tunnel established» без поднятого
    интерфейса ничего не значит, поэтому интерфейс обязан быть выделен
    ДО старта, а профиль транспорта (performance/restricted) — взят из
    тех же настроек, что использует GUI.
    """
    from core.config_manager import get_config_manager
    from core.usque_manager import get_usque_manager

    manager = get_usque_manager()
    target = _name(name)
    configs = manager.list_configs() or []
    found = next((c for c in configs if c.get("name") == target), None)
    if not found:
        raise EngineError("конфига usque «%s» нет; есть: %s"
                          % (target,
                             ", ".join(c.get("name", "") for c in configs)
                             or "ни одного"))

    if action in ("down", "restart"):
        iface = found.get("iface") or ""
        stopped = (manager.stop(iface) if iface
                   else {"ok": True, "message": "уже остановлен"})
        if action == "down":
            return stopped

    cfg = get_config_manager()
    sni = cfg.get("usque", "default_sni", default="")
    http2 = cfg.get("usque", "http2_enable", default=False)
    iface = manager.iface_for_config(found["path"])
    if not iface:
        raise EngineError("не удалось выделить интерфейс usque")
    profile = "restricted" if http2 else cfg.get(
        "usque", "transport_profile", default="performance")
    return manager.start(iface, found["path"], sni=sni,
                         transport_profile=profile)


def _tgproxy(name, action):
    """Telegram-прокси: два независимых движка под одной страницей.

    ``tgwsproxy`` — основной (tg-ws-proxy-go), ``mtproto`` — резервный
    клиент. Два запущенных сразу — это две разные ссылки ``tg://proxy``,
    поэтому имя здесь обязательно: «подними Telegram-прокси» без
    уточнения означало бы «подними наугад один из двух».
    """
    from core import tgproxy_manager as tg

    target = (name or "").strip() or "tgwsproxy"
    if target == "tgwsproxy":
        manager = tg.get_tgwsproxy_manager()
        if action == "up":
            return manager.start()
        if action == "down":
            return manager.stop()
        return manager.restart()

    if target != "mtproto":
        raise EngineError("у Telegram-прокси два движка: tgwsproxy "
                          "(основной) и mtproto (резервный); «%s» —  "
                          "ни тот, ни другой" % target)

    from core.config_manager import get_config_manager
    from core.tgproxy_manager import MTPROXY_LOCAL_PORT

    manager = tg.get_mtproxy_client_manager()
    if action in ("down", "restart"):
        stopped = manager.stop()
        if action == "down":
            return stopped

    cfg = get_config_manager()
    relay = (cfg.get("tgproxy", "tunnel_url", default="") or "").strip()
    if not relay:
        raise EngineError("резервный mtproto-клиент требует relay: "
                          "задайте tgproxy.tunnel_url на странице "
                          "Telegram-прокси")
    secret = (cfg.get("tgproxy", "tunnel_secret", default="") or "").strip()
    try:
        port = int(cfg.get("tgproxy", "port", default=MTPROXY_LOCAL_PORT)
                   or MTPROXY_LOCAL_PORT)
    except (TypeError, ValueError):
        port = MTPROXY_LOCAL_PORT
    return manager.start(port=port, relay=relay, secret=secret)


def _opera(name, action):
    """Opera Proxy: старт из сохранённых настроек + флаг и watchdog.

    Без ``opera_proxy.enabled`` автозапуск и сторож остаются мёртвыми —
    флаг гейтит обоих. Ровно это делает ``api/opera_proxy.py``, и
    расходиться с ним нельзя: иначе «поднял из MCP» переживает
    перезагрузку не так, как «поднял из GUI».
    """
    from core.config_manager import get_config_manager
    from core.opera_proxy_manager import (get_opera_proxy_manager,
                                          start_kwargs_from_config)

    manager = get_opera_proxy_manager()
    cfg = get_config_manager()

    if action in ("down", "restart"):
        cfg.set("opera_proxy", "enabled", False)
        cfg.save()
        stopped = manager.stop()
        _opera_watchdog()
        if action == "down":
            return stopped

    result = manager.start(**start_kwargs_from_config(cfg))
    if isinstance(result, dict) and result.get("ok"):
        cfg.set("opera_proxy", "enabled", True)
        cfg.save()
        _opera_watchdog()
    return result


def _opera_watchdog():
    try:
        from core.opera_proxy_watchdog import get_opera_proxy_watchdog
        get_opera_proxy_watchdog().reconfigure()
    except Exception:                           # noqa: BLE001 — граница
        pass


_ACTIONS = {
    "singbox": _singbox,
    "mihomo":  _mihomo,
    "awg":     _awg,
    "usque":   _usque,
    "tgproxy": _tgproxy,
    "opera":   _opera,
}


# ───────────────────────────── частности ────────────────────────────

def _engine(engine: str, allowed=ENGINES, why: str = "") -> str:
    name = (engine or "").strip().lower()
    if name not in ENGINES:
        raise EngineError("неизвестный движок «%s»; известные: %s"
                          % (engine, ", ".join(ENGINES)))
    if name not in allowed:
        raise EngineError("движок «%s» так не умеет: %s; умеют: %s"
                          % (name, why or "действие не поддерживается",
                             ", ".join(allowed)))
    return name


def _name(name: str) -> str:
    """Имя инстанса: проверяем ДО менеджера, слешей здесь быть не может."""
    value = (name or "").strip()
    if not value:
        raise EngineError("не передано имя конфига или инстанса")
    if "/" in value or "\\" in value or value in (".", ".."):
        raise EngineError("недопустимое имя «%s»" % name)
    return value
