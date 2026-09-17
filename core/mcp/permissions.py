# core/mcp/permissions.py
"""
Модель разрешений MCP и whitelist настроек, доступных на запись.

Здесь только **модель и проверки**. Саму запись (``config_set``,
аудит, ``mcp_undo_last``) делает S6 — она обязана спрашивать
:func:`is_writable` и ничего не решать сама.

## Разрешения

Одиннадцать переключателей в ``settings.json → mcp.permissions``, все
по умолчанию ``False``; чтение доступно всегда и переключателя не
имеет. Инструмент объявляет ``scope``; ``tools/list`` отдаёт только
разрешённые.

Два разрешения не самостоятельны:

* ``experiments`` требует ``control`` и ``probes`` — эксперимент
  применяет стратегию и выпускает трафик; включённый сам по себе, он
  обещает то, чего не может;
* ``self_edit_core`` требует ``self_edit`` — это расширение, а не
  отдельная дверь.

Невыполненная зависимость **не игнорируется молча**: :func:`denial`
возвращает причину и список того, что нужно включить, — иначе
пользователь видит выключенный инструмент при включённом разрешении и
идёт чинить то, что не сломано.

## Граница записи

Проходит по **обратимости, а не по чувствительности** (контракт §4).
Неверное значение внутри стратегии ломает часть сайтов — это видно и
откатывается одним вызовом. Неверный порт GUI, бэкенд firewall или
desync-метка оставляют роутер недоступным, и отменить изменение уже
нечем.

Поэтому:

* писать можно только в перечисленные поддеревья
  (:data:`WRITABLE_SECTIONS`) и только в **листья** — секцию целиком
  подменить нельзя;
* **запреты сильнее разрешений** (:data:`DENY_PATHS`,
  :func:`_is_denied_key`): расположения файлов и каталогов, метки
  десинка, номер очереди и всё, что похоже на секрет, не принимаются
  даже внутри разрешённого поддерева. Отклоняем **расположение**, но не
  содержимое: сами списки и lua модель правит через ``strategies_write``.

Неверный путь не «ломает громко»: GUI продолжает работать, просто часть
логики тихо выключается — поэтому пути и не отдаются на запись.
"""

import re

from core.mcp import redact


# Порядок — как в docs/mcp/00-contract.md §4.
PERMISSIONS = (
    "control", "strategies_write", "config_write", "probes", "experiments",
    "tunnels_write", "dangerous", "shell_readonly", "shell_full",
    "self_edit", "self_edit_core",
)

# Scope инструмента, доступного всегда (чтение).
READ_SCOPE = "read"

# Все допустимые значения ``scope`` в объявлении инструмента.
SCOPES = (READ_SCOPE,) + PERMISSIONS

# Разрешение → что обязано быть включено вместе с ним.
REQUIRES = {
    "experiments": ("control", "probes"),
    "self_edit_core": ("self_edit",),
}

# Короткое описание для UI и для текста отказа.
TITLES = {
    "control": "управление движками (старт/стоп/перезапуск, применение "
               "стратегий)",
    "strategies_write": "правка стратегий, hostlist'ов, ipset'ов, lua",
    "config_write": "запись настроек в разрешённые поддеревья",
    "probes": "активные пробы: трафик с роутера, blockcheck, сканер",
    "experiments": "движок экспериментов со стратегиями",
    "tunnels_write": "конфиги и запуск туннелей (sing-box, mihomo, AWG, "
                     "usque, tgproxy, opera)",
    "dangerous": "бинарники, автозапуск, миграции, правила единого слоя, "
                 "перезагрузка",
    "shell_readonly": "безопасные команды, чтение файлов и каталогов",
    "shell_full": "произвольная команда от root, запись файлов, пакеты, "
                  "службы",
    "self_edit": "чтение и правка модулей GUI на устройстве",
    "self_edit_core": "правка защищённого ядра GUI",
}

# ─────────────────────── настройки на запись ────────────────────────

# Поддеревья settings.json, открытые для config_set (S6).
#
# ``logging`` здесь не для удобства: без него модель не может поднять
# уровень лога, воспроизвести проблему и прочитать результат — то есть
# не может отладить ничего.
WRITABLE_SECTIONS = (
    "nfqws", "filter", "strategy", "blockcheck", "healthcheck", "scan",
    "block_detector", "dns_routing", "logging",
)

# Точечные запреты внутри разрешённых поддеревьев.
DENY_PATHS = frozenset((
    # На них держится перехват и собственный трафик GUI.
    "nfqws.queue_num",
    "nfqws.user",
))

# Запрет по префиксу: nfqws.desync_mark, nfqws.desync_mark_postnat.
DENY_PATH_PREFIXES = ("nfqws.desync_mark",)

# Ключи-расположения: путь, каталог, бинарник. Неверный путь не роняет
# GUI с ошибкой — он тихо выключает часть логики, и понять это снаружи
# нельзя.
DENY_KEY_RE = re.compile(
    r"(?i)(?:^|_)(?:path|paths|dir|dirs|file|files|binary|bin|exe|"
    r"workdir|root)$")

# Поля с заданным набором значений. Держим руками: источник — те же
# списки, что в web/js/pages/settings.js. Расхождение здесь не опасно
# (значение всё равно проверит менеджер), но подсказка модели врать не
# должна.
ENUMS = {
    "filter.mode": ["none", "autohostlist", "ipset", "hostlist"],
    "logging.level": ["DEBUG", "INFO", "WARNING", "ERROR"],
    "logging.persist_min_level": ["WARNING", "ERROR"],
    "blockcheck.default_mode": ["quick", "full"],
    "scan.default_mode": ["quick", "full"],
    "scan.default_protocol": ["tcp", "udp"],
    "block_detector.dns_source": ["auto", "dnsmasq_log", "adguard_log",
                                  "af_packet"],
}


# ──────────────────────────── разрешения ────────────────────────────

def current() -> dict:
    """Разрешения из конфига, все ключи, значения — ``bool``."""
    from core.mcp import auth
    return normalize(auth.permissions())


def normalize(perms=None) -> dict:
    """Привести карту разрешений к полному виду.

    Отсутствующий ключ — это ``False``: новая настройка не становится
    доступной на запись сама по себе (инвариант §5.1).
    """
    given = perms if isinstance(perms, dict) else {}
    return {name: bool(given.get(name)) for name in PERMISSIONS}


def effective(perms=None) -> dict:
    """Разрешения с учётом зависимостей.

    ``experiments`` без ``control``/``probes`` выключен, как бы ни
    стоял его собственный флаг.
    """
    granted = normalize(perms)
    out = dict(granted)
    for name, needed in REQUIRES.items():
        if out.get(name) and not all(granted.get(dep) for dep in needed):
            out[name] = False
    return out


def unmet(name: str, perms=None) -> list:
    """Какие зависимости разрешения ``name`` не включены."""
    granted = normalize(perms)
    return [dep for dep in REQUIRES.get(name, ())
            if not granted.get(dep)]


def allowed(scope, perms=None) -> bool:
    """Открыт ли ``scope`` текущими разрешениями.

    ``None``/``"read"`` — чтение, доступно всегда.
    """
    if not scope or scope == READ_SCOPE:
        return True
    return bool(effective(perms).get(scope))


def denial(scope, perms=None) -> dict:
    """Готовый ответ инструмента, которому не хватило разрешения.

    Текст читает модель: он обязан называть, что именно включить, —
    иначе она пробует ещё раз то же самое.
    """
    granted = normalize(perms)
    missing = unmet(scope, granted)
    if granted.get(scope) and missing:
        # Флаг стоит, но зависимость не выполнена — самый непонятный
        # случай, и молчать о нём нельзя.
        hint = ("разрешение «%s» включено, но требует ещё: %s — включите "
                "их в настройках MCP" % (scope, ", ".join(missing)))
        error = "разрешение %s не действует без %s" % (scope,
                                                       ", ".join(missing))
    else:
        hint = "включите разрешение «%s» в настройках MCP" % scope
        error = "нет разрешения %s" % scope
        if missing:
            hint += " (вместе с ним: %s)" % ", ".join(missing)
    return {
        "ok": False,
        "error": error,
        "permission": scope,
        "requires": list(REQUIRES.get(scope, ())),
        "missing": missing,
        "hint": hint,
    }


def describe(perms=None) -> list:
    """Таблица разрешений для UI и для ``/api/mcp/info``."""
    granted = normalize(perms)
    active = effective(granted)
    out = []
    for name in PERMISSIONS:
        out.append({
            "key": name,
            "title": TITLES.get(name, ""),
            "granted": granted[name],
            "effective": active[name],
            "requires": list(REQUIRES.get(name, ())),
            "missing": unmet(name, granted) if granted[name] else [],
        })
    return out


# ───────────────────── настройки: что можно писать ──────────────────

def is_writable(path) -> bool:
    """Можно ли записать значение по точечному пути ``settings.json``.

    Путь — строка (``"nfqws.ports_tcp"``) или последовательность
    ключей. Секцию целиком (``"nfqws"``) записать нельзя: в ней есть
    запрещённые листья, и запись пачкой обошла бы их проверку.
    """
    parts = split_path(path)
    if len(parts) < 2:
        return False
    if parts[0] not in WRITABLE_SECTIONS:
        return False

    dotted = ".".join(parts)
    if dotted in DENY_PATHS:
        return False
    if any(dotted.startswith(prefix) for prefix in DENY_PATH_PREFIXES):
        return False
    for segment in parts[1:]:
        if _is_denied_key(segment):
            return False

    # Существующее поддерево — не лист: писать в него нельзя.
    known = _default_at(parts)
    if isinstance(known, dict):
        return False
    return True


def why_not_writable(path) -> str:
    """Почему путь не принимается на запись — текстом для модели."""
    parts = split_path(path)
    if len(parts) < 2:
        return ("нужен путь вида «секция.ключ»: секцию целиком записать "
                "нельзя")
    if parts[0] not in WRITABLE_SECTIONS:
        return ("секция «%s» закрыта на запись через MCP; открыты: %s"
                % (parts[0], ", ".join(WRITABLE_SECTIONS)))
    dotted = ".".join(parts)
    if dotted in DENY_PATHS or any(dotted.startswith(p)
                                   for p in DENY_PATH_PREFIXES):
        return ("«%s» закрыт: на нём держатся перехват и собственный "
                "трафик GUI" % dotted)
    for segment in parts[1:]:
        if redact.is_secret_key(segment):
            return "«%s» похож на секрет и на запись не принимается" % dotted
        if DENY_KEY_RE.search(segment):
            return ("«%s» задаёт расположение файла или каталога: неверный "
                    "путь не ломает GUI громко, а тихо выключает часть "
                    "логики" % dotted)
    if isinstance(_default_at(parts), dict):
        return "«%s» — поддерево, а не значение: укажите конкретный ключ" \
            % dotted
    return ""


def writable_paths() -> list:
    """Все листья настроек, открытые на запись.

    Отдаётся инструменту ``config_writable_paths`` (S6): путь, тип,
    текущее значение и допустимые значения — чтобы модель не угадывала
    формат.
    """
    from core.config_manager import DEFAULT_CONFIG, get_config_manager

    cfg = get_config_manager()
    out = []
    for section in WRITABLE_SECTIONS:
        defaults = DEFAULT_CONFIG.get(section)
        if not isinstance(defaults, dict):
            continue
        for path, default in sorted(_walk(section, defaults)):
            if not is_writable(path):
                continue
            keys = path.split(".")
            value = cfg.get(*keys, default=default)
            item = {
                "path": path,
                "type": _json_type(default if default is not None else value),
                "value": value,
                "default": default,
            }
            if path in ENUMS:
                item["enum"] = list(ENUMS[path])
            out.append(item)
    return out


def non_writable_paths() -> list:
    """Листья настроек, закрытые на запись, — с причиной отказа.

    Нужна сторожу (``tests/test_mcp_writable_paths.py``): каждый ключ
    конфига обязан быть отнесён к одной из двух сторон осознанно, а не
    «не попал в whitelist, и ладно».
    """
    from core.config_manager import DEFAULT_CONFIG

    out = []
    for section in sorted(DEFAULT_CONFIG):
        defaults = DEFAULT_CONFIG.get(section)
        if not isinstance(defaults, dict):
            out.append({"path": section,
                        "reason": "значение верхнего уровня"})
            continue
        for path, _ in sorted(_walk(section, defaults)):
            if is_writable(path):
                continue
            out.append({"path": path, "reason": why_not_writable(path)})
    return out


def split_path(path) -> list:
    """Разобрать точечный путь в список ключей."""
    if isinstance(path, str):
        return [p for p in path.split(".") if p]
    if isinstance(path, (list, tuple)):
        return [str(p) for p in path if str(p)]
    return []


# ───────────────────────────── частности ────────────────────────────

def _is_denied_key(segment: str) -> bool:
    return bool(DENY_KEY_RE.search(segment)) or redact.is_secret_key(segment)


def _default_at(parts):
    """Значение по пути в ``DEFAULT_CONFIG`` (или ``None``)."""
    from core.config_manager import DEFAULT_CONFIG

    node = DEFAULT_CONFIG
    for key in parts:
        if not isinstance(node, dict) or key not in node:
            return None
        node = node[key]
    return node


def _walk(prefix: str, node: dict):
    """Пары (точечный путь, значение) по всем листьям поддерева."""
    for key, value in node.items():
        path = "%s.%s" % (prefix, key)
        if isinstance(value, dict) and value:
            for item in _walk(path, value):
                yield item
        else:
            yield path, value


def _json_type(value) -> str:
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    if isinstance(value, dict):
        return "object"
    return "null"
