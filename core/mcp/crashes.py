# core/mcp/crashes.py
"""
Падения инструментов MCP: трассировка, которую раньше выбрасывали.

До этого модуля упавший обработчик оставлял после себя строку
``TypeError: 'NoneType' object is not subscriptable`` — в ответе модели
и, подрезанной до 500 символов, в журнале. Трассировка писалась в
лог-буфер уровнем ``debug`` и пропадала вместе с ним. Ни файла, ни
строки: даже идеально составленный отчёт об ошибке не говорил, **где**
она.

Теперь ``registry.call`` в ветке ``except`` зовёт :func:`capture`, и
падение ложится записью в ``mcp-crashes.jsonl`` рядом с
``settings.json`` (``platform_dirs.config_dir()``, **не** ``/tmp``: там
tmpfs, а падение разбирают после ребута не реже, чем до). В ответ
модели уезжает ``crash_id`` — по нему ``issue_draft`` приложит
трассировку к черновику issue.

## Что в записи — и чего в ней нет

* **кадры только из файлов проекта**, пути относительно корня
  (``core/mcp/tools/lists.py``), без ``vendor/`` и stdlib: путь
  установки (``/opt/share/zapret-gui``) разработчику не нужен, а кадры
  стандартной библиотеки место в записи занимают, а ошибку не
  локализуют. Не нашлось ни одного кадра проекта — отдаём последние
  кадры как есть (тоже относительными, если можно);
* текст строки кода — он публичный (исходники лежат на GitHub) и
  экономит разработчику открытие файла нужной версии;
* аргументы — тем же ``audit._safe_args``, что журнал: маскировка
  по ключам **и** по тексту, подрезка;
* версия GUI и **признак локальных правок кода** (самоправка S13):
  номера строк после ``code_apply`` с релизом не совпадают, и сказать
  об этом надо в самой записи, а не догадываться при разборе;
* ``fingerprint`` — sha1 от инструмента, типа исключения и верхнего
  кадра проекта: одинаковые падения склеиваются в один черновик issue.

Модуль не имеет права падать сам: он вызывается из обработчика ошибки,
и исключение отсюда заменило бы собой исходное.
"""

import hashlib
import json
import os
import threading
import time
import traceback
import uuid

from core.log_buffer import log
from core.mcp import redact as redact_mod
from core.safe_io import atomic_write_text


FILE_NAME = "mcp-crashes.jsonl"

# Сколько падений держим. Файл переписывается целиком при ротации, а
# падений в здоровой системе единицы — двух десятков хватает, чтобы
# дожить до разбора, и мало, чтобы файл разросся.
KEEP = 30

# Сколько кадров проекта кладём в запись (с конца — ближайшие к месту
# падения). Глубже — это уже цепочка вызовов реестра.
MAX_FRAMES = 12

# Подрезка текста исключения и строки кода.
MAX_MESSAGE = 500
MAX_CODE = 200

# Кадр, который есть в любой трассировке инструмента, — выкидываем.
REGISTRY_FILE = "core/mcp/registry.py"

_lock = threading.Lock()


# ─────────────────────────────── пути ───────────────────────────────

def project_root() -> str:
    """Корень установки GUI: модуль лежит в ``core/mcp/``.

    Не ``code_editor.project_root()``: та читает настройки самоправки,
    а этому модулю нельзя тянуть ничего, что может упасть.
    """
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.realpath(os.path.dirname(os.path.dirname(here)))


def path() -> str:
    from core import platform_dirs
    return os.path.join(platform_dirs.config_dir(), FILE_NAME)


def relative(filename: str) -> str:
    """Путь относительно корня проекта или ``""``, если файл не наш."""
    if not filename:
        return ""
    try:
        full = os.path.realpath(filename)
    except (OSError, ValueError):
        return ""
    root = project_root()
    if not full.startswith(root + os.sep) or not os.path.isfile(full):
        return ""
    rel = os.path.relpath(full, root).replace(os.sep, "/")
    if rel.startswith("vendor/"):
        return ""
    return rel


def locate(func) -> dict:
    """Где объявлена функция: файл относительно проекта и первая строка.

    Нужна двоим: записи о падении (``handler``) и черновику issue —
    разработчику «инструмент blobs_list» ничего не говорит, а
    ``core/mcp/tools/lists.py:212`` открывается сразу.
    """
    code = getattr(func, "__code__", None)
    if code is None:
        return {}
    rel = relative(code.co_filename)
    return {"file": rel or os.path.basename(code.co_filename),
            "line": code.co_firstlineno,
            "function": getattr(func, "__qualname__", code.co_name),
            "module": getattr(func, "__module__", "")}


# ────────────────────────────── запись ──────────────────────────────

def capture(tool, exc, *, args=None, handler=None, elapsed_ms=0) -> dict:
    """Записать падение инструмента и вернуть запись (с ``crash_id``).

    Зовётся из ``except`` реестра; ``exc.__traceback__`` ещё жив.
    Любая ошибка внутри — это пустой словарь и строка в debug-логе, но
    не исключение.
    """
    try:
        entry = _build(tool, exc, args=args, handler=handler,
                       elapsed_ms=elapsed_ms)
    except Exception as e:                      # noqa: BLE001 — граница
        _debug("не удалось разобрать падение %s: %s" % (tool, e))
        return {}
    _append(entry)
    return entry


def _build(tool, exc, *, args=None, handler=None, elapsed_ms=0) -> dict:
    from core.mcp import audit
    frames = frames_of(getattr(exc, "__traceback__", None))
    exc_type = type(exc).__name__
    message = redact_mod.redact_text(str(exc), force=True)[:MAX_MESSAGE]
    entry = {
        "crash_id": "crash-%s" % uuid.uuid4().hex[:10],
        "ts": round(time.time(), 3),
        "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
        "tool": str(tool),
        "exc_type": exc_type,
        "message": message,
        "frames": frames,
        "args": audit._safe_args(args),
        "elapsed_ms": int(elapsed_ms or 0),
        "version": gui_version(),
        "fingerprint": fingerprint(tool, exc_type, frames),
    }
    where = locate(handler) if handler is not None else {}
    if where:
        entry["handler"] = where
    changes = local_code_changes()
    if changes.get("count"):
        entry["local_code_changes"] = changes
    return entry


def frames_of(tb) -> list:
    """Кадры трассировки: сначала только проектные, ближние к падению."""
    if tb is None:
        return []
    extracted = traceback.extract_tb(tb)
    ours = []
    for item in extracted:
        rel = relative(item.filename)
        # Кадр самого реестра (``registry.call`` → ``spec.handler``) есть
        # в каждой трассировке и ничего не локализует.
        if rel and not (rel == REGISTRY_FILE and item.name == "call"):
            ours.append(_frame(rel, item))
    if not ours:
        # Упало целиком внутри stdlib/vendor (или в коде, которого нет
        # на диске). Пустой список хуже чужих кадров: берём хвост.
        ours = [_frame(os.path.basename(item.filename or "?"), item)
                for item in extracted]
    return ours[-MAX_FRAMES:]


def _frame(rel, item) -> dict:
    code = redact_mod.redact_text((item.line or "").strip(), force=True)
    return {"file": rel, "line": item.lineno, "function": item.name,
            "code": code[:MAX_CODE]}


def fingerprint(tool, exc_type, frames) -> str:
    """Отпечаток падения: инструмент + тип + верхний кадр проекта.

    Номер строки в отпечаток НЕ входит: он сдвигается от любой правки
    выше по файлу, и одна ошибка после обновления GUI выглядела бы
    новой. Функция сдвигается реже.
    """
    top = frames[-1] if frames else {}
    raw = "|".join((str(tool), str(exc_type), str(top.get("file", "")),
                    str(top.get("function", ""))))
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


# ────────────────────────────── чтение ──────────────────────────────

def recent(limit: int = 0) -> list:
    """Записи о падениях, новые первыми."""
    items = _read()
    items.reverse()
    if limit and limit > 0:
        items = items[:limit]
    return items


def get(crash_id: str):
    """Запись по ``crash_id`` или ``None``."""
    if not crash_id:
        return None
    for item in _read():
        if item.get("crash_id") == crash_id:
            return item
    return None


# ───────────────────────────── частности ────────────────────────────

def gui_version() -> str:
    try:
        from core.version import GUI_VERSION
        return GUI_VERSION
    except Exception:                           # noqa: BLE001 — граница
        return ""


def local_code_changes() -> dict:
    """Правки кода на устройстве (S13): номера строк им не верны."""
    try:
        from core.code_editor import local_changes_warning
        info = local_changes_warning()
    except Exception:                           # noqa: BLE001 — граница
        return {"count": 0, "files": []}
    return info if isinstance(info, dict) else {"count": 0, "files": []}


def _read() -> list:
    try:
        with open(path(), "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return []
    out = []
    for line in lines[-KEEP * 2:]:
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue                            # полстроки после розетки
        if isinstance(item, dict):
            out.append(item)
    return out


def _append(entry: dict):
    target = path()
    if not os.path.isdir(os.path.dirname(target)):
        return
    line = json.dumps(entry, ensure_ascii=False, default=str) + "\n"
    with _lock:
        try:
            with open(target, "a", encoding="utf-8") as f:
                f.write(line)
                f.flush()
            with open(target, "r", encoding="utf-8",
                      errors="replace") as f:
                lines = f.readlines()
            if len(lines) > KEEP:
                atomic_write_text(target, "".join(lines[-KEEP:]))
        except OSError as e:
            _debug("не удалось записать падение: %s" % e)


def _debug(message: str):
    try:
        log.debug("MCP: %s" % message, source="mcp")
    except Exception:                           # noqa: BLE001 — граница
        pass
