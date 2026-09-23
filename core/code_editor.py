# core/code_editor.py
"""
Самоправка модулей GUI на устройстве: границы, staging, снимки, проверки.

**Самый опасный инструмент набора.** MCP-сервер живёт ВНУТРИ того
процесса, который модель переписывает: сломанный GUI не поднимет ни
MCP, ни свой собственный откат. Поэтому здесь два разных модуля:

* этот — правит файлы, складывает снимки и проверяет результат ДО
  того, как что-то попадёт на диск;
* :mod:`core.code_guard` — **посторонний процесс**, который ждёт, пока
  GUI вернётся, и возвращает снимок, если не дождался. Он написан
  только на stdlib и не импортирует ни одного нашего модуля: тот, кого
  откатывают, не может быть тем, кто откатывает.

## Как устроен цикл

``code_patch``/``code_write`` **не трогают диск**: правка ложится в
staging-копию рядом с ``settings.json``. ``code_check`` проверяет
именно её (см. ниже про слепок дерева), и только ``code_apply``
создаёт снимок, кладёт файлы на место атомарно, запускает сторожа и
просит GUI перезапуститься. Не пришёл ``code_commit`` за
``commit_ttl_sec`` — сторож вернул всё как было.

## Слепок дерева вместо «проверим после применения»

Проверка «файл разбирается» (``ast.parse``) ловит опечатку, но не
ловит главного: модуль может не импортироваться (сломанный импорт,
``raise`` на уровне модуля, имя, которого больше нет). Импортировать
же staging-копию под настоящим именем нельзя — её нет в дереве.

Поэтому :func:`build_shadow` собирает **слепок**: каталог, где на всё
стоят симлинки в настоящий проект, а каталоги по пути к правленым
файлам сделаны настоящими и правленый файл лежит в них реальным
файлом. ``python3 -B -c "import core.foo"`` с ``cwd`` слепка импортирует
ИМЕННО правку, а её зависимости берёт из настоящего дерева. Симлинки
на роутере бесплатны, копирование всего проекта — нет.

``-B`` (не писать ``.pyc``) здесь не украшение: каталог ``vendor`` в
слепке — симлинк, и ``__pycache__`` уехал бы по нему в настоящее
дерево. Плюс ``__pycache__`` в слепок не переносится вовсе, иначе
проверка «прошла бы» на старом байт-коде.

## Границы

Править можно только каталог установки GUI (автодетект по ``__file__``,
переопределяется ``mcp.self_edit.root``). Путь нормализуется, ``..`` и
симлинки наружу отклоняются, собственные файлы GUI (``settings.json``,
журнал MCP, снимки) не правятся вовсе — иначе модель дописала бы себе
разрешения. Файлы из :data:`CORE_PROTECTED` и из
``mcp.self_edit.protected`` требуют отдельного разрешения
``self_edit_core``: это то, чем держится сама защита.
"""

import ast
import difflib
import fnmatch
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time

from core.log_buffer import log
from core.platform_dirs import config_dir
from core.safe_io import atomic_write_bytes, atomic_write_json


SOURCE = "code"

# Дефолты дублируют DEFAULT_CONFIG["mcp"]["self_edit"]: модуль обязан
# работать и на конфиге, в котором секции ещё нет.
DEFAULTS = {
    "root": "",
    "snapshots_keep": 20,
    "restart_timeout_sec": 45,
    "commit_ttl_sec": 300,
    "run_tests": False,
    "protected": ["core/mcp/auth.py", "core/mcp/permissions.py",
                  "core/code_guard.py", "core/config_manager.py"],
}

# Защищено ВСЕГДА, чем бы ни был список в настройках. Список из
# настроек — пол, а не потолок: пользователь может добавить к нему
# свои файлы, но не может убрать эти. Здесь ровно то, чем держится
# сама защита: границы (этот модуль), сторож (он откатывает),
# авторизация и разрешения, конфиг и проверка scope в реестре.
CORE_PROTECTED = (
    "core/code_editor.py",
    "core/code_guard.py",
    "core/config_manager.py",
    "core/mcp/auth.py",
    "core/mcp/permissions.py",
    "core/mcp/registry.py",
)

# Каталоги рядом с settings.json.
SNAPSHOTS_DIRNAME = "code-snapshots"
STAGING_DIRNAME = "code-staging"
GUARD_LOG_NAME = "code-guard.log"

# Имена, которые не правятся через code_* ни при каких разрешениях:
# в них живут токен, разрешения и снимки для отката. Совпадает с
# ``tools/files.PROTECTED_NAMES`` намеренно — граница одна.
DENY_NAMES = ("settings.json", "mcp-audit.jsonl", "mcp-undo.json",
              "mcp-shell-guards.json")

# Что не показываем, не мерим и не переносим в слепок.
SKIP_DIRS = ("__pycache__", ".git", ".pytest_cache", "node_modules",
             "build", "dist", SNAPSHOTS_DIRNAME, STAGING_DIRNAME)

# Расширения, которые считаем текстом (их и показываем в дереве).
TEXT_SUFFIXES = (".py", ".js", ".json", ".css", ".html", ".md", ".txt",
                 ".sh", ".lua", ".conf", ".yml", ".yaml", ".service")

# Больше этого файл не читаем и не принимаем на правку: MCP — не
# способ заливать на роутер бинарники, а снимок обязан поместиться.
MAX_FILE_BYTES = 512 * 1024

# Состояния снимка.
STATE_PENDING = "pending"        # файлы положены, сторож ещё не судил
STATE_APPLIED = "applied"        # GUI ответил, ждём code_commit
STATE_COMMITTED = "committed"    # подтверждено моделью
STATE_REVERTED = "reverted"      # возвращено (сторожем или вручную)

OPEN_STATES = (STATE_PENDING, STATE_APPLIED)

# Сколько ждём проверочный подпроцесс.
CHECK_TIMEOUT_SEC = 30
TESTS_TIMEOUT_SEC = 120

_ID_RE = re.compile(r"^snap-\d{8}-\d{6}(?:-\d+)?$")


# ──────────────────────────── настройки ─────────────────────────────

def settings() -> dict:
    """Секция ``mcp.self_edit`` поверх дефолтов."""
    section = {}
    try:
        from core.config_manager import get_config_manager
        value = get_config_manager().get("mcp", "self_edit", default={})
        if isinstance(value, dict):
            section = value
    except Exception:                           # noqa: BLE001 — граница
        section = {}
    out = dict(DEFAULTS)
    out.update({k: v for k, v in section.items() if v is not None})
    return out


def limits() -> dict:
    """Числовые настройки, приведённые к осмысленным значениям."""
    raw = settings()
    return {
        "root": str(raw.get("root") or ""),
        "snapshots_keep": _positive(raw.get("snapshots_keep"), 20),
        "restart_timeout_sec": _positive(raw.get("restart_timeout_sec"), 45),
        "commit_ttl_sec": _positive(raw.get("commit_ttl_sec"), 300),
        "run_tests": bool(raw.get("run_tests")),
    }


def _positive(value, default: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return default
    return number if number > 0 else default


def project_root() -> str:
    """Каталог установки GUI: из настроек или автодетектом.

    Автодетект — по ``__file__``: этот модуль лежит в ``core/``, значит
    корень проекта на уровень выше. Путь установки на Entware
    (``/opt/share/zapret-gui``), в репозитории и в тестах разный, и
    захардкодить его нельзя.
    """
    configured = str(settings().get("root") or "").strip()
    if configured:
        return os.path.realpath(configured)
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.realpath(os.path.dirname(here))


def snapshots_dir() -> str:
    return os.path.join(config_dir(), SNAPSHOTS_DIRNAME)


def staging_dir() -> str:
    return os.path.join(config_dir(), STAGING_DIRNAME)


def guard_log_path() -> str:
    return os.path.join(config_dir(), GUARD_LOG_NAME)


def protected_paths() -> list:
    """Файлы, требующие ``self_edit_core`` (настройки + постоянные)."""
    listed = settings().get("protected") or []
    names = {str(p).strip().strip("/") for p in listed if str(p).strip()}
    names.update(CORE_PROTECTED)
    return sorted(names)


def is_protected(rel: str) -> bool:
    """Требует ли файл разрешения ``self_edit_core``.

    Запись в списке может быть и каталогом (``core/mcp``) — тогда
    защищено всё внутри: иначе «защитили auth.py» обходилось бы правкой
    соседнего модуля, который тот импортирует.
    """
    rel = str(rel or "").strip("/")
    for item in protected_paths():
        if rel == item or rel.startswith(item.rstrip("/") + "/"):
            return True
    return False


# ───────────────────────────── границы ──────────────────────────────

def resolve(path):
    """``(relpath, abspath, отказ)`` — путь внутри корня проекта.

    Принимаем и относительный путь (``core/foo.py`` — так удобнее
    модели), и абсолютный внутри корня. Проверка идёт по
    **резолвнутому** пути: симлинк изнутри проекта наружу — готовая
    дыра, а ``..`` в середине пути после ``normpath`` уже не виден.
    """
    raw = str(path or "").strip()
    if not raw:
        return "", "", _refusal("путь не указан",
                                "укажите путь относительно корня "
                                "проекта: core/nfqws_manager.py")
    root = project_root()
    if raw.startswith("/"):
        candidate = os.path.normpath(raw)
    else:
        if raw.startswith("./"):
            raw = raw[2:]
        candidate = os.path.normpath(os.path.join(root, raw))

    if os.path.basename(candidate) in DENY_NAMES:
        return "", "", _refusal(
            "«%s» — собственный файл GUI и через code_* не правится"
            % os.path.basename(candidate),
            "настройки меняет config_set (там своя граница записи), "
            "журнал и снимки — audit_list/mcp_undo_last")

    # Резолвим по существующей части пути: у нового файла самого ещё
    # нет, а вот его каталог уже может быть симлинком наружу.
    real = _realpath_existing(candidate)
    if real != root and not real.startswith(root.rstrip("/") + os.sep):
        return "", "", _refusal(
            "путь «%s» вне каталога установки GUI" % raw,
            "самоправка работает только внутри %s; всё остальное — "
            "file_read/file_write под shell_full" % root,
            resolved=real, root=root)

    rel = os.path.relpath(real, root).replace(os.sep, "/")
    if rel == ".":
        return "", "", _refusal("это корень проекта, а не файл",
                                "укажите файл: code_tree покажет какие")
    for part in rel.split("/"):
        if part in SKIP_DIRS:
            return "", "", _refusal(
                "каталог «%s» самоправкой не правится" % part,
                "это кеш, сборка или служебные данные — правьте "
                "исходники")
    return rel, os.path.join(root, rel), None


def _realpath_existing(path: str) -> str:
    """``realpath`` по существующей части пути.

    ``os.path.realpath`` на несуществующем пути просто нормализует
    строку, и симлинк-каталог в середине остался бы неразрешённым.
    """
    head = path
    tail = []
    while head and not os.path.exists(head):
        head, name = os.path.split(head)
        if not name:
            break
        tail.append(name)
    resolved = os.path.realpath(head or "/")
    for name in reversed(tail):
        resolved = os.path.join(resolved, name)
    return os.path.normpath(resolved)


def _refusal(error, hint, **extra) -> dict:
    out = {"ok": False, "error": error}
    if hint:
        out["hint"] = hint
    out.update(extra)
    return out


# ──────────────────────────── чтение дерева ─────────────────────────

def walk_files(mask: str = "", subdir: str = "") -> list:
    """Файлы проекта: путь, размер, mtime, признак «защищённый».

    Возвращает список словарей, отсортированный по пути. Каталоги из
    :data:`SKIP_DIRS` не обходятся вовсе: ``.git`` на роутере обычно
    нет, а ``__pycache__`` — это шум, который съест окно ответа.
    """
    root = project_root()
    base = root
    if subdir:
        rel, base, refusal = resolve(subdir)
        if refusal:
            return []
    staged = set(staged_paths())
    items = []
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS
                             and not d.startswith("."))
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            if mask and not (fnmatch.fnmatch(rel, mask)
                             or fnmatch.fnmatch(name, mask)):
                continue
            try:
                info = os.stat(full)
            except OSError:
                continue
            items.append({
                "path": rel,
                "size": info.st_size,
                "mtime": int(info.st_mtime),
                "protected": is_protected(rel),
                "staged": rel in staged,
                "text": rel.endswith(TEXT_SUFFIXES),
            })
    items.sort(key=lambda item: item["path"])
    return items


def read_bytes(abspath: str):
    """``(данные, отказ)`` — содержимое файла с лимитом."""
    try:
        size = os.path.getsize(abspath)
    except OSError as e:
        return None, _refusal("файл не прочитан: %s" % e, "")
    if size > MAX_FILE_BYTES:
        return None, _refusal(
            "файл больше %d байт" % MAX_FILE_BYTES,
            "самоправка рассчитана на исходники, а не на бинарники и "
            "дампы")
    try:
        with open(abspath, "rb") as f:
            return f.read(), None
    except OSError as e:
        return None, _refusal("файл не прочитан: %s" % e,
                              "обычно это права доступа")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def decode(data: bytes) -> str:
    return data.decode("utf-8", "replace")


def file_mode(path: str):
    try:
        return stat.S_IMODE(os.stat(path).st_mode)
    except OSError:
        return None


# ──────────────────────────────  staging ────────────────────────────
#
# Правка НЕ попадает на диск проекта до ``code_apply``: она лежит в
# копии рядом с settings.json. Так «битый синтаксис до диска не
# доезжает» становится свойством механики, а не дисциплины вызывающего.

def _staging_index() -> str:
    return os.path.join(staging_dir(), "staging.json")


def _staging_file(rel: str) -> str:
    return os.path.join(staging_dir(), "files", rel)


def staging_state() -> dict:
    """Что сейчас накоплено в staging (и кем)."""
    try:
        with open(_staging_index(), encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {"files": {}, "started": 0}
    if not isinstance(data, dict) or not isinstance(data.get("files"), dict):
        return {"files": {}, "started": 0}
    return data


def staged_paths() -> list:
    return sorted(staging_state()["files"])


def staged_bytes(rel: str):
    """Содержимое staging-копии или ``None``."""
    if rel not in staging_state()["files"]:
        return None
    try:
        with open(_staging_file(rel), "rb") as f:
            return f.read()
    except OSError:
        return None


def current_bytes(rel: str, abspath: str = ""):
    """Актуальное содержимое: staging, если он есть, иначе диск.

    Именно на этом строится цепочка правок: второй ``code_patch`` по
    тому же файлу обязан видеть результат первого, а не исходник.
    """
    staged = staged_bytes(rel)
    if staged is not None:
        return staged, None
    path = abspath or os.path.join(project_root(), rel)
    if not os.path.exists(path):
        return None, _refusal("файла «%s» нет" % rel,
                              "создать новый можно code_write")
    return read_bytes(path)


def stage(rel: str, data: bytes, tool: str = "") -> dict:
    """Положить правку в staging (диск проекта не трогаем)."""
    path = _staging_file(rel)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    atomic_write_bytes(path, data)
    state = staging_state()
    if not state.get("started"):
        state["started"] = round(time.time(), 3)
    abspath = os.path.join(project_root(), rel)
    existed = os.path.exists(abspath)
    entry = state["files"].get(rel) or {}
    if not entry:
        # sha256 исходника запоминаем при ПЕРВОЙ правке файла: по нему
        # code_apply увидит, что файл успели поменять мимо нас.
        origin = b""
        if existed:
            origin, _ = read_bytes(abspath)
            origin = origin or b""
        entry = {"existed": existed, "origin_sha256": sha256(origin)
                 if existed else ""}
    entry.update({"bytes": len(data), "sha256": sha256(data),
                  "ts": round(time.time(), 3), "tool": tool})
    state["files"][rel] = entry
    _write_staging(state)
    return dict(entry, path=rel)


def unstage(rel: str) -> bool:
    """Выкинуть одну правку из staging."""
    state = staging_state()
    if rel not in state["files"]:
        return False
    state["files"].pop(rel, None)
    _write_staging(state)
    try:
        os.remove(_staging_file(rel))
    except OSError:
        pass
    return True


def clear_staging():
    """Забыть все накопленные правки."""
    shutil.rmtree(staging_dir(), ignore_errors=True)


def _write_staging(state: dict):
    os.makedirs(staging_dir(), exist_ok=True)
    atomic_write_json(_staging_index(), state)


def staging_summary() -> dict:
    """Короткая сводка staging для ответов инструментов."""
    state = staging_state()
    files = state["files"]
    return {
        "count": len(files),
        "files": sorted(files),
        "bytes": sum(int(item.get("bytes") or 0)
                     for item in files.values()),
    }


# ─────────────────────────── правка текста ──────────────────────────

def apply_edits(text: str, edits: list):
    """``(новый текст, отказ)`` — список замен ``{old, new}``.

    Совпадение **точное и единственное**: замена, встретившаяся дважды,
    отклоняется с указанием, сколько раз нашлась. Молча заменить
    первое вхождение — это правка не того места, которую никто не
    заметит до следующего рестарта.
    """
    out = text
    applied = []
    for index, edit in enumerate(edits, 1):
        if not isinstance(edit, dict):
            return None, _refusal("правка №%d — не объект" % index,
                                  "каждая правка: {\"old\": …, "
                                  "\"new\": …}")
        old = str(edit.get("old", ""))
        new = str(edit.get("new", ""))
        if not old:
            return None, _refusal("правка №%d: пустой old" % index,
                                  "чтобы создать файл целиком, "
                                  "используйте code_write")
        found = out.count(old)
        if found == 0:
            return None, _refusal(
                "правка №%d: фрагмент не найден" % index,
                "текст должен совпадать ТОЧНО, включая отступы; "
                "прочитайте нужное место code_read и скопируйте его",
                fragment=_short(old))
        if found > 1:
            return None, _refusal(
                "правка №%d: фрагмент найден %d раза" % (index, found),
                "добавьте окружающие строки, чтобы совпадение стало "
                "единственным",
                occurrences=found, fragment=_short(old))
        out = out.replace(old, new, 1)
        applied.append({"index": index, "removed": old.count("\n") + 1,
                        "added": new.count("\n") + 1 if new else 0})
    return out, None


_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def apply_unified(text: str, diff: str):
    """``(новый текст, отказ)`` — применить unified diff.

    Реализация намеренно строгая: контекст обязан совпасть. Допуск —
    только сдвиг номера строки (файл мог уехать выше или ниже), и тот
    ищется в окне, а не по всему файлу: «похожий кусок» в другом месте
    модуля — это правка не того места.
    """
    lines = text.splitlines(True)
    hunks, refusal = _parse_unified(diff)
    if refusal:
        return None, refusal
    if not hunks:
        return None, _refusal("в диффе нет ни одного блока @@",
                              "передайте unified diff целиком или "
                              "воспользуйтесь edits")

    result = list(lines)
    shift = 0
    for number, hunk in enumerate(hunks, 1):
        start = hunk["start"] + shift - 1
        position, refusal = _locate(result, hunk, start, number)
        if refusal:
            return None, refusal
        before = hunk["before"]
        after = hunk["after"]
        result[position:position + len(before)] = after
        shift += len(after) - len(before)
    return "".join(result), None


def _parse_unified(diff: str):
    """Разобрать unified diff в блоки ``{start, before, after}``."""
    hunks = []
    current = None
    for raw in str(diff or "").splitlines():
        if raw.startswith("@@"):
            match = _HUNK_RE.match(raw)
            if not match:
                return None, _refusal("не разобран заголовок блока: %s"
                                      % _short(raw),
                                      "ожидается «@@ -a,b +c,d @@»")
            current = {"start": int(match.group(1)) or 1,
                       "before": [], "after": []}
            hunks.append(current)
            continue
        if current is None:
            # Шапка (--- / +++ / diff / index) до первого @@ — пропускаем.
            continue
        if raw.startswith("\\"):            # «\ No newline at end of file»
            continue
        tag, body = raw[:1], raw[1:] + "\n"
        if tag == " ":
            current["before"].append(body)
            current["after"].append(body)
        elif tag == "-":
            current["before"].append(body)
        elif tag == "+":
            current["after"].append(body)
        elif raw == "":
            # Пустая строка контекста, у которой потерялся пробел.
            current["before"].append("\n")
            current["after"].append("\n")
        else:
            return None, _refusal("непонятная строка диффа: %s"
                                  % _short(raw),
                                  "строки блока начинаются с пробела, "
                                  "«-» или «+»")
    return hunks, None


def _locate(lines, hunk, start, number):
    """Где в файле лежит контекст блока (``позиция``, ``отказ``)."""
    before = hunk["before"]
    window = 50
    for offset in range(0, window + 1):
        for position in {start + offset, start - offset}:
            if position < 0 or position + len(before) > len(lines):
                continue
            if lines[position:position + len(before)] == before:
                return position, None
    return None, _refusal(
        "блок №%d не лёг: контекст не совпал" % number,
        "файл на устройстве отличается от того, по которому собран "
        "дифф — прочитайте его code_read и соберите правку заново",
        expected_line=hunk["start"])


def make_diff(old: str, new: str, path: str, label_a: str = "",
              label_b: str = "") -> str:
    """Unified diff одного файла (пустая строка — различий нет)."""
    return "".join(difflib.unified_diff(
        old.splitlines(True), new.splitlines(True),
        fromfile="a/%s" % path, tofile="b/%s" % path,
        fromfiledate=label_a, tofiledate=label_b, n=3))


def _short(text: str, limit: int = 120) -> str:
    text = str(text or "").strip().replace("\n", "⏎")
    return text if len(text) <= limit else text[:limit] + "…"


# ──────────────────────────── слепок дерева ─────────────────────────

def build_shadow(dest: str, overrides: dict) -> str:
    """Собрать слепок проекта с правками (см. docstring модуля).

    ``overrides``: ``{relpath: bytes}``. Всё, что не на пути к ним, —
    симлинк в настоящее дерево; каталоги по пути — настоящие.
    """
    root = project_root()
    shutil.rmtree(dest, ignore_errors=True)
    need_dirs = {""}
    for rel in overrides:
        parts = rel.split("/")[:-1]
        for i in range(len(parts)):
            need_dirs.add("/".join(parts[:i + 1]))

    for rel in sorted(need_dirs):
        here = os.path.join(dest, rel) if rel else dest
        os.makedirs(here, exist_ok=True)
        src_dir = os.path.join(root, rel) if rel else root
        try:
            entries = sorted(os.listdir(src_dir))
        except OSError:
            entries = []
        for entry in entries:
            child = "%s/%s" % (rel, entry) if rel else entry
            if entry in SKIP_DIRS or child in need_dirs or child in overrides:
                continue
            try:
                os.symlink(os.path.realpath(os.path.join(src_dir, entry)),
                           os.path.join(here, entry))
            except OSError:
                pass
    for rel, data in overrides.items():
        target = os.path.join(dest, rel)
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, "wb") as f:
            f.write(data)
    return dest


def module_name(rel: str) -> str:
    """Имя модуля для ``import``: ``core/mcp/auth.py`` → ``core.mcp.auth``.

    Пустая строка — файл не модуль (скрипт без пакета, ``__init__`` в
    каталоге без пакета, не-``.py``).
    """
    if not rel.endswith(".py"):
        return ""
    parts = rel[:-3].split("/")
    if parts[-1] == "__init__":
        parts = parts[:-1]
    if not parts:
        return ""
    for part in parts:
        if not part.isidentifier():
            return ""
    return ".".join(parts)


# ───────────────────────────── проверки ─────────────────────────────

def check_syntax(rel: str, data: bytes) -> dict:
    """Разбор файла по его типу: ``.py`` → ast, ``.json`` → json."""
    if rel.endswith(".py"):
        try:
            ast.parse(data.decode("utf-8"), filename=rel)
        except (SyntaxError, ValueError, UnicodeDecodeError) as e:
            return {"ok": False, "kind": "py", "error": _syntax_error(e)}
        return {"ok": True, "kind": "py"}
    if rel.endswith(".json"):
        try:
            json.loads(data.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as e:
            return {"ok": False, "kind": "json", "error": str(e)}
        return {"ok": True, "kind": "json"}
    return {"ok": True, "kind": rel.rsplit(".", 1)[-1] if "." in rel
            else "text", "skipped": True}


def _syntax_error(error) -> str:
    if isinstance(error, SyntaxError):
        return "строка %s: %s" % (error.lineno or "?", error.msg)
    return str(error)


def run_check_command(argv, workdir: str, timeout: int = 0) -> dict:
    """Запустить проверочный подпроцесс через исполнение из S12.

    Второго механизма запуска у нас нет и быть не должно: таймаут,
    прибитие всей группы, обрезка вывода и маскировка секретов уже
    сделаны в ``core/shell_exec.py``. План собираем сами — safe-список
    здесь ни при чём, команду задаёт не модель.
    """
    from core import shell_exec
    plan = {"mode": "argv", "argv": list(argv), "safe": False,
            "display": " ".join(argv), "normalized": " ".join(argv)}
    return shell_exec.execute(plan, timeout_sec=timeout or CHECK_TIMEOUT_SEC,
                             workdir=workdir)


def python_binary() -> str:
    """Чем запускать проверки: тем же интерпретатором, что и GUI."""
    return sys.executable or shutil.which("python3") or "python3"


def check_import(rel: str, shadow: str, timeout: int = 0) -> dict:
    """Импортировать модуль из слепка отдельным процессом.

    ``-B`` — не писать байт-код (каталоги в слепке симлинкованы, и
    ``__pycache__`` уехал бы в настоящее дерево), ``-E``/``-s`` —
    игнорировать окружение и пользовательские пакеты: проверка обязана
    мерить код, а не машину.
    """
    name = module_name(rel)
    if not name:
        return {"ok": True, "available": False,
                "note": "файл не импортируемый модуль — проверен только "
                        "разбор"}
    result = run_check_command(
        [python_binary(), "-B", "-E", "-s", "-c", "import %s" % name],
        shadow, timeout)
    if not result.get("ok"):
        return {"ok": False, "available": True, "module": name,
                "error": result.get("error") or "проверка не выполнилась",
                "output": result.get("output", "")}
    ok = result.get("returncode") == 0
    return {"ok": ok, "available": True, "module": name,
            "output": "" if ok else _tail(result.get("output", "")),
            "error": "" if ok else "модуль не импортируется"}


def check_js(rel: str, shadow: str, timeout: int = 0) -> dict:
    """``node --check``, если node на устройстве есть."""
    node = shutil.which("node")
    if not node:
        return {"ok": True, "available": False,
                "note": "node на устройстве нет — синтаксис .js не "
                        "проверен"}
    result = run_check_command([node, "--check", rel], shadow, timeout)
    if not result.get("ok"):
        return {"ok": False, "available": True,
                "error": result.get("error") or "проверка не выполнилась"}
    ok = result.get("returncode") == 0
    return {"ok": ok, "available": True,
            "output": "" if ok else _tail(result.get("output", "")),
            "error": "" if ok else "синтаксис .js не принят node"}


def lint_tree(overrides=None) -> dict:
    """Эквивалент ``make lint``: разбор ВСЕХ ``.py`` проекта.

    Правка часто ломает не свой файл, а соседний (переименовали то, что
    импортируют). Полный разбор дешёвый (``ast.parse`` без импорта) и
    ловит это раньше, чем рестарт.
    """
    overrides = overrides or {}
    root = project_root()
    errors = []
    checked = 0
    for item in walk_files(mask="*.py"):
        rel = item["path"]
        data = overrides.get(rel)
        if data is None:
            data, refusal = read_bytes(os.path.join(root, rel))
            if refusal:
                continue
        checked += 1
        verdict = check_syntax(rel, data)
        if not verdict["ok"]:
            errors.append({"path": rel, "error": verdict["error"]})
    for rel, data in overrides.items():
        if rel.endswith(".py") and not os.path.exists(
                os.path.join(root, rel)):
            checked += 1
            verdict = check_syntax(rel, data)
            if not verdict["ok"]:
                errors.append({"path": rel, "error": verdict["error"]})
    return {"ok": not errors, "checked": checked, "errors": errors}


def run_tests(pattern: str = "", timeout: int = 0,
              shadow: str = "") -> dict:
    """``python3 -m pytest tests/ -q [-k pattern]`` с таймаутом."""
    workdir = shadow or project_root()
    if not os.path.isdir(os.path.join(workdir, "tests")):
        return {"ok": True, "available": False,
                "note": "каталога tests/ на устройстве нет"}
    argv = [python_binary(), "-B", "-m", "pytest", "tests/", "-q",
            "-p", "no:cacheprovider"]
    if pattern:
        argv += ["-k", str(pattern)]
    result = run_check_command(argv, workdir,
                               timeout or TESTS_TIMEOUT_SEC)
    output = result.get("output", "")
    if not result.get("ok"):
        return {"ok": False, "available": True,
                "timed_out": bool(result.get("timed_out")),
                "error": result.get("error") or "прогон не завершился",
                "output": _tail(output)}
    code = result.get("returncode")
    if code == 5:                       # «no tests ran» — не провал
        return {"ok": True, "available": True, "returncode": code,
                "note": "под фильтр не попал ни один тест",
                "output": _tail(output)}
    if code == 4 and "unrecognized arguments" in output:
        return {"ok": True, "available": False,
                "note": "pytest на устройстве нет или он слишком старый",
                "output": _tail(output)}
    if code != 0 and "No module named pytest" in output:
        return {"ok": True, "available": False,
                "note": "pytest на устройстве не установлен",
                "output": _tail(output)}
    return {"ok": code == 0, "available": True, "returncode": code,
            "output": _tail(output),
            "error": "" if code == 0 else "тесты не прошли"}


def _tail(text: str, limit: int = 4000) -> str:
    text = str(text or "")
    if len(text) <= limit:
        return text
    return "…\n" + text[-limit:]


def check_staged(paths=None, with_tests: bool = False,
                 test_pattern: str = "", lint: bool = True,
                 timeout: int = 0) -> dict:
    """Проверить накопленные правки, ничего не применяя.

    Порядок: разбор → импорт из слепка → полный разбор дерева →
    (опционально) тесты. Любая упавшая проверка делает ответ
    неуспешным, но **файлы на диске не трогаются в любом случае** —
    это свойство staging, а не вежливость проверки.
    """
    state = staging_state()["files"]
    wanted = [p for p in (paths or sorted(state))]
    unknown = [p for p in wanted if p not in state]
    if unknown:
        return _refusal("этих правок в staging нет: %s"
                        % ", ".join(unknown),
                        "накопленное показывает code_diff, "
                        "положить правку — code_patch/code_write",
                        staging=staging_summary())
    if not wanted:
        return _refusal("в staging нет ни одной правки",
                        "положите правку code_patch или code_write")

    # Слепок собираем по ВСЕМ накопленным правкам, даже если проверить
    # просят одну: применятся они вместе, и модуль, проверенный в дереве
    # без остальных правок, проверен не в том дереве.
    overrides = {}
    for rel in sorted(state):
        data = staged_bytes(rel)
        if data is None:
            if rel in wanted:
                return _refusal("staging-копия «%s» пропала" % rel,
                                "повторите правку")
            continue
        overrides[rel] = data

    files = []
    ok = True
    shadow = os.path.join(staging_dir(), "shadow")
    build_shadow(shadow, overrides)
    try:
        for rel in wanted:
            entry = {"path": rel, "protected": is_protected(rel)}
            syntax = check_syntax(rel, overrides[rel])
            entry["syntax"] = "ok" if syntax["ok"] else "fail"
            entry["kind"] = syntax.get("kind", "text")
            if not syntax["ok"]:
                entry["error"] = syntax["error"]
                ok = False
                files.append(entry)
                continue
            if rel.endswith(".py"):
                verdict = check_import(rel, shadow, timeout)
                entry["import"] = ("ok" if verdict["ok"]
                                   else "fail") if verdict.get("available") \
                    else "skipped"
                if verdict.get("note"):
                    entry["note"] = verdict["note"]
                if not verdict["ok"]:
                    entry["error"] = verdict.get("error", "")
                    entry["output"] = verdict.get("output", "")
                    ok = False
            elif rel.endswith(".js"):
                verdict = check_js(rel, shadow, timeout)
                entry["node"] = ("ok" if verdict["ok"] else "fail") \
                    if verdict.get("available") else "skipped"
                if verdict.get("note"):
                    entry["note"] = verdict["note"]
                if not verdict["ok"]:
                    entry["error"] = verdict.get("error", "")
                    entry["output"] = verdict.get("output", "")
                    ok = False
            files.append(entry)

        result = {"ok": ok, "checked": len(files), "files": files,
                  "failed": sum(1 for f in files if f.get("error"))}
        if lint:
            result["lint"] = lint_tree(overrides)
            ok = ok and result["lint"]["ok"]
        if with_tests:
            result["tests"] = run_tests(test_pattern, timeout, shadow)
            ok = ok and result["tests"]["ok"]
        result["ok"] = ok
        if not ok:
            result["error"] = "проверки не пройдены"
            result["hint"] = ("правки остались в staging и на диск не "
                              "попали: почините и повторите code_check")
        return result
    finally:
        shutil.rmtree(shadow, ignore_errors=True)


# ──────────────────────────────  снимки ─────────────────────────────

def snapshot_ids() -> list:
    """Идентификаторы снимков, новые первыми.

    Порядок — по времени из манифеста, а НЕ по имени. Имя уникально
    только в пределах секунды (дальше идёт суффикс), а после ротации
    освободившееся имя переиспользуется: сортировка по строке однажды
    объявила бы самый новый снимок самым старым и выкинула его.
    """
    try:
        names = [n for n in os.listdir(snapshots_dir()) if _ID_RE.match(n)]
    except OSError:
        return []
    return sorted(names, key=_snapshot_order, reverse=True)


def _snapshot_order(snapshot_id: str):
    manifest = read_manifest(snapshot_id)
    stamp = 0.0
    if manifest:
        try:
            stamp = float(manifest.get("created_ts") or 0)
        except (TypeError, ValueError):
            stamp = 0.0
    if not stamp:
        try:
            stamp = os.path.getmtime(manifest_path(snapshot_id))
        except OSError:
            stamp = 0.0
    return (stamp, snapshot_id)


def snapshot_path(snapshot_id: str) -> str:
    """Каталог снимка. Идентификатор сверяется с форматом — всегда.

    Он приходит из аргументов модели и из query страницы MCP.
    ``../../<каталог>`` превратил бы чужой ``manifest.json`` в снимок —
    со своим ``root`` и своим списком файлов, — и ``code_rollback``
    восстановил бы по нему что угодно, включая защищённое ядро без
    ``self_edit_core``.
    """
    if not _ID_RE.match(str(snapshot_id or "")):
        raise ValueError("неверный идентификатор снимка: %r"
                         % (snapshot_id,))
    return os.path.join(snapshots_dir(), snapshot_id)


def manifest_path(snapshot_id: str) -> str:
    return os.path.join(snapshot_path(snapshot_id), "manifest.json")


def read_manifest(snapshot_id: str):
    try:
        with open(manifest_path(snapshot_id), encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def write_manifest(manifest: dict):
    atomic_write_json(manifest_path(manifest["id"]), manifest)


def update_manifest(snapshot_id: str, **fields):
    """Перечитать манифест и дописать поля.

    Перечитываем именно перед записью: манифест правят два процесса —
    GUI (``code_commit``) и сторож. Полная перезапись из устаревшей
    копии потеряла бы чужое поле.
    """
    manifest = read_manifest(snapshot_id)
    if manifest is None:
        return None
    manifest.update(fields)
    write_manifest(manifest)
    return manifest


def last_open_snapshot():
    """Последний снимок, судьба которого ещё не решена."""
    for snapshot_id in snapshot_ids():
        manifest = read_manifest(snapshot_id)
        if manifest and manifest.get("state") in OPEN_STATES:
            return manifest
    return None


def pending_commit() -> dict:
    """Применённая правка, которая ждёт ``code_commit``, и её дедлайн.

    Считает то же, что ``recover_after_restart``: дедмен сторожа
    отмеряется от момента применения и складывается из ожидания
    перезапуска и ``commit_ttl_sec``. Держать эту арифметику в двух
    местах нельзя — индикатор «осталось N с» на странице MCP разойдётся
    с моментом, когда файлы действительно вернутся.
    """
    manifest = last_open_snapshot()
    if not manifest:
        return {}
    conf = limits()
    started = float(manifest.get("applied_at")
                    or manifest.get("created_ts") or 0)
    deadline = (started + conf["commit_ttl_sec"]
                + conf["restart_timeout_sec"]) if started else 0.0
    return {
        "snapshot_id": manifest.get("id", ""),
        "state": manifest.get("state", ""),
        "reason": manifest.get("reason", ""),
        "files": [f.get("path") for f in (manifest.get("files") or [])],
        "commit_ttl_sec": conf["commit_ttl_sec"],
        "deadline": round(deadline, 3),
        "left_sec": max(0, int(deadline - time.time())) if deadline else 0,
    }


def create_snapshot(rels, reason: str = "", tool: str = "") -> dict:
    """Скопировать текущие версии файлов и записать манифест.

    **Манифест пишется ДО правки файлов**: выключение питания посреди
    применения обязано оставлять восстановимое состояние, а не
    полуприменённое без описи.
    """
    root = project_root()
    base = time.strftime("snap-%Y%m%d-%H%M%S")
    snapshot_id = base
    suffix = 1
    while os.path.exists(snapshot_path(snapshot_id)):
        snapshot_id = "%s-%d" % (base, suffix)
        suffix += 1
    directory = snapshot_path(snapshot_id)
    os.makedirs(os.path.join(directory, "files"), exist_ok=True)

    files = []
    for rel in rels:
        abspath = os.path.join(root, rel)
        entry = {"path": rel, "existed": os.path.exists(abspath),
                 "protected": is_protected(rel)}
        if entry["existed"]:
            data, refusal = read_bytes(abspath)
            if refusal:
                return refusal
            entry.update({"bytes": len(data), "sha256": sha256(data),
                          "mode": file_mode(abspath)})
            copy_to = os.path.join(directory, "files", rel)
            os.makedirs(os.path.dirname(copy_to), exist_ok=True)
            atomic_write_bytes(copy_to, data)
        files.append(entry)

    from core.version import GUI_VERSION
    manifest = {
        "id": snapshot_id,
        "created": time.strftime("%Y-%m-%d %H:%M:%S"),
        "created_ts": round(time.time(), 3),
        "gui_version": GUI_VERSION,
        "root": root,
        "state": STATE_PENDING,
        "reason": str(reason or ""),
        "tool": str(tool or ""),
        "files": files,
        "git": git_info(),
    }
    write_manifest(manifest)
    return manifest


def git_info() -> dict:
    """``git rev-parse HEAD`` рядом со снимком, если git вообще есть.

    Зависимости от git нет: на роутере его обычно не ставят. Но если
    правка делается в рабочей копии разработчика, знать коммит,
    относительно которого она сделана, дорогого стоит.
    """
    root = project_root()
    if not os.path.isdir(os.path.join(root, ".git")):
        return {"available": False}
    binary = shutil.which("git")
    if not binary:
        return {"available": False, "note": "каталог .git есть, а git нет"}
    try:
        out = subprocess.run([binary, "rev-parse", "HEAD"], cwd=root,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, timeout=10)
        head = out.stdout.decode("utf-8", "replace").strip()
    except (OSError, subprocess.SubprocessError):
        return {"available": False}
    return {"available": True, "head": head}


def rotate_snapshots(keep: int = 0):
    """Оставить ``snapshots_keep`` последних каталогов."""
    keep = keep or limits()["snapshots_keep"]
    for snapshot_id in snapshot_ids()[keep:]:
        manifest = read_manifest(snapshot_id)
        if manifest and manifest.get("state") in OPEN_STATES:
            # Незакрытый снимок не выкидываем: именно он нужен откату.
            continue
        shutil.rmtree(snapshot_path(snapshot_id), ignore_errors=True)


def restore_snapshot(snapshot_id: str, reason: str = "") -> dict:
    """Вернуть файлы снимка на место (без перезапуска GUI)."""
    manifest = read_manifest(snapshot_id)
    if manifest is None:
        return _refusal("снимка «%s» нет" % snapshot_id,
                        "список снимков — code_history")
    root = manifest.get("root") or project_root()
    restored, removed, failed = [], [], []
    for entry in manifest.get("files") or []:
        rel = entry.get("path") or ""
        target = os.path.join(root, rel)
        try:
            if entry.get("existed"):
                source = os.path.join(snapshot_path(snapshot_id), "files",
                                      rel)
                with open(source, "rb") as f:
                    data = f.read()
                atomic_write_bytes(target, data)
                if entry.get("mode") is not None:
                    os.chmod(target, int(entry["mode"]))
                restored.append(rel)
            else:
                if os.path.exists(target):
                    os.remove(target)
                removed.append(rel)
        except OSError as e:
            failed.append({"path": rel, "error": str(e)})
    if failed:
        return {"ok": False, "snapshot_id": snapshot_id,
                "error": "часть файлов не восстановлена",
                "restored": restored, "removed": removed,
                "failed": failed}
    update_manifest(snapshot_id, state=STATE_REVERTED,
                    reverted_at=round(time.time(), 3),
                    revert_reason=str(reason or ""))
    log.warning("Самоправка откачена: снимок %s (%s)"
                % (snapshot_id, reason or "по запросу"), source=SOURCE)
    return {"ok": True, "snapshot_id": snapshot_id, "restored": restored,
            "removed": removed, "state": STATE_REVERTED}


# ─────────────────────────── применение ─────────────────────────────

def apply_staged(reason: str = "", restart: bool = True,
                 with_tests=None, test_pattern: str = "",
                 timeout: int = 0) -> dict:
    """Снимок → проверки → файлы на место → сторож → перезапуск.

    Порядок именно такой. Сторож поднимается **до** перезапуска: тот,
    кто просит GUI умереть, не может быть тем, кто дождётся его
    возвращения.
    """
    state = staging_state()["files"]
    if not state:
        return _refusal("в staging нет ни одной правки",
                        "положите правку code_patch или code_write")
    open_snapshot = last_open_snapshot()
    if open_snapshot:
        return _refusal(
            "предыдущая правка ещё не подтверждена (снимок %s, состояние "
            "%s)" % (open_snapshot["id"], open_snapshot.get("state")),
            "подтвердите её code_commit или верните code_rollback — "
            "две неподтверждённые правки подряд нечем откатывать",
            snapshot_id=open_snapshot["id"])

    conf = limits()
    if with_tests is None:
        with_tests = conf["run_tests"]
    checks = check_staged(with_tests=bool(with_tests),
                          test_pattern=test_pattern, timeout=timeout)
    if not checks.get("ok"):
        checks["applied"] = False
        checks["hint"] = ("правки остались в staging, файлы на диске не "
                          "тронуты: почините и повторите")
        return checks

    rels = sorted(state)
    root = project_root()
    # Файл, изменившийся МИМО нас между правкой и применением, — это
    # чужая запись (обновление GUI, ручная правка по ssh). Перезаписать
    # её молча значит потерять её без следа.
    drifted = []
    for rel in rels:
        entry = state[rel]
        abspath = os.path.join(root, rel)
        if not entry.get("existed"):
            continue
        data, refusal = read_bytes(abspath)
        if refusal or sha256(data or b"") != entry.get("origin_sha256"):
            drifted.append(rel)
    if drifted:
        return _refusal(
            "на диске изменились файлы, по которым собрана правка: %s"
            % ", ".join(drifted),
            "перечитайте их code_read и соберите правку заново "
            "(code_patch по устаревшему тексту затёр бы чужую правку)",
            drifted=drifted)

    snapshot = create_snapshot(rels, reason=reason, tool="code_apply")
    if not snapshot.get("id"):
        return snapshot
    snapshot_id = snapshot["id"]

    written, failed = [], []
    for rel in rels:
        data = staged_bytes(rel)
        if data is None:
            failed.append({"path": rel, "error": "staging-копия пропала"})
            continue
        abspath = os.path.join(root, rel)
        keep_mode = file_mode(abspath)
        try:
            atomic_write_bytes(abspath, data)
            if keep_mode is not None:
                # Атомарная запись создаёт НОВЫЙ файл: без chmod
                # исполняемый скрипт потерял бы +x.
                os.chmod(abspath, keep_mode)
        except OSError as e:
            failed.append({"path": rel, "error": str(e)})
            continue
        written.append(rel)

    if failed:
        # Частично применённая правка хуже неприменённой: возвращаем.
        restore_snapshot(snapshot_id, reason="write_failed")
        return _refusal("часть файлов не записана", "", failed=failed,
                        snapshot_id=snapshot_id, applied=False)

    clear_staging()
    rotate_snapshots(conf["snapshots_keep"])

    from core import system_control
    restart_cmd = system_control.restart_command() if restart else ""
    update_manifest(snapshot_id, applied_files=written,
                    restart={"requested": bool(restart),
                             "command": restart_cmd,
                             "pid": os.getpid()})
    guard = start_guard(snapshot_id,
                        restart_timeout=conf["restart_timeout_sec"],
                        commit_ttl=conf["commit_ttl_sec"],
                        expect_restart=bool(restart and restart_cmd))

    restarted = {"requested": False}
    if restart and restart_cmd:
        restarted = system_control.restart_gui()
    elif restart:
        restarted = {"ok": False, "requested": True,
                     "error": "способа перезапуска на этой системе нет"}

    log.warning("Самоправка применена: %d файл(ов), снимок %s"
                % (len(written), snapshot_id), source=SOURCE)
    return {
        "ok": True,
        "snapshot_id": snapshot_id,
        "applied": True,
        "files": written,
        "checks": {"files": checks.get("files"),
                   "lint": checks.get("lint"),
                   "tests": checks.get("tests")},
        "guard": guard,
        "restart": restarted,
        "restarting": bool(restart and restart_cmd and restarted.get("ok")),
        "commit_ttl_sec": conf["commit_ttl_sec"],
        "state": STATE_PENDING,
        "hint": ("соединение сейчас оборвётся: подождите 5–10 секунд, "
                 "повторите system_status и вызовите "
                 "code_commit(snapshot_id=\"%s\") — без подтверждения "
                 "сторож вернёт прежние файлы через %d с"
                 % (snapshot_id, conf["commit_ttl_sec"])),
    }


def start_guard(snapshot_id: str, restart_timeout: int = 0,
                commit_ttl: int = 0, expect_restart: bool = True) -> dict:
    """Запустить сторожа ОТВЯЗАННЫМ процессом.

    ``start_new_session`` — не деталь: сторож, оставшийся в группе
    процессов GUI, умрёт вместе с ним ровно тогда, когда он нужен.
    """
    conf = limits()
    argv = [python_binary(), "-B", "-m", "core.code_guard",
            "--snapshot", snapshot_id,
            "--timeout", str(restart_timeout or conf["restart_timeout_sec"]),
            "--commit-ttl", str(commit_ttl or conf["commit_ttl_sec"]),
            "--config-dir", config_dir(),
            "--root", project_root()]
    if not expect_restart:
        argv.append("--no-restart-wait")
    try:
        proc = subprocess.Popen(
            argv, cwd=project_root(),
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL, start_new_session=True,
            env=_guard_env())
    except OSError as e:
        log.error("Сторож самоправки не запустился: %s" % e, source=SOURCE)
        return {"ok": False, "error": str(e),
                "hint": "правка применена, но автоматического отката "
                        "нет — проверьте GUI и подтвердите вручную"}
    update_manifest(snapshot_id, guard={"pid": proc.pid,
                                        "started": round(time.time(), 3)})
    return {"ok": True, "pid": proc.pid,
            "restart_timeout_sec": restart_timeout
            or conf["restart_timeout_sec"],
            "commit_ttl_sec": commit_ttl or conf["commit_ttl_sec"]}


def _guard_env() -> dict:
    """Окружение сторожа: минимальное, но с каталогом конфига."""
    from core import shell_exec
    env = shell_exec.environ()
    env["ZAPRET_GUI_CONFIG_DIR"] = config_dir()
    return env


def commit(snapshot_id: str = "") -> dict:
    """Подтвердить применённую правку — отменить дедмен сторожа."""
    manifest = (read_manifest(snapshot_id) if snapshot_id
                else last_open_snapshot())
    if manifest is None:
        return _refusal(
            "нечего подтверждать: неподтверждённых правок нет",
            "снимки и их состояния показывает code_history")
    if manifest.get("state") not in OPEN_STATES:
        return _refusal(
            "снимок %s уже в состоянии «%s»"
            % (manifest["id"], manifest.get("state")),
            "подтверждать можно только правку, которая ещё ждёт")
    updated = update_manifest(manifest["id"], state=STATE_COMMITTED,
                              committed_at=round(time.time(), 3))
    log.info("Самоправка подтверждена: снимок %s" % manifest["id"],
             source=SOURCE)
    return {"ok": True, "snapshot_id": manifest["id"],
            "state": STATE_COMMITTED,
            "files": [f.get("path") for f in manifest.get("files") or []],
            "was": manifest.get("state"),
            "committed_at": (updated or {}).get("committed_at"),
            "hint": "дедмен снят; вернуть правку можно code_rollback"}


def rollback(snapshot_id: str = "", reason: str = "",
             restart: bool = True) -> dict:
    """Откатиться к снимку: к последнему или к названному."""
    if not snapshot_id:
        manifest = last_open_snapshot()
        if manifest is None:
            ids = snapshot_ids()
            if not ids:
                return _refusal("снимков нет",
                                "откатывать нечего: правок через "
                                "code_apply ещё не было")
            manifest = read_manifest(ids[0])
        snapshot_id = manifest["id"]
    result = restore_snapshot(snapshot_id, reason=reason or "code_rollback")
    if not result.get("ok"):
        return result
    from core import system_control
    if restart and system_control.restart_command():
        result["restart"] = system_control.restart_gui()
        result["restarting"] = bool(result["restart"].get("ok"))
        result["hint"] = ("файлы возвращены, GUI перезапускается: "
                          "подождите 5–10 секунд и повторите "
                          "system_status")
    else:
        result["restarting"] = False
        result["hint"] = ("файлы возвращены; перезапустите GUI, чтобы "
                          "он подхватил прежний код")
    return result


def history(limit: int = 20) -> list:
    """Снимки: id, время, файлы, размер diff, состояние."""
    out = []
    for snapshot_id in snapshot_ids()[:max(1, int(limit or 20))]:
        manifest = read_manifest(snapshot_id)
        if not manifest:
            continue
        files = manifest.get("files") or []
        out.append({
            "snapshot_id": snapshot_id,
            "created": manifest.get("created"),
            "state": manifest.get("state"),
            "reason": manifest.get("reason", ""),
            "gui_version": manifest.get("gui_version", ""),
            "files": [f.get("path") for f in files],
            "diff_bytes": snapshot_diff_size(snapshot_id, manifest),
            "revert_reason": manifest.get("revert_reason", ""),
            "committed_at": manifest.get("committed_at"),
            "reverted_at": manifest.get("reverted_at"),
        })
    return out


def snapshot_bytes(snapshot_id: str, rel: str):
    """Содержимое файла ИЗ снимка (``None`` — файла в снимке нет)."""
    try:
        path = os.path.join(snapshot_path(snapshot_id), "files", rel)
        with open(path, "rb") as f:
            return f.read()
    except (OSError, ValueError):
        return None


def snapshot_diff_size(snapshot_id: str, manifest=None) -> int:
    """Сколько байт занимает дифф «снимок → сейчас»."""
    return len(snapshot_diff(snapshot_id, manifest).encode("utf-8"))


def snapshot_diff(snapshot_id: str, manifest=None) -> str:
    """Unified diff «файлы снимка → то, что на диске сейчас»."""
    manifest = manifest or read_manifest(snapshot_id)
    if not manifest:
        return ""
    root = manifest.get("root") or project_root()
    chunks = []
    for entry in manifest.get("files") or []:
        rel = entry.get("path") or ""
        old = snapshot_bytes(snapshot_id, rel) if entry.get("existed") \
            else b""
        new = b""
        abspath = os.path.join(root, rel)
        if os.path.exists(abspath):
            data, refusal = read_bytes(abspath)
            new = data if not refusal else b""
        if old == new:
            continue
        chunks.append(make_diff(decode(old), decode(new), rel,
                                "снимок %s" % snapshot_id, "сейчас"))
    return "".join(chunks)


def staging_diff(paths=None) -> str:
    """Unified diff «диск → staging»: что именно будет применено."""
    state = staging_state()["files"]
    root = project_root()
    chunks = []
    for rel in sorted(state):
        if paths and rel not in paths:
            continue
        new = staged_bytes(rel)
        if new is None:
            continue
        old = b""
        abspath = os.path.join(root, rel)
        if os.path.exists(abspath):
            data, refusal = read_bytes(abspath)
            old = data if not refusal else b""
        chunks.append(make_diff(decode(old), decode(new), rel,
                                "на диске", "staging"))
    return "".join(chunks)


def baseline_bytes(rel: str):
    """Самая ранняя сохранённая версия файла (эталон локальных правок).

    Правки на устройстве живут до следующего обновления GUI, и
    выгрузить их надо относительно того, с чего начинали, а не
    относительно предыдущего снимка.
    """
    for snapshot_id in reversed(snapshot_ids()):
        manifest = read_manifest(snapshot_id)
        if not manifest:
            continue
        for entry in manifest.get("files") or []:
            if entry.get("path") != rel:
                continue
            if not entry.get("existed"):
                return b""
            data = snapshot_bytes(snapshot_id, rel)
            if data is not None:
                return data
    return None


def local_changes() -> list:
    """Файлы, которые правились на устройстве и отличаются от эталона.

    Этим же списком пользуется предупреждение при обновлении GUI:
    обновление затрёт локальные правки, и о них надо сказать ДО, а не
    после.
    """
    root = project_root()
    seen = set()
    changed = []
    for snapshot_id in snapshot_ids():
        manifest = read_manifest(snapshot_id)
        if not manifest:
            continue
        for entry in manifest.get("files") or []:
            rel = entry.get("path") or ""
            if not rel or rel in seen:
                continue
            seen.add(rel)
            base = baseline_bytes(rel)
            if base is None:
                continue
            abspath = os.path.join(root, rel)
            now = b""
            if os.path.exists(abspath):
                data, refusal = read_bytes(abspath)
                now = data if not refusal else b""
            if now != base:
                changed.append(rel)
    return sorted(changed)


def local_changes_warning() -> dict:
    """Предупреждение «обновление GUI затрёт локальные правки».

    Одна формулировка на все места, где она нужна: сравнение версий в
    UI (``gui_updater``) и ``updates_check`` в MCP. Правки на
    устройстве живут до ближайшего обновления, и сказать об этом надо
    ДО него, а не после.
    """
    try:
        files = local_changes()
    except Exception:                           # noqa: BLE001 — граница
        return {"count": 0, "files": []}
    out = {"count": len(files), "files": files}
    if files:
        out["warning"] = ("на устройстве есть локальные правки кода "
                          "(%d файл(ов)) — обновление GUI затрёт их без "
                          "следа" % len(files))
        out["hint"] = ("выгрузите их одним патчем (code_export_patch) и "
                       "перенесите в репозиторий")
    return out


def export_patch() -> dict:
    """Все локальные правки одним unified diff.

    Без этого удачная находка живёт до ближайшего обновления GUI и
    исчезает вместе с ним: перенести её в репозиторий — единственный
    способ сохранить.
    """
    root = project_root()
    chunks = []
    files = []
    for rel in local_changes():
        base = baseline_bytes(rel)
        if base is None:
            continue
        abspath = os.path.join(root, rel)
        now = b""
        if os.path.exists(abspath):
            data, refusal = read_bytes(abspath)
            now = data if not refusal else b""
        chunk = make_diff(decode(base), decode(now), rel,
                          "эталон", "устройство")
        if chunk:
            chunks.append(chunk)
            files.append(rel)
    from core.version import GUI_VERSION
    return {"ok": True, "files": files, "count": len(files),
            "gui_version": GUI_VERSION, "root": root,
            "patch": "".join(chunks),
            "git": git_info()}


# ────────────────── восстановление после перезапуска ────────────────

def recover_after_restart(source: str = SOURCE) -> dict:
    """Досудить снимки, чей сторож не пережил перезагрузку.

    Выключение питания посреди применения убивает и GUI, и сторожа, а
    правка остаётся на диске неподтверждённой. Манифест пережил это на
    диске: просроченные возвращаем немедленно, живым перезаряжаем
    сторожа (тот же приём, что у дедменов shell в S12).
    """
    reverted, rearmed = [], []
    for snapshot_id in snapshot_ids():
        manifest = read_manifest(snapshot_id)
        if not manifest or manifest.get("state") not in OPEN_STATES:
            continue
        conf = limits()
        started = float(manifest.get("applied_at")
                        or manifest.get("created_ts") or 0)
        deadline = started + conf["commit_ttl_sec"] \
            + conf["restart_timeout_sec"]
        if time.time() >= deadline:
            result = restore_snapshot(snapshot_id, reason="guard_lost")
            if result.get("ok"):
                reverted.append(snapshot_id)
            continue
        # GUI уже поднялся — ждать перезапуска сторожу больше незачем,
        # его дело теперь только дедмен подтверждения.
        left = max(30, int(deadline - time.time()))
        start_guard(snapshot_id, restart_timeout=5, commit_ttl=left,
                    expect_restart=False)
        rearmed.append(snapshot_id)
    if reverted or rearmed:
        log.warning("Самоправка после перезапуска: возвращено %d, "
                    "сторож перезаряжен у %d"
                    % (len(reverted), len(rearmed)), source=source)
    return {"ok": True, "reverted": reverted, "rearmed": rearmed}
