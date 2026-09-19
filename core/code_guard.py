# core/code_guard.py
"""
Сторож самоправки: ждёт, пока GUI вернётся, и возвращает снимок, если нет.

Запускается **отдельным отвязанным процессом** из
``core/code_editor.apply_staged``:

.. code-block:: sh

    python3 -B -m core.code_guard --snapshot snap-20260919-153012 \\
        --timeout 45 --commit-ttl 300 --config-dir /opt/etc/zapret-gui

Зачем отдельный процесс. MCP-сервер живёт внутри того же процесса,
который модель переписывает: правка, ломающая импорт, убивает и GUI, и
MCP, и любой откат, задуманный «изнутри». Откатывать должен
посторонний, и он обязан пережить смерть родителя — отсюда
``start_new_session`` на той стороне.

**Только stdlib и ни одного нашего импорта.** Это не стиль, а условие
работы: модуль, который откатывает сломанный код, не может зависеть от
сломанного кода. Настройки читаются прямым ``json.load`` из
``settings.json``, файлы возвращаются своими руками, команда
перезапуска берётся из манифеста снимка (её вычислил GUI, пока был
жив). Поэтому же здесь продублированы 30 строк атомарной записи из
``core/safe_io.py`` — переиспользование стоило бы работоспособности в
единственном случае, ради которого всё написано.

## Что он делает

1. Убеждается, что прямо сейчас GUI отвечает (нас запустил он). Не
   отвечает — значит, проверка здоровья недостоверна (пароль, порт), и
   сторож работает **только по дедмену подтверждения**: ложный откат
   исправного GUI хуже отсутствия отката.
2. Ждёт, пока GUI уйдёт на перезапуск (``restart_timeout_sec``). Не
   ушёл — значит, перезапуск не состоялся, код на диске лежит
   незагруженным; это не провал, но и не успех: решает дедмен.
3. Ждёт, пока ``/api/status`` снова ответит **телом**, а не просто
   TCP-коннектом. Ответил — снимок переходит в ``applied``, и сторож
   ждёт ``code_commit`` до ``commit_ttl_sec``. Не ответил —
   немедленно возвращает файлы, перезапускает GUI и пишет причину в
   персистентный лог.
"""

import argparse
import base64
import json
import os
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


# Имена и состояния продублированы из core/code_editor: импортировать
# его сторожу нельзя (см. docstring модуля), а разойтись они не могут —
# это фиксирует tests/test_mcp_code_guard.py.
SNAPSHOTS_DIRNAME = "code-snapshots"
GUARD_LOG_NAME = "code-guard.log"
DEFAULT_CONFIG_DIR = "/opt/etc/zapret-gui"

STATE_PENDING = "pending"
STATE_APPLIED = "applied"
STATE_COMMITTED = "committed"
STATE_REVERTED = "reverted"
OPEN_STATES = (STATE_PENDING, STATE_APPLIED)

# Как часто спрашиваем «жив?» и «подтвердили?».
POLL_SEC = 1.0
HEALTH_TIMEOUT_SEC = 5

# Персистентный лог сторожа: причина отката обязана пережить и GUI, и
# перезагрузку — иначе «всё само откатилось» остаётся без объяснения.
LOG_MAX_BYTES = 128 * 1024


# ──────────────────────────── мелкий I/O ───────────────────────────

def read_json(path: str):
    """JSON с диска или ``None`` (сторож не падает никогда)."""
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def write_bytes(path: str, data: bytes, mode=None):
    """Атомарная запись (temp в той же ФС → fsync → replace)."""
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".guard-")
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        tmp = None
    finally:
        if tmp is not None:
            try:
                os.remove(tmp)
            except OSError:
                pass
    if mode is not None:
        try:
            os.chmod(path, int(mode))
        except OSError:
            pass


def write_json(path: str, obj):
    write_bytes(path, json.dumps(obj, indent=2,
                                 ensure_ascii=False).encode("utf-8"))


def journal(config_dir: str, message: str):
    """Строка в персистентный лог сторожа (с грубой ротацией)."""
    path = os.path.join(config_dir, GUARD_LOG_NAME)
    line = "%s  %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), message)
    try:
        os.makedirs(config_dir, exist_ok=True)
        if os.path.exists(path) and os.path.getsize(path) > LOG_MAX_BYTES:
            with open(path, "rb") as f:
                tail = f.read()[-LOG_MAX_BYTES // 2:]
            write_bytes(path, tail)
        with open(path, "a", encoding="utf-8") as f:
            f.write(line)
    except OSError:
        pass


# ──────────────────────── проверка «GUI жив» ───────────────────────

def health_target(config_dir: str) -> dict:
    """Адрес ``/api/status`` и Basic-авторизация из ``settings.json``.

    Читаем файл напрямую: ``config_manager`` — один из защищённых
    модулей, и именно он мог быть сломан правкой, ради которой сторож
    и запущен.
    """
    settings = read_json(os.path.join(config_dir, "settings.json")) or {}
    gui = settings.get("gui") if isinstance(settings.get("gui"), dict) \
        else {}
    host = str(gui.get("host") or "127.0.0.1")
    if host in ("0.0.0.0", "::", "*", ""):
        host = "127.0.0.1"
    port = gui.get("port") or 8080
    try:
        port = int(port)
    except (TypeError, ValueError):
        port = 8080
    target = {"url": "http://%s:%d/api/status" % (host, port),
              "auth": ""}
    if gui.get("auth_enabled") and gui.get("auth_password"):
        pair = "%s:%s" % (gui.get("auth_user") or "admin",
                          gui.get("auth_password"))
        target["auth"] = "Basic " + base64.b64encode(
            pair.encode("utf-8")).decode("ascii")
    return target


def check_health(target: dict, timeout: int = HEALTH_TIMEOUT_SEC) -> bool:
    """Ответил ли GUI осмысленным телом.

    TCP-коннекта мало: порт держит и наполовину поднявшийся процесс, и
    чужая программа, занявшая его после падения нашей. Спрашиваем
    ``/api/status`` и проверяем, что в ответе наш JSON.
    """
    request = urllib.request.Request(target["url"], method="GET")
    if target.get("auth"):
        request.add_header("Authorization", target["auth"])
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            if response.status != 200:
                return False
            body = response.read(64 * 1024)
    except (urllib.error.URLError, OSError, ValueError):
        return False
    try:
        data = json.loads(body.decode("utf-8", "replace"))
    except ValueError:
        return False
    return bool(isinstance(data, dict) and data.get("ok")
                and ("gui_version" in data or "nfqws" in data))


# ───────────────────────── откат и перезапуск ──────────────────────

def restore(snapshot_dir: str, manifest: dict) -> dict:
    """Вернуть файлы снимка на место."""
    root = manifest.get("root") or ""
    restored, removed, failed = [], [], []
    for entry in manifest.get("files") or []:
        rel = entry.get("path") or ""
        if not rel or not root:
            continue
        target = os.path.join(root, rel)
        try:
            if entry.get("existed"):
                source = os.path.join(snapshot_dir, "files", rel)
                with open(source, "rb") as f:
                    write_bytes(target, f.read(), entry.get("mode"))
                restored.append(rel)
            else:
                if os.path.exists(target):
                    os.remove(target)
                removed.append(rel)
        except OSError as e:
            failed.append("%s: %s" % (rel, e))
    return {"restored": restored, "removed": removed, "failed": failed}


def restart_gui(manifest: dict) -> bool:
    """Перезапустить GUI командой, вычисленной ещё живым GUI.

    Свой детект (Entware / OpenWrt / systemd) сторожу не нужен: команду
    положил в манифест ``code_apply``, и это заведомо та же команда,
    которой GUI перезапускает себя сам.
    """
    command = ((manifest.get("restart") or {}).get("command") or "").strip()
    if not command:
        return False
    try:
        subprocess.Popen(["/bin/sh", "-c", "sleep 1; %s" % command],
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL,
                         stdin=subprocess.DEVNULL,
                         start_new_session=True)
        return True
    except OSError:
        return False


# ────────────────────────────── сторож ─────────────────────────────

def guard(snapshot_dir: str, *, timeout: int = 45, commit_ttl: int = 300,
          config_dir: str = "", health=None, restart=None,
          sleep=time.sleep, clock=time.time,
          expect_restart: bool = True) -> dict:
    """Досмотреть одну применённую правку до конца.

    Все внешние действия — параметрами (``health``, ``restart``,
    ``sleep``, ``clock``): тесты гоняют сторожа с поддельным
    health-check'ом и мгновенными часами, не поднимая ни GUI, ни
    таймеров.
    """
    config_dir = config_dir or os.path.dirname(
        os.path.dirname(snapshot_dir))
    manifest_path = os.path.join(snapshot_dir, "manifest.json")
    manifest = read_json(manifest_path)
    if manifest is None:
        return {"ok": False, "action": "none", "error": "манифеста нет"}
    snapshot_id = manifest.get("id") or os.path.basename(snapshot_dir)
    if manifest.get("state") not in OPEN_STATES:
        return {"ok": True, "action": "none",
                "state": manifest.get("state")}

    if health is None:
        target = health_target(config_dir)
        def health():                                   # noqa: E306
            return check_health(target)
    if restart is None:
        def restart():                                  # noqa: E306
            return restart_gui(manifest)

    # 1. Достоверна ли сама проверка. Нас запустил живой GUI — если он
    #    не отвечает уже сейчас, дело не в правке (порт, пароль, bind),
    #    и судить по этой проверке нельзя.
    usable = health()
    if not usable:
        journal(config_dir,
                "%s: health-check недостоверен (GUI не ответил до "
                "перезапуска) — работаю только по дедмену подтверждения"
                % snapshot_id)

    observed_down = False
    alive = True
    if usable and expect_restart:
        # 2. Ждём, пока GUI уйдёт на перезапуск.
        deadline = clock() + timeout
        while clock() < deadline:
            if not health():
                observed_down = True
                break
            sleep(POLL_SEC)
        if observed_down:
            # 3. И пока вернётся — с телом ответа, а не просто портом.
            alive = False
            deadline = clock() + timeout
            while clock() < deadline:
                if health():
                    alive = True
                    break
                sleep(POLL_SEC)

    if not alive:
        return _revert(snapshot_dir, manifest, config_dir, restart,
                       reason="health_timeout",
                       message="GUI не ответил за %d с после перезапуска"
                               % timeout)

    # Снимок могли закрыть, пока мы ждали: подтвердить из GUI или
    # откатить вручную. Поднимать его обратно в «ждём» нельзя.
    fresh = read_json(manifest_path) or {}
    if fresh.get("state") not in OPEN_STATES:
        return {"ok": True, "snapshot_id": snapshot_id,
                "action": ("committed"
                           if fresh.get("state") == STATE_COMMITTED
                           else "reverted_elsewhere")}
    _patch(manifest_path, {"state": STATE_APPLIED,
                           "applied_at": round(clock(), 3),
                           "restart_observed": observed_down,
                           "health_usable": usable})
    journal(config_dir, "%s: применено, жду code_commit до %d с"
            % (snapshot_id, commit_ttl))

    # 4. Дедмен подтверждения. Единственный источник правды — состояние
    #    на диске: подтвердить могли из другого процесса.
    deadline = clock() + commit_ttl
    while clock() < deadline:
        current = read_json(manifest_path) or {}
        state = current.get("state")
        if state == STATE_COMMITTED:
            journal(config_dir, "%s: подтверждено" % snapshot_id)
            return {"ok": True, "action": "committed",
                    "snapshot_id": snapshot_id}
        if state == STATE_REVERTED:
            return {"ok": True, "action": "reverted_elsewhere",
                    "snapshot_id": snapshot_id}
        sleep(POLL_SEC)

    return _revert(snapshot_dir, read_json(manifest_path) or manifest,
                   config_dir, restart, reason="commit_timeout",
                   message="code_commit не пришёл за %d с" % commit_ttl)


def _revert(snapshot_dir, manifest, config_dir, restart, reason, message):
    """Вернуть снимок, перезапустить GUI, записать причину."""
    snapshot_id = manifest.get("id") or os.path.basename(snapshot_dir)
    result = restore(snapshot_dir, manifest)
    _patch(os.path.join(snapshot_dir, "manifest.json"),
           {"state": STATE_REVERTED,
            "reverted_at": round(time.time(), 3),
            "revert_reason": reason,
            "revert_detail": message,
            "revert_result": result})
    restarted = bool(restart())
    journal(config_dir,
            "%s: ОТКАТ (%s) — %s; возвращено %d, удалено %d, ошибок %d, "
            "перезапуск %s"
            % (snapshot_id, reason, message, len(result["restored"]),
               len(result["removed"]), len(result["failed"]),
               "запрошен" if restarted else "недоступен"))
    return {"ok": True, "action": "reverted", "reason": reason,
            "snapshot_id": snapshot_id, "restarted": restarted,
            "restored": result["restored"], "removed": result["removed"],
            "failed": result["failed"]}


def _patch(path: str, fields: dict) -> dict:
    """Дописать в манифест СВОИ поля, перечитав его с диска.

    Манифест правят двое: сторож и GUI (``code_commit``). Записать
    целиком свою копию значит потерять подтверждение, пришедшее
    секундой раньше, — поэтому наружу отдаётся не «весь манифест», а
    набор полей, которые сторож действительно менял.
    """
    current = read_json(path) or {}
    current.update(fields)
    write_json(path, current)
    return current


# ──────────────────────────────── CLI ──────────────────────────────

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="code_guard",
        description="Сторож самоправки zapret-gui: ждёт возвращения GUI "
                    "и откатывает правку, если он не вернулся или её не "
                    "подтвердили.")
    parser.add_argument("--snapshot", required=True,
                        help="идентификатор снимка (snap-YYYYmmdd-HHMMSS)")
    parser.add_argument("--timeout", type=int, default=45,
                        help="сколько ждать /api/status после перезапуска")
    parser.add_argument("--commit-ttl", type=int, default=300,
                        help="сколько ждать code_commit")
    parser.add_argument("--config-dir", default="",
                        help="каталог settings.json и снимков")
    parser.add_argument("--root", default="",
                        help="каталог установки GUI (для журнала)")
    parser.add_argument("--no-restart-wait", action="store_true",
                        help="не ждать перезапуска: GUI уже поднят")
    args = parser.parse_args(argv)

    config = (args.config_dir or os.environ.get("ZAPRET_GUI_CONFIG_DIR")
              or DEFAULT_CONFIG_DIR)
    snapshot_dir = os.path.join(config, SNAPSHOTS_DIRNAME, args.snapshot)
    if not os.path.isdir(snapshot_dir):
        journal(config, "%s: каталога снимка нет — сторож не нужен"
                % args.snapshot)
        return 1
    result = guard(snapshot_dir, timeout=max(1, args.timeout),
                   commit_ttl=max(1, args.commit_ttl), config_dir=config,
                   expect_restart=not args.no_restart_wait)
    return 0 if result.get("action") in ("committed", "none") else 2


if __name__ == "__main__":
    sys.exit(main())
