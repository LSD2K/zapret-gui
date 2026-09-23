# api/mcp_ui.py
"""
Роуты страницы «MCP-сервер» (`web/js/pages/mcp.js`).

Почему отдельный файл, а не продолжение ``api/mcp.py``:

* **это не MCP, а GUI.** Здесь выдают токен и раздают разрешения —
  то есть решают, что модели МОЖНО. Пускать сюда по Bearer-токену
  значило бы отдать модели право расширить себе права, поэтому
  ``app.py`` исключает поддерево ``/api/mcp/ui/`` из врезки «MCP со
  своим токеном проходит мимо гейта GUI». Дверь тут одна — общая
  авторизация веб-интерфейса;
* ``api/mcp.py`` — транспорт протокола, и мешать с ним панель
  управления значит каждый раз читать 900 строк ради одного роута.

**Один роут — один ответ.** ``GET /api/mcp/ui/state`` отдаёт всё, что
показывает страница: сводку сервера, доступ, журнал, эксперимент,
правки кода, shell и черновики issue. Собирать это в JS из шести вызовов нельзя —
на роутере со 128 МБ страница будет мигать (задание S15, «Грабли»).

**Блоки 6–8 задания** (эксперимент, самоправка, shell) показываются
только если соответствующий модуль на устройстве есть: ``available``
в каждом блоке. Отсутствие модуля — не ошибка и не «в разработке»,
а просто скрытый блок.
"""

from bottle import request, response

from api.mcp import info_payload
from core.mcp import audit, auth, permissions


_JSON_CT = "application/json; charset=utf-8"

# Сколько записей журнала показывает страница (задание S15, блок 5).
AUDIT_LIMIT = 50

# Потолок diff'а, который страница показывает целиком.
DIFF_LIMIT_KB = 64


def register(app):

    # ────────────────────────── состояние ───────────────────────────

    @app.route("/api/mcp/ui/state")
    def api_mcp_ui_state():
        """Всё, что показывает страница MCP, одним ответом."""
        response.content_type = _JSON_CT
        return _state()

    # ─────────────────────── включение и токен ──────────────────────

    @app.post("/api/mcp/ui/enabled")
    def api_mcp_ui_enabled():
        """Включить или выключить точку доступа MCP."""
        response.content_type = _JSON_CT
        body = _body()
        if body is None:
            return _bad("Ожидается JSON-объект")
        enabled = bool(body.get("enabled"))
        _write(("mcp", "enabled", enabled))
        _log("MCP-сервер %s из веб-интерфейса"
             % ("включён" if enabled else "выключен"),
             level="warning" if enabled else "info")
        return {"ok": True, "info": info_payload()}

    @app.post("/api/mcp/ui/transports")
    def api_mcp_ui_transports():
        """Переключить транспорты: ``sse`` и/или ``http`` (S17).

        Выключенный ``http`` закрывает ``POST /api/mcp`` для всех
        клиентов, но не эту страницу: она ходит в ``/api/mcp/ui/*`` под
        авторизацией GUI и включит транспорт обратно. Поэтому отдельного
        подтверждения здесь нет — отрезать себя этим переключателем
        нельзя.
        """
        response.content_type = _JSON_CT
        body = _body()
        if body is None:
            return _bad("Ожидается JSON-объект")
        known = [name for name in ("sse", "http") if name in body]
        if not known:
            return _bad("Ожидается поле sse или http")
        for name in known:
            _write(("mcp", "transports", name, bool(body.get(name))))
            if name == "http":
                _log("Основной транспорт MCP (POST /api/mcp) %s из "
                     "веб-интерфейса"
                     % ("включён" if body.get("http") else "выключен"),
                     level="warning")
        return {"ok": True, "info": info_payload()}

    @app.post("/api/mcp/ui/token")
    def api_mcp_ui_token_write():
        """Создать новый токен или стереть имеющийся."""
        response.content_type = _JSON_CT
        body = _body()
        if body is None:
            return _bad("Ожидается JSON-объект")
        action = str(body.get("action") or "").strip().lower()

        if action == "clear":
            _write(("mcp", "token", ""))
            _log("MCP-токен стёрт из веб-интерфейса", level="warning")
            return {"ok": True, "token": "", "info": info_payload()}

        if action not in ("rotate", "generate"):
            return _bad("action: rotate | clear")

        token = auth.generate_token()
        _write(("mcp", "token", token))
        # В журнал — факт, но не значение: токен не пишется в лог
        # никогда (инвариант §5.3 контракта).
        _log("MCP-токен перевыпущен из веб-интерфейса; подключённые "
             "клиенты придётся перенастроить", level="warning")
        return {"ok": True, "token": token, "info": info_payload()}

    @app.route("/api/mcp/ui/token")
    def api_mcp_ui_token_read():
        """Показать токен — по явному клику, не в общем состоянии."""
        response.content_type = _JSON_CT
        token = auth.settings().get("token") or ""
        if not token:
            return _bad("токен не задан — нажмите «Сгенерировать»")
        _log("MCP-токен показан в веб-интерфейсе", level="warning")
        return {"ok": True, "token": token}

    # ───────────────────────── разрешения ───────────────────────────

    @app.post("/api/mcp/ui/permissions")
    def api_mcp_ui_permissions():
        """Раздать или отобрать разрешения; эффект — сразу.

        Рассылку ``notifications/tools/list_changed`` открытым сессиям
        делает круг keep-alive (S14): он сам замечает смену разрешений,
        куда бы её ни записали.
        """
        response.content_type = _JSON_CT
        body = _body()
        if body is None:
            return _bad("Ожидается JSON-объект")
        given = body.get("permissions")
        if not isinstance(given, dict) or not given:
            return _bad("Ожидается непустой объект permissions")

        unknown = [k for k in given if k not in permissions.PERMISSIONS]
        if unknown:
            return _bad("Неизвестные разрешения: %s" % ", ".join(unknown))

        current = auth.permissions()
        merged = permissions.normalize(current)
        for key, value in given.items():
            merged[key] = bool(value)
        _write(("mcp", "permissions", merged))

        changed = [k for k in permissions.PERMISSIONS
                   if bool(current.get(k)) != merged[k]]
        if changed:
            _log("Разрешения MCP изменены из веб-интерфейса: %s"
                 % ", ".join("%s=%s" % (k, "вкл" if merged[k] else "выкл")
                             for k in changed),
                 level="warning")
        return {"ok": True, "changed": changed, "info": info_payload()}

    # ─────────────────────────── журнал ─────────────────────────────

    @app.post("/api/mcp/ui/undo")
    def api_mcp_ui_undo():
        """«Отменить последнее изменение» — то же, что ``mcp_undo_last``."""
        response.content_type = _JSON_CT
        body = _body() or {}
        result = audit.undo_last(str(body.get("kind") or ""))
        if not result.get("ok"):
            response.status = 400
        return result

    # ──────────────────────── эксперимент ───────────────────────────

    @app.post("/api/mcp/ui/experiment/commit")
    def api_mcp_ui_experiment_commit():
        """Оставить применённый вариант и снять авто-откат."""
        response.content_type = _JSON_CT
        runner = _experiment()
        if runner is None:
            return _bad("Движок экспериментов недоступен")
        return _guarded(lambda: runner.commit())

    @app.post("/api/mcp/ui/experiment/rollback")
    def api_mcp_ui_experiment_rollback():
        """Вернуть состояние к снимку, не дожидаясь дедлайна."""
        response.content_type = _JSON_CT
        runner = _experiment()
        if runner is None:
            return _bad("Движок экспериментов недоступен")
        return _guarded(runner.rollback)

    # ───────────────────────── правка кода ──────────────────────────

    @app.route("/api/mcp/ui/code/diff")
    def api_mcp_ui_code_diff():
        """Дифф снимка правки — для кнопки «Показать diff»."""
        response.content_type = _JSON_CT
        editor = _module("core.code_editor")
        if editor is None:
            return _bad("Самоправка недоступна")
        snapshot_id = str(request.query.get("snapshot_id") or "").strip()
        if not snapshot_id:
            return _bad("Укажите snapshot_id")
        if not editor.read_manifest(snapshot_id):
            return _bad("Снимка %s нет" % snapshot_id)
        return _guarded(lambda: {
            "ok": True,
            "snapshot_id": snapshot_id,
            "diff": _cut(editor.snapshot_diff(snapshot_id)),
        })

    @app.route("/api/mcp/ui/code/patch")
    def api_mcp_ui_code_patch():
        """Все локальные правки одним диффом («Выгрузить патч»)."""
        response.content_type = _JSON_CT
        editor = _module("core.code_editor")
        if editor is None:
            return _bad("Самоправка недоступна")

        def build():
            export = editor.export_patch()
            export["patch"] = _cut(export.get("patch", ""))
            return export

        return _guarded(build)

    @app.post("/api/mcp/ui/code/commit")
    def api_mcp_ui_code_commit():
        """Подтвердить применённую правку, пока сторож не вернул файлы."""
        response.content_type = _JSON_CT
        editor = _module("core.code_editor")
        if editor is None:
            return _bad("Самоправка недоступна")
        body = _body() or {}
        return _guarded(lambda: editor.commit(
            str(body.get("snapshot_id") or "")))

    @app.post("/api/mcp/ui/code/rollback")
    def api_mcp_ui_code_rollback():
        """Вернуть файлы снимка на место (GUI перезапустится)."""
        response.content_type = _JSON_CT
        editor = _module("core.code_editor")
        if editor is None:
            return _bad("Самоправка недоступна")
        body = _body() or {}
        _log("Откат правки кода из веб-интерфейса: %s"
             % (body.get("snapshot_id") or "последний снимок"),
             level="warning")
        return _guarded(lambda: editor.rollback(
            str(body.get("snapshot_id") or ""),
            reason="откат из веб-интерфейса",
            restart=body.get("restart", True) is not False))

    # ──────────────────────── черновики issue ───────────────────────

    @app.route("/api/mcp/ui/issues/draft")
    def api_mcp_ui_issues_draft():
        """Черновик целиком: текст issue и ссылка «открыть на GitHub».

        Текст — по клику, а не в общем состоянии: он собирается из
        журнала и лога и весит килобайты на черновик.
        """
        from core.mcp import issues

        response.content_type = _JSON_CT
        draft_id = str(request.query.get("id") or "").strip()
        draft = issues.get(draft_id) if draft_id else None
        if draft is None:
            return _bad("Черновика %s нет" % (draft_id or "(без id)"))
        return _guarded(lambda: dict(issues.describe(draft), ok=True))

    @app.post("/api/mcp/ui/issues/status")
    def api_mcp_ui_issues_status():
        """Отметить черновик отправленным (или вернуть в черновики)."""
        from core.mcp import issues

        response.content_type = _JSON_CT
        body = _body() or {}
        return _guarded(lambda: issues.set_status(
            str(body.get("id") or ""), str(body.get("status") or "")))

    @app.post("/api/mcp/ui/issues/delete")
    def api_mcp_ui_issues_delete():
        """Удалить черновик — отправленный или ненужный."""
        from core.mcp import issues

        response.content_type = _JSON_CT
        body = _body() or {}
        return _guarded(lambda: issues.delete(str(body.get("id") or "")))

    # ────────────────────────── shell ───────────────────────────────

    @app.post("/api/mcp/ui/shell/panic")
    def api_mcp_ui_shell_panic():
        """«Запретить shell немедленно»: гасим оба переключателя и задачи.

        Снять разрешения мало: уже запущенная асинхронная команда
        продолжает работать, а неотозванный токен подтверждения — это
        заряженное ружьё. Поэтому три действия разом, и только вместе
        они значат то, что написано на кнопке.
        """
        response.content_type = _JSON_CT
        perms = permissions.normalize(auth.permissions())
        perms["shell_full"] = False
        perms["shell_readonly"] = False
        _write(("mcp", "permissions", perms))

        stopped, dropped = [], 0
        shell = _module("core.shell_exec")
        if shell is not None:
            try:
                stopped = [j.get("job_id") for j in shell.stop_all_jobs()]
                dropped = len(shell.list_confirms())
                shell.reset_confirms()
            except Exception as e:              # noqa: BLE001 — граница
                _log("Аварийный запрет shell: задачи не сняты: %s" % e,
                     level="error")
        _log("Shell-доступ MCP запрещён из веб-интерфейса; снято задач: "
             "%d, отозвано подтверждений: %d" % (len(stopped), dropped),
             level="warning")
        return {"ok": True, "stopped": stopped, "dropped_confirms": dropped,
                "info": info_payload()}

    @app.post("/api/mcp/ui/shell/confirm")
    def api_mcp_ui_shell_confirm():
        """Подтвердить или отклонить команду, ждущую решения человека."""
        response.content_type = _JSON_CT
        shell = _module("core.shell_exec")
        if shell is None:
            return _bad("Shell-инструменты недоступны")
        body = _body()
        if body is None:
            return _bad("Ожидается JSON-объект")
        token = str(body.get("token") or "").strip()
        decision = str(body.get("decision") or "").strip().lower()
        if not token:
            return _bad("Укажите token")
        if decision not in ("approve", "reject"):
            return _bad("decision: approve | reject")

        if decision == "reject":
            if not shell.drop_confirm(token):
                return _bad("подтверждение не найдено или просрочено")
            _log("Команда MCP отклонена в веб-интерфейсе (%s)" % token,
                 level="warning")
            return {"ok": True, "decision": "reject"}

        record, refusal = shell.take_confirm(token)
        if refusal:
            response.status = 400
            return refusal
        # Токен сам по себе прав не даёт: разрешение проверяется и на
        # этом шаге — ровно как в инструменте shell_confirm.
        scope = record.get("scope") or "shell_full"
        if not permissions.granted(scope):
            response.status = 403
            return {"ok": False,
                    "error": "нужно разрешение %s — оно выключено" % scope,
                    "permission": scope}
        _log("Команда MCP подтверждена в веб-интерфейсе: %s"
             % record.get("summary", ""), level="warning")
        return _guarded(lambda: shell.run_confirmed(record))


# ───────────────────────────── сборка состояния ─────────────────────

def _state() -> dict:
    """Снимок для страницы: сводка, доступ, журнал и три блока сессий."""
    info = info_payload()
    return {
        "ok": True,
        "info": info,
        "access": _access(info),
        "audit": _audit_block(),
        "experiment": _experiment_block(),
        "code": _code_block(),
        "shell": _shell_block(),
        "issues": _issues_block(),
    }


def _access(info: dict) -> dict:
    """Как до точки доступа добираются и чем это грозит.

    Считает бэкенд, а не JS: ``gui.host`` странице неизвестен, а
    именно он решает, видна ли точка кому-то, кроме самого роутера.
    """
    from core.config_manager import get_config_manager

    cfg = get_config_manager()
    host = str(cfg.get("gui", "host", default="127.0.0.1") or "")
    port = cfg.get("gui", "port", default=8080)
    loopback = host.startswith("127.") or host in ("::1", "localhost")
    return {
        "gui_host": host,
        "gui_port": port,
        # GUI слушает петлю — MCP доступен только с самого роутера
        # (по ssh или через stdio-мост).
        "loopback_only": loopback or info.get("bind") == "local",
        "bind_local": info.get("bind") == "local",
        # Своего TLS у GUI нет: по обычному HTTP токен уезжает
        # открытым текстом в каждом запросе. Схему страница знает сама
        # (location.protocol) — тут только факт, что помочь нечем.
        "tls_builtin": False,
        "endpoint": info.get("endpoint", "/api/mcp"),
        "sse_endpoint": (info.get("sse") or {}).get("endpoint", ""),
        "stdio_hint": "zapret-gui mcp --stdio",
    }


def _audit_block() -> dict:
    """Последние вызовы и то, что ещё можно откатить."""
    try:
        records, stats = audit.read_records(limit=AUDIT_LIMIT)
    except Exception as e:                      # noqa: BLE001 — граница
        return {"enabled": audit.is_enabled(), "records": [],
                "error": str(e), "undoable": []}
    try:
        snapshots = audit.snapshots()
    except Exception:                           # noqa: BLE001 — граница
        snapshots = []
    return {
        "enabled": bool(stats.get("enabled")),
        "path": stats.get("path", ""),
        "skipped_lines": stats.get("skipped_lines", 0),
        "records": records,
        "undoable": [{"id": s.get("id"), "kind": s.get("kind"),
                      "target": s.get("target"), "time": s.get("time"),
                      "detail": s.get("detail", "")}
                     for s in snapshots[:10]],
    }


def _experiment_block() -> dict:
    """Идущий эксперимент: вариант, прогресс, сколько до авто-отката."""
    runner = _experiment()
    if runner is None:
        return {"available": False}
    try:
        status = runner.get_status()
    except Exception as e:                      # noqa: BLE001 — граница
        return {"available": True, "error": str(e)}
    return {"available": True, "status": status}


def _code_block() -> dict:
    """Снимки правок, ожидание подтверждения и локальные отличия."""
    editor = _module("core.code_editor")
    if editor is None:
        return {"available": False}
    try:
        return {
            "available": True,
            "snapshots": editor.history(limit=20),
            # «Применена правка, ждёт подтверждения: осталось N с» —
            # это и есть дедмен сторожа (core/code_guard.py).
            "waiting": editor.pending_commit(),
            "staging": editor.staging_summary(),
            "local_changes": editor.local_changes(),
        }
    except Exception as e:                      # noqa: BLE001 — граница
        return {"available": True, "error": str(e)}


def _shell_block() -> dict:
    """Команды, задачи и то, что ждёт решения человека."""
    shell = _module("core.shell_exec")
    if shell is None:
        return {"available": False}
    try:
        return {
            "available": True,
            "jobs": shell.jobs()[:10],
            "pending": shell.list_confirms(),
            "guards": shell.armed_guards(),
        }
    except Exception as e:                      # noqa: BLE001 — граница
        return {"available": True, "error": str(e)}


def _issues_block() -> dict:
    """Черновики issue от модели и падения инструментов без черновика."""
    try:
        from core.mcp import issues
        return {
            "available": True,
            "drafts": [issues.summary(d) for d in issues.list_drafts()],
            "crashes": issues.crashes_without_draft(),
        }
    except Exception as e:                      # noqa: BLE001 — граница
        return {"available": True, "drafts": [], "crashes": [],
                "error": str(e)}


# ──────────────────────────── частности ─────────────────────────────

def _module(name: str):
    """Модуль по имени или ``None``.

    Через ``importlib``, а не ``from core import X``: у пакета ``core``
    атрибут остаётся от чужого импорта, и проверка «есть ли модуль»
    через него всегда отвечает «есть» (грабли S14).
    """
    import importlib

    try:
        return importlib.import_module(name)
    except Exception:                           # noqa: BLE001 — граница
        return None


def _experiment():
    """Синглтон движка экспериментов или ``None``."""
    module = _module("core.strategy_experiment")
    if module is None:
        return None
    try:
        return module.get_experiment_runner()
    except Exception:                           # noqa: BLE001 — граница
        return None


def _guarded(call):
    """Вызвать и не дать исключению уйти в 500 с голой трассой."""
    try:
        result = call()
    except Exception as e:                      # noqa: BLE001 — граница
        response.status = 500
        return {"ok": False, "error": str(e)}
    if isinstance(result, dict) and not result.get("ok", True):
        response.status = 400
    return result


def _body():
    """Тело запроса как dict; ``None`` — не объект или не JSON."""
    try:
        data = request.json
    except Exception:                           # noqa: BLE001 — граница
        return None
    return data if isinstance(data, dict) else None


def _bad(text: str) -> dict:
    response.status = 400
    return {"ok": False, "error": text}


def _cut(text: str) -> str:
    """Обрезать дифф до потолка: страница читает человек, а не модель."""
    limit = DIFF_LIMIT_KB * 1024
    text = text or ""
    if len(text.encode("utf-8", "replace")) <= limit:
        return text
    return text[:limit] + "\n… дифф обрезан, целиком — code_export_patch"


def _write(path_value):
    """Записать значение в settings.json и сохранить его на диск.

    ``ConfigManager.set()`` меняет только память (грабли S13) — без
    ``save()`` разрешения вернутся при перезапуске GUI, и это читалось
    бы как «настройка не работает».
    """
    from core.config_manager import get_config_manager

    cfg = get_config_manager()
    cfg.set(*path_value)
    cfg.save()


def _log(message: str, level: str = "info"):
    """Записать в журнал GUI под источником ``mcp``."""
    from core.log_buffer import log

    getattr(log, level, log.info)(message, source="mcp")
