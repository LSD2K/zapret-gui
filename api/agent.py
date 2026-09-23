# api/agent.py
"""
Роуты страницы «Агент» (`web/js/pages/agent.js`).

    GET  /api/agent/state     — всё, что показывает страница, одним ответом
    POST /api/agent/settings  — адрес сервера, модель, лимиты
    POST /api/agent/test      — проверить связь и получить список моделей
    POST /api/agent/start     — запустить прогон (задача или готовый сценарий)
    POST /api/agent/stop      — остановить
    GET  /api/agent/run       — транскрипт прогона (для опроса страницей)

Две вещи, которые здесь важнее остального.

**Ключ не отдаём никогда.** ``api_key`` уезжает на страницу как факт
«задан / не задан», ровно как токен MCP: страница, показывающая ключ,
показывает его и тому, кто заглянул через плечо. Пустая строка в
запросе означает «не менять», а не «стереть» — иначе сохранение любой
соседней настройки затирало бы ключ.

**Дверь тут одна — общая авторизация GUI.** Врезка «MCP со своим
токеном проходит мимо гейта» (`app.py`, ``_is_mcp_path``) сюда не
распространяется: она действует только на поддерево ``/api/mcp``. Это
важно и намеренно — здесь запускают агента, то есть дают инструментам
исполняться, и Bearer-токен MCP такого права не даёт.
"""

from bottle import request, response

from core import agent_runner


_JSON_CT = "application/json; charset=utf-8"

# Сколько шагов транскрипта отдаём странице за раз. Прогон на двенадцать
# шагов с вызовами — это десятки записей, а страница опрашивается раз в
# полторы секунды: отдавать всё каждый раз незачем.
STEPS_LIMIT = 200


def register(app):

    @app.route("/api/agent/state")
    def api_agent_state():
        """Настройки, доступность и текущий прогон — одним ответом."""
        response.content_type = _JSON_CT
        return _state()

    @app.post("/api/agent/settings")
    def api_agent_settings():
        """Сохранить настройки агента (ключ — только если передан)."""
        response.content_type = _JSON_CT
        body = _body()
        if body is None:
            return _bad("Ожидается JSON-объект")

        from core.config_manager import get_config_manager
        from core.llm_client import normalize_base_url

        cfg = get_config_manager()
        current = dict(cfg.get("agent", default={}) or {})
        for key in ("enabled",):
            if key in body:
                current[key] = bool(body[key])
        if "base_url" in body:
            current["base_url"] = normalize_base_url(body["base_url"])
        if "model" in body:
            current["model"] = str(body.get("model") or "").strip()[:200]
        if "tools" in body:
            current["tools"] = ("all" if body.get("tools") == "all"
                                else "scenarios")
        for key in ("max_steps", "timeout_sec", "tool_result_chars"):
            if key in body:
                try:
                    current[key] = int(body[key])
                except (TypeError, ValueError):
                    return _bad("Поле %s должно быть числом" % key)
        if "temperature" in body:
            try:
                current["temperature"] = float(body["temperature"])
            except (TypeError, ValueError):
                return _bad("Поле temperature должно быть числом")
        # Пустая строка — «не менять»: иначе сохранение соседней
        # настройки затирало бы ключ, введённый минуту назад.
        if str(body.get("api_key") or "").strip():
            current["api_key"] = str(body["api_key"]).strip()
        if body.get("clear_api_key"):
            current["api_key"] = ""

        cfg.set("agent", current)
        cfg.save()
        _log("Настройки встроенного агента изменены (адрес %s, модель %s)"
             % (current.get("base_url") or "—",
                current.get("model") or "по умолчанию"))
        return {"ok": True, "settings": _public_settings()}

    @app.post("/api/agent/test")
    def api_agent_test():
        """Проверить связь с сервером модели и забрать список моделей."""
        response.content_type = _JSON_CT
        body = _body() or {}

        from core.llm_client import LLMClient, LLMError

        cfg = agent_runner.settings()
        base_url = str(body.get("base_url") or cfg["base_url"]).strip()
        api_key = str(body.get("api_key") or "").strip() or cfg["api_key"]
        try:
            client = LLMClient(base_url, api_key, min(cfg["timeout_sec"], 20))
            models = client.models()
        except LLMError as e:
            return {"ok": False, "error": str(e), "base_url": base_url}
        except Exception as e:                  # noqa: BLE001 — граница
            return {"ok": False,
                    "error": "%s: %s" % (type(e).__name__, e),
                    "base_url": base_url}
        return {"ok": True, "base_url": client.base_url, "models": models,
                "count": len(models)}

    @app.post("/api/agent/start")
    def api_agent_start():
        """Запустить прогон: своя задача или готовый сценарий."""
        response.content_type = _JSON_CT
        body = _body()
        if body is None:
            return _bad("Ожидается JSON-объект")

        preset = str(body.get("preset") or "").strip()
        goal = str(body.get("goal") or "").strip()
        if preset:
            try:
                goal = agent_runner.goal_for(preset,
                                             body.get("argument", ""))
            except ValueError as e:
                return _bad(str(e))
        if not goal:
            return _bad("Опишите задачу или выберите готовую")

        result = agent_runner.get_agent_runner().start(goal, preset)
        if not result.get("ok"):
            response.status = 409 if result.get("run_id") else 400
        return result

    @app.post("/api/agent/stop")
    def api_agent_stop():
        """Попросить прогон остановиться."""
        response.content_type = _JSON_CT
        return agent_runner.get_agent_runner().stop()

    @app.route("/api/agent/run")
    def api_agent_run():
        """Транскрипт прогона (страница опрашивает его)."""
        response.content_type = _JSON_CT
        run_id = str(request.query.get("run_id") or "").strip()
        return agent_runner.get_agent_runner().status(run_id,
                                                      steps=STEPS_LIMIT)


# ──────────────────────────── частности ─────────────────────────────

def _state() -> dict:
    """Всё, что показывает страница «Агент», одним ответом.

    Один роут — один ответ, как у страницы MCP: на роутере со 128 МБ
    страница, собирающая состояние из пяти вызовов, мигает.
    """
    from core.mcp import permissions as perms_mod

    runner = agent_runner.get_agent_runner()
    perms = perms_mod.current()
    specs = agent_runner.tool_specs(perms)
    return {
        "ok": True,
        "settings": _public_settings(),
        "available": agent_runner.is_enabled(),
        "presets": agent_runner.presets(),
        "tools": {
            "count": len(specs),
            "names": [spec.name for spec in specs],
            "mode": agent_runner.settings()["tools"],
        },
        # Разрешения агент берёт у MCP и своих не имеет: человек должен
        # видеть это на странице, а не узнавать из документации.
        "permissions": perms,
        "permissions_effective": perms_mod.effective(perms),
        "permissions_info": perms_mod.describe(perms),
        "run": runner.status(steps=STEPS_LIMIT),
        "history": runner.history(),
    }


def _public_settings() -> dict:
    """Настройки для страницы: без ключа, только факт его наличия."""
    cfg = agent_runner.settings()
    out = {key: value for key, value in cfg.items() if key != "api_key"}
    out["api_key_set"] = bool(cfg["api_key"])
    return out


def _body():
    try:
        body = request.json
    except Exception:                           # noqa: BLE001 — граница
        return None
    return body if isinstance(body, dict) else None


def _bad(message: str) -> dict:
    response.status = 400
    return {"ok": False, "error": message}


def _log(message: str) -> None:
    try:
        from core.log_buffer import log
        log.info(message, source="agent")
    except Exception:                           # noqa: BLE001 — граница
        pass
