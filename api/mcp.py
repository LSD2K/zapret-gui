# api/mcp.py
"""
HTTP-транспорт MCP-сервера.

    POST   /api/mcp        — JSON-RPC (один запрос или батч)
    GET    /api/mcp        — 405 + Allow: POST (SSE появится в S14)
    DELETE /api/mcp        — 405 + Allow: POST
    GET    /api/mcp/info   — метаданные для UI, локально и без токена

Точка живёт в том же веб-сервере, что и GUI: адрес, порт и TLS — это
``gui.host``/``gui.port``. При ``gui.host=127.0.0.1`` MCP доступен только
с самого роутера — самый безопасный режим, и он же по умолчанию.

Транспорт без состояния. ``Mcp-Session-Id`` выдаётся на ``initialize`` и
принимается обратно, но сервер на нём ничего не держит: роутер
перезагружается чаще, чем живёт сессия модели.
"""

import json
import uuid

from bottle import request, response

from core.mcp import (audit, auth, permissions, prompts, registry,
                      resources, server)


# Заголовок, которым клиент сообщает ревизию спеки (обязателен после
# initialize — см. спеку MCP, раздел про HTTP-транспорт).
PROTOCOL_HEADER = "MCP-Protocol-Version"
SESSION_HEADER = "Mcp-Session-Id"

_JSON_CT = "application/json; charset=utf-8"


def register(app):

    @app.route("/api/mcp", method="POST")
    def api_mcp_rpc():
        """Единственная рабочая точка MCP: JSON-RPC поверх HTTP POST."""
        response.content_type = _JSON_CT

        # 1. Доступ: bind → Origin → токен → рейт-лимит.
        headers = _Headers(request.environ)
        decision = auth.check(
            method="POST",
            remote_addr=request.environ.get("REMOTE_ADDR", ""),
            headers=headers,
            auth_pair=_basic_auth(),
        )
        if not decision.ok:
            return _refuse(decision)

        # 2. Ревизия спеки. Заголовка может не быть (первый initialize,
        #    старые клиенты) — это не ошибка; ошибка — заголовок с
        #    версией, которой мы не знаем.
        version = (headers.get(PROTOCOL_HEADER, "") or "").strip()
        if version and version not in server.SUPPORTED_PROTOCOL_VERSIONS:
            response.status = 400
            return _body({
                "ok": False,
                "error": "неподдерживаемая ревизия MCP: %s" % _safe(version),
                "supported": list(server.SUPPORTED_PROTOCOL_VERSIONS),
            })

        # 3. Тело.
        ctype = (request.content_type or "").split(";")[0].strip().lower()
        if ctype and ctype != "application/json":
            response.status = 415
            return _body({
                "ok": False,
                "error": "ожидается Content-Type: application/json "
                         "(получено %s)" % _safe(ctype),
            })

        raw = request.body.read() if request.body else b""
        try:
            payload = json.loads(raw.decode("utf-8") or "null")
        except (ValueError, UnicodeDecodeError) as e:
            response.status = 200  # ошибка JSON-RPC едет с кодом 200
            return _body(server.parse_error(str(e)))

        if payload is None:
            return _body(server.parse_error("тело пустое"))

        # 4. Сессия: выдаём на initialize, принимаем обратно, ничего на
        #    ней не держим.
        session_id = (headers.get(SESSION_HEADER, "") or "").strip()
        if not session_id:
            session_id = uuid.uuid4().hex
        response.set_header(SESSION_HEADER, session_id)

        answer = server.dispatch(payload, {
            "permissions": auth.permissions(),
            "session_id": session_id,
            "subject": decision.subject,
            # Адрес вызывающего нужен журналу (core/mcp/audit.py): без
            # него в нём не видно, кто именно менял настройки.
            "remote_addr": request.environ.get("REMOTE_ADDR", ""),
            "protocol_version": version or server.PROTOCOL_VERSION,
        })

        if answer is None:
            # Тело состояло только из уведомлений — отвечать нечем.
            response.status = 202
            return b""
        return _body(answer)

    @app.route("/api/mcp", method="GET")
    def api_mcp_get():
        """SSE-канала нет — и это не поломка, а свойство транспорта."""
        return _method_not_allowed(
            "GET /api/mcp не поддерживается: транспорт работает без SSE, "
            "все вызовы идут через POST /api/mcp. Это не ошибка сервера — "
            "клиенту достаточно POST."
        )

    @app.route("/api/mcp", method="DELETE")
    def api_mcp_delete():
        """Сессию нечего удалять: сервер без состояния."""
        return _method_not_allowed(
            "DELETE /api/mcp не поддерживается: сервер не хранит сессий, "
            "закрывать нечего. Mcp-Session-Id выдаётся для совместимости "
            "и ни на что не влияет."
        )

    @app.route("/api/mcp/info")
    def api_mcp_info():
        """Метаданные для страницы настроек: включён ли, что разрешено.

        Без токена — иначе UI не покажет, что MCP выключен, пока токен
        не заведён. Зато только с самого роутера: снаружи это разведка
        (видно, какие разрешения открыты).
        """
        response.content_type = _JSON_CT
        remote = request.environ.get("REMOTE_ADDR", "")
        if not auth.is_local_address(remote):
            response.status = 403
            return _body({"ok": False,
                          "error": "/api/mcp/info доступен только с самого "
                                   "роутера"})

        cfg = auth.settings()
        perms = auth.permissions()
        return _body({
            "ok": True,
            "enabled": bool(cfg.get("enabled")),
            "active": auth.is_enabled(),
            # Сам токен не отдаём никогда — только факт, что он задан.
            "token_set": bool(cfg.get("token")),
            "allow_gui_auth": bool(cfg.get("allow_gui_auth")),
            "bind": cfg.get("bind", "inherit"),
            "transports": cfg.get("transports", {}),
            "permissions": perms,
            # Разрешение может стоять, но не действовать: experiments без
            # control/probes выключен. UI обязан показывать именно это,
            # иначе пользователь видит включённый флаг и выключенные
            # инструменты (модель разрешений — core/mcp/permissions.py).
            "permissions_effective": permissions.effective(perms),
            "permissions_info": permissions.describe(perms),
            "limits": cfg.get("limits", {}),
            "protocol_version": server.PROTOCOL_VERSION,
            "supported_protocol_versions":
                list(server.SUPPORTED_PROTOCOL_VERSIONS),
            "gui_version": _gui_version(),
            "tools_total": len(server.all_tools()),
            "tools_available": len(server.available_tools(perms)),
            "tools_by_scope": registry.scope_counts(perms),
            # Справочники и сценарии разрешений не требуют: их число
            # показывает UI, и по нему видно, что клиент подключился к
            # полноценному серверу, а не к пустой заглушке.
            # Журнал и снимки: страница MCP показывает, ведётся ли
            # журнал и есть ли что откатывать (`mcp_undo_last`).
            "audit": {
                "enabled": audit.is_enabled(),
                "keep": audit.keep(),
                "path": audit.journal_path(),
                "undoable": len(audit.snapshots()),
            },
            "resources": len(resources.list_resources()),
            "prompts": len(prompts.list_prompts()),
            "endpoint": "/api/mcp",
        })


# ───────────────────────────── помощники ────────────────────────────

class _Headers:
    """Регистронезависимый доступ к заголовкам, устойчивый к мусору.

    ``bottle.request.headers`` декодирует значение как latin-1 → utf-8
    и бросает ``UnicodeError`` на байтах, которые не складываются в
    UTF-8. Для точки, куда каждый желающий шлёт ``Authorization``, это
    означает 500 вместо честного 401: достаточно одного неверного
    байта в токене. Здесь битое значение превращается в замену, а не в
    исключение, — решение о доступе всё равно примет ``auth.check``.
    """

    __slots__ = ("_data",)

    def __init__(self, environ):
        self._data = {}
        for key, value in (environ or {}).items():
            if not key.startswith("HTTP_") or not isinstance(value, str):
                continue
            self._data[key[5:].replace("_", "-").lower()] = _decode(value)

    def get(self, name, default=""):
        return self._data.get(str(name).lower(), default)


def _decode(value: str) -> str:
    """Вернуть заголовок как текст, не падая на неверных байтах."""
    try:
        return value.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        try:
            return value.encode("latin-1", "replace").decode("utf-8",
                                                             "replace")
        except UnicodeError:
            return value


def _basic_auth():
    """Разобранная Basic-пара или None (bottle бросает на мусоре)."""
    try:
        return request.auth
    except Exception:
        return None



def _refuse(decision):
    """Отдать отказ авторизации с нужным кодом и заголовками."""
    response.status = decision.status
    for name, value in (decision.headers or {}).items():
        response.set_header(name, value)
    return _body({"ok": False, "error": decision.error,
                  "reason": decision.reason})


def _method_not_allowed(text):
    response.status = 405
    response.set_header("Allow", "POST")
    response.content_type = _JSON_CT
    return _body({"ok": False, "error": text, "allow": ["POST"]})


def _body(payload):
    """Сериализовать тело в UTF-8 байты.

    Bottle отдаёт тело как байты и считает Content-Length по ним: если
    вернуть str с кириллицей, длина разъедется с содержимым и клиент
    получит обрезанный JSON.
    """
    return json.dumps(payload, ensure_ascii=False,
                      default=str).encode("utf-8")


def _gui_version():
    from core.version import GUI_VERSION
    return GUI_VERSION


def _safe(text, limit=80):
    """Обрезать внешнюю строку перед вставкой в текст ответа."""
    text = (text or "").replace("\n", " ").replace("\r", " ")
    return text if len(text) <= limit else text[:limit - 1] + "…"
