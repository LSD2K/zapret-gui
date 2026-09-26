# api/_updates_lock.py
"""
Замок обновлений (debian-gw, docs/gw/spec-t4-updates.md).

При `updates.locked == true` в settings.json эндпоинты установки,
обновления и удаления бинарей и самого GUI отвечают 403 и ничего не
запускают: на gw это делает gw-panel с проверкой и откатом.

`refuse_if_locked()` зовётся первой строкой обработчика:

    denied = refuse_if_locked()
    if denied:
        return denied

`register()` добавляет `GET /api/updates/lock` для вебки (показать замок).
"""

from bottle import response

LOCK_ERROR = "locked"
LOCK_MESSAGE = "обновления на этом хосте делает gw-panel"


def is_locked() -> bool:
    """Включён ли замок. Ошибка чтения конфига = замка нет (как раньше)."""
    try:
        from core.config_manager import get_config_manager
        section = get_config_manager().current().get("updates") or {}
        return section.get("locked") is True
    except Exception:
        return False


def refuse_if_locked():
    """Ответ 403 при замке, иначе None."""
    if not is_locked():
        return None
    response.status = 403
    response.content_type = "application/json; charset=utf-8"
    return {"ok": False, "error": LOCK_ERROR, "message": LOCK_MESSAGE}


def register(app):

    @app.route("/api/updates/lock")
    def api_updates_lock():
        """Состояние замка для вебки: {ok, locked, message}."""
        response.content_type = "application/json; charset=utf-8"
        locked = is_locked()
        return {"ok": True, "locked": locked,
                "message": LOCK_MESSAGE if locked else ""}
