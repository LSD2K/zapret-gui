# api/agh_routes.py
"""
API маршрутов через AdGuard Home («какие домены в какой туннель»).

Эндпоинты:
  GET  /api/agh-routes         , настройки (пароль замаскирован)
  PUT  /api/agh-routes         , частичное обновление (пустой пароль и
                                  маска *** пароль не меняют)
  GET  /api/agh-routes/sources , что можно выбрать в правилах: hostlist'ы,
                                  named lists, geosite; ?config=<имя> -
                                  ещё outbound'ы этого конфига sing-box
  GET  /api/agh-routes/plan    , что изменит применение, без записи
  POST /api/agh-routes/apply   , применить (sing-box, затем AdGuard)
  POST /api/agh-routes/test    , связь с AdGuard Home (версия); в теле
                                  можно передать несохранённые
                                  agh_url/agh_user/agh_password

Логика, core/agh_routes.py.
"""

from bottle import request, response


def _body():
    try:
        return request.json or {}
    except Exception:
        return None


def register(app):

    @app.route("/api/agh-routes")
    def api_agh_routes_get():
        """Настройки маршрутов (пароль замаскирован)."""
        response.content_type = "application/json; charset=utf-8"
        from core import agh_routes
        return {"ok": True, "settings": agh_routes.public_settings()}

    @app.put("/api/agh-routes")
    def api_agh_routes_put():
        """Частичное обновление настроек."""
        response.content_type = "application/json; charset=utf-8"
        from core import agh_routes
        body = _body()
        if not isinstance(body, dict):
            response.status = 400
            return {"ok": False, "error": "Ожидается JSON-объект"}
        try:
            res = agh_routes.update_settings(body)
        except ValueError as e:
            response.status = 400
            return {"ok": False, "error": str(e)}
        return {"ok": True, **res}

    @app.route("/api/agh-routes/sources")
    def api_agh_routes_sources():
        """Доступные источники доменов и outbound'ы конфига."""
        response.content_type = "application/json; charset=utf-8"
        from core import agh_routes
        name = (request.query.get("config") or "").strip()
        return {"ok": True, **agh_routes.list_sources(name)}

    @app.route("/api/agh-routes/plan")
    def api_agh_routes_plan():
        """План применения (без записи)."""
        response.content_type = "application/json; charset=utf-8"
        from core import agh_routes
        return {"ok": True, "plan": agh_routes.plan()}

    @app.post("/api/agh-routes/apply")
    def api_agh_routes_apply():
        """Применить маршруты. Ошибки плана, ok:false + errors (HTTP 200:
        страница показывает их списком)."""
        response.content_type = "application/json; charset=utf-8"
        from core import agh_routes
        return agh_routes.apply()

    @app.post("/api/agh-routes/test")
    def api_agh_routes_test():
        """Проверка связи с AdGuard Home."""
        response.content_type = "application/json; charset=utf-8"
        from core import agh_routes
        body = _body()
        return agh_routes.test_connection(body if isinstance(body, dict)
                                          else None)
