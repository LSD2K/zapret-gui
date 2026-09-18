# api/control.py
"""
API управления nfqws2.

POST /api/start     — запустить nfqws2 + применить FW правила
POST /api/stop      — остановить nfqws2 + снять FW правила
POST /api/restart   — перезапустить nfqws2

Сама последовательность (правила firewall, пересборка аргументов активной
стратегии, откат правил при неудаче) живёт в ``core/nfqws_control.py``:
ею пользуются и эти роуты, и MCP, и CLI — иначе «запустить обход из
модели» отличалось бы от «запустить кнопкой».
"""

from bottle import request, response


def _body_args():
    """``strategy_args`` из тела запроса или None, если их не передали.

    Пустой список — это тоже None: ``core/nfqws_control`` понимает None
    как «пересобрать активную стратегию», и запуск «ни с чем» означал бы
    голый nfqws2 без десинка, то есть выключенный обход при зелёном
    ответе.
    """
    try:
        body = request.json
    except Exception:
        return None
    if not body or "strategy_args" not in body:
        return None
    args = body["strategy_args"]
    if isinstance(args, str):
        args = args.split()
    if isinstance(args, list) and args:
        return [str(a) for a in args]
    return None


def _reply(result):
    """Ответ роута из результата ``core/nfqws_control``.

    Форма ответа сохранена дословно (``ok``/``error``/``nfqws``/
    ``firewall``): её читают web/js и внешние скрипты.
    """
    out = {
        "ok": bool(result.get("ok")),
        "nfqws": result.get("nfqws") or {},
        "firewall": result.get("firewall") or {},
    }
    if not out["ok"]:
        response.status = 500
        out["error"] = result.get("error") or "Ошибка управления nfqws2"
    return out


def register(app):

    @app.post("/api/start")
    def api_start():
        """
        Запустить nfqws2 с опциональными аргументами стратегии.

        Body (JSON, опционально):
            { "strategy_args": ["--filter-tcp=443", ...] }
        """
        response.content_type = "application/json; charset=utf-8"

        from core import nfqws_control
        return _reply(nfqws_control.start(_body_args()))

    @app.post("/api/stop")
    def api_stop():
        """Остановить nfqws2 и снять правила firewall."""
        response.content_type = "application/json; charset=utf-8"

        from core import nfqws_control
        return _reply(nfqws_control.stop())

    @app.post("/api/restart")
    def api_restart():
        """
        Перезапустить nfqws2.

        Body (JSON, опционально):
            { "strategy_args": ["--filter-tcp=443", ...] }
        """
        response.content_type = "application/json; charset=utf-8"

        from core import nfqws_control
        return _reply(nfqws_control.restart(_body_args()))
