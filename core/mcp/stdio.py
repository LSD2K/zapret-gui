# core/mcp/stdio.py
"""
stdio-мост MCP: JSON-RPC построчно из ``stdin`` в ``stdout``.

Главный сценарий — **клиент пришёл по SSH**::

    "command": "ssh", "args": ["router", "zapret-gui", "mcp", "--stdio"]

Ни порта, ни токена, ни TLS: канал уже есть, его дал ssh. На роутере,
который не смотрит в интернет, это единственный способ подключить
Claude Desktop или Cline, не открывая наружу веб-интерфейс.

Два режима:

* **локальный** (по умолчанию) — строка уходит прямо в диспетчер
  ``core/mcp/server.dispatch``, без HTTP и без сокета вообще;
* **прокси** (``--url`` и ``--token``) — строка пересылается в
  ``POST /api/mcp`` другого экземпляра. Нужен, когда GUI работает на
  другом устройстве, а клиент умеет только stdio.

## Правила, которые нельзя нарушать

1. **Одна строка — один JSON-RPC объект** (или батч-массив). Никаких
   переводов строки внутри: ``json.dumps`` без ``indent`` их и не даёт,
   но это условие протокола, а не следствие реализации.
2. **stdout священен.** Любая посторонняя строка в нём — и клиент
   захлёбывается: он разбирает её как сообщение и обрывает сессию. Одно
   ``print()`` в любом импортированном модуле ломает мост, поэтому на
   время работы ``sys.stdout`` подменяется на ``stderr``, а настоящий
   дескриптор остаётся только здесь. Отладка — только через stderr.
3. **Мусор в stdin — не повод падать.** Нечитаемая строка получает
   ``-32700`` и мост работает дальше: иначе одна кривая строка убивала
   бы сессию целиком.
4. **EOF завершает** мост с нулевым кодом — клиент закрыл канал, это
   штатный конец, а не сбой.
5. **Уведомление ответа не порождает.** Диспетчер возвращает ``None`` —
   в stdout не уходит ничего.
"""

import json
import sys


# Таймаут одного запроса в режиме прокси (сек).
DEFAULT_TIMEOUT_SEC = 120

# Коды JSON-RPC, которые мост выставляет сам.
PARSE_ERROR = -32700
INTERNAL_ERROR = -32603


def serve(stdin=None, stdout=None, stderr=None, *, url: str = "",
          token: str = "", timeout: int = 0) -> int:
    """Прогнать мост до EOF. Вернуть код возврата процесса.

    ``stdin``/``stdout``/``stderr`` передаются тестами; в бою берутся
    настоящие, и тогда же включается защита stdout (см. правило 2).
    """
    own_streams = stdin is None and stdout is None
    stdin = stdin if stdin is not None else sys.stdin
    out = stdout if stdout is not None else sys.stdout
    err = stderr if stderr is not None else sys.stderr

    timeout = int(timeout or DEFAULT_TIMEOUT_SEC)
    handle = _proxy(url, token, timeout, err) if url else _local(err)

    saved_stdout = sys.stdout
    if own_streams:
        # Чужой print() уедет в stderr, а не в протокол.
        sys.stdout = err
    try:
        for line in stdin:
            line = (line or "").strip()
            if not line:
                continue
            answer = _handle(line, handle, err)
            if answer is not None:
                _write(out, answer, err)
    except KeyboardInterrupt:
        return 0
    except (BrokenPipeError, ConnectionResetError):
        # Клиент закрыл канал на полуслове — это конец сессии, не сбой.
        return 0
    finally:
        if own_streams:
            sys.stdout = saved_stdout
    return 0


# ───────────────────────────── одна строка ──────────────────────────

def _handle(line: str, handle, err):
    """Разобрать строку, отдать обработчику, вернуть ответ или ``None``."""
    try:
        payload = json.loads(line)
    except ValueError as e:
        _note(err, "нечитаемая строка: %s" % e)
        return _error(None, PARSE_ERROR,
                      "тело запроса не разобрано как JSON: %s" % e)
    if payload is None:
        return _error(None, PARSE_ERROR, "тело запроса пустое")
    try:
        return handle(payload)
    except Exception as e:                      # noqa: BLE001 — граница
        # Мост не имеет права умереть от ошибки одного запроса: клиент
        # ждёт ответа на свой id и без него висит до собственного
        # таймаута.
        _note(err, "ошибка обработки: %s: %s" % (type(e).__name__, e))
        return _error(_id_of(payload), INTERNAL_ERROR,
                      "мост не смог обработать запрос: %s" % e)


def _local(err):
    """Локальный режим: диспетчер напрямую, без HTTP."""
    from core.mcp import auth, server

    if not auth.settings().get("enabled"):
        # Не отказ: канал дал ssh, а не токен. Но сказать об этом надо —
        # иначе непонятно, почему клиент работает, а веб-точка 401.
        _note(err, "mcp.enabled=false: точка /api/mcp закрыта, но "
                   "локальный мост работает — доступ дал ssh, а не токен")

    def handle(payload):
        return server.dispatch(payload, {
            "permissions": auth.permissions(),
            "subject": "stdio",
            "remote_addr": "",
            "transport": "stdio",
        })
    return handle


def _proxy(url: str, token: str, timeout: int, err):
    """Режим прокси: пересылка в ``POST /api/mcp`` другого экземпляра."""
    import urllib.error
    import urllib.request

    endpoint = _endpoint(url)
    _note(err, "прокси в %s" % endpoint)

    def handle(payload):
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers = {"Content-Type": "application/json",
                   "Accept": "application/json"}
        if token:
            headers["Authorization"] = "Bearer " + token
        request = urllib.request.Request(endpoint, data=data,
                                         headers=headers, method="POST")
        try:
            with urllib.request.urlopen(request, timeout=timeout) as resp:
                body = resp.read()
                status = getattr(resp, "status", resp.getcode())
        except urllib.error.HTTPError as e:
            body = e.read() or b""
            status = e.code
            answer = _parse_answer(body)
            if answer is not None:
                return answer
            return _error(_id_of(payload), INTERNAL_ERROR,
                          "%s ответил HTTP %s: %s"
                          % (endpoint, status, _short(body)))
        except Exception as e:                  # noqa: BLE001 — граница
            return _error(_id_of(payload), INTERNAL_ERROR,
                          "%s недоступен: %s" % (endpoint, e))
        if status == 202 or not body.strip():
            # Тело состояло только из уведомлений — отвечать нечем.
            return None
        answer = _parse_answer(body)
        if answer is None:
            return _error(_id_of(payload), INTERNAL_ERROR,
                          "ответ %s не разобран как JSON: %s"
                          % (endpoint, _short(body)))
        return answer
    return handle


def _endpoint(url: str) -> str:
    """Дополнить адрес до точки MCP, если дали только корень."""
    url = (url or "").strip().rstrip("/")
    if not url:
        return ""
    if url.endswith("/api/mcp") or "/api/mcp" in url:
        return url
    return url + "/api/mcp"


# ───────────────────────────── вывод ────────────────────────────────

def _write(out, payload, err):
    """Одна строка — один объект. Кириллица не должна ломать вывод."""
    try:
        text = json.dumps(payload, ensure_ascii=False, default=str)
    except (TypeError, ValueError) as e:
        _note(err, "ответ не сериализуется: %s" % e)
        return
    try:
        out.write(text + "\n")
    except UnicodeEncodeError:
        # Локаль без UTF-8 (на роутере это норма): \u-экранирование —
        # тот же самый JSON, просто в ASCII. Строку собираем заново
        # целиком: половина строки в stdout хуже, чем ASCII-запись.
        out.write(json.dumps(payload, ensure_ascii=True, default=str) + "\n")
    try:
        out.flush()
    except Exception:                           # noqa: BLE001 — граница
        pass


def _note(err, text: str):
    """Служебное сообщение — только в stderr (правило 2)."""
    if err is None:
        return
    try:
        err.write("zapret-gui mcp: %s\n" % text)
        err.flush()
    except Exception:                           # noqa: BLE001 — граница
        pass


# ───────────────────────────── мелочи ───────────────────────────────

def _error(request_id, code: int, message: str) -> dict:
    return {"jsonrpc": "2.0", "id": request_id,
            "error": {"code": code, "message": message}}


def _id_of(payload):
    """``id`` запроса, если он вообще есть (у батча и уведомления — нет)."""
    if isinstance(payload, dict):
        return payload.get("id")
    return None


def _parse_answer(body: bytes):
    try:
        return json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError, AttributeError):
        return None


def _short(body, limit: int = 200) -> str:
    try:
        text = body.decode("utf-8", "replace")
    except AttributeError:
        text = str(body)
    text = text.replace("\n", " ").replace("\r", " ").strip()
    return text if len(text) <= limit else text[:limit - 1] + "…"
