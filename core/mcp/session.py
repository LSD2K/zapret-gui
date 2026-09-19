# core/mcp/session.py
"""
Сессии legacy-SSE транспорта MCP (ревизия спеки ``2024-11-05``).

Основной транспорт — ``POST /api/mcp`` — работает **без состояния**, и
это правильно: роутер перезагружается чаще, чем живёт сессия модели.
Но часть живых клиентов (сборки LM Studio, старые Cline) умеют только
старую схему «два канала»:

  1. клиент открывает ``GET /api/mcp/sse`` и получает первым событием
     ``event: endpoint`` с адресом, куда слать запросы;
  2. запросы уходят ``POST``-ом на этот адрес и получают ``202``;
  3. **ответы приходят обратно в SSE-поток**, а не в тело POST.

Значит, между двумя HTTP-запросами нужно что-то, что помнит клиента, —
вот эта очередь. Сессия здесь **только для доставки ответа**: ни
разрешений, ни состояния протокола она не держит, диспетчер
``core/mcp/server.py`` остаётся тем же самым.

## Почему мёртвая сессия — это не мелочь

На роутере со 128 МБ брошенная очередь на сто сообщений — настоящая
утечка, и клиент, который «просто закрыл ноутбук», оставляет её после
себя. Поэтому живость сессии подтверждается **ходом самого потока**:
генератор ``api/mcp.py`` дёргает :meth:`Session.touch` на каждом круге
(не реже ``KEEPALIVE_SEC``), а :func:`sweep` выкидывает всех, кто молчит
дольше ``IDLE_TIMEOUT_SEC``. Уборка зовётся из обычных операций
(открытие сессии, поиск, счёт) — отдельного потока-сторожа нет: лишний
тред ради четырёх записей в словаре на таком железе не окупается.

Штатный путь всё равно другой: разрыв клиента роняет ``GeneratorExit`` в
генераторе, тот в ``finally`` зовёт :func:`close`. ``sweep`` — это сеть
под ним, на случай сервера, который бросил генератор, не закрыв.

## Рассылка ``notifications/tools/list_changed``

У stateless-HTTP её не было и быть не могло: некуда слать. С открытым
потоком она появляется по-настоящему — :func:`poll_permissions`
сравнивает текущие разрешения со снимком и, если пользователь щёлкнул
переключатель в настройках, рассылает уведомление всем открытым
сессиям. Опрос, а не крючок в месте записи: разрешения меняются и через
``config_set``, и через страницу настроек GUI, и руками в
``settings.json`` — крючок пришлось бы вешать в каждую из этих точек,
а опрос на круге keep-alive ловит их все и стоит одного чтения конфига
раз в 15 секунд.
"""

import copy
import queue
import threading
import time
import uuid


# Как часто поток шлёт keep-alive (сек). Тот же интервал, что у
# SSE-логов (``api/logs.py``): он же задаёт и период опроса разрешений.
KEEPALIVE_SEC = 15

# Сколько сессия может молчать, прежде чем её уберут. Полтора
# keep-alive — живой поток отмечается втрое чаще.
IDLE_TIMEOUT_SEC = 90

# Сколько сообщений держим в очереди одной сессии. Клиент, который не
# читает сотню ответов подряд, сломан — копить ему больше незачем.
QUEUE_MAXSIZE = 100

# Сколько сессий держим, если в настройках ничего не сказано.
DEFAULT_MAX_SESSIONS = 4

# Уведомление о смене набора инструментов (спека MCP).
TOOLS_CHANGED = {"jsonrpc": "2.0",
                 "method": "notifications/tools/list_changed"}


class TooManySessions(RuntimeError):
    """Открытых потоков уже ``mcp.limits.max_sessions``."""


class Session:
    """Один открытый SSE-поток: очередь ответов и отметка живости."""

    __slots__ = ("id", "created", "last_tick", "subject", "remote_addr",
                 "sent", "closed", "_queue")

    def __init__(self, session_id: str, subject: str = "",
                 remote_addr: str = ""):
        self.id = session_id
        self.created = time.time()
        self.last_tick = self.created
        self.subject = subject or ""
        self.remote_addr = remote_addr or ""
        self.sent = 0
        self.closed = False
        self._queue = queue.Queue(maxsize=QUEUE_MAXSIZE)

    # ─── поток ───

    def touch(self):
        """Отметить, что поток жив (зовётся на каждом круге генератора)."""
        self.last_tick = time.time()

    def get(self, timeout=None):
        """Следующее сообщение; ``queue.Empty`` — пора слать keep-alive."""
        message = self._queue.get(timeout=timeout)
        self.touch()
        return message

    # ─── доставка ───

    def put(self, message) -> bool:
        """Положить ответ в очередь. ``False`` — очередь переполнена.

        Не блокируем: POST с ответом висел бы до таймаута клиента, а
        причина у переполнения одна — SSE-поток никто не читает.
        """
        if self.closed:
            return False
        try:
            self._queue.put_nowait(message)
        except queue.Full:
            return False
        return True

    def pending(self) -> int:
        return self._queue.qsize()

    def idle_sec(self) -> float:
        return max(0.0, time.time() - self.last_tick)

    def to_dict(self) -> dict:
        """Вид сессии для ``/api/mcp/info`` — без содержимого сообщений."""
        return {
            "id": self.id,
            "created": self.created,
            "age_sec": int(max(0.0, time.time() - self.created)),
            "idle_sec": int(self.idle_sec()),
            "subject": self.subject,
            "remote_addr": self.remote_addr,
            "pending": self.pending(),
            "sent": self.sent,
        }


_lock = threading.Lock()

# id → Session.
_sessions = {}

# Последний известный снимок разрешений (для poll_permissions).
_perms_snapshot = None


# ──────────────────────────── настройки ─────────────────────────────

def max_sessions() -> int:
    """``mcp.limits.max_sessions`` или дефолт."""
    try:
        from core.mcp import auth
        value = int(auth.settings().get("limits", {}).get(
            "max_sessions", DEFAULT_MAX_SESSIONS))
    except Exception:                           # noqa: BLE001 — граница
        return DEFAULT_MAX_SESSIONS
    return value if value > 0 else DEFAULT_MAX_SESSIONS


def sse_enabled() -> bool:
    """Включён ли legacy-SSE (``mcp.transports.sse``).

    Читается на каждом запросе, а не при старте: включение и выключение
    транспорта не должно требовать перезапуска GUI.
    """
    try:
        from core.mcp import auth
        transports = auth.settings().get("transports") or {}
    except Exception:                           # noqa: BLE001 — граница
        return False
    return bool(transports.get("sse"))


# ───────────────────────── жизненный цикл ───────────────────────────

def open_session(subject: str = "", remote_addr: str = "") -> Session:
    """Завести сессию под новый поток.

    Бросает :class:`TooManySessions`, если живых потоков уже столько,
    сколько разрешено. Мёртвые перед счётом выметаются — иначе один
    отвалившийся клиент занимал бы место до конца своего таймаута.
    """
    global _perms_snapshot

    sweep()
    limit = max_sessions()
    session = Session(uuid.uuid4().hex, subject=subject,
                      remote_addr=remote_addr)
    with _lock:
        if len(_sessions) >= limit:
            raise TooManySessions(limit)
        _sessions[session.id] = session
        # Снимок разрешений заводим на первой сессии: без него первый же
        # опрос счёл бы «ничего → что-то» сменой и разослал бы лишнее
        # уведомление.
        if _perms_snapshot is None:
            _perms_snapshot = _read_permissions()
    return session


def get(session_id: str):
    """Сессия по идентификатору или ``None`` (мёртвые не отдаём)."""
    if not session_id:
        return None
    sweep()
    with _lock:
        return _sessions.get(str(session_id))


def close(session) -> bool:
    """Закрыть сессию по объекту или по идентификатору."""
    session_id = getattr(session, "id", session)
    if not session_id:
        return False
    with _lock:
        existing = _sessions.pop(str(session_id), None)
    if existing is None:
        return False
    existing.closed = True
    return True


def count() -> int:
    """Сколько живых потоков открыто."""
    sweep()
    with _lock:
        return len(_sessions)


def sessions() -> list:
    """Снимок сессий для ``/api/mcp/info`` (без тел сообщений)."""
    sweep()
    with _lock:
        items = list(_sessions.values())
    return [s.to_dict() for s in items]


def sweep(now: float = 0.0) -> int:
    """Выкинуть сессии, чей поток молчит дольше ``IDLE_TIMEOUT_SEC``."""
    now = now or time.time()
    with _lock:
        dead = [s for s in _sessions.values()
                if now - s.last_tick > IDLE_TIMEOUT_SEC]
        for session in dead:
            _sessions.pop(session.id, None)
            session.closed = True
    return len(dead)


def reset():
    """Закрыть всё и забыть снимок разрешений (для тестов)."""
    global _perms_snapshot
    with _lock:
        for session in _sessions.values():
            session.closed = True
        _sessions.clear()
        _perms_snapshot = None


# ───────────────────────────── рассылка ─────────────────────────────

def broadcast(message) -> int:
    """Разослать сообщение всем открытым потокам. Вернуть, скольким."""
    with _lock:
        targets = list(_sessions.values())
    delivered = 0
    for session in targets:
        if session.put(copy.deepcopy(message)):
            delivered += 1
    return delivered


def poll_permissions() -> bool:
    """Сверить разрешения со снимком и разослать ``tools/list_changed``.

    Зовётся с круга keep-alive: ловит и ``config_set``, и правку в UI, и
    ручную правку ``settings.json`` — все три случая выглядят одинаково.
    """
    global _perms_snapshot
    current = _read_permissions()
    if current is None:
        return False
    with _lock:
        previous = _perms_snapshot
        if previous is None:
            _perms_snapshot = current
            return False
        if previous == current:
            return False
        _perms_snapshot = current
    broadcast(TOOLS_CHANGED)
    return True


def _read_permissions():
    try:
        from core.mcp import auth
        return auth.permissions()
    except Exception:                           # noqa: BLE001 — граница
        return None
