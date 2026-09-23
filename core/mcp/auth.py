# core/mcp/auth.py
"""
Доступ к точке ``/api/mcp``: токен, Origin, bind, рейт-лимит.

Точка обслуживается тем же веб-сервером, что и GUI, поэтому своей
привязки к адресу у неё нет — вместо неё четыре проверки, в порядке
«дешёвая и грубая раньше дорогой и точной»:

  1. **bind** — ``mcp.bind=local`` отдаёт 403 всем, кроме 127.0.0.1/::1;
  2. **Origin** — если заголовок есть, он должен быть своим, localhost-
     подобным или из ``gui.cors_origins``, иначе 403. Это защита от
     DNS-rebinding: спека MCP требует её для локальных серверов, потому
     что браузер на чужом сайте иначе доберётся до роутера;
  3. **токен** — Bearer, ``secrets.token_hex(32)``, сравнение через
     ``hmac.compare_digest``. Пустой токен или ``mcp.enabled=false`` —
     401 всем. Альтернатива: ``mcp.allow_gui_auth`` разрешает обычную
     Basic-авторизацию GUI (тогда MCP-доступ равен доступу к GUI);
  4. **рейт-лимит** ``mcp.limits.calls_per_minute`` на токен → 429.

Токен действует **только** на ``/api/mcp*``: на любом другом маршруте
API он не проверяется и ничего не открывает.

**Токен не пишется в лог никогда** — ни предъявленный, ни настроенный.
Отказы логируются со сворачиванием: одна строка раз в 30 секунд со
счётчиком, иначе перебор токена забьёт лог-буфер за минуту.
"""

import copy
import hashlib
import hmac
import secrets
import threading
import time
import urllib.parse

from core.log_buffer import log


# Как часто печатать сводку об отказах (сек).
DENY_LOG_INTERVAL_SEC = 30

# Окно рейт-лимита (сек).
RATE_WINDOW_SEC = 60

_lock = threading.Lock()

# token_key → список меток времени вызовов внутри окна.
_rate_state = {}

# Сворачивание отказов: причина → {"count": n, "last_log": ts}.
_deny_state = {}


class AuthDecision:
    """Решение по запросу: пускать или нет, и с каким кодом.

    ``ok``      — пускать;
    ``status``  — HTTP-код отказа (401/403/429);
    ``error``   — человекочитаемый текст для тела ответа;
    ``headers`` — заголовки, которые обязан нести отказ
                  (``WWW-Authenticate``, ``Retry-After``);
    ``subject`` — чем авторизовались (``token`` | ``gui`` | ``""``);
    ``reason``  — короткий код причины для лога.
    """

    __slots__ = ("ok", "status", "error", "headers", "subject", "reason")

    def __init__(self, ok, status=200, error="", headers=None,
                 subject="", reason=""):
        self.ok = ok
        self.status = status
        self.error = error
        self.headers = headers or {}
        self.subject = subject
        self.reason = reason


# ──────────────────────────── настройки ─────────────────────────────

def settings() -> dict:
    """Секция ``mcp`` поверх дефолтов.

    Берём дефолты из ``DEFAULT_CONFIG`` и накрываем сохранённым: если
    конфиг ещё не загружен (ранний старт, тесты) или в нём нет свежего
    ключа, лимиты и разрешения всё равно определены. Иначе пришлось бы
    в каждой точке писать ``default=``, и один забытый default отдал бы
    ``None`` там, где ждут число.
    """
    from core.config_manager import DEFAULT_CONFIG, get_config_manager

    merged = copy.deepcopy(DEFAULT_CONFIG.get("mcp", {}))
    saved = get_config_manager().get("mcp", default=None)
    if isinstance(saved, dict):
        _deep_merge(merged, saved)
    return merged


def permissions() -> dict:
    """Карта разрешений: все ключи из дефолтов, значения — bool."""
    perms = settings().get("permissions", {})
    return {k: bool(v) for k, v in perms.items()}


def http_enabled() -> bool:
    """Включён ли основной транспорт — ``POST /api/mcp``.

    Флаг ``mcp.transports.http`` до S17 не влиял ни на что, и это было
    хуже его отсутствия: пользователь видел переключатель в
    ``settings.json``, выключал его и продолжал работать. Теперь он
    действительно закрывает точку — читается на каждом запросе, как и
    флаг SSE, поэтому перезапуск GUI не нужен.

    Выключение **не отрезает от управления**: страница MCP
    (``/api/mcp/ui/*``) — отдельная дверь под авторизацией GUI, и
    включить транспорт обратно можно оттуда. Отсутствие ключа — это
    «включён»: транспорт был всегда, и молча выключиться при
    обновлении GUI он не должен.
    """
    transports = settings().get("transports")
    if not isinstance(transports, dict) or "http" not in transports:
        return True
    return bool(transports.get("http"))


def is_enabled() -> bool:
    """MCP включён и способен кого-то пустить.

    Пустой токен при выключенном ``allow_gui_auth`` — это выключенный
    MCP, как бы ни стоял флаг ``enabled``: пускать некого.
    """
    cfg = settings()
    if not cfg.get("enabled"):
        return False
    return bool(cfg.get("token")) or bool(cfg.get("allow_gui_auth"))


def generate_token() -> str:
    """Новый токен: 64 hex-символа (``secrets.token_hex(32)``)."""
    return secrets.token_hex(32)


# ───────────────────────────── проверки ─────────────────────────────

def check(*, method: str, remote_addr: str, headers, auth_pair=None,
          count_call: bool = True) -> AuthDecision:
    """Проверить запрос к ``/api/mcp``.

    ``headers``   — объект с ``.get(name, default)`` (заголовки запроса);
    ``auth_pair`` — разобранная Basic-пара ``(user, password)`` или None;
    ``count_call``— учитывать вызов в рейт-лимите (для ``/info`` — нет).
    """
    cfg = settings()

    # 1. bind=local — до всего остального: внешнему адресу здесь ловить
    #    нечего, и незачем давать ему даже различать «нет токена» и
    #    «неверный токен».
    if str(cfg.get("bind") or "inherit") == "local" and \
            not is_local_address(remote_addr):
        return _deny(403, "mcp.bind=local: доступ разрешён только с самого "
                          "роутера (127.0.0.1)", reason="bind")

    # 2. Origin (DNS-rebinding). Заголовка нет — запрос не из браузера.
    origin = (headers.get("Origin", "") or "").strip()
    if origin and not origin_allowed(origin, headers.get("Host", "") or ""):
        return _deny(403, "Origin %s не разрешён: добавьте его в "
                          "gui.cors_origins" % _safe(origin), reason="origin")

    # 3. Авторизация.
    if not cfg.get("enabled"):
        return _deny(401, "MCP-сервер выключен: включите mcp.enabled в "
                          "настройках", reason="disabled",
                     headers=_www_authenticate())

    authorization = (headers.get("Authorization", "") or "").strip()
    subject = ""

    if authorization[:7].lower() == "bearer ":
        presented = authorization[7:].strip()
        expected = str(cfg.get("token") or "")
        if not expected:
            return _deny(401, "MCP-токен не задан: сгенерируйте его в "
                              "настройках MCP", reason="no-token",
                         headers=_www_authenticate())
        if not secret_equal(presented, expected):
            return _deny(401, "неверный MCP-токен", reason="bad-token",
                         headers=_www_authenticate())
        subject = "token"
    elif cfg.get("allow_gui_auth") and auth_pair:
        if not _gui_auth_ok(auth_pair):
            return _deny(401, "неверные логин или пароль GUI",
                         reason="bad-gui-auth", headers=_www_authenticate())
        subject = "gui"
    else:
        hint = ("Authorization: Bearer <токен> обязателен"
                if not cfg.get("allow_gui_auth")
                else "нужен Authorization: Bearer <токен> или Basic-"
                     "авторизация GUI")
        return _deny(401, hint, reason="no-auth", headers=_www_authenticate())

    # 4. Рейт-лимит — уже после успешной авторизации, на субъект: иначе
    #    любой неавторизованный шум выбивал бы квоту у легального клиента.
    if count_call:
        limit = _int(cfg.get("limits", {}).get("calls_per_minute"), 60)
        if limit > 0:
            allowed, retry_after = _rate_allow(_subject_key(cfg, subject),
                                               limit)
            if not allowed:
                return _deny(
                    429,
                    "превышен лимит %d запросов в минуту (mcp.limits."
                    "calls_per_minute); повторите через %d с"
                    % (limit, retry_after),
                    reason="rate-limit",
                    headers={"Retry-After": str(retry_after)},
                )

    return AuthDecision(True, subject=subject)


def token_is_valid(authorization: str) -> bool:
    """Предъявлен ли в заголовке действующий MCP-токен.

    Нужен глобальному security-гейту ``app.py``: при включённой
    Basic-авторизации GUI он обязан пропустить MCP-клиента с валидным
    Bearer к ``/api/mcp`` (у MCP своя авторизация, браузерных кук у него
    нет). Все прочие проверки — в :func:`check`.
    """
    cfg = settings()
    if not cfg.get("enabled"):
        return False
    expected = str(cfg.get("token") or "")
    authorization = (authorization or "").strip()
    if not expected or authorization[:7].lower() != "bearer ":
        return False
    return secret_equal(authorization[7:].strip(), expected)


def secret_equal(given, expected) -> bool:
    """Сравнение секрета за постоянное время — по БАЙТАМ, а не по str.

    ``hmac.compare_digest`` на строках принимает только ASCII и на любом
    другом символе бросает ``TypeError``. Здесь это не теория: пароль
    GUI бывает кириллическим, а в заголовок ``Authorization`` кто угодно
    пришлёт что угодно (битые байты ``_Headers`` превращает в U+FFFD).
    Исключение вместо ``False`` — это 500 вместо честного 401, а для
    кириллического пароля — вход, который не работает никогда.
    """
    def _raw(value) -> bytes:
        return str("" if value is None else value).encode("utf-8",
                                                          "surrogatepass")
    return hmac.compare_digest(_raw(given), _raw(expected))


def is_local_address(addr: str) -> bool:
    """Адрес принадлежит самому роутеру (loopback)."""
    if not addr:
        # REMOTE_ADDR пуст только у unix-сокета/внутреннего вызова —
        # это локально по построению.
        return True
    addr = addr.strip().strip("[]")
    if addr.startswith("::ffff:"):          # IPv4-mapped IPv6
        addr = addr[7:]
    return addr == "::1" or addr == "localhost" or addr.startswith("127.")


def origin_allowed(origin: str, host_header: str = "") -> bool:
    """Допустим ли ``Origin``.

    Свой (совпадает с ``Host``), localhost-подобный или явно внесённый в
    ``gui.cors_origins``. Схему при сравнении с ``Host`` не учитываем —
    иначе TLS-терминирующий прокси ломает same-origin.
    """
    if not origin:
        return True
    try:
        parsed = urllib.parse.urlparse(origin)
    except ValueError:
        return False

    netloc = (parsed.netloc or "").lower()
    if netloc and netloc == (host_header or "").lower():
        return True

    hostname = (parsed.hostname or "").lower()
    if hostname and (hostname == "localhost" or hostname == "::1"
                     or hostname.startswith("127.")
                     or hostname.endswith(".localhost")):
        return True

    from core.config_manager import get_config_manager
    allowed = get_config_manager().get("gui", "cors_origins", default=[])
    return isinstance(allowed, list) and origin in allowed


# ──────────────────────────── рейт-лимит ────────────────────────────

def reset_rate_limit():
    """Сбросить окно рейт-лимита и сворачивание отказов (для тестов)."""
    with _lock:
        _rate_state.clear()
        _deny_state.clear()


def _rate_allow(key: str, limit: int):
    """(пустить?, через сколько секунд повторить)."""
    now = time.time()
    with _lock:
        hits = [t for t in _rate_state.get(key, ())
                if now - t < RATE_WINDOW_SEC]
        if len(hits) >= limit:
            _rate_state[key] = hits
            retry = max(1, int(RATE_WINDOW_SEC - (now - hits[0])) + 1)
            return False, retry
        hits.append(now)
        _rate_state[key] = hits
        return True, 0


def _subject_key(cfg: dict, subject: str) -> str:
    """Ключ рейт-лимита.

    Для токена — его хеш, а не он сам: ключи словаря попадают в дампы и
    трассировки, а токен не должен всплывать нигде, кроме settings.json.
    """
    if subject == "token":
        token = str(cfg.get("token") or "")
        digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
        return "token:" + digest[:16]
    return "gui"


# ───────────────────────────── отказы ───────────────────────────────

def _deny(status: int, error: str, *, reason: str,
          headers=None) -> AuthDecision:
    _log_deny(reason, status)
    return AuthDecision(False, status=status, error=error,
                        headers=headers, reason=reason)


def _log_deny(reason: str, status: int):
    """Записать отказ со сворачиванием: строка раз в 30 с со счётчиком."""
    now = time.time()
    with _lock:
        state = _deny_state.setdefault(reason, {"count": 0, "last_log": 0.0})
        state["count"] += 1
        if now - state["last_log"] < DENY_LOG_INTERVAL_SEC:
            return
        count = state["count"]
        state["count"] = 0
        state["last_log"] = now
    suffix = "" if count == 1 else " (×%d за %d с)" % (count,
                                                       DENY_LOG_INTERVAL_SEC)
    log.warning("MCP: запрос отклонён (%s, HTTP %d)%s" % (reason, status,
                                                          suffix),
                source="mcp")


def _www_authenticate() -> dict:
    # realm называет ресурс, а не значение токена — светить нечего.
    return {"WWW-Authenticate": 'Bearer realm="zapret-gui-mcp"'}


# ───────────────────────────── мелочи ───────────────────────────────

def _gui_auth_ok(auth_pair) -> bool:
    from core.config_manager import get_config_manager
    cfg = get_config_manager()
    if not cfg.get("gui", "auth_enabled", default=False):
        return False
    password = cfg.get("gui", "auth_password", default="") or ""
    if not password:
        return False
    user = cfg.get("gui", "auth_user", default="admin") or "admin"
    try:
        given_user, given_pass = auth_pair
    except (TypeError, ValueError):
        return False
    return (secret_equal(given_user, user)
            and secret_equal(given_pass, password))


def _deep_merge(base: dict, override: dict):
    for key, value in override.items():
        if (key in base and isinstance(base[key], dict)
                and isinstance(value, dict)):
            _deep_merge(base[key], value)
        else:
            base[key] = value


def _int(value, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _safe(text: str, limit: int = 120) -> str:
    """Обрезать внешнюю строку перед вставкой в текст ответа.

    Origin приходит из внешнего мира: длинный или многострочный не
    должен растекаться по телу ответа и логу.
    """
    text = (text or "").replace("\n", " ").replace("\r", " ")
    return text if len(text) <= limit else text[:limit - 1] + "…"
