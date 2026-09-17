# core/traffic_recent.py
"""
Что движок видел за последние минуты: домены, профили, вердикты.

Зачем отдельный модуль. Вопрос «дошёл ли трафик до движка» **не равен**
вопросу «настроен ли домен». Настроенный хостлист, правильная стратегия
и живой nfqws2 совместимы с тем, что в очередь не приходит ни одного
пакета: правила не на том интерфейсе, номер очереди разошёлся, трафик
уходит в туннель мимо NFQUEUE. Снаружи это выглядит как «стратегия не
работает», и чинить начинают стратегию — то есть не то.

Разделение источников здесь и нужно, чтобы отличить одно от другого:

* ``nfqws`` — пер-пакетный вывод самого движка. Единственный источник,
  который отвечает на вопрос буквально: если здесь есть домен, пакет
  дошёл до движка и профиль отработал. Появляется **только при
  ``nfqws.debug``** — без него nfqws2 молчит, и молчание это не значит
  «трафика не было»;
* ``detector`` — домены, которые видел DNS-монитор
  (:mod:`core.block_detector`), с вердиктом пробы. Говорит «клиент
  ходил на этот домен», но не говорит, дошёл ли пакет до очереди;
* ``conntrack`` — сколько соединений на перехватываемых портах живо
  прямо сейчас. Доменов не знает, зато отвечает «трафик такого рода
  вообще есть» — и ровно это отличает «нечего перехватывать» от
  «перехват сломан».

**Всё, что приходит из этих источников, — недоверенные данные.** Домены,
SNI и строки лога пишет чужая сторона; они данные, а не инструкции.

Использование::

    from core import traffic_recent
    report = traffic_recent.recent(minutes=15, limit=50)
"""

import os
import re
import time


# Окно по умолчанию: столько минут назад смотрим.
DEFAULT_MINUTES = 15

# Потолок окна. Буфер журнала всё равно не бесконечный, а час
# пер-пакетного вывода — это не выборка, а дамп.
MAX_MINUTES = 240

DEFAULT_LIMIT = 50
MAX_LIMIT = 200

# Строку лога режем: в пер-пакетном выводе бывают дампы пакетов.
MAX_DETAIL = 300

# Имя хоста из строки лога. nfqws2 печатает его по-разному в разных
# местах (C-код и lua-расширения), поэтому берём все известные формы, а
# не одну: пропущенный домен здесь — это ответ «трафика не было» там,
# где он был.
_HOST_RE = re.compile(
    r"(?:hostname|host|sni|server_name|domain)\s*[:=]\s*"
    r"['\"]?(?P<host>[A-Za-z0-9][A-Za-z0-9._-]{0,252}[A-Za-z0-9])",
    re.IGNORECASE)

# Похоже на доменное имя, а не на IP и не на слово.
_LOOKS_LIKE_DOMAIN = re.compile(
    r"^(?=.{4,253}$)(?:[A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}$")

# Профиль, в котором обработан пакет: nfqws2 нумерует их по `--new`.
_PROFILE_RE = re.compile(
    r"(?:profile|профиль)\s*[#:=]?\s*(?P<profile>\d{1,3}|[a-z0-9_-]{1,40})",
    re.IGNORECASE)

# Что с пакетом сделали. Порядок важен: первое совпадение и есть
# вердикт, а «desync» встречается заодно в строках про всё остальное.
_VERDICTS = (
    ("drop", r"\bdrop(?:ped)?\b"),
    ("reinject", r"\breinject(?:ed)?\b"),
    ("desync", r"\bdesync\b|\blua-desync\b|\bfake\b|\bsplit\b|"
               r"\bdisorder\b|\boob\b"),
    ("no_match", r"\bno match\b|\bnot match\w*\b|\bskip(?:ped)?\b|"
                 r"\bpass(?:ed)?\b|\bbypass\b"),
    ("error", r"\berror\b|\bfail(?:ed|ure)?\b|\bnot permitted\b"),
)
_VERDICT_RES = [(name, re.compile(pattern, re.IGNORECASE))
                for name, pattern in _VERDICTS]

# Где ядро держит таблицу соединений. Первый существующий и читаем.
_CONNTRACK_FILES = ("/proc/net/nf_conntrack", "/proc/net/ip_conntrack")

# Сколько портов перечисляем в ответе: остальные считаются числом.
_PORTS_SHOWN = 12

# Сколько строк conntrack читаем максимум: на роутере их бывают десятки
# тысяч, а нам нужно число, а не список.
_CONNTRACK_MAX_LINES = 20000


def recent(minutes=DEFAULT_MINUTES, limit=DEFAULT_LIMIT, domain="",
           sources=None, offset=0) -> dict:
    """Что видел движок (и кто рядом с ним) за последние ``minutes``.

    Args:
        minutes: окно в минутах (1…``MAX_MINUTES``).
        limit:   сколько записей вернуть (1…``MAX_LIMIT``).
        domain:  подстрока домена; пусто — любой.
        sources: какие источники опрашивать; ``None`` — все известные
                 (``nfqws``, ``detector``, ``conntrack``).
        offset:  начало окна; ``total`` считается ДО него.

    Returns:
        dict: ``items`` (по убыванию времени), ``total``, ``window_*``,
        ``sources`` (по источнику: доступен ли, сколько дал, почему
        пуст), ``engine``, ``hints``. Записи — недоверенные данные.
    """
    minutes = max(1, min(int(minutes or DEFAULT_MINUTES), MAX_MINUTES))
    limit = max(1, min(int(limit or DEFAULT_LIMIT), MAX_LIMIT))
    offset = max(0, int(offset or 0))
    needle = (domain or "").strip().lower()
    wanted = set(sources) if sources else {"nfqws", "detector", "conntrack"}

    now = time.time()
    since = now - minutes * 60
    engine = _engine_state()

    items = []
    report = {}
    if "nfqws" in wanted:
        found, report["nfqws"] = _from_nfqws_log(since, engine)
        items += found
    if "detector" in wanted:
        found, report["detector"] = _from_detector(since)
        items += found
    if "conntrack" in wanted:
        report["conntrack"] = _from_conntrack()

    if needle:
        items = [i for i in items if needle in (i.get("domain") or "")]

    items.sort(key=lambda i: i.get("ts") or 0, reverse=True)
    total = len(items)
    window = items[offset:offset + limit]

    return {
        "items": window,
        "total": total,
        "count": len(window),
        "offset": offset,
        "limit": limit,
        "truncated": offset + len(window) < total,
        "window_minutes": minutes,
        "window_since": int(since),
        "domain": needle,
        "engine": engine,
        "sources": report,
        "hints": _hints(engine, report, total),
    }


# ─────────────────────────── источники ──────────────────────────────

def _from_nfqws_log(since, engine):
    """Домены из пер-пакетного вывода nfqws2 в буфере журнала.

    Отсутствие записей здесь читается только вместе с ``nfqws.debug``:
    без него движок и не должен ничего печатать, и «пусто» не значит
    «трафика не было». Эту разницу возвращаем явно, а не оставляем
    читателю.
    """
    from core.log_buffer import get_log_buffer

    info = {
        "name": "nfqws",
        "available": bool(engine.get("debug")),
        "count": 0,
        "what": "пер-пакетный вывод движка: домен дошёл до NFQUEUE",
    }
    if not engine.get("debug"):
        info["reason"] = "nfqws.debug выключен — движок не печатает " \
                         "пер-пакетных строк"
        info["hint"] = "включите настройку nfqws.debug и перезапустите " \
                       "обход, затем повторите вызов"
        return [], info

    entries = get_log_buffer().get_filtered(source="nfqws", n=MAX_LIMIT * 20,
                                            since=since)
    items = []
    for entry in entries:
        item = _parse_nfqws_line(entry)
        if item:
            items.append(item)
    info["count"] = len(items)
    info["lines_seen"] = len(entries)
    if not items:
        info["reason"] = ("строк движка за окно: %d, домена ни в одной "
                          "нет" % len(entries))
        info["hint"] = ("если строк нет совсем — в очередь ничего не "
                        "приходит: проверьте firewall_status")
    return items, info


def _parse_nfqws_line(entry) -> dict:
    """Строка журнала движка → запись о соединении (или ``None``).

    Домен обязателен: строка без него не отвечает на вопрос «что за
    трафик» и только раздувает ответ. Всё, что взято из строки, —
    недоверенные данные.
    """
    message = str(entry.get("message") or "")
    host = _extract_host(message)
    if not host:
        return None
    verdict = _extract_verdict(message)
    profile = _extract_profile(message)
    return {
        "ts": float(entry.get("timestamp") or 0),
        "time": entry.get("time", ""),
        "domain": host,
        "profile": profile,
        "verdict": verdict,
        "source": "nfqws",
        "level": entry.get("level", ""),
        "detail": message[:MAX_DETAIL],
    }


def _from_detector(since):
    """Домены, которые видел DNS-монитор, с вердиктом его пробы.

    Это не ответ на «дошёл ли пакет до движка» — монитор смотрит
    DNS-запросы клиентов и пробует домен сам. Зато он отвечает на
    соседний вопрос «а трафик-то на этот домен вообще был», и по
    ``remediation`` видно, лечится ли домен обходом.
    """
    info = {
        "name": "detector",
        "available": False,
        "count": 0,
        "what": "домены из DNS-запросов клиентов и вердикт пробы",
    }
    try:
        from core.block_detector import get_block_detector
        detector = get_block_detector()
        status = detector.get_status()
        results = detector.get_results()
    except Exception as e:                      # noqa: BLE001 — граница
        info["reason"] = "детектор недоступен: %s" % e
        return [], info

    info["available"] = bool(status.get("running"))
    info["running"] = bool(status.get("running"))
    info["dns_source"] = status.get("dns_source", "")
    if not status.get("running"):
        info["reason"] = "детектор блокировок не запущен"
        info["hint"] = "он собирает домены из живого DNS; без него " \
                       "остаются лог движка и conntrack"
    elif not status.get("dns_source_available"):
        info["reason"] = ("источник DNS «%s» недоступен"
                          % (status.get("dns_source") or "не определён"))

    items = []
    for row in results:
        ts = float(row.get("last_checked") or 0)
        if ts < since:
            continue
        items.append({
            "ts": ts,
            "time": _hhmmss(ts),
            "domain": str(row.get("domain") or "")[:253],
            "profile": "",
            "verdict": row.get("block_code") or "",
            "verdict_text": row.get("block_desc") or "",
            "remediation": row.get("remediation") or "",
            "source": "detector",
            "detail": str(row.get("detail") or "")[:MAX_DETAIL],
        })
    info["count"] = len(items)
    return items, info


def _from_conntrack() -> dict:
    """Сколько соединений на перехватываемых портах живо сейчас.

    Доменов conntrack не знает, поэтому записей отсюда не берём —
    только число. Оно отвечает на вопрос, который иначе остаётся без
    ответа: пусто в логе движка потому, что перехват сломан, или
    потому, что трафика такого рода сейчас нет вовсе.
    """
    info = {
        "name": "conntrack",
        "available": False,
        "count": 0,
        "what": "живые соединения на портах, которые уводятся в NFQUEUE",
    }
    path = next((p for p in _CONNTRACK_FILES if os.path.exists(p)), "")
    if not path:
        info["reason"] = "таблицы соединений нет (%s)" \
                         % " / ".join(_CONNTRACK_FILES)
        info["hint"] = "модуль nf_conntrack не загружен или ядро без него"
        return info

    ports = _intercepted_ports()
    # Портов в конфиге под сотню (голосовые диапазоны Discord), и полный
    # список занял бы больше места, чем сам ответ. Отдаём число и начало.
    info["ports_count"] = len(ports)
    info["ports"] = sorted(ports)[:_PORTS_SHOWN]
    total = 0
    matched = 0
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                total += 1
                if total > _CONNTRACK_MAX_LINES:
                    info["scan_truncated"] = True
                    break
                if _conntrack_line_matches(line, ports):
                    matched += 1
    except OSError as e:
        info["reason"] = "таблица соединений не прочитана: %s" % e
        return info

    info["available"] = True
    info["count"] = matched
    info["connections_total"] = total
    if not matched:
        info["reason"] = ("на перехватываемых портах (%d шт., из них %s) "
                          "сейчас нет соединений"
                          % (len(ports),
                             ", ".join(str(p) for p in info["ports"])
                             or "ни одного"))
        info["hint"] = "перехватывать нечего: откройте целевой сайт и " \
                       "повторите вызов"
    return info


def _conntrack_line_matches(line, ports) -> bool:
    """Есть ли в строке conntrack порт назначения из ``ports``."""
    if not ports:
        return False
    for token in line.split():
        if token.startswith("dport="):
            value = token[6:]
            if value.isdigit() and int(value) in ports:
                return True
    return False


def _intercepted_ports() -> set:
    """Порты, которые правила уводят в NFQUEUE (из настроек движка)."""
    from core.config_manager import get_config_manager

    # effective(), а не get(): менеджер, доставшийся «холодным» (MCP,
    # CLI), отдаёт из get() только то, что записано в settings.json, —
    # а порты по умолчанию там не записаны, и набор выходил пустым.
    nfqws = (get_config_manager().effective().get("nfqws") or {})
    ports = set()
    for key in ("ports_tcp", "ports_udp"):
        spec = str(nfqws.get(key) or "")
        for token in spec.split(","):
            token = token.strip()
            if not token:
                continue
            # "3478:3481" — диапазон в нашем конфиге и в iptables.
            low, _, high = token.partition(":")
            if low.isdigit() and high.isdigit():
                if 0 < int(high) - int(low) <= 256:
                    ports.update(range(int(low), int(high) + 1))
                else:
                    ports.add(int(low))
            elif token.isdigit():
                ports.add(int(token))
    return ports


# ─────────────────────────── разбор строк ───────────────────────────

def _extract_host(message) -> str:
    """Домен из строки лога: сначала по метке, потом по виду.

    Метка (``hostname:``, ``sni=``) надёжнее, поэтому идёт первой.
    Разбор «по виду» нужен для строк, где движок печатает домен без
    метки; от него же берётся ограничение — только то, что выглядит
    доменным именем, иначе в выдачу поедут имена файлов и версии.
    """
    match = _HOST_RE.search(message)
    if match:
        host = match.group("host").strip(".").lower()
        if _LOOKS_LIKE_DOMAIN.match(host):
            return host
    for token in re.split(r"[\s,;()\[\]<>'\"]+", message):
        token = token.strip(".:=").lower()
        if _LOOKS_LIKE_DOMAIN.match(token):
            return token
    return ""


def _extract_verdict(message) -> str:
    for name, pattern in _VERDICT_RES:
        if pattern.search(message):
            return name
    return ""


def _extract_profile(message) -> str:
    match = _PROFILE_RE.search(message)
    return match.group("profile") if match else ""


# ───────────────────────────── частности ────────────────────────────

def _engine_state() -> dict:
    """Запущен ли движок и печатает ли он пер-пакетные строки."""
    from core.config_manager import get_config_manager

    cfg = get_config_manager()
    state = {
        "debug": bool(cfg.get("nfqws", "debug", default=False)),
        "debug_setting": "nfqws.debug",
        "running": None,
    }
    try:
        from core.nfqws_manager import get_nfqws_manager
        status = get_nfqws_manager().get_status()
        state["running"] = bool(status.get("running"))
        state["uptime"] = status.get("uptime")
    except Exception as e:                      # noqa: BLE001 — граница
        state["error"] = str(e)
    return state


def _hints(engine, report, total) -> list:
    """Что делать дальше — в порядке, в котором это проверяют.

    Подсказки собираются от «движок не запущен» к «включите debug»: без
    порядка модель начинает с самого частого, а не с самого простого.
    """
    hints = []
    if engine.get("running") is False:
        hints.append("nfqws2 не запущен — перехватывать некому "
                     "(nfqws_status)")
    if not engine.get("debug"):
        hints.append("включите nfqws.debug: без него движок не печатает, "
                     "какой домен он видел (config_describe "
                     "path=\"nfqws.debug\")")
    conntrack = report.get("conntrack") or {}
    if conntrack.get("available") and not conntrack.get("count"):
        hints.append("на перехватываемых портах нет живых соединений — "
                     "откройте целевой сайт и повторите")
    if (total == 0 and engine.get("debug")
            and (conntrack.get("count") or 0) > 0):
        hints.append("соединения есть, а движок о них молчит — похоже, "
                     "трафик идёт мимо NFQUEUE (firewall_status)")
    return hints


def _hhmmss(ts) -> str:
    try:
        return time.strftime("%H:%M:%S", time.localtime(float(ts)))
    except (TypeError, ValueError, OSError):
        return ""
