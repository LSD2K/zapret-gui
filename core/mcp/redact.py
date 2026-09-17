# core/mcp/redact.py
"""
Вырезание секретов из ответа инструмента.

Применяется в **одной** точке — при сериализации результата
``tools/call`` (``core/mcp/registry.tool_result``). Не в каждом
инструменте: инструментов будет несколько десятков, и «забыли
замаскировать» в одном из них — это утёкший токен, а не мелкая
недоработка.

Как маскируем — **по ключам, а не по значениям**. Поиск «похожего на
секрет» в строках выглядит надёжнее, но в наших ответах живут домены,
аргументы стратегий, lua-выражения и base64-пейлоады: эвристика по
значению съела бы рабочие данные модели, а это тихая порча ответа. Нет
ключа — нет маски.

Что режется:

* ключ подходит под :data:`SECRET_KEY_RE` (``pass|secret|token|key|
  licen|uuid|auth|credential``) — строковое значение заменяется на
  ``***``, словарь/список — целиком;
* булевы значения и числа под такими ключами **не трогаем**:
  ``gui.auth_enabled=true`` секретом не является, а ответ, где половина
  флагов превратилась в ``***``, модель прочитать не может;
* ключ похож на URL подписки (:data:`URL_KEY_RE`) — от адреса остаётся
  ``https://host/…``: хост нужен для диагностики, путь и query — это и
  есть подписка. Адрес не по HTTP (``tg://proxy?…secret=``) проходит
  текстовую чистку: схема другая, а секрет тот же;
* строки под ключами из :data:`TEXT_KEYS` (``stdout``, ``stderr``,
  ``message``, ``error``…) дополнительно прогоняются через
  :func:`redact_text` — туда секрет попадает из внешнего мира, а не из
  нашего конфига.

Чего НЕ режем: домены, hostlist'ы, имена файлов, аргументы nfqws2 — это
рабочие данные, ради которых модель сюда и пришла.

:func:`redact_text` вынесена отдельно: ею пользуется S12 (вывод
shell-команд) — там ключей нет, есть сырой текст.
"""

import re


MASK = "***"

# Ключи, значение которых наружу не уезжает никогда.
SECRET_KEY_RE = re.compile(
    r"(?i)pass|secret|token|key|licen|uuid|auth|credential")

# Ключи, в которых лежит URL подписки: оставляем схему и хост.
URL_KEY_RE = re.compile(r"(?i)subscri|(?:^|_)(?:url|link|endpoint)s?$")

# Ключи, под которыми лежит текст из внешнего мира: к нему применяется
# ещё и текстовая чистка (``token=…`` внутри строки).
TEXT_KEYS = frozenset((
    "stdout", "stderr", "output", "command", "cmd", "log", "log_tail",
    "tail", "message", "line", "lines",
    # Сюда приезжает текст ЧУЖИХ программ: последняя строка лога движка
    # (`last_error` в tunnels_status), сообщение упавшего вызова,
    # cmdline постороннего процесса в находке диагностики. Секрет в
    # такой строке — обычное дело (sing-box пишет URL подписки, usque —
    # токен), а ни под одно «секретное» имя ключа она не подходит.
    "error", "last_error", "detail", "diagnostic",
))

# Предохранитель от самодельных циклических структур и слишком глубоких
# ответов: глубже 24 уровней у нас не бывает ничего осмысленного.
MAX_DEPTH = 24

# Правила текстовой чистки: (шаблон, номер группы, которую маскируем).
# Условие на шаблон: склейка ВСЕХ его групп должна давать полное
# совпадение — иначе замена потеряет кусок строки.
_TEXT_RULES = (
    # Authorization: Bearer <...> / Basic <...>
    (re.compile(r"(?i)(authorization\s*:\s*(?:bearer|basic)?\s*)(\S+)"), 2),
    # token = ..., private_key: ..., password=...
    (re.compile(r"(?i)((?:api[_-]?key|private[_-]?key|public[_-]?key|"
                r"preshared[_-]?key|secret|token|password|passwd|pwd|"
                r"licen[sc]e|credential)s?\s*[:=]\s*)(\"?)"
                r"([^\s\"',;&]+)"), 3),
    # ?token=... в адресе подписки
    (re.compile(r"(?i)([?&](?:token|key|secret|auth|password|"
                r"access[_-]?key)=)([^&\s]+)"), 2),
    # https://user:password@host
    (re.compile(r"(?i)(https?://[^\s:/@]+:)([^\s@/]+)(@)"), 2),
)


def redact(value, _depth: int = 0):
    """Вернуть копию ``value`` без секретов.

    Исходная структура не меняется: инструменты отдают куски живого
    конфига, и порча их по дороге обошлась бы дороже утечки.
    """
    if _depth > MAX_DEPTH:
        return value

    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            name = str(key)
            if _is_secret_key(name):
                out[key] = _mask_value(item)
            elif isinstance(item, str) and URL_KEY_RE.search(name):
                out[key] = shorten_url(item)
            elif isinstance(item, str) and name.lower() in TEXT_KEYS:
                out[key] = redact_text(item)
            else:
                out[key] = redact(item, _depth + 1)
        return out

    if isinstance(value, (list, tuple)):
        return [redact(item, _depth + 1) for item in value]

    return value


def redact_text(text: str) -> str:
    """Замаскировать секреты в сыром тексте (вывод команд, логи).

    Работает по словам-маркерам (``token=``, ``Authorization:``), а не
    по виду значения: иначе под маску попадут домены и аргументы
    стратегий, ради которых текст и запрашивали.
    """
    if not isinstance(text, str) or not text:
        return text
    for pattern, index in _TEXT_RULES:
        text = pattern.sub(lambda m, i=index: _join_masked(m, i), text)
    return text


def shorten_url(value: str) -> str:
    """Оставить от адреса схему и хост: ``https://host/…``.

    Подписка — это путь и query; хост оставляем, потому что по нему
    видно, куда ходит GUI, и это сама по себе полезная диагностика.
    """
    if not isinstance(value, str):
        return value
    text = value.strip()
    lowered = text.lower()
    if not (lowered.startswith("http://") or lowered.startswith("https://")):
        # Не HTTP — но и не обязательно безобидно: `tg://proxy?…secret=`
        # это готовый доступ к прокси, а «ключ похож на URL» про схему
        # ничего не обещает. Отдаём такой адрес через текстовую чистку.
        return redact_text(value)
    scheme, _, rest = text.partition("://")
    host = rest.split("/", 1)[0].split("?", 1)[0]
    if "@" in host:                       # user:pass@host
        host = host.rsplit("@", 1)[1]
    if len(rest) <= len(host):
        return "%s://%s" % (scheme, host)
    return "%s://%s/…" % (scheme, host)


def is_secret_key(name: str) -> bool:
    """Публичная проверка: считается ли такой ключ секретным.

    Нужна модели путей (``core/mcp/permissions.py``): секретное поле не
    только не отдаётся наружу, но и не принимается на запись.
    """
    return _is_secret_key(str(name))


# ───────────────────────────── частности ────────────────────────────

def _is_secret_key(name: str) -> bool:
    return bool(SECRET_KEY_RE.search(name))


def _mask_value(item):
    """Чем заменить значение секретного ключа.

    ``bool`` и числа пропускаем: флаг ``auth_enabled`` секретом не
    является, а ответ из одних ``***`` нечитаем. Всё остальное —
    строки, словари, списки — заменяется целиком.
    """
    if isinstance(item, bool) or item is None:
        return item
    if isinstance(item, (int, float)):
        return item
    if isinstance(item, str):
        return MASK if item else item
    return MASK


def _join_masked(match, index: int) -> str:
    """Склеить группы совпадения, заменив ``index``-ю на маску."""
    parts = []
    for number, group in enumerate(match.groups(), 1):
        if group is None:
            continue
        parts.append(MASK if number == index else group)
    return "".join(parts)
