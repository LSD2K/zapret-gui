# core/lua_capture.py
"""
Lua-дамп движка: ``--writable`` + ``zapret-pcap.lua``.

Зачем, если есть tcpdump (``core/traffic_capture.py``). Снифер стоит
**после** движка и видит, что ушло в сеть. Но «в дампе ничего нет» у
него значит две совершенно разные вещи: пакеты не дошли до nfqws2
(правила NFQUEUE, ``--filter-*``, hostlist профиля) или дошли, а
десинк не сделал с ними ничего заметного. Снаружи их не различить.

Движок умеет писать pcap сам: функция ``pcap`` из ``zapret-pcap.lua``
кладёт в файл пакет, который профиль получил из очереди, — ровно то,
что увидел бы первый приём стратегии. Два дампа рядом и дают ответ:

* lua-дамп пуст → пакеты не дошли до стратегии, чинить надо фильтр, а
  не приём;
* lua-дамп полон, а tcpdump показывает ClientHello неразрезанным →
  приём получил пакет и не справился.

Что здесь есть:

* :func:`writable_args` — ``--writable=<каталог>``, без которого
  ``pcap`` с относительным именем файла пишет в текущий каталог
  процесса (под ``--user nobody`` это отказ в записи и оборванная
  обработка пакета). Зовёт ``NFQWSManager.compose_command`` — то есть
  флаг получает любая стратегия с ``pcap``, а не только эксперимент.
  Свой ``--writable`` стратегии не положен: nfqws2 делает ``chown``
  названного каталога пользователю движка от root, и на существующем
  тоже (``make_writable_dir``, nfq2/darkmagic.c), — ``--writable=/etc``
  отдал бы ``/etc`` пользователю ``nobody``. Сборщик такой аргумент
  вырезает (``strategy_lint.ENGINE_OWNED_OPTIONS``) и ставит наш;
* :func:`inject` — вставить ``--lua-desync=pcap:file=…`` в каждый
  профиль argv (чистая функция, без I/O);
* :func:`collect` — прочитать дампы (:mod:`core.pcap_reader`), свернуть
  в сводку той же формы, что у tcpdump, и удалить файлы.

## Где встаёт ``pcap`` и почему именно там

Перед ПЕРВЫМ ``--lua-desync`` профиля. ``--payload``/``--out-range``/
``--in-range`` действуют на все следующие за ними инстансы, и ставить
``pcap`` раньше них со своими диапазонами нельзя: его диапазоны
унаследовали бы приёмы стратегии, и мерили бы мы уже не её. Встав
перед первым приёмом, ``pcap`` получает ровно то окно, что и приём, —
и ничего в стратегии не меняет.

Записывает он ``raw_packet(ctx)`` — пакет, каким его отдала очередь, а
не каким его сделал десинк: изменённое приёмом уходит ``rawsend``'ом
мимо инстансов. Поэтому lua-дамп — это «что движок ПОЛУЧИЛ», а «что
отправил» по-прежнему видно только tcpdump'ом.

## Рамки

Каталог — во временной ФС (``/tmp`` на роутере — tmpfs): дамп нужен на
минуту, и писать его на флеш незачем. Объём ограничен тем, что вообще
доходит до очереди (``connbytes`` в правилах firewall — первые пакеты
соединения), а читаем мы не больше :data:`MAX_FILE_BYTES` с файла.
Файлы удаляются сразу после разбора.
"""

import os
import re
import tempfile

from core.log_buffer import log


# Имя функции записи из zapret-pcap.lua и сам скрипт.
PCAP_FUNC = "pcap"
PCAP_LUA_FILE = "zapret-pcap.lua"

# Подкаталог во временной ФС, который отдаётся движку через --writable.
WRITABLE_DIR_NAME = "zapret-gui-writable"

# Больше этого с одного файла не читаем: дамп, выросший сверх плана, не
# должен съесть память роутера на разборе.
MAX_FILE_BYTES = 2 * 1024 * 1024

# Сколько пакетов разбираем с одного файла.
MAX_PACKETS = 1000

# ``--lua-desync=<имя>`` — имя функции инстанса.
_DESYNC_RE = re.compile(r"^--lua-desync=([A-Za-z0-9_]+)")

# Что может стоять в имени файла дампа. Аргументы lua-инстанса
# разделяются двоеточием, пробел рвёт argv — оба запрещены.
_TAG_RE = re.compile(r"[^A-Za-z0-9_\-]+")


def writable_dir() -> str:
    """Каталог, который движок получает через ``--writable``."""
    return os.path.join(tempfile.gettempdir(), WRITABLE_DIR_NAME)


def uses_pcap(argv) -> bool:
    """Есть ли в argv инстанс ``pcap``."""
    for arg in argv or []:
        match = _DESYNC_RE.match(str(arg))
        if match and match.group(1) == PCAP_FUNC:
            return True
    return False


def has_writable(argv) -> bool:
    """Задан ли каталог записи явно (в т.ч. старым именем до 1.0)."""
    for arg in argv or []:
        text = str(arg)
        for flag in ("--writable", "--writeable"):
            if text == flag or text.startswith(flag + "="):
                return True
    return False


def writable_args(argv, directory: str = "") -> list:
    """``["--writable=<каталог>"]``, если стратегии он нужен, иначе ``[]``.

    Нужен он ровно тогда, когда в argv есть ``pcap``. ``has_writable``
    здесь — страховка для argv, собранного в обход сборщика: сам
    ``compose_command`` чужой ``--writable`` вырезает ДО этого вызова.
    """
    if not uses_pcap(argv) or has_writable(argv):
        return []
    return ["--writable=%s" % (directory or writable_dir())]


def prepare_dir(directory: str = "", user: str = "") -> str:
    """Создать каталог записи и отдать его пользователю движка.

    nfqws2 сбрасывает права до ``--user`` (обычно ``nobody``), и
    ``--writable`` он делает ``chown`` сам. Готовим каталог заранее по
    другой причине: ``/tmp`` открыт на запись всем, и на месте каталога
    может заранее лежать **симлинк** (``/tmp/zapret-gui-writable →
    /etc``) — движок сделал бы ``chown`` по нему от root. Поэтому
    ссылку убираем и создаём настоящий каталог. Не вышло — не беда:
    запись упадёт внутри lua, это будет видно в логе движка, а старт
    стратегии не сорвётся.
    """
    directory = directory or writable_dir()
    try:
        if os.path.islink(directory):
            os.remove(directory)
        os.makedirs(directory, mode=0o755, exist_ok=True)
    except OSError as e:
        log.debug("Каталог --writable не создан: %s" % e, source="nfqws")
        return directory
    if user and hasattr(os, "chown"):
        try:
            import pwd
            entry = pwd.getpwnam(user)
            os.chown(directory, entry.pw_uid, entry.pw_gid)
        except (KeyError, ImportError, OSError) as e:
            log.debug("Каталог --writable не отдан %s: %s" % (user, e),
                      source="nfqws")
    return directory


def safe_tag(text: str, default: str = "cap") -> str:
    """Кусок имени файла из метки варианта: только безопасные символы."""
    tag = _TAG_RE.sub("_", str(text or "")).strip("_")[:24]
    return tag or default


def inject(argv, tag: str) -> tuple:
    """Вставить ``pcap`` перед первым приёмом каждого профиля.

    Возвращает ``(новый argv, [{profile, file}])``. Профиль без
    ``--lua-desync`` пропускается: писать в нём нечего — пакеты он
    пропускает мимо lua. Инстанс ``pcap``, уже стоящий в стратегии,
    не трогаем и второй не добавляем: модель его поставила сама.
    """
    argv = [str(a) for a in (argv or [])]
    tag = safe_tag(tag)
    out, files = [], []
    profile = 1
    placed = False
    for arg in argv:
        if arg == "--new" or arg.startswith("--new="):
            profile += 1
            placed = False
            out.append(arg)
            continue
        match = _DESYNC_RE.match(arg)
        if match and not placed:
            placed = True
            if match.group(1) != PCAP_FUNC:
                name = "%s-p%d.pcap" % (tag, profile)
                out.append("--lua-desync=%s:file=%s" % (PCAP_FUNC, name))
                files.append({"profile": profile, "file": name})
        out.append(arg)
    return out, files


def clear(files, directory: str = "") -> None:
    """Убрать дампы прошлого прогона с теми же именами."""
    directory = directory or writable_dir()
    for item in files or []:
        _remove(os.path.join(directory, item["file"]))


def collect(files, directory: str = "") -> dict:
    """Прочитать дампы, свернуть в сводку и удалить файлы.

    Сводка — той же формы, что у tcpdump (``pcap_reader.summarize``),
    плюс разбивка по профилям: «первый профиль видел трафик, второй
    нет» — это ответ на вопрос, какой фильтр не сработал.
    """
    from core import pcap_reader

    directory = directory or writable_dir()
    items, profiles, errors = [], [], []
    for item in files or []:
        path = os.path.join(directory, item["file"])
        row = {"profile": item["profile"], "packets": 0}
        try:
            if not os.path.isfile(path):
                # Файла нет — pcap не вызывался ни разу: ни один пакет
                # не дошёл до этого профиля. Это результат, а не сбой.
                profiles.append(row)
                continue
            if os.path.getsize(path) > MAX_FILE_BYTES:
                row["error"] = "файл больше %d байт — не разбирали" \
                               % MAX_FILE_BYTES
                errors.append(row["error"])
                profiles.append(row)
                continue
            report = pcap_reader.read_file(path, limit=MAX_PACKETS)
            packets = report.get("packets") or []
            row["packets"] = len(packets)
            row["total"] = report.get("total", len(packets))
            items.extend(packets)
        except (OSError, pcap_reader.PcapError) as e:
            row["error"] = str(e)[:200]
            errors.append(row["error"])
        finally:
            _remove(path)
        profiles.append(row)

    out = pcap_reader.summarize(items)
    out["measured"] = bool(files) and not errors
    out["profiles"] = profiles
    out["sni"] = out["sni"][:5]
    out["hosts"] = out["hosts"][:5]
    if errors:
        out["error"] = "; ".join(errors[:3])
    return out


def _remove(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass
