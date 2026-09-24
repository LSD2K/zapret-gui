# core/agh_routes.py
"""
Маршруты через AdGuard Home: «какие домены в какой туннель».

Одно место правды, секция ``agh_routes`` в settings.json: правила
«списки доменов → outbound sing-box». Из них раскладываются:

  (а) route-правила sing-box ``{"domain_suffix": [...], "outbound": tag}``
      в выбранный конфиг: сразу после ``hijack-dns`` (нет его, после
      ``sniff``, нет и его, в начало) и до ``{"inbound": ["tun-in"], ...}``.
      Сам конфиг собирает FakeIP-сборщик в режиме внешнего фронт-DNS,
      этот модуль его только дополняет. Подсети правила (``subnets``, для
      приложений, ходящих по IP без DNS) ставятся рядом отдельным правилом
      ``{"ip_cidr": [...], "outbound": tag}``, в AdGuard они не попадают;
  (б) upstream-строки AdGuard Home ``[/a.com/b.org/]127.0.0.1:1053`` -
      глобально (``/control/dns_config``) или поклиентно
      (``/control/clients/*``), чтобы AdGuard отдавал домены из правил в
      dns-in sing-box (fakeip), а остальное, своим обычным upstream'ам.

Что считается «нашим»:
  * в AdGuard, строки, заканчивающиеся на ``]<dns_target>`` (и на цели
    прошлых применений из ``_applied.agh.targets``: смена цели не должна
    оставлять хвостов);
  * в sing-box, правила из ``_applied.singbox.rules``. Пометить их полем
    нельзя (sing-box отвергает неизвестные поля), поэтому снимаем по
    точному совпадению.

Все HTTP-вызовы к AdGuard идут через одну обёртку :func:`_http_request`
(urllib, мимо прокси окружения), тесты мокают именно её.

Схема сети и постановка, docs/gw/spec-b3-agh-routes.md.
"""

import base64
import copy
import http.client
import ipaddress
import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from core.log_buffer import log


SOURCE = "agh_routes"

# Таймаут одного запроса к AdGuard Home, секунды.
HTTP_TIMEOUT = 10

# Доменов в одной upstream-строке AdGuard. Длинные строки AdGuard
# принимает, но в его интерфейсе их не прочитать.
LINE_CHUNK = 40

# Маска пароля в ответах API (как у gui.auth_password в /api/config).
MASK = "***"

# Имя конфига sing-box, то же правило, что у singbox_manager.
_CONFIG_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,32}$")
_RULE_ID_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,40}$")

# Домен-суффикс после нормализации: метки a-z0-9- через точку; `_`
# допустим только первым символом метки (_dmarc, _acme-challenge).
_LABEL = r"_?(?!-)[a-z0-9-]+(?<!-)"
_DOMAIN_RE = re.compile(r"^%s(?:\.%s)*$" % (_LABEL, _LABEL))

# Цель DNS для AdGuard: адрес upstream'а без пробелов и комментариев
# (127.0.0.1:1053, [::1]:1053, udp://127.0.0.1:1053).
_TARGET_RE = re.compile(r"^[A-Za-z0-9._:/\[\]-]+$")

_apply_lock = threading.Lock()


class AghError(Exception):
    """Ошибка обращения к AdGuard Home (сеть, авторизация, HTTP-код)."""


# ─────────────────────── нормализация ────────────────────────────────

def _to_ascii(s: str) -> str:
    """IDN → punycode (AdGuard и sing-box ждут ASCII). Не вышло, ''."""
    if s.isascii():
        return s
    try:
        return s.encode("idna").decode("ascii").lower()
    except (UnicodeError, ValueError):
        return ""


def normalize_domains(items) -> list:
    """
    Привести записи к суффиксам доменов: нижний регистр, без схемы, пути,
    ``*.``/``www.``, без IP и localhost (как
    ``singbox_config._norm_suffix_domains``). Дополнительно срезаются
    хвостовые комментарии и маркеры hostlist'ов (``^``, ведущая точка),
    IDN переводится в punycode, мусор отбрасывается. Порядок сохраняется,
    дубликаты убираются.
    """
    from core.singbox_config import _norm_suffix_domains

    pre = []
    for raw in items or []:
        s = str(raw or "").split("#", 1)[0].strip()
        if not s:
            continue
        s = s.split()[0].lstrip("^.")
        if s:
            pre.append(s)
    out, seen = [], set()
    for d in _norm_suffix_domains(pre):
        d = _to_ascii(d)
        if not d or len(d) > 253 or not _DOMAIN_RE.match(d):
            continue
        if any(len(label) > 63 for label in d.split(".")):
            continue
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def _norm_client_id(raw) -> str:
    """IP или подсеть клиента в каноническом виде (/32 → голый IP).
    Некорректное значение → ValueError."""
    s = str(raw or "").strip()
    if not s:
        raise ValueError("пустой адрес")
    if "/" in s:
        net = ipaddress.ip_network(s, strict=False)
        if net.prefixlen == net.max_prefixlen:
            return str(net.network_address)
        return str(net)
    return str(ipaddress.ip_address(s))


def _split_tokens(v) -> list:
    """
    Записи из текста textarea или списка строк. Режем построчно, в каждой
    строке срезаем комментарий ``#…`` и только потом делим по пробелам,
    запятым и точкам с запятой: иначе слова из комментария
    («example.org # мой сайт») становились бы доменами.
    """
    items = v if isinstance(v, (list, tuple)) else [v]
    tokens = []
    for item in items:
        for line in str(item or "").splitlines():
            line = line.split("#", 1)[0]
            tokens.extend(t for t in re.split(r"[\s,;]+", line) if t)
    return tokens


def _clean_subnets(tokens, name: str, warns: list) -> list:
    """Подсети правила: только IPv4, адрес без маски = /32, хост-биты
    обнуляются (149.154.167.41/20 → 149.154.160.0/20). IPv6 и мусор
    отбрасываются с предупреждением. Порядок сохраняется, без дублей."""
    out, bad, v6 = [], [], []
    for tok in tokens:
        try:
            net = ipaddress.ip_network(tok, strict=False)
        except ValueError:
            bad.append(tok)
            continue
        if net.version != 4:
            v6.append(tok)
            continue
        out.append(str(net))
    if bad:
        warns.append("правило «%s»: отброшено %d подсетей (%s)"
                     % (name, len(bad), ", ".join(bad[:5])))
    if v6:
        warns.append("правило «%s»: IPv6 не поддерживается, отброшено "
                     "(%s)" % (name, ", ".join(v6[:5])))
    return _dedup(out)


def _dedup(seq) -> list:
    seen, out = set(), []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


# ─────────────────────── строки AdGuard ──────────────────────────────

def render_agh_lines(domains, target: str) -> list:
    """
    Upstream-строки AdGuard вида ``[/a.com/b.org/]127.0.0.1:1053``, не
    больше LINE_CHUNK доменов в строке. Домены сортируются и
    дедуплицируются, одинаковый вход даёт одинаковые строки.
    """
    doms = sorted(set(d for d in (domains or []) if d))
    return ["[/%s/]%s" % ("/".join(doms[i:i + LINE_CHUNK]), target)
            for i in range(0, len(doms), LINE_CHUNK)]


def is_managed_line(line, targets) -> bool:
    """Наша ли это строка: ``[/…/]<цель>`` с одной из управляемых целей."""
    s = str(line or "").strip()
    if not s.startswith("[/"):
        return False
    return any(t and s.endswith("]" + t) for t in targets)


def line_domains(line: str) -> list:
    """Домены из строки ``[/a/b/]upstream``."""
    s = str(line or "").strip()
    if not s.startswith("[/"):
        return []
    end = s.find("/]")
    if end < 0:
        return []
    return [d for d in s[2:end].split("/") if d]


def replace_managed(lines, new_lines, targets) -> list:
    """
    Заменить наши строки новыми, остальные оставить как есть. Новые встают
    на место первой нашей строки (порядок чужих строк не меняется), а если
    наших не было, в конец.
    """
    out, inserted = [], False
    for line in lines or []:
        if is_managed_line(line, targets):
            if not inserted:
                out.extend(new_lines)
                inserted = True
            continue
        out.append(line)
    if not inserted:
        out.extend(new_lines)
    return out


# ─────────────────────── правила sing-box ────────────────────────────

def _is_tun_in_rule(rule) -> bool:
    if not isinstance(rule, dict):
        return False
    inb = rule.get("inbound")
    if isinstance(inb, str):
        return inb == "tun-in"
    return isinstance(inb, list) and "tun-in" in inb


def merge_singbox_rules(cfg: dict, old_rules, new_rules) -> dict:
    """
    Снять из ``route.rules`` ранее поставленные нами правила (точное
    совпадение с ``old_rules``) и вставить ``new_rules`` сразу после
    ``hijack-dns`` (нет его, после ``sniff``, нет и его, в начало), но
    не позже правила ``{"inbound": ["tun-in"], ...}``. cfg меняется на
    месте и возвращается. Чистая функция.
    """
    old_rules = list(old_rules or [])
    new_rules = list(new_rules or [])
    route = cfg.get("route")
    if not isinstance(route, dict):
        if not new_rules:
            return cfg
        route = cfg["route"] = {}
    rules = route.get("rules")
    if not isinstance(rules, list):
        rules = []
    kept = [r for r in rules if r not in old_rules]

    hijack = sniff = None
    for i, r in enumerate(kept):
        if isinstance(r, dict):
            if r.get("action") == "hijack-dns":
                hijack = i
            elif r.get("action") == "sniff":
                sniff = i
    if hijack is not None:
        pos = hijack + 1
    elif sniff is not None:
        pos = sniff + 1
    else:
        pos = 0
    tun = next((i for i, r in enumerate(kept) if _is_tun_in_rule(r)), None)
    if tun is not None and tun < pos:
        pos = tun
    kept[pos:pos] = [copy.deepcopy(r) for r in new_rules]
    if kept or "rules" in route:
        route["rules"] = kept
    return cfg


def outbound_tags(cfg) -> list:
    """Теги outbound'ов и endpoint'ов конфига: [{tag, type, kind}]."""
    out = []
    if not isinstance(cfg, dict):
        return out
    for kind in ("outbounds", "endpoints"):
        for ob in cfg.get(kind) or []:
            if isinstance(ob, dict) and ob.get("tag"):
                out.append({"tag": str(ob["tag"]),
                            "type": str(ob.get("type") or ""),
                            "kind": kind[:-1]})
    return out


def _dns_in_mismatch(cfg, target: str) -> str:
    """Адрес dns-in конфига, если цель DNS на него не попадает, иначе ''.
    Сравниваем порт и адрес (адрес, только если dns-in слушает не все
    интерфейсы)."""
    m = re.match(r"^(?:[a-z]+://)?\[?([^\]]*?)\]?:(\d+)$", target or "")
    if not m or not isinstance(cfg, dict):
        return ""
    host, port = m.group(1), int(m.group(2))
    for ib in cfg.get("inbounds") or []:
        if not (isinstance(ib, dict) and ib.get("tag") == "dns-in"):
            continue
        try:
            lport = int(ib.get("listen_port") or 0)
        except (TypeError, ValueError):
            return ""
        listen = str(ib.get("listen") or "")
        if not lport:
            return ""
        if lport != port or (listen not in ("", "0.0.0.0", "::")
                             and listen != host):
            return "%s:%d" % (listen or "0.0.0.0", lport)
        return ""
    return ""


# ─────────────────────── настройки ───────────────────────────────────

def _cm():
    from core.config_manager import get_config_manager
    cm = get_config_manager()
    cm.current()            # загрузить, если ещё не грузили
    return cm


def get_settings() -> dict:
    """Секция agh_routes (дефолты, накрытые сохранённым), копия."""
    from core.config_manager import DEFAULT_CONFIG
    base = copy.deepcopy(DEFAULT_CONFIG["agh_routes"])
    saved = _cm().effective().get("agh_routes")
    if isinstance(saved, dict):
        base.update(saved)
    if not isinstance(base.get("_applied"), dict):
        base["_applied"] = {}
    return base


def public_settings(s: dict = None) -> dict:
    """Настройки для API: пароль замаскирован, служебное вынесено."""
    s = copy.deepcopy(s if s is not None else get_settings())
    applied = s.pop("_applied", None) or {}
    for r in s.get("rules") or []:
        if isinstance(r, dict):
            r.setdefault("subnets", [])
    s["has_password"] = bool(s.get("agh_password"))
    if s.get("agh_password"):
        s["agh_password"] = MASK
    sb = applied.get("singbox") or {}
    agh = applied.get("agh") or {}
    s["applied"] = {
        "at": int(applied.get("at") or 0),
        "singbox_config": sb.get("config") or "",
        "singbox_rules": len(sb.get("rules") or []),
        "mode": agh.get("mode") or "",
        "clients": len(agh.get("clients") or []),
    }
    return s


def _clean_target(v) -> str:
    t = str(v or "").strip()
    if not t or not _TARGET_RE.match(t):
        raise ValueError("Цель DNS: адрес вида 127.0.0.1:1053")
    m = re.match(r"^(?:[a-z]+://)?(\[[^\]]+\]|[^:/]+):(\d+)$", t)
    if m and not (1 <= int(m.group(2)) <= 65535):
        raise ValueError("Цель DNS: порт вне диапазона 1..65535")
    return t


def _clean_url(v) -> str:
    """
    Адрес API AdGuard Home: http(s)://хост[:порт][/путь]. Логин/пароль в
    адресе, query и fragment запрещены: учётные данные живут в отдельных
    полях, а адрес уходит в логи и в интерфейс.
    """
    if not isinstance(v, str):
        raise ValueError("Адрес AdGuard Home должен быть строкой")
    raw = v.strip().rstrip("/")
    try:
        u = urllib.parse.urlsplit(raw)
        u.port          # бросает ValueError на порте вне 0..65535
    except ValueError:
        raise ValueError("Адрес AdGuard Home: некорректный порт")
    if u.scheme not in ("http", "https") or not u.hostname:
        raise ValueError("Адрес AdGuard Home: http(s)://хост:порт")
    if u.username is not None or u.password is not None or "@" in u.netloc:
        raise ValueError("Адрес AdGuard Home: логин и пароль задаются "
                         "отдельными полями, не в адресе")
    if u.query or u.fragment or "?" in raw or "#" in raw:
        raise ValueError("Адрес AdGuard Home: без ?query и #fragment")
    if re.search(r"\s", raw):
        raise ValueError("Адрес AdGuard Home: пробелы недопустимы")
    return raw


def _clean_url_quiet(v) -> str:
    try:
        return _clean_url(v)
    except ValueError:
        return str(v or "")


def _url_origin(url: str) -> str:
    """scheme://хост:порт, для логов и сообщений (без пути и прочего)."""
    try:
        u = urllib.parse.urlsplit(str(url or ""))
        host = u.hostname or "?"
        if ":" in host:
            host = "[%s]" % host
        return "%s://%s%s" % (u.scheme or "http", host,
                              ":%d" % u.port if u.port else "")
    except ValueError:
        return "?"


def _need_str(data: dict, key: str) -> str:
    v = data.get(key)
    if v is None:
        return ""
    if not isinstance(v, str):
        raise ValueError("%s: ожидается строка" % key)
    return v


def _need_bool(data: dict, key: str, where: str = "") -> bool:
    v = data.get(key)
    if not isinstance(v, bool):
        raise ValueError("%s%s: ожидается true или false"
                         % (where, key))
    return v


def _need_str_list(v, what: str, allow_text: bool = False) -> list:
    """Список строк (или, если allow_text, текст textarea)."""
    if v is None:
        return []
    if isinstance(v, str) and allow_text:
        return [v]
    if not isinstance(v, list) or not all(isinstance(x, str) for x in v):
        raise ValueError("%s: ожидается список строк" % what)
    return v


def _clean_clients(v) -> list:
    v = _need_str_list(v, "clients", allow_text=True)
    out, bad = [], []
    for tok in _split_tokens(v):
        try:
            out.append(_norm_client_id(tok))
        except ValueError:
            bad.append(tok)
    if bad:
        raise ValueError("Некорректные адреса клиентов: %s (нужен IP или "
                         "подсеть, например 10.10.10.5 или 10.10.10.0/24)"
                         % ", ".join(bad[:5]))
    return _dedup(out)


def _clean_rules(v) -> tuple:
    """Нормализовать список правил. Возвращает (rules, warnings)."""
    if not isinstance(v, list):
        raise ValueError("rules должен быть массивом")
    out, warns, ids = [], [], set()
    for i, r in enumerate(v):
        where = "rules[%d]." % i
        if not isinstance(r, dict):
            raise ValueError("rules[%d]: ожидается объект" % i)
        for key in ("id", "name", "outbound"):
            if r.get(key) is not None and not isinstance(r[key], str):
                raise ValueError("%s%s: ожидается строка" % (where, key))
        enabled = _need_bool(r, "enabled", where) if "enabled" in r else True
        rid = (r.get("id") or "").strip()
        if not _RULE_ID_RE.match(rid) or rid in ids:
            # os.urandom, а не uuid: на Entware python3-light без uuid
            rid = "r-" + os.urandom(3).hex()
        ids.add(rid)
        name = (r.get("name") or "").strip()[:80] or rid
        raw = _split_tokens(_need_str_list(r.get("domains"),
                                           where + "domains",
                                           allow_text=True))
        domains = normalize_domains(raw)
        dropped = [t for t in raw if not normalize_domains([t])]
        if dropped:
            warns.append("правило «%s»: отброшено %d записей (%s)"
                         % (name, len(dropped), ", ".join(dropped[:5])))
        subnets = _clean_subnets(
            _split_tokens(_need_str_list(r.get("subnets"),
                                         where + "subnets",
                                         allow_text=True)), name, warns)
        lists = _need_str_list(r.get("lists"), where + "lists")
        lists = _dedup(x.strip() for x in lists if x.strip())
        if any(len(x) > 200 for x in lists):
            raise ValueError("%slists: слишком длинный идентификатор" % where)
        out.append({
            "id": rid,
            "name": name,
            "enabled": enabled,
            "outbound": (r.get("outbound") or "").strip(),
            "lists": lists,
            "domains": domains,
            "subnets": subnets,
        })
    return out, warns


def update_settings(data: dict) -> dict:
    """
    Частичное обновление настроек (PUT /api/agh-routes). Пустой пароль и
    маска ``***`` пароль не меняют. Ошибка валидации, ValueError, при
    ней ничего не записывается.
    """
    if not isinstance(data, dict):
        raise ValueError("Ожидается JSON-объект")
    upd, warns = {}, []
    if "enabled" in data:
        upd["enabled"] = _need_bool(data, "enabled")
    if "agh_url" in data:
        upd["agh_url"] = _clean_url(data["agh_url"])
    if "agh_user" in data:
        upd["agh_user"] = _need_str(data, "agh_user").strip()
    if "agh_password" in data:
        pw = _need_str(data, "agh_password")
        if pw and pw != MASK:
            upd["agh_password"] = pw
    if "dns_target" in data:
        upd["dns_target"] = _clean_target(_need_str(data, "dns_target"))
    if "singbox_config" in data:
        name = _need_str(data, "singbox_config").strip()
        if name.endswith(".json"):
            name = name[:-5]
        if name and not _CONFIG_NAME_RE.match(name):
            raise ValueError("Имя конфига sing-box: A-Za-z0-9._-, до 32 "
                             "символов")
        upd["singbox_config"] = name
    if "clients" in data:
        upd["clients"] = _clean_clients(data["clients"])
    if "rules" in data:
        upd["rules"], w = _clean_rules(data["rules"])
        warns += w
    if upd:
        cm = _cm()
        for key, value in upd.items():
            cm.set("agh_routes", key, value)
        cm.save()
        log.info("agh_routes: настройки обновлены (%s)"
                 % ", ".join(sorted(upd)), source=SOURCE)
    return {"settings": public_settings(), "updated": sorted(upd),
            "warnings": warns}


def _store_applied(applied: dict) -> None:
    cm = _cm()
    cm.set("agh_routes", "_applied", applied)
    cm.save()


# ─────────────────────── источники доменов ───────────────────────────

def _collect_detail(rule: dict) -> tuple:
    """
    (отсортированные домены правила, предупреждения, ошибки).

    Источник, который не удалось прочитать (geosite не скачался и нет
    кэша, список удалён, hostlist-файла нет, исключение при чтении), -
    ОШИБКА плана: иначе применение молча сняло бы его домены из sing-box
    и AdGuard. Пустой, но существующий hostlist, только предупреждение.
    """
    name = str(rule.get("name") or rule.get("id") or "?")
    raw, warns, errs = [], [], []
    for item in rule.get("lists") or []:
        s = str(item or "").strip()
        low = s.lower()
        if not s:
            continue
        try:
            if low.startswith("hl:"):
                from core.hostlist_manager import get_hostlist_manager
                hm = get_hostlist_manager()
                doms = hm.get_hostlist(s[3:]) or []
                if not doms:
                    if s[3:] in hm.list_names():
                        warns.append("правило «%s»: hostlist %s пуст"
                                     % (name, s[3:]))
                    else:
                        errs.append("правило «%s»: hostlist %s не найден"
                                    % (name, s[3:]))
                raw += doms
            elif low.startswith("ipl:") or low.startswith("geoip:"):
                warns.append("правило «%s»: %s пропущен, поддерживаются "
                             "только домены" % (name, s))
            elif low.startswith("geosite:"):
                from core.routing import alias_resolver
                res = alias_resolver.expand_domains([low]) or {}
                if res.get("aliases_failed") or not res.get("domains"):
                    errs.append("правило «%s»: не удалось получить %s "
                                "(нет сети и кэша или нет такого списка)"
                                % (name, low))
                raw += res.get("domains") or []
            else:
                from core import named_lists
                it = named_lists.get(s)
                if it is None:
                    errs.append("правило «%s»: список %s не найден"
                                % (name, s))
                else:
                    raw += it.get("domains") or []
        except Exception as e:
            errs.append("правило «%s»: %s: %s" % (name, s, e))
    raw += list(rule.get("domains") or [])
    return sorted(set(normalize_domains(raw))), warns, errs


def collect(rule: dict) -> list:
    """Домены правила: списки + свои домены, без дублей, отсортированы."""
    return _collect_detail(rule)[0]


def list_sources(config_name: str = "") -> dict:
    """Что можно выбрать в правилах: hostlist'ы, named lists, geosite;
    для указанного конфига sing-box, его outbound'ы."""
    out = {"hostlists": [], "named_lists": [], "geosite": [], "outbounds": []}
    try:
        from core.hostlist_manager import get_hostlist_manager
        hm = get_hostlist_manager()
        stats = hm.get_stats()
        for nm in hm.list_names():
            st = stats.get(nm) or {}
            out["hostlists"].append({"id": "hl:" + nm, "name": nm,
                                     "count": int(st.get("count") or 0)})
    except Exception as e:
        log.warning("agh_routes: hostlist'ы: %s" % e, source=SOURCE)
    try:
        from core import named_lists
        for it in named_lists.list_all():
            out["named_lists"].append({
                "id": it.get("id"), "name": it.get("name") or it.get("id"),
                "count": int(it.get("domain_count") or 0)})
    except Exception as e:
        log.warning("agh_routes: named lists: %s" % e, source=SOURCE)
    try:
        from core.routing import alias_resolver
        cached = {c["name"]: c for c in alias_resolver.list_cached()
                  if c.get("kind") == "geosite"}
        names = _dedup(list(alias_resolver.list_suggestions()["geosite"])
                       + sorted(cached))
        for nm in names:
            c = cached.get(nm) or {}
            out["geosite"].append({"id": "geosite:" + nm, "name": nm,
                                   "cached": bool(c),
                                   "count": int(c.get("count") or 0)})
    except Exception as e:
        log.warning("agh_routes: geosite: %s" % e, source=SOURCE)
    name = str(config_name or "").strip()
    if name:
        try:
            from core.singbox_manager import get_singbox_manager
            r = get_singbox_manager().get_config(name)
            out["outbounds"] = outbound_tags(r.get("parsed") or {})
        except Exception as e:
            log.warning("agh_routes: outbound'ы %s: %s" % (name, e),
                        source=SOURCE)
    return out


# ─────────────────────── HTTP к AdGuard Home ─────────────────────────

def _http_request(method: str, url: str, *, body=None, user: str = "",
                  password: str = "", timeout: float = HTTP_TIMEOUT):
    """
    Единственная точка HTTP к AdGuard Home. Basic-авторизация, таймаут,
    мимо прокси окружения (HTTPS_PROXY на роутере обычно смотрит в обход
    блокировок, и 127.0.0.1 через него не открыть). Возвращает
    (код, данные): данные, разобранный JSON, текст или {} для пустого
    тела. Сеть, авторизация и коды ≥ 400 → AghError.
    """
    headers = {"Accept": "application/json",
               "User-Agent": "zapret-gui/agh-routes"}
    data = None
    if body is not None:
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if user or password:
        token = base64.b64encode(
            ("%s:%s" % (user, password)).encode("utf-8")).decode("ascii")
        headers["Authorization"] = "Basic " + token
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        req = urllib.request.Request(url, data=data, headers=headers,
                                     method=method)
        with opener.open(req, timeout=timeout) as resp:
            code = resp.getcode()
            raw = resp.read()
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            raise AghError("AdGuard Home: неверный логин или пароль "
                           "(HTTP %d)" % e.code)
        try:
            detail = e.read()[:300].decode("utf-8", "replace").strip()
        except Exception:
            detail = ""
        path = urllib.parse.urlsplit(url).path
        raise AghError("AdGuard Home %s %s: HTTP %d%s"
                       % (method, path, e.code,
                          (": " + detail) if detail else ""))
    except (urllib.error.URLError, http.client.HTTPException, OSError,
            ValueError) as e:
        reason = getattr(e, "reason", None) or e
        raise AghError("нет связи с AdGuard Home (%s): %s"
                       % (_url_origin(url), reason or type(e).__name__))
    text = raw.decode("utf-8", "replace")
    if not text.strip():
        return code, {}
    try:
        return code, json.loads(text)
    except ValueError:
        return code, text


def _agh_call(s: dict, method: str, path: str, body=None):
    url = str(s.get("agh_url") or "").rstrip("/") + path
    _code, data = _http_request(method, url, body=body,
                                user=s.get("agh_user") or "",
                                password=s.get("agh_password") or "")
    return data


def test_connection(overrides: dict = None) -> dict:
    """GET /control/status → версия AdGuard Home. overrides, несохранённые
    url/логин/пароль из формы (пустой пароль и маска = сохранённый)."""
    s = get_settings()
    ov = overrides if isinstance(overrides, dict) else {}
    pw = ov.get("agh_password")
    pw = pw if isinstance(pw, str) and pw and pw != MASK else ""
    url = ov.get("agh_url")
    if isinstance(url, str) and url.strip():
        try:
            url = _clean_url(url)
        except ValueError as e:
            return {"ok": False, "error": str(e)}
        # Сохранённый пароль уходит только на сохранённый адрес: иначе
        # кнопкой «Проверить» его можно было бы отправить куда угодно.
        if url != _clean_url_quiet(s.get("agh_url")) and not pw:
            return {"ok": False, "error": "Адрес отличается от сохранённого: "
                    "введите пароль для проверки"}
        s["agh_url"] = url
    elif url is not None and not isinstance(url, str):
        return {"ok": False, "error": "agh_url: ожидается строка"}
    if isinstance(ov.get("agh_user"), str):
        s["agh_user"] = ov["agh_user"].strip()
    if pw:
        s["agh_password"] = pw
    try:
        st = _agh_call(s, "GET", "/control/status")
    except AghError as e:
        log.warning("agh_routes: проверка связи с %s: %s"
                    % (_url_origin(s.get("agh_url")), e), source=SOURCE)
        return {"ok": False, "error": str(e)}
    if not isinstance(st, dict):
        return {"ok": False, "error": "неожиданный ответ /control/status"}
    return {"ok": True, "version": str(st.get("version") or ""),
            "running": bool(st.get("running")),
            "protection_enabled": bool(st.get("protection_enabled")),
            "dns_port": st.get("dns_port")}


# ─────────────────────── план ────────────────────────────────────────

def _rules_part(s: dict, enabled: bool, errors: list, warnings: list):
    """Домены и подсети по правилам с учётом «первое правило выигрывает».
    Возвращает (rules_info, rules_desired, all_domains)."""
    info, desired, assigned, nets_assigned = [], [], {}, {}
    for r in s.get("rules") or []:
        if not isinstance(r, dict):
            continue
        name = str(r.get("name") or r.get("id") or "?")
        item = {"id": r.get("id") or "", "name": name,
                "enabled": bool(r.get("enabled", True)),
                "outbound": str(r.get("outbound") or ""),
                "domains": 0, "sample": [], "subnets": 0,
                "subnets_sample": [], "skipped": ""}
        info.append(item)
        if not enabled or not item["enabled"]:
            item["skipped"] = "выключено"
            continue
        doms, warns, errs = _collect_detail(r)
        warnings.extend(warns)
        errors.extend(errs)
        own, dup, shadow = [], {}, {}
        for d in doms:
            if d in assigned:
                dup[assigned[d]] = dup.get(assigned[d], 0) + 1
                continue
            # Суффикс из правила выше перекрывает домен: sing-box отдаст
            # его первому совпавшему правилу (google.com раньше mail.google.com).
            parts = d.split(".")
            for i in range(1, len(parts)):
                other = assigned.get(".".join(parts[i:]))
                if other and other != name:
                    shadow[other] = shadow.get(other, 0) + 1
                    break
            own.append(d)
        for d in own:
            assigned[d] = name
        for other, n in dup.items():
            warnings.append("правило «%s»: %d доменов уже есть в правиле "
                            "«%s», берётся первое" % (name, n, other))
        for other, n in shadow.items():
            warnings.append("правило «%s»: %d доменов перекрыты суффиксами "
                            "правила «%s» выше, в sing-box сработает оно"
                            % (name, n, other))
        single = [d for d in own if "." not in d]
        if single:
            warnings.append("правило «%s»: однометочные суффиксы (%s) "
                            "заворачивают всю зону" % (name,
                                                       ", ".join(single[:5])))
        item["domains"] = len(own)
        item["sample"] = own[:5]
        nets = _rule_subnets(r, name, nets_assigned, warnings)
        item["subnets"] = len(nets)
        item["subnets_sample"] = nets[:5]
        if not own and not nets:
            item["skipped"] = "нет доменов"
            warnings.append("правило «%s»: нет доменов, пропущено" % name)
            continue
        if not item["outbound"]:
            errors.append("правило «%s»: не выбран outbound" % name)
            continue
        if own:
            desired.append({"domain_suffix": own,
                            "outbound": item["outbound"]})
        if nets:
            desired.append({"ip_cidr": nets, "outbound": item["outbound"]})
    return info, desired, sorted(assigned)


def _rule_subnets(rule, name, nets_assigned, warnings) -> list:
    """Подсети правила без уже занятых правилами выше (первое выигрывает).
    Вложенные подсети разных правил только предупреждение: в sing-box
    сработает правило выше. nets_assigned пополняется."""
    own, dup, overlap = [], {}, {}
    for raw in rule.get("subnets") or []:
        try:
            net = ipaddress.ip_network(str(raw), strict=False)
        except ValueError:
            continue
        if net.version != 4:
            continue
        key = str(net)
        if key in nets_assigned:
            other = nets_assigned[key][0]
            if other != name:
                dup[other] = dup.get(other, 0) + 1
            continue
        for other, other_net in nets_assigned.values():
            if other != name and net.overlaps(other_net):
                overlap[other] = overlap.get(other, 0) + 1
                break
        nets_assigned[key] = (name, net)
        own.append(key)
    for other, n in dup.items():
        warnings.append("правило «%s»: %d подсетей уже есть в правиле "
                        "«%s», берётся первое" % (name, n, other))
    for other, n in overlap.items():
        warnings.append("правило «%s»: %d подсетей пересекаются с "
                        "подсетями правила «%s»" % (name, n, other))
    return own


def _singbox_part(s, enabled, rules_desired, errors, warnings, ctx):
    name = str(s.get("singbox_config") or "").strip()
    applied = (s.get("_applied") or {}).get("singbox") or {}
    prev_name = str(applied.get("config") or "")
    prev_rules = list(applied.get("rules") or [])
    sb = {"config": name, "found": False, "running": False,
          "rules_desired": rules_desired, "rules_current": [],
          "outbounds": [], "changed": False, "cleanup_config": ""}
    ctx["sb_name"] = name
    ctx["sb_rules"] = rules_desired

    from core.singbox_manager import get_singbox_manager
    mgr = get_singbox_manager()
    ctx["sb_mgr"] = mgr

    # Конфиг сменили, наши правила из прежнего надо снять.
    if prev_name and prev_name != name and prev_rules:
        r = mgr.get_config(prev_name)
        cfg = r.get("parsed") if r.get("ok") else None
        if isinstance(cfg, dict):
            new = merge_singbox_rules(copy.deepcopy(cfg), prev_rules, [])
            if new != cfg:
                sb["cleanup_config"] = prev_name
                ctx["sb_cleanup"] = (prev_name, new, r.get("text") or "")
        elif r.get("ok"):
            warnings.append("прежний конфиг sing-box «%s» не разобран: наши "
                            "правила из него не сняты" % prev_name)

    old = prev_rules if prev_name == name else []
    if not name:
        if rules_desired:
            errors.append("не выбран конфиг sing-box")
        return sb
    r = mgr.get_config(name)
    cfg = r.get("parsed") if r.get("ok") else None
    if not isinstance(cfg, dict):
        why = (r.get("error") or "не найден") if not r.get("ok") else \
            "не разобран: " + "; ".join(r.get("errors") or [])
        # Ставить некуда, ошибка. Снимать не из чего (выключено, файла
        # нет), предупреждение: AdGuard всё равно надо почистить.
        (errors if rules_desired else warnings).append(
            "конфиг sing-box «%s»: %s" % (name, why))
        if old:
            # Запись о поставленном не теряем: конфиг может вернуться,
            # и тогда наши правила из него надо будет снять.
            ctx["sb_keep_applied"] = True
        return sb
    sb["found"] = True
    sb["running"] = bool(mgr.is_running(name))
    sb["systemd"] = False
    if not sb["running"]:
        from core import singbox_autostart
        sb["systemd"] = bool(singbox_autostart.unit_runs_config(name))
    tags = outbound_tags(cfg)
    sb["outbounds"] = [t["tag"] for t in tags]
    for ob in _dedup(rule["outbound"] for rule in rules_desired):
        if ob not in sb["outbounds"]:
            errors.append("outbound «%s» не найден в конфиге sing-box «%s»"
                          % (ob, name))
    cur_rules = ((cfg.get("route") or {}).get("rules") or []) \
        if isinstance(cfg.get("route"), dict) else []
    sb["rules_current"] = [x for x in cur_rules if x in old]
    missing = len([x for x in old if x not in cur_rules])
    if missing:
        sb["drift"] = missing
        warnings.append("в конфиге «%s» не найдено %d из %d поставленных "
                        "правил: их изменили вручную, изменённые останутся "
                        "как есть" % (name, missing, len(old)))
    new_cfg = merge_singbox_rules(copy.deepcopy(cfg), old, rules_desired)
    sb["changed"] = new_cfg != cfg
    if sb["changed"]:
        ctx["sb_write"] = (name, new_cfg, r.get("text") or "")
    target = str(s.get("dns_target") or "")
    bad = _dns_in_mismatch(cfg, target) if enabled else ""
    if bad:
        warnings.append("в конфиге «%s» dns-in слушает %s, а цель DNS "
                        "для AdGuard, %s" % (name, bad, target))
    return sb


def _is_general_upstream(line) -> bool:
    """Обычный upstream (для всех доменов): не комментарий, не пусто и не
    доменная строка ``[/…/]``. Без хотя бы одного такого AdGuard не
    знает, куда слать остальные домены."""
    s = str(line or "").strip()
    return bool(s) and not s.startswith("#") and not s.startswith("[/")


def _as_network(raw):
    """IP/подсеть из id клиента AdGuard (MAC и ClientID → None)."""
    try:
        return ipaddress.ip_network(str(raw).strip(), strict=False)
    except ValueError:
        return None


def _covering_clients(clients, cid, exclude) -> list:
    """Клиенты AdGuard (кроме exclude), чья подсеть покрывает cid."""
    net = _as_network(cid)
    out = []
    if net is None:
        return out
    for c in clients:
        if c is exclude:
            continue
        for raw in c.get("ids") or []:
            other = _as_network(raw)
            if (other is None or other.version != net.version
                    or other.prefixlen == other.max_prefixlen
                    or other == net):
                continue
            if net.subnet_of(other):
                out.append("%s (%s)" % (c.get("name"), raw))
                break
    return out


def _find_client(clients, cid):
    for c in clients:
        for raw in c.get("ids") or []:
            try:
                if _norm_client_id(raw) == cid:
                    return c
            except ValueError:
                continue
    return None


def _agh_part(s, mode, lines, target, errors, warnings, ctx):
    applied = (s.get("_applied") or {}).get("agh") or {}
    targets = _dedup([target] + [t for t in applied.get("targets") or []
                                 if t])
    agh = {"mode": mode, "reachable": False, "target": target,
           "lines": lines, "current": [], "desired": [], "add": [],
           "remove": [], "domains_add": [], "domains_remove": [],
           "global_changed": False, "clients": [], "changed": False,
           "upstream_dns_file": ""}
    ctx["agh_targets"] = targets
    try:
        info = _agh_call(s, "GET", "/control/dns_info")
        cl = _agh_call(s, "GET", "/control/clients")
    except AghError as e:
        errors.append(str(e))
        return agh
    if not isinstance(info, dict) or not isinstance(cl, dict):
        errors.append("AdGuard Home: неожиданный ответ API")
        return agh
    agh["reachable"] = True

    upstreams = [str(x) for x in (info.get("upstream_dns") or [])]
    if info.get("upstream_dns_file"):
        agh["upstream_dns_file"] = str(info["upstream_dns_file"])
        warnings.append("в AdGuard задан upstream_dns_file (%s): глобальный "
                        "список upstream'ов не действует"
                        % info["upstream_dns_file"])
    current = [x for x in upstreams if is_managed_line(x, targets)]
    base = [x for x in upstreams if not is_managed_line(x, targets)]
    desired = list(lines) if mode == "global" else []
    new_up = replace_managed(upstreams, desired, targets)
    cur_d = set(d for x in current for d in line_domains(x))
    des_d = set(d for x in desired for d in line_domains(x))
    agh.update({
        "current": current, "desired": desired,
        "add": [x for x in desired if x not in current],
        "remove": [x for x in current if x not in desired],
        "domains_add": sorted(des_d - cur_d),
        "domains_remove": sorted(cur_d - des_d),
        "global_changed": new_up != upstreams,
    })
    if agh["global_changed"]:
        if not agh["upstream_dns_file"] and not any(
                _is_general_upstream(x) for x in new_up):
            errors.append("в глобальных upstream'ах AdGuard не останется "
                          "ни одного обычного upstream'а (только доменные "
                          "строки): добавьте его в AdGuard")
        # Минимальное тело: AdGuard меняет только переданные поля, эхо
        # всего dns_info нам не нужно и рискованно между версиями.
        ctx["agh_global"] = {"upstream_dns": new_up}

    # ── клиенты ──
    agh_clients = [c for c in (cl.get("clients") or [])
                   if isinstance(c, dict) and c.get("name")]
    prev = {str(r.get("name")): r for r in applied.get("clients") or []
            if isinstance(r, dict)}
    ops, records, handled = [], [], set()
    wanted = []
    if mode == "clients" and lines:
        for raw in s.get("clients") or []:
            try:
                wanted.append(_norm_client_id(raw))
            except ValueError:
                warnings.append("клиент %s: некорректный адрес, пропущен"
                                % raw)
    for cid in _dedup(wanted):
        c = _find_client(agh_clients, cid)
        cover = _covering_clients(agh_clients, cid, c)
        if cover:
            warnings.append("клиент %s входит в подсеть клиента AdGuard %s: "
                            "для этого адреса будут действовать настройки "
                            "клиента %s, а не подсети"
                            % (cid, ", ".join(cover),
                               c.get("name") if c else "zg-" + cid))
        if c is None:
            name = "zg-" + cid
            if name in handled:
                continue
            new = base + list(lines)
            if not any(_is_general_upstream(x) for x in new):
                errors.append("клиент %s: в глобальных upstream'ах AdGuard "
                              "нет ни одного обычного upstream'а, новому "
                              "клиенту нечего дать кроме наших строк" % cid)
            # use_global_settings оставляем true: в AdGuard этот флаг
            # про фильтрацию (блокировки, safe search и т.п.), а не про
            # upstream'ы, поклиентные upstream'ы действуют при любом
            # его значении. С false новый клиент остался бы без фильтров.
            payload = {"name": name, "ids": [cid], "tags": [],
                       "use_global_settings": True,
                       "use_global_blocked_services": True,
                       "upstreams": new}
            ops.append({"id": cid, "name": name, "action": "add",
                        "exists": False, "current": 0, "desired": len(lines),
                        "path": "/control/clients/add", "body": payload})
            records.append({"id": cid, "name": name, "base": "global",
                            "created": True})
            handled.add(name)
            continue
        name = str(c["name"])
        if name in handled:
            continue
        handled.add(name)
        cur = [str(x) for x in (c.get("upstreams") or [])]
        own = [x for x in cur if not is_managed_line(x, targets)]
        rec = prev.get(name)
        # Без записи о прошлом применении: пустые или равные глобальным
        # upstream'ы, клиент живёт на глобальных, иначе у него свои.
        kind = (rec.get("base") if rec else
                ("global" if not own or own == base else "own"))
        if kind == "global":
            # Клиент ходил через глобальные upstream'ы: даём ему текущие
            # глобальные (без наших) плюс наши строки.
            new = base + list(lines)
        else:
            # У клиента свои upstream'ы, их не трогаем, меняем только наши.
            new = replace_managed(cur, list(lines), targets)
        n_cur = len([x for x in cur if is_managed_line(x, targets)])
        op = {"id": cid, "name": name, "exists": True,
              "action": "update" if new != cur else "none",
              "current": n_cur, "desired": len(lines)}
        if new != cur and new and not any(_is_general_upstream(x)
                                          for x in new):
            errors.append("клиент AdGuard %s: после замены не останется ни "
                          "одного обычного upstream'а" % name)
        if new != cur:
            data = copy.deepcopy(c)
            data["upstreams"] = new
            op["path"] = "/control/clients/update"
            op["body"] = {"name": name, "data": data}
        ops.append(op)
        records.append({"id": cid, "name": name, "base": kind,
                        "created": bool(rec and rec.get("created"))})

    # Наши строки у клиентов вне списка (или при пустом списке) снимаем.
    for c in agh_clients:
        name = str(c["name"])
        if name in handled:
            continue
        cur = [str(x) for x in (c.get("upstreams") or [])]
        n_cur = len([x for x in cur if is_managed_line(x, targets)])
        rec = prev.get(name)
        ours = bool(rec and rec.get("created") and name.startswith("zg-"))
        if not n_cur and not ours:
            continue
        ids = ",".join(str(x) for x in c.get("ids") or [])
        if ours:
            # Клиента создавали мы, снимаем его целиком.
            ops.append({"id": ids, "name": name, "action": "delete",
                        "exists": True, "current": n_cur, "desired": 0,
                        "path": "/control/clients/delete",
                        "body": {"name": name}})
            continue
        rest = [x for x in cur if not is_managed_line(x, targets)]
        kind = rec.get("base") if rec else ("global" if rest == base
                                            else "own")
        # Клиент до нас ходил через глобальные, возвращаем его к ним.
        new = [] if kind == "global" else rest
        if new and not any(_is_general_upstream(x) for x in new):
            errors.append("клиент AdGuard %s: после снятия наших строк не "
                          "останется ни одного обычного upstream'а" % name)
        data = copy.deepcopy(c)
        data["upstreams"] = new
        ops.append({"id": ids, "name": name, "action": "remove",
                    "exists": True, "current": n_cur, "desired": 0,
                    "path": "/control/clients/update",
                    "body": {"name": name, "data": data}})

    agh["clients"] = ops
    agh["changed"] = agh["global_changed"] or any(
        o["action"] != "none" for o in ops)
    ctx["agh_ops"] = ops
    ctx["agh_records"] = records
    ctx["agh_prev_records"] = prev
    return agh


def _compute(s: dict) -> tuple:
    """План и контекст для apply (что именно писать)."""
    errors, warnings, ctx = [], [], {}
    enabled = bool(s.get("enabled"))
    mode = "clients" if s.get("clients") else "global"
    target = str(s.get("dns_target") or "").strip()
    try:
        target = _clean_target(target)
        target_ok = True
    except ValueError as e:
        errors.append(str(e))
        target_ok = False

    rules_info, rules_desired, domains = _rules_part(s, enabled, errors,
                                                     warnings)
    if enabled and not domains and not rules_desired:
        warnings.append("нет ни одного домена: применение снимет всё, что "
                        "было поставлено раньше")
    lines = render_agh_lines(domains, target) if target_ok else []

    try:
        sb = _singbox_part(s, enabled, rules_desired, errors, warnings, ctx)
    except Exception as e:
        errors.append("sing-box: %s" % e)
        sb = {"config": s.get("singbox_config") or "", "found": False,
              "running": False, "rules_desired": rules_desired,
              "rules_current": [], "outbounds": [], "changed": False,
              "cleanup_config": ""}
    if target_ok:
        agh = _agh_part(s, mode, lines, target, errors, warnings, ctx)
    else:
        agh = {"mode": mode, "reachable": False, "target": target,
               "lines": [], "clients": [], "changed": False}
    ctx["mode"] = mode
    ctx["target"] = target
    changed = bool(sb.get("changed") or sb.get("cleanup_config")
                   or agh.get("changed"))
    if not enabled:
        warnings.append("маршруты выключены" + (
            ": применение снимет всё, что было поставлено раньше"
            if changed else ""))
    plan = {
        "enabled": enabled,
        "mode": mode,
        "domains_total": len(domains),
        "rules": rules_info,
        "agh": agh,
        "singbox": sb,
        "errors": errors,
        "warnings": warnings,
        "changed": changed,
    }
    return plan, ctx


def _public_plan(plan: dict) -> dict:
    """План без внутренних тел запросов."""
    out = copy.deepcopy(plan)
    for op in (out.get("agh") or {}).get("clients") or []:
        op.pop("body", None)
        op.pop("path", None)
    return out


def plan() -> dict:
    """Что изменит apply(), без записи."""
    return _public_plan(_compute(get_settings())[0])


# ─────────────────────── применение ──────────────────────────────────

def _write_singbox(mgr, name: str, cfg: dict, prev_text: str) -> dict:
    """
    check → save → рестарт того, кто держит инстанс: процесс панели
    (SingboxManager) или systemd-юнит sing-box-gui с этим конфигом. Не
    поднялся, возвращаем прежний текст и перезапускаем снова; что
    получилось на самом деле, пишем в ответ.
    """
    from core import singbox_autostart
    from core.singbox_config import render_conf
    text = render_conf(cfg)
    res = {"config": name, "saved": False, "running": False,
           "restarted": False, "restart_via": ""}
    chk = mgr.check_text(text)
    if not chk.get("ok"):
        if not chk.get("no_binary"):
            res["error"] = "sing-box check «%s»: %s" % (
                name, chk.get("error") or "конфиг не принят")
            return res
        res["warning"] = "sing-box не установлен: конфиг сохранён без проверки"
    sv = mgr.save_config(name, text=text)
    if not sv.get("ok"):
        res["error"] = "sing-box: не удалось сохранить «%s»: %s" % (
            name, sv.get("error") or "")
        return res
    res["saved"] = True
    log.info("agh_routes: конфиг sing-box «%s» обновлён" % name,
             source=SOURCE)
    if mgr.is_running(name):
        res["restart_via"] = "panel"

        def restart():
            return mgr.restart(name)
    elif singbox_autostart.unit_runs_config(name):
        res["restart_via"] = "systemd"

        def restart():
            return singbox_autostart.restart_unit()
    else:
        return res
    res["running"] = True
    rr = restart()
    if rr.get("ok"):
        res["restarted"] = True
        log.info("agh_routes: sing-box «%s» перезапущен (%s)"
                 % (name, res["restart_via"]), source=SOURCE)
        return res
    res["error"] = "sing-box «%s» не перезапустился: %s" % (
        name, rr.get("error") or "")
    res["rolled_back"] = False
    if not prev_text:
        res["error"] += "; прежнего текста конфига нет, откатить нечем"
        return res
    sv = mgr.save_config(name, text=prev_text)
    if not sv.get("ok"):
        res["error"] += ("; вернуть прежний конфиг не удалось: %s, в файле "
                         "остался новый" % (sv.get("error") or "ошибка записи"))
        return res
    res["rolled_back"] = True
    back = restart()
    res["error"] += "; прежний конфиг возвращён%s" % (
        " и запущен" if back.get("ok") else
        ", но инстанс не поднялся: %s" % (back.get("error") or ""))
    return res


def apply() -> dict:
    """Применить план: сначала sing-box, потом AdGuard. Без изменений
    ничего не пишет."""
    if not _apply_lock.acquire(blocking=False):
        return {"ok": False, "changed": False,
                "error": "Применение уже выполняется"}
    try:
        return _apply_locked()
    finally:
        _apply_lock.release()


def _apply_locked() -> dict:
    s = get_settings()
    pl, ctx = _compute(s)
    public = _public_plan(pl)
    if pl["errors"]:
        for e in pl["errors"]:
            log.error("agh_routes: %s" % e, source=SOURCE)
        return {"ok": False, "changed": False, "plan": public,
                "errors": pl["errors"],
                "error": "; ".join(pl["errors"][:3])}
    if not pl["changed"]:
        log.info("agh_routes: изменений нет", source=SOURCE)
        return {"ok": True, "changed": False, "plan": public, "errors": []}

    applied = copy.deepcopy(s.get("_applied") or {})
    result = {"ok": True, "changed": True, "plan": public, "errors": [],
              "singbox": {}, "agh": {"global_updated": False,
                                     "clients": []}}
    mgr = ctx.get("sb_mgr")

    # 1. sing-box: сначала маршруты, потом AdGuard начнёт слать домены.
    if ctx.get("sb_cleanup"):
        name, cfg, prev_text = ctx["sb_cleanup"]
        r = _write_singbox(mgr, name, cfg, prev_text)
        result["singbox"]["cleanup"] = r
        if r.get("error"):
            log.error("agh_routes: %s" % r["error"], source=SOURCE)
            return dict(result, ok=False, errors=[r["error"]],
                        error=r["error"])
    if ctx.get("sb_write"):
        name, cfg, prev_text = ctx["sb_write"]
        r = _write_singbox(mgr, name, cfg, prev_text)
        result["singbox"].update(r)
        if r.get("error"):
            log.error("agh_routes: %s" % r["error"], source=SOURCE)
            if r.get("saved") and not r.get("rolled_back"):
                applied["singbox"] = {"config": name,
                                      "rules": ctx["sb_rules"]}
                _store_applied(applied)
            return dict(result, ok=False, errors=[r["error"]],
                        error=r["error"])
    if not ctx.get("sb_keep_applied"):
        applied["singbox"] = {"config": ctx.get("sb_name") or "",
                              "rules": ctx.get("sb_rules") or []}
        _store_applied(applied)

    # 2. AdGuard: клиентам, до смены глобального списка, снятие, после.
    errors, failed = [], set()
    ops = ctx.get("agh_ops") or []

    def _run(op):
        try:
            _agh_call(s, "POST", op["path"], op["body"])
            result["agh"]["clients"].append(
                {"name": op["name"], "action": op["action"]})
            log.info("agh_routes: AdGuard клиент %s: %s"
                     % (op["name"], op["action"]), source=SOURCE)
        except AghError as e:
            failed.add(op["name"])
            errors.append("клиент %s: %s" % (op["name"], e))

    for op in ops:
        if op["action"] in ("add", "update"):
            _run(op)
    if ctx.get("agh_global") is not None:
        try:
            _agh_call(s, "POST", "/control/dns_config", ctx["agh_global"])
            result["agh"]["global_updated"] = True
            log.info("agh_routes: AdGuard upstream_dns обновлён (%d наших "
                     "строк)" % len(pl["agh"]["desired"]), source=SOURCE)
        except AghError as e:
            errors.append("upstream_dns: %s" % e)
    for op in ops:
        if op["action"] in ("remove", "delete"):
            _run(op)

    targets = [ctx["target"]]
    if errors:
        # Строки со старой целью могли остаться, помним её до успеха.
        targets = _dedup(targets + list(ctx.get("agh_targets") or []))
    records = list(ctx.get("agh_records") or [])
    # Не снятых из-за ошибки клиентов помним до следующего применения
    # (иначе созданный нами zg-* потерял бы отметку created).
    known = {r["name"] for r in records}
    for name, rec in (ctx.get("agh_prev_records") or {}).items():
        if name in failed and name not in known:
            records.append(rec)
    applied["agh"] = {"mode": ctx["mode"], "targets": targets,
                      "clients": records}
    applied["at"] = int(time.time())
    _store_applied(applied)

    if errors:
        for e in errors:
            log.error("agh_routes: %s" % e, source=SOURCE)
        result.update(ok=False, errors=errors, error="; ".join(errors[:3]))
    else:
        log.success("agh_routes: применено (%d доменов, режим %s)"
                    % (pl["domains_total"], ctx["mode"]), source=SOURCE)
    return result
