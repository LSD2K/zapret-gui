# core/agh_routes.py
"""
Маршруты через AdGuard Home: «какие домены в какой туннель».

Одно место правды — секция ``agh_routes`` в settings.json: правила
«списки доменов → outbound sing-box». Из них раскладываются:

  (а) route-правила sing-box ``{"domain_suffix": [...], "outbound": tag}``
      в выбранный конфиг: сразу после ``hijack-dns`` (нет его — после
      ``sniff``, нет и его — в начало) и до ``{"inbound": ["tun-in"], ...}``.
      Сам конфиг собирает FakeIP-сборщик в режиме внешнего фронт-DNS,
      этот модуль его только дополняет;
  (б) upstream-строки AdGuard Home ``[/a.com/b.org/]127.0.0.1:1053`` —
      глобально (``/control/dns_config``) или поклиентно
      (``/control/clients/*``), чтобы AdGuard отдавал домены из правил в
      dns-in sing-box (fakeip), а остальное — своим обычным upstream'ам.

Что считается «нашим»:
  * в AdGuard — строки, заканчивающиеся на ``]<dns_target>`` (и на цели
    прошлых применений из ``_applied.agh.targets``: смена цели не должна
    оставлять хвостов);
  * в sing-box — правила из ``_applied.singbox.rules``. Пометить их полем
    нельзя (sing-box отвергает неизвестные поля), поэтому снимаем по
    точному совпадению.

Все HTTP-вызовы к AdGuard идут через одну обёртку :func:`_http_request`
(urllib, мимо прокси окружения) — тесты мокают именно её.

Схема сети и постановка — docs/gw/spec-b3-agh-routes.md.
"""

import base64
import copy
import ipaddress
import json
import os
import re
import threading
import time
import urllib.error
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

# Поля ответа /control/dns_info, которых нет в теле /control/dns_config.
_DNS_INFO_READONLY = ("default_local_ptr_upstreams",)

# Имя конфига sing-box — то же правило, что у singbox_manager.
_CONFIG_NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,32}$")
_RULE_ID_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,40}$")

# Домен-суффикс после нормализации: метки a-z0-9_- через точку.
_LABEL = r"(?!-)[a-z0-9_-]{1,63}(?<!-)"
_DOMAIN_RE = re.compile(r"^%s(?:\.%s)*$" % (_LABEL, _LABEL))

# Цель DNS для AdGuard: адрес upstream'а без пробелов и комментариев
# (127.0.0.1:1053, [::1]:1053, udp://127.0.0.1:1053).
_TARGET_RE = re.compile(r"^[A-Za-z0-9._:/\[\]-]+$")

_apply_lock = threading.Lock()


class AghError(Exception):
    """Ошибка обращения к AdGuard Home (сеть, авторизация, HTTP-код)."""


# ─────────────────────── нормализация ────────────────────────────────

def _to_ascii(s: str) -> str:
    """IDN → punycode (AdGuard и sing-box ждут ASCII). Не вышло — ''."""
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
    """Список строк из списка или текста (пробелы/запятые/переводы строк)."""
    if isinstance(v, (list, tuple)):
        tokens = []
        for x in v:
            tokens.extend(re.split(r"[\s,;]+", str(x or "")))
    else:
        tokens = re.split(r"[\s,;]+", str(v or ""))
    return [t for t in tokens if t]


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
    дедуплицируются — одинаковый вход даёт одинаковые строки.
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
    наших не было — в конец.
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
    ``hijack-dns`` (нет его — после ``sniff``, нет и его — в начало), но
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
    Сравниваем порт и адрес (адрес — только если dns-in слушает не все
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


def _clean_clients(v) -> list:
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
    for r in v:
        if not isinstance(r, dict):
            continue
        rid = str(r.get("id") or "").strip()
        if not _RULE_ID_RE.match(rid) or rid in ids:
            # os.urandom, а не uuid: на Entware python3-light без uuid
            rid = "r-" + os.urandom(3).hex()
        ids.add(rid)
        name = str(r.get("name") or "").strip()[:80] or rid
        raw = _split_tokens(r.get("domains"))
        domains = normalize_domains(raw)
        dropped = [t for t in raw if not normalize_domains([t])]
        if dropped:
            warns.append("правило «%s»: отброшено %d записей (%s)"
                         % (name, len(dropped), ", ".join(dropped[:5])))
        lists = r.get("lists") or []
        if isinstance(lists, str):
            lists = [lists]
        lists = _dedup(str(x).strip() for x in lists if str(x or "").strip())
        out.append({
            "id": rid,
            "name": name,
            "enabled": bool(r.get("enabled", True)),
            "outbound": str(r.get("outbound") or "").strip(),
            "lists": lists,
            "domains": domains,
        })
    return out, warns


def update_settings(data: dict) -> dict:
    """
    Частичное обновление настроек (PUT /api/agh-routes). Пустой пароль и
    маска ``***`` пароль не меняют. Ошибка валидации — ValueError, при
    ней ничего не записывается.
    """
    if not isinstance(data, dict):
        raise ValueError("Ожидается JSON-объект")
    upd, warns = {}, []
    if "enabled" in data:
        upd["enabled"] = bool(data["enabled"])
    if "agh_url" in data:
        url = str(data["agh_url"] or "").strip().rstrip("/")
        if not re.match(r"^https?://[^/\s]+", url):
            raise ValueError("Адрес AdGuard Home: http(s)://хост:порт")
        upd["agh_url"] = url
    if "agh_user" in data:
        upd["agh_user"] = str(data["agh_user"] or "").strip()
    if "agh_password" in data:
        pw = str(data["agh_password"] or "")
        if pw and pw != MASK:
            upd["agh_password"] = pw
    if "dns_target" in data:
        upd["dns_target"] = _clean_target(data["dns_target"])
    if "singbox_config" in data:
        name = str(data["singbox_config"] or "").strip()
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
    """(отсортированные домены правила, предупреждения)."""
    name = str(rule.get("name") or rule.get("id") or "?")
    raw, warns = [], []
    for item in rule.get("lists") or []:
        s = str(item or "").strip()
        low = s.lower()
        if not s:
            continue
        try:
            if low.startswith("hl:"):
                from core.hostlist_manager import get_hostlist_manager
                doms = get_hostlist_manager().get_hostlist(s[3:]) or []
                if not doms:
                    warns.append("правило «%s»: hostlist %s пуст или не "
                                 "найден" % (name, s[3:]))
                raw += doms
            elif low.startswith("ipl:") or low.startswith("geoip:"):
                warns.append("правило «%s»: %s пропущен, поддерживаются "
                             "только домены" % (name, s))
            elif low.startswith("geosite:"):
                from core.routing import alias_resolver
                res = alias_resolver.expand_domains([low]) or {}
                if res.get("aliases_failed"):
                    warns.append("правило «%s»: не удалось получить %s"
                                 % (name, low))
                raw += res.get("domains") or []
            else:
                from core import named_lists
                it = named_lists.get(s)
                if it is None:
                    warns.append("правило «%s»: список %s не найден"
                                 % (name, s))
                else:
                    raw += it.get("domains") or []
        except Exception as e:
            warns.append("правило «%s»: %s: %s" % (name, s, e))
    raw += list(rule.get("domains") or [])
    return sorted(set(normalize_domains(raw))), warns


def collect(rule: dict) -> list:
    """Домены правила: списки + свои домены, без дублей, отсортированы."""
    return _collect_detail(rule)[0]


def list_sources(config_name: str = "") -> dict:
    """Что можно выбрать в правилах: hostlist'ы, named lists, geosite;
    для указанного конфига sing-box — его outbound'ы."""
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
    (код, данные): данные — разобранный JSON, текст или {} для пустого
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
        raise AghError("AdGuard Home %s %s: HTTP %d%s"
                       % (method, url, e.code,
                          (" — " + detail) if detail else ""))
    except (urllib.error.URLError, OSError, ValueError) as e:
        reason = getattr(e, "reason", None) or e
        raise AghError("нет связи с AdGuard Home (%s): %s" % (url, reason))
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
    """GET /control/status → версия AdGuard Home. overrides — несохранённые
    url/логин/пароль из формы (пустой пароль и маска = сохранённый)."""
    s = get_settings()
    ov = overrides if isinstance(overrides, dict) else {}
    if str(ov.get("agh_url") or "").strip():
        s["agh_url"] = str(ov["agh_url"]).strip().rstrip("/")
    if "agh_user" in ov:
        s["agh_user"] = str(ov.get("agh_user") or "").strip()
    pw = str(ov.get("agh_password") or "")
    if pw and pw != MASK:
        s["agh_password"] = pw
    try:
        st = _agh_call(s, "GET", "/control/status")
    except AghError as e:
        log.warning("agh_routes: проверка связи: %s" % e, source=SOURCE)
        return {"ok": False, "error": str(e)}
    if not isinstance(st, dict):
        return {"ok": False, "error": "неожиданный ответ /control/status"}
    return {"ok": True, "version": str(st.get("version") or ""),
            "running": bool(st.get("running")),
            "protection_enabled": bool(st.get("protection_enabled")),
            "dns_port": st.get("dns_port")}


# ─────────────────────── план ────────────────────────────────────────

def _rules_part(s: dict, enabled: bool, errors: list, warnings: list):
    """Домены по правилам с учётом «первое правило выигрывает».
    Возвращает (rules_info, rules_desired, all_domains)."""
    info, desired, assigned = [], [], {}
    for r in s.get("rules") or []:
        if not isinstance(r, dict):
            continue
        name = str(r.get("name") or r.get("id") or "?")
        item = {"id": r.get("id") or "", "name": name,
                "enabled": bool(r.get("enabled", True)),
                "outbound": str(r.get("outbound") or ""),
                "domains": 0, "sample": [], "skipped": ""}
        info.append(item)
        if not enabled or not item["enabled"]:
            item["skipped"] = "выключено"
            continue
        doms, warns = _collect_detail(r)
        warnings.extend(warns)
        own, dup = [], {}
        for d in doms:
            if d in assigned:
                dup[assigned[d]] = dup.get(assigned[d], 0) + 1
                continue
            assigned[d] = name
            own.append(d)
        for other, n in dup.items():
            warnings.append("правило «%s»: %d доменов уже есть в правиле "
                            "«%s», берётся первое" % (name, n, other))
        item["domains"] = len(own)
        item["sample"] = own[:5]
        if not own:
            item["skipped"] = "нет доменов"
            warnings.append("правило «%s»: нет доменов, пропущено" % name)
            continue
        if not item["outbound"]:
            errors.append("правило «%s»: не выбран outbound" % name)
            continue
        desired.append({"domain_suffix": own, "outbound": item["outbound"]})
    return info, desired, sorted(assigned)


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

    # Конфиг сменили — наши правила из прежнего надо снять.
    if prev_name and prev_name != name and prev_rules:
        r = mgr.get_config(prev_name)
        cfg = r.get("parsed") if r.get("ok") else None
        if isinstance(cfg, dict):
            new = merge_singbox_rules(copy.deepcopy(cfg), prev_rules, [])
            if new != cfg:
                sb["cleanup_config"] = prev_name
                ctx["sb_cleanup"] = (prev_name, new, r.get("text") or "")

    old = prev_rules if prev_name == name else []
    # Конфиг нужен, если есть что ставить или что снимать.
    needed = bool(rules_desired or old)
    if not name:
        if rules_desired:
            errors.append("не выбран конфиг sing-box")
        return sb
    r = mgr.get_config(name)
    cfg = r.get("parsed") if r.get("ok") else None
    if not isinstance(cfg, dict):
        why = (r.get("error") or "не найден") if not r.get("ok") else \
            "не разобран: " + "; ".join(r.get("errors") or [])
        (errors if needed else warnings).append(
            "конфиг sing-box «%s»: %s" % (name, why))
        return sb
    sb["found"] = True
    sb["running"] = bool(mgr.is_running(name))
    tags = outbound_tags(cfg)
    sb["outbounds"] = [t["tag"] for t in tags]
    for rule in rules_desired:
        if rule["outbound"] not in sb["outbounds"]:
            errors.append("outbound «%s» не найден в конфиге sing-box «%s»"
                          % (rule["outbound"], name))
    cur_rules = ((cfg.get("route") or {}).get("rules") or []) \
        if isinstance(cfg.get("route"), dict) else []
    sb["rules_current"] = [x for x in cur_rules if x in old]
    new_cfg = merge_singbox_rules(copy.deepcopy(cfg), old, rules_desired)
    sb["changed"] = new_cfg != cfg
    if sb["changed"]:
        ctx["sb_write"] = (name, new_cfg, r.get("text") or "")
    target = str(s.get("dns_target") or "")
    bad = _dns_in_mismatch(cfg, target) if enabled else ""
    if bad:
        warnings.append("в конфиге «%s» dns-in слушает %s, а цель DNS "
                        "для AdGuard — %s" % (name, bad, target))
    return sb


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
        body = {k: v for k, v in info.items()
                if k not in _DNS_INFO_READONLY}
        body["upstream_dns"] = new_up
        ctx["agh_global"] = body

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
        if c is None:
            name = "zg-" + cid
            if name in handled:
                continue
            new = base + list(lines)
            # use_global_settings оставляем true: в AdGuard этот флаг
            # про фильтрацию (блокировки, safe search и т.п.), а не про
            # upstream'ы — поклиентные upstream'ы действуют при любом
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
        # upstream'ы — клиент живёт на глобальных, иначе у него свои.
        kind = (rec.get("base") if rec else
                ("global" if not own or own == base else "own"))
        if kind == "global":
            # Клиент ходил через глобальные upstream'ы: даём ему текущие
            # глобальные (без наших) плюс наши строки.
            new = base + list(lines)
        else:
            # У клиента свои upstream'ы — их не трогаем, меняем только наши.
            new = replace_managed(cur, list(lines), targets)
        n_cur = len([x for x in cur if is_managed_line(x, targets)])
        op = {"id": cid, "name": name, "exists": True,
              "action": "update" if new != cur else "none",
              "current": n_cur, "desired": len(lines)}
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
        if not n_cur:
            continue
        rest = [x for x in cur if not is_managed_line(x, targets)]
        rec = prev.get(name)
        kind = rec.get("base") if rec else ("global" if rest == base
                                            else "own")
        # Клиент до нас ходил через глобальные — возвращаем его к ним.
        new = [] if kind == "global" else rest
        data = copy.deepcopy(c)
        data["upstreams"] = new
        ops.append({"id": ",".join(str(x) for x in c.get("ids") or []),
                    "name": name, "action": "remove", "exists": True,
                    "current": n_cur, "desired": 0,
                    "path": "/control/clients/update",
                    "body": {"name": name, "data": data}})

    agh["clients"] = ops
    agh["changed"] = agh["global_changed"] or any(
        o["action"] != "none" for o in ops)
    ctx["agh_ops"] = ops
    ctx["agh_records"] = records
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
    if enabled and not domains:
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
    """Что изменит apply() — без записи."""
    return _public_plan(_compute(get_settings())[0])


# ─────────────────────── применение ──────────────────────────────────

def _write_singbox(mgr, name: str, cfg: dict, prev_text: str) -> dict:
    """check → save → restart (если запущен). Не поднялся после
    рестарта — возвращаем прежний текст и перезапускаем снова."""
    from core.singbox_config import render_conf
    text = render_conf(cfg)
    res = {"config": name, "saved": False, "running": False,
           "restarted": False}
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
    if not mgr.is_running(name):
        return res
    res["running"] = True
    rr = mgr.restart(name)
    if rr.get("ok"):
        res["restarted"] = True
        log.info("agh_routes: sing-box «%s» перезапущен" % name,
                 source=SOURCE)
        return res
    res["error"] = "sing-box «%s» не перезапустился: %s" % (
        name, rr.get("error") or "")
    if prev_text:
        mgr.save_config(name, text=prev_text)
        back = mgr.restart(name)
        res["rolled_back"] = True
        res["error"] += "; прежний конфиг возвращён%s" % (
            "" if back.get("ok") else " (но не запустился)")
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
    applied["singbox"] = {"config": ctx.get("sb_name") or "",
                          "rules": ctx.get("sb_rules") or []}
    _store_applied(applied)

    # 2. AdGuard: клиентам — до смены глобального списка, снятие — после.
    errors = []
    ops = ctx.get("agh_ops") or []

    def _run(op):
        try:
            _agh_call(s, "POST", op["path"], op["body"])
            result["agh"]["clients"].append(
                {"name": op["name"], "action": op["action"]})
            log.info("agh_routes: AdGuard клиент %s: %s"
                     % (op["name"], op["action"]), source=SOURCE)
        except AghError as e:
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
        if op["action"] == "remove":
            _run(op)

    targets = [ctx["target"]]
    if errors:
        # Строки со старой целью могли остаться — помним её до успеха.
        targets = _dedup(targets + list(ctx.get("agh_targets") or []))
    applied["agh"] = {"mode": ctx["mode"], "targets": targets,
                      "clients": ctx.get("agh_records") or []}
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
