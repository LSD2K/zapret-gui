# core/singbox_fakeip_front.py
"""
FakeIP за внешним фронт-DNS (форк debian-gw, docs/gw/spec-b2-fakeip-front.md).

Режим `front_dns="external"`: DNS всей LAN остаётся у AdGuard Home, а он для
доменов из списка ходит в sing-box как в upstream (`[/домен/]127.0.0.1:1053`).
sing-box отвечает fakeip на A, пустым NOERROR на AAAA/HTTPS/SVCB, остальное
резолвит прямым DNS. Маршрут 198.18.0.0/15 в TUN ставится снаружи (networkd),
поэтому TUN без auto_route и никакого перехвата :53.

Модуль отдельный, чтобы не раздувать апстримные singbox_config/singbox_fakeip
(правило форка: минимум диффов в чужих файлах). Там только хуки:
  singbox_config.build_fakeip_config(front_dns=...) → build_config_hook
  singbox_fakeip.build_and_save(front_dns=...)      → build_and_save_front
  singbox_fakeip.build_options()                     → form_options
  SingboxManager._config_dns_in_port / delete_config → is_external_front /
                                                       forget_front

Режим конфига хранится в settings.json → singbox.fakeip_front[<имя>] =
{"front_dns": "external", "dns_listen": ..., "dns_port": ...}: по нему
менеджер не ставит REDIRECT :53 на up и не снимает чужой перехват на down.
"""

from __future__ import annotations

import ipaddress
import json
import os
import subprocess

from core.log_buffer import log


FAKEIP_FRONT_MODES = ("engine", "external")

EXTERNAL_DEFAULT_NAME = "fakeip-agh"
EXTERNAL_DNS_LISTEN = "127.0.0.1"
EXTERNAL_DNS_PORT = 1053
EXTERNAL_DIRECT_DNS = "https://1.1.1.1/dns-query"
EXTERNAL_TUN_ADDRESS = "172.19.0.1/30"
EXTERNAL_CACHE_PATH = "/var/lib/sing-box/cache.db"

# Строка upstream'а для AdGuard: по столько доменов в одной строке, чтобы
# её можно было читать и вставлять кусками.
ADGUARD_UPSTREAM_CHUNK = 40

# Удалены в sing-box 1.13, из чужого конфига не переносим.
_DROPPED_OUTBOUND_TYPES = ("block", "dns")
_GROUP_TYPES = ("selector", "urltest")
_DEFAULT_DNS_PORTS = {"udp": 53, "tls": 853, "https": 443}


# ─────────────────────── проверка ввода ───────────────────────

def norm_listen(value) -> str:
    """Адрес dns-in: только IP-литерал, иначе ValueError."""
    s = str(value if value is not None else "").strip().strip("[]") \
        or EXTERNAL_DNS_LISTEN
    try:
        return str(ipaddress.ip_address(s))
    except ValueError:
        raise ValueError("адрес DNS-листенера: нужен IP, получено %r" % s)


def norm_port(value) -> int:
    """Порт dns-in: 1–65535, пусто → 1053. bool не порт (True == 1)."""
    if value is None or value == "":
        return EXTERNAL_DNS_PORT
    if isinstance(value, bool):
        raise ValueError("порт DNS: нужно число, получено %r" % value)
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ValueError("порт DNS: нужно число, получено %r" % value)
    if not 1 <= port <= 65535:
        raise ValueError("порт DNS вне диапазона 1–65535: %d" % port)
    return port


def norm_tun_address(value) -> str:
    """Адрес TUN: CIDR с явным префиксом, в каноническом виде."""
    s = str(value if value is not None else "").strip() or EXTERNAL_TUN_ADDRESS
    if "/" not in s:
        raise ValueError("адрес TUN: нужен CIDR с префиксом (например %s), "
                         "получено %r" % (EXTERNAL_TUN_ADDRESS, s))
    try:
        return str(ipaddress.ip_interface(s))
    except ValueError:
        raise ValueError("адрес TUN: нужен CIDR, получено %r" % s)


# ─────────────────────── сборка конфига ───────────────────────

def _resolver_tag(value) -> str:
    if isinstance(value, dict):
        return str(value.get("server") or "")
    return str(value or "")


def fakeip_external_outbounds(outbounds, endpoints=None, dns_tags=None):
    """
    Набор выходов для режима external (п.3 спеки): (outbounds, endpoints).

    Outbound'ы и endpoint'ы копируются как есть, кроме:
      - block/dns (удалены в 1.13) выбрасываются;
      - без тега → `proxy`/`proxy-2`/…; повтор тега даёт ValueError (sing-box
        всё равно не стартует, а так видно, в чём дело);
      - `domain_resolver` с тегом, которого нет среди dns_tags, снимается
        (из чужого конфига DNS-серверы не переносятся);
      - в selector/urltest только существующие теги, без повторов;
        группа без членов выбрасывается, `default` вне членов снимается.
    Если тега `proxy-out` нет, добавляется `selector` proxy-out: сначала
    группы, потом серверы, потом endpoint'ы; по умолчанию первый. Он встаёт
    перед первым direct. `direct` добавляется, если такого тега нет.
    """
    obs = [json.loads(json.dumps(o)) for o in (outbounds or [])
           if isinstance(o, dict) and o.get("type")
           and o.get("type") not in _DROPPED_OUTBOUND_TYPES]
    eps = [json.loads(json.dumps(e)) for e in (endpoints or [])
           if isinstance(e, dict) and e.get("type")]

    taken = {o.get("tag") for o in obs + eps if o.get("tag")}
    n = 1
    for o in obs + eps:
        if not o.get("tag"):
            while ("proxy" if n == 1 else "proxy-%d" % n) in taken:
                n += 1
            o["tag"] = "proxy" if n == 1 else "proxy-%d" % n
            taken.add(o["tag"])
    seen = set()
    for o in obs + eps:
        tag = o["tag"]
        if tag in seen:
            raise ValueError("тег '%s' повторяется у outbound/endpoint" % tag)
        seen.add(tag)
        if tag == "direct" and o.get("type") != "direct":
            raise ValueError("тег 'direct' занят outbound'ом типа %s"
                             % o.get("type"))

    if dns_tags is not None:
        for o in obs + eps:
            tag = _resolver_tag(o.get("domain_resolver"))
            if tag and tag not in dns_tags:
                o.pop("domain_resolver", None)

    # Группы: чистим членов, пока выбрасывание пустых групп что-то меняет
    # (группа могла ссылаться на другую пустую группу).
    while True:
        tags = {o["tag"] for o in obs + eps}
        kept = []
        for o in obs:
            if o.get("type") in _GROUP_TYPES:
                members = [m for m in dict.fromkeys(o.get("outbounds") or [])
                           if isinstance(m, str) and m in tags
                           and m != o["tag"]]
                if not members:
                    continue
                o["outbounds"] = members
                if o.get("default") and o["default"] not in members:
                    o.pop("default")
            kept.append(o)
        dropped = len(kept) != len(obs)
        obs = kept
        if not dropped:
            break

    tags = [o["tag"] for o in obs + eps]
    if "proxy-out" not in tags:
        groups = [o["tag"] for o in obs if o.get("type") in _GROUP_TYPES]
        leaves = [o["tag"] for o in obs
                  if o.get("type") not in _GROUP_TYPES + ("direct",)]
        members = list(dict.fromkeys(groups + leaves + [e["tag"] for e in eps]))
        if not members:
            raise ValueError("нет ни одного прокси-outbound'а")
        at = next((i for i, o in enumerate(obs) if o.get("type") == "direct"),
                  len(obs))
        obs.insert(at, {"type": "selector", "tag": "proxy-out",
                        "outbounds": members, "default": members[0]})
    if "direct" not in tags:
        obs.append({"type": "direct", "tag": "direct"})
    return obs, eps


def build_fakeip_external_config(*, proxy_outbounds, proxy_endpoints=None,
                                 direct_dns: str = EXTERNAL_DIRECT_DNS,
                                 dns_listen: str = EXTERNAL_DNS_LISTEN,
                                 dns_port: int = EXTERNAL_DNS_PORT,
                                 tun_iface: str = "singbox-tun",
                                 tun_address=None,
                                 stack: str = "system",
                                 cache_path: str = "") -> dict:
    """
    FakeIP за внешним фронт-DNS (п.1 спеки B2).

    dns-in (direct, только UDP) на dns_listen:dns_port всегда, без перехвата
    :53. DNS: AAAA, HTTPS и SVCB → пустой NOERROR (IPv6 в сети нет, а
    ipv4hint из HTTPS-записи, пришедший через DoH, увёл бы клиента на
    настоящий IP мимо fakeip), A → fakeip, остальное → прямой DNS (typed,
    1.12+). TUN без auto_route/strict_route/auto_redirect; всё из TUN →
    proxy-out, остальное → direct.

    Намеренно НЕТ: domain_suffix-правил fakeip (домены отбирает AdGuard),
    `ip_is_private → direct` (fakeip-диапазон приватный, правило утянуло бы
    всё в direct), mtu у TUN. Доменные правила `domain_suffix → <outbound>`
    добавляет отдельный модуль через insert_route_rule_after_managed(): они
    встают после sniff/hijack-dns и перед правилом `inbound: tun-in`.

    `default_domain_resolver` = dns-direct всегда (1.14 без него не стартует).
    `cache_file.path` абсолютный. ValueError на непригодный ввод.
    """
    from core.singbox_config import (
        make_direct_dns_servers, make_sniff_rule, make_hijack_dns_rule,
        FAKEIP_INET4, FAKEIP_INET6)

    servers = make_direct_dns_servers(direct_dns)
    if servers is None:
        raise ValueError("прямой DNS не распознан: %r (ожидается local, IP, "
                         "IP:порт, udp://, tls:// или https://)" % direct_dns)
    dns_tags = {s["tag"] for s in servers} | {"dns-fakeip"}
    obs, eps = fakeip_external_outbounds(proxy_outbounds, proxy_endpoints,
                                         dns_tags=dns_tags)

    if isinstance(tun_address, (list, tuple)):
        addrs = [norm_tun_address(a) for a in tun_address if str(a).strip()]
    else:
        addrs = [norm_tun_address(tun_address)] if tun_address else []
    tun = {
        "type": "tun",
        "tag": "tun-in",
        "interface_name": tun_iface or "singbox-tun",
        "address": addrs or [EXTERNAL_TUN_ADDRESS],
        "auto_route": False,
        "strict_route": False,
        "stack": stack or "system",
    }
    dns_in = {"type": "direct", "tag": "dns-in",
              "listen": norm_listen(dns_listen),
              "listen_port": norm_port(dns_port), "network": "udp"}

    cfg = {
        "log": {"level": "info"},
        "dns": {
            "servers": [servers[0],
                        {"type": "fakeip", "tag": "dns-fakeip",
                         "inet4_range": FAKEIP_INET4,
                         "inet6_range": FAKEIP_INET6}] + servers[1:],
            "rules": [
                {"query_type": ["AAAA"], "action": "predefined",
                 "rcode": "NOERROR"},
                {"query_type": ["HTTPS", "SVCB"], "action": "predefined",
                 "rcode": "NOERROR"},
                {"query_type": ["A"], "server": "dns-fakeip"},
            ],
            "final": "dns-direct",
        },
        "inbounds": [dns_in, tun],
        "outbounds": obs,
    }
    if eps:
        cfg["endpoints"] = eps
    cfg["route"] = {
        "rules": [
            make_sniff_rule(),
            make_hijack_dns_rule(),
            {"inbound": ["tun-in"], "outbound": "proxy-out"},
        ],
        "final": "direct",
        "auto_detect_interface": True,
        "default_domain_resolver": "dns-direct",
    }
    cfg["experimental"] = {
        "cache_file": {"enabled": True,
                       "path": cache_path or EXTERNAL_CACHE_PATH,
                       "store_fakeip": True},
    }
    return cfg


def build_config_hook(front_dns, *, proxy_outbound=None,
                      direct_dns=EXTERNAL_DIRECT_DNS, tun_iface="singbox-tun",
                      tun_address=None, stack="system", dns_port=None,
                      dns_listen=EXTERNAL_DNS_LISTEN, cache_path="",
                      proxy_outbounds=None, proxy_endpoints=None) -> dict:
    """Хук singbox_config.build_fakeip_config для front_dns != engine."""
    if front_dns not in FAKEIP_FRONT_MODES or front_dns == "engine":
        raise ValueError("front_dns: ожидается %s"
                         % " | ".join(FAKEIP_FRONT_MODES))
    obs = proxy_outbounds
    if obs is None:
        obs = [proxy_outbound] if proxy_outbound else []
    return build_fakeip_external_config(
        proxy_outbounds=obs, proxy_endpoints=proxy_endpoints,
        direct_dns=direct_dns, dns_listen=dns_listen,
        dns_port=EXTERNAL_DNS_PORT if dns_port is None else dns_port,
        tun_iface=tun_iface, tun_address=tun_address, stack=stack,
        cache_path=cache_path)


# ─────────────────────── settings.json: режим конфига ───────────────────────

def get_front(name: str) -> dict:
    """Запись фронт-DNS конфига `name` ({} для engine или неизвестного)."""
    try:
        from core.config_manager import get_config_manager
        fronts = get_config_manager().get(
            "singbox", "fakeip_front", default={}) or {}
        ent = fronts.get(name) if isinstance(fronts, dict) else None
        return dict(ent) if isinstance(ent, dict) else {}
    except Exception:
        return {}


def is_external_front(name: str) -> bool:
    """Конфиг собран с внешним фронт-DNS → DNS-перехват :53 не нужен."""
    return get_front(name).get("front_dns") == "external"


def _store_front(name: str, entry) -> None:
    """Записать (entry=None: стереть) отметку и сохранить settings.json.
    RuntimeError, если файл не записался; в памяти тогда прежнее значение."""
    from core.config_manager import get_config_manager
    cm = get_config_manager()
    before = cm.get("singbox", "fakeip_front", default={}) or {}
    fronts = dict(before) if isinstance(before, dict) else {}
    if entry is None:
        if name not in fronts:
            return                       # нечего стирать, settings не трогаем
        fronts.pop(name)
    else:
        if fronts.get(name) == entry:
            return
        fronts[name] = dict(entry)
    cm.set("singbox", "fakeip_front", fronts)
    if not cm.save():
        cm.set("singbox", "fakeip_front", before)
        raise RuntimeError("не удалось записать settings.json")


def remember_front(name: str, entry: dict) -> None:
    _store_front(name, entry)


def forget_front(name: str) -> None:
    _store_front(name, None)


def clear_front(name: str) -> str:
    """Снять отметку перед сборкой engine под тем же именем. '' или ошибка:
    без этого менеджер не поставил бы engine-конфигу перехват :53."""
    try:
        forget_front(name)
    except Exception as e:
        return ("конфиг '%s' помечен как собранный с внешним фронт-DNS, а "
                "снять отметку не удалось: %s" % (name, e))
    return ""


def fakeip_cache_path(name: str, platform=None) -> str:
    """Абсолютный путь cache_file:
    <platform.data_dir | run_dir | /var/lib/sing-box>/cache-<name>.db."""
    if platform is None:
        try:
            from core.singbox_platform import detect_singbox_platform
            platform = detect_singbox_platform()
        except Exception:
            platform = None
    base = (getattr(platform, "data_dir", "") or
            getattr(platform, "run_dir", "") or "/var/lib/sing-box")
    return os.path.join(base, "cache-%s.db" % name)


# ─────────────────────── подсказки ───────────────────────

def _host_port(host: str, port: int) -> str:
    return "%s:%d" % ("[%s]" % host if ":" in host else host, int(port))


def adguard_upstream_lines(domains, dns_listen: str, dns_port: int,
                           chunk: int = ADGUARD_UPSTREAM_CHUNK) -> list:
    """Строки upstream'а для AdGuard: `[/a.com/b.org/]127.0.0.1:1053`, по
    `chunk` доменов в строке. Без доменов []."""
    target = _host_port(dns_listen, dns_port)
    doms = list(domains or [])
    return ["[/%s/]%s" % ("/".join(doms[i:i + chunk]), target)
            for i in range(0, len(doms), chunk)]


def _host_addresses() -> set:
    """IP-адреса интерфейсов этого хоста (`ip -o addr`); set(), если не вышло."""
    try:
        r = subprocess.run(["ip", "-o", "addr", "show"], capture_output=True,
                           text=True, timeout=3)
    except (OSError, subprocess.SubprocessError):
        return set()
    if r.returncode != 0:
        return set()
    out = set()
    for line in (r.stdout or "").splitlines():
        parts = line.split()
        for i, tok in enumerate(parts):
            if tok in ("inet", "inet6") and i + 1 < len(parts):
                try:
                    out.add(ipaddress.ip_interface(parts[i + 1]).ip)
                except ValueError:
                    pass
                break
    return out


def direct_dns_problems(direct_dns: str, dns_listen: str, dns_port: int,
                        own=None):
    """
    (ошибки, предупреждения) про петли прямого DNS в режиме external.

    Системный резолвер и DNS на самом хосте (loopback, адреса интерфейсов)
    на gw это AdGuard: для доменов из списка он снова спросит sing-box,
    получится петля. Прямой DNS, указывающий на сам dns-in, это ошибка.
    """
    from core.singbox_config import parse_direct_dns
    errors, warnings = [], []
    srv = parse_direct_dns(direct_dns)
    if srv is None:
        return errors, warnings
    loop_hint = ("для доменов из списка получится петля через AdGuard; "
                 "лучше %s" % EXTERNAL_DIRECT_DNS)
    if srv["type"] == "local":
        warnings.append("прямой DNS = local: системный резолвер, скорее всего, "
                        "и есть AdGuard, " + loop_hint)
        return errors, warnings
    try:
        ip = ipaddress.ip_address(srv.get("server", ""))
    except ValueError:
        return errors, warnings          # имя: резолвит bootstrap, не судим
    own = _host_addresses() if own is None else set(own)
    local_ip = ip.is_loopback or ip in own or ip.is_unspecified
    port = srv.get("server_port") or _DEFAULT_DNS_PORTS[srv["type"]]
    listen = ipaddress.ip_address(dns_listen)
    hits_dns_in = (srv["type"] == "udp" and port == int(dns_port) and
                   (ip == listen or (listen.is_unspecified and local_ip)))
    if hits_dns_in:
        errors.append("прямой DNS %s это сам dns-in sing-box: запросы "
                      "пойдут по кругу" % _host_port(str(ip), port))
    elif local_ip and port in _DEFAULT_DNS_PORTS.values():
        warnings.append("прямой DNS %s это сам хост (там, скорее всего, "
                        "AdGuard): %s" % (_host_port(str(ip), port), loop_hint))
    return errors, warnings


def listen_warnings(dns_listen: str) -> list:
    if ipaddress.ip_address(dns_listen).is_loopback:
        return []
    return ["dns-in слушает %s, а не loopback: sing-box с FakeIP виден из "
            "сети; AdGuard на этом же хосте достаточно %s"
            % (dns_listen, EXTERNAL_DNS_LISTEN)]


def form_options(configs) -> dict:
    """Добавка к singbox_fakeip.build_options(): режимы и их дефолты."""
    return {
        # Фронт-DNS: engine (sing-box перехватывает DNS LAN) | external
        # (AdGuard Home впереди, sing-box его upstream для доменов списка).
        "front_dns": "engine",
        "front_dns_modes": list(FAKEIP_FRONT_MODES),
        "engine_defaults": {"name": "fakeip", "dns_port": 1153,
                            "direct_dns": "local"},
        "external_defaults": {
            "name": EXTERNAL_DEFAULT_NAME,
            "dns_listen": EXTERNAL_DNS_LISTEN,
            "dns_port": EXTERNAL_DNS_PORT,
            "direct_dns": EXTERNAL_DIRECT_DNS,
            "tun_address": EXTERNAL_TUN_ADDRESS,
            "stack": "system",
        },
        "fronts": {n: get_front(n) for n in (configs or []) if get_front(n)},
    }


# ─────────────────────── прокси ───────────────────────

def _resolve_proxy_set(proxy_link: str, proxy_config: str) -> dict:
    """
    {ok, outbounds, endpoints}: все выходы прокси.

    Ссылка → один outbound (тег из ссылки; пустой или `direct` → `proxy`).
    Конфиг → все его outbounds и endpoints как есть; чистка (block/dns,
    чужие domain_resolver, битые члены групп) и selector proxy-out: в
    fakeip_external_outbounds.
    """
    link = (proxy_link or "").strip()
    if link:
        from core.singbox_subscription import uri_to_outbound
        res = uri_to_outbound(link)
        if not res.get("ok"):
            return {"ok": False,
                    "error": "ссылка не распознана: %s" % res.get("error")}
        ob = dict(res["outbound"])
        if (ob.get("tag") or "") in ("", "direct", "proxy-out"):
            ob["tag"] = "proxy"
        return {"ok": True, "outbounds": [ob], "endpoints": []}

    cfgname = (proxy_config or "").strip()
    if cfgname:
        from core.singbox_manager import get_singbox_manager
        from core.singbox_config import parse_conf
        r = get_singbox_manager().get_config(cfgname)
        if not r.get("ok"):
            return {"ok": False, "error": "конфиг '%s' не найден" % cfgname}
        cfg = r.get("parsed") or parse_conf(r.get("text") or "{}")
        obs = [dict(o) for o in (cfg.get("outbounds") or [])
               if isinstance(o, dict) and o.get("type")]
        eps = [dict(e) for e in (cfg.get("endpoints") or [])
               if isinstance(e, dict) and e.get("type")]
        leaves = [o for o in obs if o.get("type") not in
                  _GROUP_TYPES + _DROPPED_OUTBOUND_TYPES + ("direct",)]
        if not leaves and not eps:
            return {"ok": False,
                    "error": "в конфиге '%s' нет прокси-outbound'ов, "
                             "вставьте ссылку vless://…" % cfgname}
        return {"ok": True, "outbounds": obs, "endpoints": eps}

    return {"ok": False,
            "error": "укажите ссылку на прокси или существующий конфиг"}


# ─────────────────────── перехват :53 под тем же именем ───────────────────

def _capture_conflict(mgr, name: str) -> str:
    """Под этим именем ЗАПУЩЕН конфиг с перехватом :53 → текст отказа.

    Пересобрать его на ходу нельзя: после перезаписи менеджер перестанет
    считать конфиг «перехватывающим», и REDIRECT :53 останется без хозяина
    (LAN без DNS). Снимать перехват под живым процессом тоже плохо: FakeIP
    engine-конфига молча перестанет работать. Поэтому отказ."""
    port = mgr._config_dns_in_port(name)
    if port and mgr.is_running(name):
        return ("конфиг '%s' запущен и перехватывает DNS LAN (:53 → %d); "
                "остановите его перед пересборкой с внешним фронт-DNS или "
                "выберите другое имя" % (name, port))
    return ""


def _drop_stale_capture(mgr, name: str, port: int) -> None:
    """Прежний engine-конфиг `name` (не запущен) мог оставить REDIRECT :53
    после падения; раньше его снял бы `down` этого конфига, после пересборки
    уже не снимет. Убираем, только если перехват не нужен другому
    запущенному конфигу."""
    if not port:
        return
    try:
        for c in mgr.list_configs():
            other = c.get("name")
            if (other != name and c.get("running")
                    and mgr._config_dns_in_port(other)):
                return
        mgr._remove_dns_capture()
    except Exception as e:
        log.warning("singbox FakeIP: снять старый перехват :53: %s" % e,
                    source="singbox")


# ─────────────────────── сборка + проверка + запись ───────────────────────

def build_and_save_front(front_dns, *, name="", proxy_link="",
                         proxy_config="", hostlists=None, domains=None,
                         direct_dns=None, tun_iface="singbox-tun",
                         stack="system", dns_port=None,
                         dns_listen=EXTERNAL_DNS_LISTEN,
                         tun_address="") -> dict:
    """
    Хук singbox_fakeip.build_and_save для front_dns != engine.

    Только typed-DNS (1.12+): default_domain_resolver и predefined-ответов в
    legacy нет. Домены из списков/формы в конфиг не попадают (их отбирает
    AdGuard), из них собираются строки upstream'а для AdGuard. Отметка
    режима пишется в settings.json ДО конфига: без неё менеджер на
    iptables-платформе поставил бы REDIRECT :53.
    """
    from core.singbox_config import (
        render_conf, parse_direct_dns, _norm_suffix_domains)
    from core.singbox_manager import get_singbox_manager
    from core.hostlist_manager import get_hostlist_manager

    front = str(front_dns or "").strip().lower()
    if front not in FAKEIP_FRONT_MODES or front == "engine":
        return {"ok": False,
                "error": "front_dns: ожидается %s"
                         % " | ".join(FAKEIP_FRONT_MODES)}
    name = (name or "").strip() or EXTERNAL_DEFAULT_NAME
    tun_iface = (tun_iface or "singbox-tun").strip()[:15]
    try:
        listen = norm_listen(dns_listen)
        port = norm_port(dns_port)
        addr = norm_tun_address(tun_address)
    except ValueError as e:
        return {"ok": False, "error": str(e)}

    dd = (direct_dns or "").strip() or EXTERNAL_DIRECT_DNS
    if parse_direct_dns(dd) is None:
        return {"ok": False,
                "error": "прямой DNS не распознан: %r (например %s, "
                         "tls://1.1.1.1, 1.1.1.1:53)" % (dd, EXTERNAL_DIRECT_DNS)}
    errors, warnings = direct_dns_problems(dd, listen, port)
    if errors:
        return {"ok": False, "error": "; ".join(errors)}
    warnings += listen_warnings(listen)

    pr = _resolve_proxy_set(proxy_link, proxy_config)
    if not pr.get("ok"):
        return pr

    mgr = get_singbox_manager()
    busy = _capture_conflict(mgr, name)
    if busy:
        return {"ok": False, "error": busy}
    stale_port = mgr._config_dns_in_port(name)

    hm = get_hostlist_manager()
    proxied = list(domains or [])
    for hl in (hostlists or []):
        try:
            proxied += hm.get_hostlist(hl)
        except Exception:
            pass
    proxied = _norm_suffix_domains(proxied)

    cache_path = fakeip_cache_path(name)
    try:
        cfg = build_fakeip_external_config(
            proxy_outbounds=pr["outbounds"], proxy_endpoints=pr["endpoints"],
            direct_dns=dd, dns_listen=listen, dns_port=port,
            tun_iface=tun_iface, tun_address=[addr], stack=stack or "system",
            cache_path=cache_path)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    text = render_conf(cfg)

    warning = ""
    chk = mgr.check_text(text)
    if chk.get("no_binary"):
        warning = "sing-box не установлен, конфиг сохранён без проверки"
    elif not chk.get("ok"):
        return {"ok": False,
                "error": "sing-box отверг сгенерированный конфиг: %s"
                         % (chk.get("error") or "неизвестная ошибка")}

    prev = get_front(name)
    try:
        remember_front(name, {"front_dns": front, "dns_listen": listen,
                              "dns_port": port})
    except Exception as e:
        return {"ok": False,
                "error": "режим конфига не записан в settings.json (%s), "
                         "конфиг не сохранён" % e}
    save = mgr.save_config(name, text=text)
    if not save.get("ok"):
        try:
            if prev:
                remember_front(name, prev)
            else:
                forget_front(name)
        except Exception as e:
            log.warning("singbox FakeIP: откат отметки '%s': %s" % (name, e),
                        source="singbox")
        return {"ok": False, "error": save.get("error")}
    warnings += save.get("warnings") or []

    _drop_stale_capture(mgr, name, stale_port)
    try:
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    except OSError as e:
        warnings.append("каталог кэша %s: %s"
                        % (os.path.dirname(cache_path), e))

    n_proxies = len([o for o in cfg["outbounds"]
                     if o.get("type") not in ("direct",) + _GROUP_TYPES])
    n_proxies += len(cfg.get("endpoints") or [])
    log.info("singbox FakeIP: конфиг '%s' создан (фронт-DNS внешний, "
             "dns-in %s, прокси=%d, домены для AdGuard=%d)"
             % (name, _host_port(listen, port), n_proxies, len(proxied)),
             source="singbox")
    return {
        "ok": True, "name": name, "front_dns": front,
        "dns_format": "typed", "fakeip": True, "route_all": False,
        "domains": len(proxied), "cidrs": 0, "auto_redirect": False,
        "dns_capture": "external",
        "dns_listen": listen, "dns_port": port, "direct_dns": dd,
        "tun_address": addr, "cache_path": cache_path,
        "proxies": n_proxies,
        "adguard_upstream": adguard_upstream_lines(proxied, listen, port),
        "adguard_upstream_hint": "[/домен/]%s" % _host_port(listen, port),
        "warning": warning,
        "warnings": warnings,
    }
