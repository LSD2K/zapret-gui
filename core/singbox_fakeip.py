# core/singbox_fakeip.py
"""
FakeIP-роутинг для sing-box — «умный доменный роутинг» (как podkop, но
мультиплатформенно).

Собирает self-contained конфиг: TUN(auto_route) + DNS(FakeIP) + hijack-dns +
domain/cidr route-правила. Домены берём из существующих hostlist-списков
пользователя (те же, что для nfqws) + произвольные домены/подсети из формы.
Прокси-сервер — из вставленной ссылки (vless:// / ss:// / …) или из готового
конфига.

Формат DNS подбираем под версию движка и ПРОВЕРЯЕМ `sing-box check`-ом до
сохранения: legacy (1.8–1.13) или typed (1.12+). См. skill §13.

Точки входа (вызываются из api/singbox.py):
  build_options()  — данные для формы (версия, списки, конфиги, nft).
  build_and_save() — собрать, проверить бинарём, сохранить конфиг.

Фронт-DNS (front_dns): `engine` — sing-box сам DNS всей LAN (перехват :53,
как выше); `external` — впереди AdGuard Home, sing-box слушает upstream
127.0.0.1:1053 и видит только домены из списка AdGuard (см.
docs/gw/spec-b2-fakeip-front.md). Режим external запоминается в
settings.json → singbox.fakeip_front[<имя>], по нему SingboxManager не
трогает DNS-перехват.
"""

from __future__ import annotations

import ipaddress
import os
import re

from core.log_buffer import log


_VER_RE = re.compile(r"(\d+)\.(\d+)")


def _parse_minor(version: str):
    """'1.13.0' → (1, 13). Неразобранное → (0, 0)."""
    m = _VER_RE.search(version or "")
    if not m:
        return (0, 0)
    return (int(m.group(1)), int(m.group(2)))


def dns_format_order(version: str) -> list:
    """
    В каком порядке пробовать форматы DNS: [typed_first, …].

    Окна валидности пересекаются: typed-серверы живут с 1.12, legacy
    (`dns.servers[].address`) — по 1.13 включительно, в 1.14 удалён.

    Версия НЕ определилась (бинаря ещё нет) — typed. Раньше здесь брался
    legacy как «самый совместимый», но совместимость успела перевернуться:
    установщик ставит ПОСЛЕДНИЙ релиз, а это 1.14+, где legacy-DNS не
    парсится. Без бинаря проверить конфиг нечем, он сохраняется как есть —
    то есть выбор вслепую становился нерабочим ровно в тот момент, когда
    пользователь доходил до установки.
    """
    ver = _parse_minor(version)
    legacy_first = ver != (0, 0) and ver < (1, 12)
    return [False, True] if legacy_first else [True, False]


# ─────────────────────── proxy resolution ───────────────────────

def _resolve_proxy(proxy_link: str, proxy_config: str) -> dict:
    """Вернуть {ok, outbound} — конкретный прокси-outbound (vless/ss/...)."""
    link = (proxy_link or "").strip()
    if link:
        from core.singbox_subscription import uri_to_outbound
        res = uri_to_outbound(link)
        if not res.get("ok"):
            return {"ok": False,
                    "error": "ссылка не распознана: %s" % res.get("error")}
        return {"ok": True, "outbound": res["outbound"]}

    cfgname = (proxy_config or "").strip()
    if cfgname:
        from core.singbox_manager import get_singbox_manager
        from core.singbox_config import parse_conf
        mgr = get_singbox_manager()
        r = mgr.get_config(cfgname)
        if not r.get("ok"):
            return {"ok": False, "error": "конфиг '%s' не найден" % cfgname}
        cfg = r.get("parsed") or parse_conf(r.get("text") or "{}")
        for ob in (cfg.get("outbounds") or []):
            if (isinstance(ob, dict)
                    and ob.get("type") not in ("direct", "block", "dns",
                                               "selector", "urltest")
                    and ob.get("server")):
                return {"ok": True, "outbound": dict(ob)}
        return {"ok": False,
                "error": "в конфиге '%s' нет простого прокси-сервера — "
                         "вставьте ссылку vless://…" % cfgname}

    return {"ok": False,
            "error": "укажите ссылку на прокси или существующий конфиг"}


# Спец-выходы, удалённые в sing-box 1.13: из чужого конфига не переносим
# (route-правила источника не копируются, ссылаться на них некому).
_DROPPED_OUTBOUND_TYPES = ("block", "dns")


def _resolve_proxy_set(proxy_link: str, proxy_config: str) -> dict:
    """
    Режим external: {ok, outbounds, endpoints} — все выходы прокси.

    Ссылка → один outbound (тег из ссылки; пустой или `direct` → `proxy`).
    Конфиг → все его outbounds и endpoints как есть, кроме удалённых в 1.13
    block/dns. Selector proxy-out достраивает сборщик
    (singbox_config.fakeip_external_outbounds).
    """
    link = (proxy_link or "").strip()
    if link:
        from core.singbox_subscription import uri_to_outbound
        res = uri_to_outbound(link)
        if not res.get("ok"):
            return {"ok": False,
                    "error": "ссылка не распознана: %s" % res.get("error")}
        ob = dict(res["outbound"])
        if (ob.get("tag") or "") in ("", "direct"):
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
               if isinstance(o, dict) and o.get("type")
               and o.get("type") not in _DROPPED_OUTBOUND_TYPES]
        eps = [dict(e) for e in (cfg.get("endpoints") or [])
               if isinstance(e, dict) and e.get("type")]
        proxies = [o for o in obs if o.get("type") not in ("direct",)]
        if not proxies and not eps:
            return {"ok": False,
                    "error": "в конфиге '%s' нет прокси-outbound'ов — "
                             "вставьте ссылку vless://…" % cfgname}
        return {"ok": True, "outbounds": obs, "endpoints": eps}

    return {"ok": False,
            "error": "укажите ссылку на прокси или существующий конфиг"}


# ─────────────────────── фронт-DNS: settings.json ───────────────────────
#
# singbox.fakeip_front[<имя>] = {"front_dns": "external", "dns_listen": …,
# "dns_port": …}. Пишем только при сборке external, стираем при сборке
# engine под тем же именем и при удалении конфига.

def get_front(name: str) -> dict:
    """Запись фронт-DNS конфига `name` ({} — режим engine/неизвестно)."""
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
    from core.config_manager import get_config_manager
    cm = get_config_manager()
    fronts = cm.get("singbox", "fakeip_front", default={}) or {}
    fronts = dict(fronts) if isinstance(fronts, dict) else {}
    if entry is None:
        if name not in fronts:
            return                       # нечего стирать — settings не трогаем
        fronts.pop(name)
    else:
        if fronts.get(name) == entry:
            return
        fronts[name] = entry
    cm.set("singbox", "fakeip_front", fronts)
    cm.save()


def remember_front(name: str, entry: dict) -> None:
    _store_front(name, dict(entry))


def forget_front(name: str) -> None:
    try:
        _store_front(name, None)
    except Exception as e:
        log.warning("singbox FakeIP: fakeip_front[%s]: %s" % (name, e),
                    source="singbox")


def fakeip_cache_path(name: str, platform=None) -> str:
    """Абсолютный путь cache_file для режима external:
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


# ─────────────────────── options for the form ───────────────────────

def build_options() -> dict:
    from core.singbox_detector import get_singbox_detector
    from core.singbox_manager import get_singbox_manager
    from core.singbox_platform import detect_singbox_platform
    from core.hostlist_manager import get_hostlist_manager

    det = get_singbox_detector().detect_binary()
    mgr = get_singbox_manager()
    hm = get_hostlist_manager()

    stats = hm.get_stats()
    hostlists = [{"name": n, "count": stats[n]["count"]}
                 for n in hm.list_names() if n in stats]

    try:
        configs = [c["name"] for c in mgr.list_configs()]
    except Exception:
        configs = []

    nft = False
    try:
        nft = bool(detect_singbox_platform().supports_nftables())
    except Exception:
        pass

    from core.singbox_config import (
        FAKEIP_FRONT_MODES, EXTERNAL_DNS_LISTEN, EXTERNAL_DNS_PORT,
        EXTERNAL_DIRECT_DNS, EXTERNAL_TUN_ADDRESS)
    fronts = {n: get_front(n) for n in configs if get_front(n)}

    return {
        "ok": True,
        "installed": bool(det.get("installed")),
        "version": det.get("version") or "",
        "nft": nft,
        "hostlists": hostlists,
        "configs": configs,
        "default_direct_dns": "local",
        "fakeip_range": "198.18.0.0/15",
        # Фронт-DNS: engine (sing-box перехватывает DNS LAN) | external
        # (AdGuard Home впереди, sing-box — его upstream для доменов списка).
        "front_dns": "engine",
        "front_dns_modes": list(FAKEIP_FRONT_MODES),
        "engine_defaults": {"dns_port": 1153, "direct_dns": "local"},
        "external_defaults": {
            "dns_listen": EXTERNAL_DNS_LISTEN,
            "dns_port": EXTERNAL_DNS_PORT,
            "direct_dns": EXTERNAL_DIRECT_DNS,
            "tun_address": EXTERNAL_TUN_ADDRESS,
            "stack": "system",
        },
        "fronts": fronts,
    }


# ─────────────────────── build + validate + save ───────────────────────

def build_and_save(*, name: str = "fakeip", proxy_link: str = "",
                   proxy_config: str = "", hostlists=None, domains=None,
                   cidrs=None, direct_dns: str = None,
                   route_all: bool = False, tun_iface: str = "singbox-tun",
                   stack: str = "system", capture_dns: bool = True,
                   dns_port: int = None, front_dns: str = "engine",
                   dns_listen: str = "127.0.0.1",
                   tun_address: str = "") -> dict:
    """
    Собрать, проверить `sing-box check` и сохранить FakeIP-конфиг.

    front_dns='engine' — как раньше (dns_port по умолчанию 1153, direct_dns
    local, перехват :53 по capture_dns). front_dns='external' —
    _build_external_and_save: dns_listen:dns_port (по умолчанию
    127.0.0.1:1053) как upstream для AdGuard, direct_dns по умолчанию
    https://1.1.1.1/dns-query, capture_dns/route_all/cidrs игнорируются.
    """
    from core.singbox_config import (
        build_fakeip_config, render_conf, FAKEIP_FRONT_MODES)
    from core.singbox_manager import get_singbox_manager
    from core.singbox_platform import detect_singbox_platform
    from core.singbox_detector import get_singbox_detector
    from core.hostlist_manager import get_hostlist_manager

    name = (name or "fakeip").strip()
    tun_iface = (tun_iface or "singbox-tun").strip()[:15]

    front = (front_dns or "engine").strip().lower()
    if front not in FAKEIP_FRONT_MODES:
        return {"ok": False,
                "error": "front_dns: ожидается %s"
                         % " | ".join(FAKEIP_FRONT_MODES)}
    if front == "external":
        return _build_external_and_save(
            name=name, proxy_link=proxy_link, proxy_config=proxy_config,
            hostlists=hostlists, domains=domains, direct_dns=direct_dns,
            tun_iface=tun_iface, tun_address=tun_address, stack=stack,
            dns_listen=dns_listen, dns_port=dns_port)
    if dns_port is None:
        dns_port = 1153

    pr = _resolve_proxy(proxy_link, proxy_config)
    if not pr.get("ok"):
        return pr
    proxy_outbound = pr["outbound"]

    # Домены: из выбранных hostlist'ов + произвольные из формы.
    hm = get_hostlist_manager()
    proxied = list(domains or [])
    for hl in (hostlists or []):
        try:
            proxied += hm.get_hostlist(hl)
        except Exception:
            pass
    cidrs = [str(c).strip() for c in (cidrs or []) if str(c).strip()]

    if not route_all and not proxied and not cidrs:
        return {"ok": False,
                "error": "выберите списки/домены/подсети для проксирования "
                         "или включите режим «весь трафик»"}

    nft = False
    try:
        nft = bool(detect_singbox_platform().supports_nftables())
    except Exception:
        pass
    # nft: forwarded DNS забирает auto_redirect TUN. iptables (Keenetic):
    # нужен REDIRECT :53 → dns-in порт (его ставит SingboxManager на старте).
    auto_redirect = nft
    fw_capture = bool(capture_dns) and not nft

    def _mk(typed: bool):
        cfg = build_fakeip_config(
            proxy_outbound=proxy_outbound, proxied_domains=proxied,
            proxied_cidrs=cidrs, route_all=route_all, direct_dns=direct_dns,
            tun_iface=tun_iface, stack=stack, auto_redirect=auto_redirect,
            typed_dns=typed, capture_dns=fw_capture, dns_port=dns_port)
        return render_conf(cfg)

    # Порядок форматов — см. dns_format_order (typed везде, кроме заведомо
    # старого бинаря: legacy-DNS удалён в 1.14, а ставим мы последний релиз).
    order = dns_format_order(
        get_singbox_detector().detect_binary().get("version"))

    mgr = get_singbox_manager()
    chosen_text, fmt, warning = None, "", ""
    last_err = ""
    for typed in order:
        text = _mk(typed)
        chk = mgr.check_text(text)
        if chk.get("no_binary"):
            # Проверить нечем — берём первый из dns_format_order.
            chosen_text = text
            fmt = "typed" if typed else "legacy"
            warning = "sing-box не установлен — конфиг сохранён без проверки"
            break
        if chk.get("ok"):
            chosen_text = text
            fmt = "typed" if typed else "legacy"
            break
        last_err = chk.get("error") or last_err

    if chosen_text is None:
        return {"ok": False,
                "error": "sing-box отверг сгенерированный конфиг: %s"
                         % (last_err or "неизвестная ошибка")}

    save = mgr.save_config(name, text=chosen_text)
    if not save.get("ok"):
        return {"ok": False, "error": save.get("error")}
    # Имя раньше могло быть собрано в режиме external — снять отметку, иначе
    # менеджер не поставит этому конфигу перехват :53.
    forget_front(name)

    fakeip_on = (not route_all) and bool(proxied)
    if nft and capture_dns:
        dns_capture = "auto_redirect"     # TUN auto_redirect сам ловит :53
    elif fw_capture:
        dns_capture = "iptables-redirect"  # REDIRECT :53 ставит менеджер на up
    else:
        dns_capture = "manual"             # LAN-клиенты должны слать DNS на роутер
    log.info("singbox FakeIP: конфиг '%s' создан (формат=%s, домены=%d, "
             "подсети=%d, режим=%s, dns=%s)"
             % (name, fmt, len(proxied), len(cidrs),
                "всё" if route_all else "выборочно", dns_capture),
             source="singbox")
    return {
        "ok": True, "name": name, "dns_format": fmt, "fakeip": fakeip_on,
        "route_all": bool(route_all), "domains": len(proxied),
        "cidrs": len(cidrs), "auto_redirect": auto_redirect,
        "dns_capture": dns_capture,
        "warning": warning,
        "warnings": save.get("warnings") or [],
    }


def adguard_upstream_line(domains, dns_listen: str, dns_port: int) -> str:
    """
    Строка upstream'а для AdGuard Home: `[/a.com/b.org/]127.0.0.1:1053`.
    Без доменов — шаблон `[/домен/]…` (подсказка для ручной настройки).
    """
    host = dns_listen if ":" not in dns_listen else "[%s]" % dns_listen
    doms = "/".join(domains) if domains else "домен"
    return "[/%s/]%s:%d" % (doms, host, int(dns_port))


def _build_external_and_save(*, name, proxy_link, proxy_config, hostlists,
                             domains, direct_dns, tun_iface, tun_address,
                             stack, dns_listen, dns_port) -> dict:
    """
    Режим front_dns='external' (AdGuard Home впереди). Конфиг только typed
    (1.12+): default_domain_resolver и predefined-ответ в legacy нет.

    Домены из списков/формы в конфиг не попадают (их отбирает AdGuard) — из
    них собирается только строка upstream'а для AdGuard. Режим запоминается в
    settings.json (singbox.fakeip_front), каталог cache_file создаётся здесь.
    """
    from core.singbox_config import (
        build_fakeip_config, render_conf, parse_direct_dns,
        _norm_suffix_domains, EXTERNAL_DNS_LISTEN, EXTERNAL_DNS_PORT,
        EXTERNAL_DIRECT_DNS, EXTERNAL_TUN_ADDRESS)
    from core.singbox_manager import get_singbox_manager
    from core.hostlist_manager import get_hostlist_manager

    listen = (dns_listen or "").strip() or EXTERNAL_DNS_LISTEN
    try:
        ipaddress.ip_address(listen)
    except ValueError:
        return {"ok": False,
                "error": "адрес DNS-листенера: нужен IP, получено %r" % listen}
    try:
        port = int(dns_port) if dns_port not in (None, "") \
            else EXTERNAL_DNS_PORT
    except (TypeError, ValueError):
        return {"ok": False, "error": "порт DNS: нужно число"}
    if not 1 <= port <= 65535:
        return {"ok": False, "error": "порт DNS вне диапазона 1–65535"}

    dd = (direct_dns or "").strip() or EXTERNAL_DIRECT_DNS
    if parse_direct_dns(dd) is None:
        return {"ok": False,
                "error": "прямой DNS не распознан: %r (например %s, "
                         "tls://1.1.1.1, 1.1.1.1:53)" % (dd, EXTERNAL_DIRECT_DNS)}
    warnings = []
    if dd == "local":
        # Системный резолвер на gw — это сам AdGuard: запросы sing-box по
        # доменам из списка (HTTPS/TXT/…) вернутся в sing-box по кругу.
        warnings.append("прямой DNS = local: системный резолвер, скорее всего, "
                        "и есть AdGuard, для доменов из списка получится "
                        "петля; лучше %s" % EXTERNAL_DIRECT_DNS)

    addr = (tun_address or "").strip() or EXTERNAL_TUN_ADDRESS
    try:
        ipaddress.ip_interface(addr)
    except ValueError:
        return {"ok": False, "error": "адрес TUN: нужен CIDR, получено %r"
                                      % addr}

    pr = _resolve_proxy_set(proxy_link, proxy_config)
    if not pr.get("ok"):
        return pr

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
        cfg = build_fakeip_config(
            proxy_outbound=None, proxy_outbounds=pr["outbounds"],
            proxy_endpoints=pr["endpoints"], front_dns="external",
            direct_dns=dd, dns_listen=listen, dns_port=port,
            tun_iface=tun_iface, tun_address=[addr],
            stack=stack or "system", typed_dns=True, cache_path=cache_path)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    text = render_conf(cfg)

    mgr = get_singbox_manager()
    warning = ""
    chk = mgr.check_text(text)
    if chk.get("no_binary"):
        warning = "sing-box не установлен — конфиг сохранён без проверки"
    elif not chk.get("ok"):
        return {"ok": False,
                "error": "sing-box отверг сгенерированный конфиг: %s"
                         % (chk.get("error") or "неизвестная ошибка")}

    save = mgr.save_config(name, text=text)
    if not save.get("ok"):
        return {"ok": False, "error": save.get("error")}
    warnings += save.get("warnings") or []

    try:
        os.makedirs(os.path.dirname(cache_path), exist_ok=True)
    except OSError as e:
        warnings.append("каталог кэша %s: %s"
                        % (os.path.dirname(cache_path), e))

    try:
        remember_front(name, {"front_dns": "external", "dns_listen": listen,
                              "dns_port": port})
    except Exception as e:
        # Без отметки менеджер на iptables-платформе поставил бы REDIRECT :53.
        return {"ok": False,
                "error": "конфиг сохранён, но режим не записан в settings: %s"
                         % e}

    upstream = adguard_upstream_line(proxied, listen, port)
    n_out = len([o for o in cfg["outbounds"]
                 if o.get("type") not in ("direct", "selector", "urltest")])
    log.info("singbox FakeIP: конфиг '%s' создан (фронт-DNS внешний, "
             "dns-in %s:%d, прокси=%d, домены для AdGuard=%d)"
             % (name, listen, port, n_out + len(cfg.get("endpoints") or []),
                len(proxied)), source="singbox")
    return {
        "ok": True, "name": name, "front_dns": "external",
        "dns_format": "typed", "fakeip": True, "route_all": False,
        "domains": len(proxied), "cidrs": 0, "auto_redirect": False,
        "dns_capture": "external",
        "dns_listen": listen, "dns_port": port, "direct_dns": dd,
        "tun_address": addr, "cache_path": cache_path,
        "proxies": n_out + len(cfg.get("endpoints") or []),
        "adguard_upstream": upstream,
        "warning": warning,
        "warnings": warnings,
    }


# ─────────────────────── lite-route (kernel-стек, low-CPU) ───────────────

def build_lite_route_and_save(*, name: str = "lite-route", proxy_link: str = "",
                              proxy_config: str = "", source_ips=None,
                              route_all: bool = False, reject_quic: bool = False,
                              tun_iface: str = "singbox-tun") -> dict:
    """
    Собрать конфиг маршрутизации на KERNEL-стеке (auto_route + system +
    source_ip_cidr внутри движка) — низкий CPU, без gvisor. См.
    core.singbox_config.build_system_route_config.
    """
    import secrets
    from core.singbox_config import (
        build_system_route_config, render_conf, ensure_clash_api)
    from core.singbox_manager import get_singbox_manager
    from core.singbox_platform import detect_singbox_platform
    from core.singbox_detector import get_singbox_detector
    from core.proxy_tester import _free_port

    name = (name or "lite-route").strip()
    tun_iface = (tun_iface or "singbox-tun").strip()[:15]

    pr = _resolve_proxy(proxy_link, proxy_config)
    if not pr.get("ok"):
        return pr
    proxy_outbound = pr["outbound"]

    srcs = [str(s).strip() for s in (source_ips or []) if str(s).strip()]
    if not route_all and not srcs:
        return {"ok": False,
                "error": "укажите IP устройств (source_ip) или включите"
                         " режим «весь трафик»"}

    nft = False
    try:
        nft = bool(detect_singbox_platform().supports_nftables())
    except Exception:
        pass

    def _mk(typed: bool):
        cfg = build_system_route_config(
            proxy_outbound=proxy_outbound, source_ips=srcs,
            route_all=route_all, tun_iface=tun_iface, typed_dns=typed,
            reject_quic=reject_quic, auto_redirect=nft)
        try:
            ensure_clash_api(cfg, port=_free_port(),
                             secret=secrets.token_hex(8))
        except Exception:
            pass
        return render_conf(cfg)

    order = dns_format_order(
        get_singbox_detector().detect_binary().get("version"))

    mgr = get_singbox_manager()
    chosen_text, fmt, warning, last_err = None, "", "", ""
    for typed in order:
        text = _mk(typed)
        chk = mgr.check_text(text)
        if chk.get("no_binary"):
            chosen_text, fmt = text, ("typed" if typed else "legacy")
            warning = "sing-box не установлен — конфиг сохранён без проверки"
            break
        if chk.get("ok"):
            chosen_text, fmt = text, ("typed" if typed else "legacy")
            break
        last_err = chk.get("error") or last_err

    if chosen_text is None:
        return {"ok": False,
                "error": "sing-box отверг сгенерированный конфиг: %s"
                         % (last_err or "неизвестная ошибка")}

    save = mgr.save_config(name, text=chosen_text)
    if not save.get("ok"):
        return {"ok": False, "error": save.get("error")}

    log.info("singbox lite-route: конфиг '%s' создан (формат=%s, source=%d,"
             " режим=%s, auto_redirect=%s)"
             % (name, fmt, len(srcs), "всё" if route_all else "выборочно",
                nft), source="singbox")
    return {
        "ok": True, "name": name, "dns_format": fmt, "stack": "system",
        "route_all": bool(route_all), "sources": len(srcs),
        "auto_redirect": nft, "warning": warning,
        "warnings": save.get("warnings") or [],
    }
