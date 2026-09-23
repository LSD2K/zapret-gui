# tests/test_singbox_fakeip_front.py
"""FakeIP с внешним фронт-DNS (docs/gw/spec-b2-fakeip-front.md).

Главный сторож здесь — снапшот режима engine: `tests/fixtures/
singbox_fakeip_engine_snapshot.json` снят с `build_fakeip_config` и
`build_and_save` ДО появления режима external. Новый режим не имеет права
сдвинуть сборку engine ни на байт (Keenetic/OpenWrt пользователи апстрима).
"""

import hashlib
import json
import os
import unittest
from unittest import mock

from core.singbox_config import build_fakeip_config, render_conf


_SNAPSHOT = os.path.join(os.path.dirname(__file__), "fixtures",
                         "singbox_fakeip_engine_snapshot.json")


def _load_snapshot():
    with open(_SNAPSHOT, encoding="utf-8") as f:
        return json.load(f)


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# Единственное осознанное отличие engine от снапшота — п.2 спеки: typed-DNS
# с непустым прямым DNS. Раньше IP давал udp с `detour: direct` (FATAL на
# `run` у 1.12+), а https/tls/ip:port молча превращались в `local`. Меняется
# ТОЛЬКО сервер dns-direct, всё остальное обязано совпасть со снапшотом.
_P2_DIRECT = {
    "77.88.8.8": {"type": "udp", "tag": "dns-direct", "server": "77.88.8.8"},
    "https://1.1.1.1/dns-query": {"type": "https", "tag": "dns-direct",
                                  "server": "1.1.1.1"},
    "tls://1.1.1.1": {"type": "tls", "tag": "dns-direct",
                      "server": "1.1.1.1"},
    "8.8.8.8:53": {"type": "udp", "tag": "dns-direct", "server": "8.8.8.8",
                   "server_port": 53},
    "udp://8.8.8.8:53": {"type": "udp", "tag": "dns-direct",
                         "server": "8.8.8.8", "server_port": 53},
}


def _p2_affected(kw) -> bool:
    return bool(kw.get("typed_dns")) and kw.get("direct_dns") in _P2_DIRECT


class TestEngineSnapshot(unittest.TestCase):
    """Режим engine собирается ровно так же, как до правок B2."""

    def test_builder_matches_snapshot(self):
        for case in _load_snapshot()["build_fakeip_config"]:
            kw = case["kwargs"]
            with self.subTest(**{k: v for k, v in kw.items()
                                 if k in ("typed_dns", "direct_dns",
                                          "route_all", "capture_dns",
                                          "auto_redirect", "stack")}):
                cfg = build_fakeip_config(**kw)
                if not _p2_affected(kw):
                    self.assertEqual(cfg, case["config"])
                    self.assertEqual(_sha(render_conf(cfg)), case["sha256"])
                    continue
                want = json.loads(json.dumps(case["config"]))
                servers = want["dns"]["servers"]
                idx = [s["tag"] for s in servers].index("dns-direct")
                servers[idx] = _P2_DIRECT[kw["direct_dns"]]
                self.assertEqual(cfg, want)

    def test_p2_cases_are_covered_by_snapshot(self):
        # Сторож на сам снапшот: исключения выше реально в нём есть, а
        # legacy-вариант тех же direct_dns остался нетронутым.
        cases = _load_snapshot()["build_fakeip_config"]
        affected = {c["kwargs"]["direct_dns"] for c in cases
                    if _p2_affected(c["kwargs"])}
        self.assertEqual(affected, set(_P2_DIRECT))
        legacy = [c for c in cases if not c["kwargs"].get("typed_dns")
                  and c["kwargs"].get("direct_dns") in _P2_DIRECT]
        self.assertTrue(legacy)

    def test_orchestrator_matches_snapshot(self):
        from core import singbox_fakeip
        vless = {"type": "vless", "tag": "myserver", "server": "1.2.3.4",
                 "server_port": 443, "uuid": "u-1",
                 "tls": {"enabled": True, "server_name": "ex.com"}}

        class _Mgr:
            saved = None

            def check_text(self, text):
                return {"ok": True}

            def save_config(self, name, text=""):
                self.saved = (name, text)
                return {"ok": True, "warnings": []}

        class _Plat:
            def __init__(self, nft):
                self._nft = nft

            def supports_nftables(self):
                return self._nft

        class _Det:
            def detect_binary(self):
                return {"version": "1.14.1", "installed": True}

        class _HM:
            def get_hostlist(self, name):
                return ["youtube.com", "*.youtube.com"]

        for case in _load_snapshot()["build_and_save"]:
            with self.subTest(nft=case["nft"], capture=case["capture_dns"]):
                mgr = _Mgr()
                ps = [
                    mock.patch("core.singbox_manager.get_singbox_manager",
                               return_value=mgr),
                    mock.patch("core.singbox_platform.detect_singbox_platform",
                               return_value=_Plat(case["nft"])),
                    mock.patch("core.singbox_detector.get_singbox_detector",
                               return_value=_Det()),
                    mock.patch("core.hostlist_manager.get_hostlist_manager",
                               return_value=_HM()),
                    mock.patch("core.singbox_subscription.uri_to_outbound",
                               return_value={"ok": True,
                                             "outbound": dict(vless)}),
                ]
                for p in ps:
                    p.start()
                try:
                    res = singbox_fakeip.build_and_save(
                        name="fi", proxy_link="vless://u@h:443",
                        domains=["a.com"], hostlists=["svc"],
                        cidrs=["203.0.113.0/24"],
                        capture_dns=case["capture_dns"])
                finally:
                    for p in ps:
                        p.stop()
                self.assertEqual(res, case["result"])
                self.assertEqual(mgr.saved[0], case["saved_name"])
                self.assertEqual(mgr.saved[1], case["saved_text"])


class TestDirectDns(unittest.TestCase):
    """п.2: прямой DNS в typed-формате больше не схлопывается в local."""

    def _parse(self, v):
        from core.singbox_config import parse_direct_dns
        return parse_direct_dns(v)

    def test_variants(self):
        cases = {
            "": {"type": "local"},
            "local": {"type": "local"},
            "1.1.1.1": {"type": "udp", "server": "1.1.1.1"},
            "1.1.1.1:5353": {"type": "udp", "server": "1.1.1.1",
                             "server_port": 5353},
            "[2606:4700::1111]:53": {"type": "udp",
                                     "server": "2606:4700::1111",
                                     "server_port": 53},
            "2606:4700::1111": {"type": "udp", "server": "2606:4700::1111"},
            "udp://8.8.8.8:53": {"type": "udp", "server": "8.8.8.8",
                                 "server_port": 53},
            "udp://8.8.8.8": {"type": "udp", "server": "8.8.8.8"},
            "tls://1.1.1.1": {"type": "tls", "server": "1.1.1.1"},
            "tls://dns.google:853": {"type": "tls", "server": "dns.google",
                                     "server_port": 853},
            "https://1.1.1.1/dns-query": {"type": "https",
                                          "server": "1.1.1.1"},
            "https://1.1.1.1": {"type": "https", "server": "1.1.1.1"},
            "https://dns.example.net:8443/custom": {
                "type": "https", "server": "dns.example.net",
                "server_port": 8443, "path": "/custom"},
        }
        for value, want in cases.items():
            with self.subTest(value=value):
                self.assertEqual(self._parse(value), want)

    def test_never_sets_detour(self):
        # detour на пустой direct у typed-сервера = FATAL на `run` (1.12+).
        for v in ("1.1.1.1", "udp://1.1.1.1", "tls://1.1.1.1",
                  "https://1.1.1.1/dns-query"):
            with self.subTest(value=v):
                self.assertNotIn("detour", self._parse(v))

    def test_garbage_is_not_recognized(self):
        for v in ("dns.google", "quic://1.1.1.1", "https://", "1.1.1.1:x",
                  "1.1.1.1:99999", "[::1", "tls://1.1.1.1:0x35"):
            with self.subTest(value=v):
                self.assertIsNone(self._parse(v))

    def test_domain_server_gets_bootstrap(self):
        from core.singbox_config import (
            make_direct_dns_servers, DNS_BOOTSTRAP_TAG)
        servers = make_direct_dns_servers("https://cloudflare-dns.com/dns-query")
        self.assertEqual(servers, [
            {"type": "https", "tag": "dns-direct",
             "server": "cloudflare-dns.com",
             "domain_resolver": DNS_BOOTSTRAP_TAG},
            {"type": "local", "tag": DNS_BOOTSTRAP_TAG},
        ])
        self.assertEqual(len(make_direct_dns_servers("tls://1.1.1.1")), 1)

    def test_fakeip_dns_typed_uses_parsed_server(self):
        from core.singbox_config import make_fakeip_dns
        for value, typ in (("https://1.1.1.1/dns-query", "https"),
                           ("tls://1.1.1.1", "tls"),
                           ("9.9.9.9:53", "udp")):
            with self.subTest(value=value):
                dns = make_fakeip_dns(proxied_domains=["a.com"],
                                      direct_dns=value, typed=True)
                d = {s["tag"]: s for s in dns["servers"]}["dns-direct"]
                self.assertEqual(d["type"], typ)
                self.assertNotIn("detour", d)

    def test_fakeip_dns_typed_unknown_falls_back_to_local(self):
        # Нераспознанное в engine ведёт себя как раньше (local), чтобы не
        # ломать чужие конфиги; режим external такое отвергает сам.
        from core.singbox_config import make_fakeip_dns
        dns = make_fakeip_dns(proxied_domains=["a.com"],
                              direct_dns="quic://1.1.1.1", typed=True)
        d = {s["tag"]: s for s in dns["servers"]}["dns-direct"]
        self.assertEqual(d, {"tag": "dns-direct", "type": "local"})

    def test_legacy_passes_string_through(self):
        from core.singbox_config import make_fakeip_dns
        dns = make_fakeip_dns(proxied_domains=["a.com"],
                              direct_dns="https://1.1.1.1/dns-query",
                              typed=False)
        d = {s["tag"]: s for s in dns["servers"]}["dns-direct"]
        self.assertEqual(d, {"tag": "dns-direct",
                             "address": "https://1.1.1.1/dns-query",
                             "detour": "direct"})


# ─────────────────────── режим external ───────────────────────

def _vless(tag="p1", server="1.2.3.4"):
    return {"type": "vless", "tag": tag, "server": server,
            "server_port": 443, "uuid": "u-1"}


# Целевая форма из спеки (проверена sing-box 1.14.1: check + run). Одно
# отличие от текста спеки: у dns-direct нет `detour: direct` — typed-сервер
# с detour на пустой direct проходит check, но падает на run (FATAL
# «detour to an empty direct outbound makes no sense»).
EXPECTED_ONE_PROXY = {
    "log": {"level": "info"},
    "dns": {
        "servers": [
            {"type": "https", "tag": "dns-direct", "server": "1.1.1.1"},
            {"type": "fakeip", "tag": "dns-fakeip",
             "inet4_range": "198.18.0.0/15", "inet6_range": "fc00::/18"},
        ],
        "rules": [
            {"query_type": ["AAAA"], "action": "predefined",
             "rcode": "NOERROR"},
            {"query_type": ["A"], "server": "dns-fakeip"},
        ],
        "final": "dns-direct",
    },
    "inbounds": [
        {"type": "direct", "tag": "dns-in", "listen": "127.0.0.1",
         "listen_port": 1053, "network": "udp"},
        {"type": "tun", "tag": "tun-in", "interface_name": "singbox-tun",
         "address": ["172.19.0.1/30"], "auto_route": False,
         "strict_route": False, "stack": "system"},
    ],
    "outbounds": [
        {"type": "vless", "tag": "p1", "server": "1.2.3.4",
         "server_port": 443, "uuid": "u-1"},
        {"type": "selector", "tag": "proxy-out", "outbounds": ["p1"],
         "default": "p1"},
        {"type": "direct", "tag": "direct"},
    ],
    "route": {
        "rules": [
            {"action": "sniff"},
            {"protocol": "dns", "action": "hijack-dns"},
            {"inbound": ["tun-in"], "outbound": "proxy-out"},
        ],
        "final": "direct",
        "auto_detect_interface": True,
        "default_domain_resolver": "dns-direct",
    },
    "experimental": {"cache_file": {"enabled": True,
                                    "path": "/var/lib/sing-box/cache.db",
                                    "store_fakeip": True}},
}


def _external(**kw):
    base = dict(proxy_outbound=_vless(), front_dns="external",
                direct_dns="https://1.1.1.1/dns-query")
    base.update(kw)
    return build_fakeip_config(**base)


class TestExternalConfig(unittest.TestCase):
    """п.1: форма конфига режима external."""

    def test_exact_shape_one_proxy(self):
        cfg = _external()
        self.assertEqual(cfg, EXPECTED_ONE_PROXY)
        self.assertEqual(list(cfg), ["log", "dns", "inbounds", "outbounds",
                                     "route", "experimental"])

    def test_passes_structural_validator(self):
        from core.singbox_config import validate, parse_conf
        cfg = _external()
        self.assertEqual(validate(cfg), [])
        self.assertEqual(parse_conf(render_conf(cfg)), cfg)

    def test_params(self):
        cfg = _external(dns_listen="192.168.1.1", dns_port=5300,
                        tun_iface="sb-fake", tun_address="172.20.0.1/30",
                        stack="gvisor", cache_path="/srv/sb/cache-x.db")
        dns_in, tun = cfg["inbounds"]
        self.assertEqual((dns_in["listen"], dns_in["listen_port"]),
                         ("192.168.1.1", 5300))
        self.assertEqual(tun["interface_name"], "sb-fake")
        self.assertEqual(tun["address"], ["172.20.0.1/30"])
        self.assertEqual(tun["stack"], "gvisor")
        self.assertEqual(cfg["experimental"]["cache_file"]["path"],
                         "/srv/sb/cache-x.db")

    def test_engine_only_knobs_are_ignored(self):
        # capture_dns/auto_redirect/route_all/домены — вещи режима engine.
        cfg = _external(capture_dns=True, auto_redirect=True, route_all=True,
                        proxied_domains=["youtube.com"],
                        proxied_cidrs=["203.0.113.0/24"], typed_dns=False)
        self.assertEqual(cfg, EXPECTED_ONE_PROXY)

    def test_no_forbidden_rules(self):
        text = render_conf(_external())
        for bad in ("ip_is_private", "domain_suffix", "auto_redirect",
                    "\"mtu\"", "\"detour\""):
            self.assertNotIn(bad, text)

    def test_domain_rules_insert_before_tun_rule(self):
        # B3 вставляет domain_suffix → outbound; сборщик не должен мешать.
        from core.singbox_config import insert_route_rule_after_managed
        cfg = _external()
        rule = {"domain_suffix": ["example.com"], "outbound": "p1"}
        insert_route_rule_after_managed(cfg, rule)
        rules = cfg["route"]["rules"]
        self.assertEqual(rules.index(rule), 2)
        self.assertEqual(rules[-1], {"inbound": ["tun-in"],
                                     "outbound": "proxy-out"})

    def test_domain_doh_gets_bootstrap(self):
        cfg = _external(direct_dns="https://cloudflare-dns.com/dns-query")
        tags = [s["tag"] for s in cfg["dns"]["servers"]]
        self.assertEqual(tags, ["dns-direct", "dns-fakeip", "dns-bootstrap"])
        self.assertEqual(cfg["dns"]["servers"][0]["domain_resolver"],
                         "dns-bootstrap")

    def test_bad_direct_dns_raises(self):
        with self.assertRaises(ValueError):
            _external(direct_dns="quic://1.1.1.1")

    def test_unknown_front_raises(self):
        with self.assertRaises(ValueError):
            _external(front_dns="agh")

    def test_default_port_differs_by_mode(self):
        self.assertEqual(_external()["inbounds"][0]["listen_port"], 1053)
        eng = build_fakeip_config(proxy_outbound=_vless(),
                                  proxied_domains=["a.com"],
                                  capture_dns=True)
        dns_in = [i for i in eng["inbounds"] if i["tag"] == "dns-in"][0]
        self.assertEqual(dns_in["listen_port"], 1153)


class TestExternalOutbounds(unittest.TestCase):
    """п.3: несколько прокси, группы, endpoint'ы."""

    def _obs(self, outbounds, endpoints=None):
        cfg = build_fakeip_config(
            proxy_outbound=None, proxy_outbounds=outbounds,
            proxy_endpoints=endpoints, front_dns="external")
        return cfg

    def test_two_proxies_get_selector(self):
        cfg = self._obs([_vless("p1"), _vless("p2", "vpn.example.com")])
        self.assertEqual(cfg["outbounds"], [
            _vless("p1"), _vless("p2", "vpn.example.com"),
            {"type": "selector", "tag": "proxy-out",
             "outbounds": ["p1", "p2"], "default": "p1"},
            {"type": "direct", "tag": "direct"},
        ])

    def test_groups_go_first(self):
        auto = {"type": "urltest", "tag": "auto", "outbounds": ["p1", "p2"]}
        cfg = self._obs([_vless("p1"), _vless("p2"), auto])
        sel = [o for o in cfg["outbounds"] if o["tag"] == "proxy-out"][0]
        self.assertEqual(sel["outbounds"], ["auto", "p1", "p2"])
        self.assertEqual(sel["default"], "auto")

    def test_existing_proxy_out_is_kept(self):
        mine = {"type": "selector", "tag": "proxy-out",
                "outbounds": ["p2", "p1"], "default": "p2"}
        cfg = self._obs([_vless("p1"), _vless("p2"), mine])
        self.assertEqual([o["tag"] for o in cfg["outbounds"]],
                         ["p1", "p2", "proxy-out", "direct"])
        self.assertIn(mine, cfg["outbounds"])

    def test_existing_direct_not_duplicated(self):
        cfg = self._obs([_vless("p1"), {"type": "direct", "tag": "direct"}])
        tags = [o["tag"] for o in cfg["outbounds"]]
        self.assertEqual(tags.count("direct"), 1)
        sel = [o for o in cfg["outbounds"] if o["tag"] == "proxy-out"][0]
        self.assertEqual(sel["outbounds"], ["p1"])

    def test_endpoints_are_members(self):
        wg = {"type": "wireguard", "tag": "wg0", "address": ["10.0.0.2/32"],
              "private_key": "x", "peers": []}
        cfg = self._obs([_vless("p1")], [wg])
        self.assertEqual(cfg["endpoints"], [wg])
        self.assertEqual(list(cfg)[:5], ["log", "dns", "inbounds",
                                         "outbounds", "endpoints"])
        sel = [o for o in cfg["outbounds"] if o["tag"] == "proxy-out"][0]
        self.assertEqual(sel["outbounds"], ["p1", "wg0"])

    def test_untagged_proxy_gets_tag(self):
        ob = _vless()
        ob.pop("tag")
        cfg = self._obs([ob])
        self.assertEqual(cfg["outbounds"][0]["tag"], "proxy")

    def test_input_not_mutated(self):
        obs = [_vless("p1")]
        self._obs(obs)
        self.assertEqual(obs, [_vless("p1")])

    def test_no_proxies_raises(self):
        with self.assertRaises(ValueError):
            self._obs([{"type": "direct", "tag": "direct"}])


class _FakeCM:
    """Минимальный config manager (get/set/save), без записи на диск."""

    def __init__(self, data=None):
        self.data = json.loads(json.dumps(data or {}))
        self.saves = 0

    def get(self, *keys, default=None):
        node = self.data
        for k in keys:
            if isinstance(node, dict) and k in node:
                node = node[k]
            else:
                return default
        return node

    def set(self, *args):
        *keys, value = args
        node = self.data
        for k in keys[:-1]:
            node = node.setdefault(k, {})
        node[keys[-1]] = value

    def save(self):
        self.saves += 1
        return True


class TestFrontSidecar(unittest.TestCase):
    """п.4: режим хранится в settings.json → singbox.fakeip_front."""

    def setUp(self):
        from core import singbox_fakeip
        self.sf = singbox_fakeip
        self.cm = _FakeCM()
        self._p = mock.patch("core.config_manager.get_config_manager",
                             return_value=self.cm)
        self._p.start()

    def tearDown(self):
        self._p.stop()

    def test_remember_and_forget(self):
        self.assertFalse(self.sf.is_external_front("fi"))
        entry = {"front_dns": "external", "dns_listen": "127.0.0.1",
                 "dns_port": 1053}
        self.sf.remember_front("fi", entry)
        self.assertTrue(self.sf.is_external_front("fi"))
        self.assertEqual(self.cm.data["singbox"]["fakeip_front"]["fi"], entry)
        self.sf.forget_front("fi")
        self.assertFalse(self.sf.is_external_front("fi"))
        self.assertEqual(self.cm.saves, 2)

    def test_forget_missing_does_not_write(self):
        self.sf.forget_front("nope")
        self.assertEqual(self.cm.saves, 0)

    def test_default_config_has_section(self):
        from core.config_manager import DEFAULT_CONFIG
        self.assertEqual(DEFAULT_CONFIG["singbox"]["fakeip_front"], {})


class _Plat:
    def __init__(self, base, nft=False):
        self.data_dir = os.path.join(base, "lib")
        self.run_dir = os.path.join(base, "run")
        self._nft = nft

    def supports_nftables(self):
        return self._nft


class _Mgr:
    def __init__(self, check=None, cfg=None):
        self.check = check or {"ok": True}
        self.checked = []
        self.saved = None
        self.cfg = cfg

    def check_text(self, text):
        self.checked.append(text)
        return self.check

    def save_config(self, name, text=""):
        self.saved = (name, text)
        return {"ok": True, "warnings": []}

    def get_config(self, name):
        if self.cfg is None:
            return {"ok": False}
        return {"ok": True, "parsed": self.cfg}


class _HM:
    def get_hostlist(self, name):
        return {"yt": ["youtube.com", "*.googlevideo.com"]}.get(name, [])


class TestExternalOrchestrator(unittest.TestCase):
    """build_and_save(front_dns='external') — сборка, проверка, запись."""

    def setUp(self):
        import tempfile
        from core import singbox_fakeip
        self.sf = singbox_fakeip
        self.tmp = tempfile.mkdtemp(prefix="zg-fi-front-")
        self.cm = _FakeCM()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _run(self, mgr, link=_vless(tag="my-srv"), nft=False, **kw):
        plat = _Plat(self.tmp, nft)
        ps = [
            mock.patch("core.singbox_manager.get_singbox_manager",
                       return_value=mgr),
            mock.patch("core.singbox_platform.detect_singbox_platform",
                       return_value=plat),
            mock.patch("core.hostlist_manager.get_hostlist_manager",
                       return_value=_HM()),
            mock.patch("core.singbox_subscription.uri_to_outbound",
                       return_value={"ok": True, "outbound": dict(link)}),
            mock.patch("core.config_manager.get_config_manager",
                       return_value=self.cm),
        ]
        for p in ps:
            p.start()
        try:
            args = dict(name="fi", front_dns="external")
            args.update(kw)
            return self.sf.build_and_save(**args)
        finally:
            for p in ps:
                p.stop()

    def test_link_builds_saves_and_remembers(self):
        mgr = _Mgr()
        res = self._run(mgr, proxy_link="vless://x", hostlists=["yt"],
                        domains=["Example.org"])
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["front_dns"], "external")
        self.assertEqual(res["dns_capture"], "external")
        self.assertEqual((res["dns_listen"], res["dns_port"]),
                         ("127.0.0.1", 1053))
        self.assertEqual(res["direct_dns"], "https://1.1.1.1/dns-query")
        self.assertEqual(
            res["adguard_upstream"],
            "[/example.org/youtube.com/googlevideo.com/]127.0.0.1:1053")
        # одна проверка (только typed), сохранено то, что проверено
        self.assertEqual(len(mgr.checked), 1)
        self.assertEqual(mgr.saved, ("fi", mgr.checked[0]))
        cfg = json.loads(mgr.saved[1])
        cache = os.path.join(self.tmp, "lib", "cache-fi.db")
        self.assertEqual(cfg["experimental"]["cache_file"]["path"], cache)
        self.assertTrue(os.path.isabs(cache))
        self.assertTrue(os.path.isdir(os.path.dirname(cache)))
        self.assertEqual([o["tag"] for o in cfg["outbounds"]],
                         ["my-srv", "proxy-out", "direct"])
        # домены в конфиг не попадают — их отбирает AdGuard
        self.assertNotIn("youtube.com", mgr.saved[1])
        self.assertEqual(self.cm.data["singbox"]["fakeip_front"]["fi"],
                         {"front_dns": "external", "dns_listen": "127.0.0.1",
                          "dns_port": 1053})

    def test_no_domains_needed(self):
        res = self._run(_Mgr(), proxy_link="vless://x")
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["adguard_upstream"], "[/домен/]127.0.0.1:1053")

    def test_same_on_nft_and_iptables(self):
        a, b = _Mgr(), _Mgr()
        self._run(a, proxy_link="vless://x", nft=False)
        self._run(b, proxy_link="vless://x", nft=True)
        self.assertEqual(a.saved, b.saved)
        self.assertNotIn("auto_redirect", a.saved[1])

    def test_cache_falls_back_to_run_dir(self):
        mgr = _Mgr()
        plat = _Plat(self.tmp)
        plat.data_dir = ""
        self.assertEqual(self.sf.fakeip_cache_path("x", plat),
                         os.path.join(self.tmp, "run", "cache-x.db"))

    def test_proxy_config_takes_all_outbounds(self):
        src = {"outbounds": [
            _vless("a"), _vless("b"),
            {"type": "urltest", "tag": "auto", "outbounds": ["a", "b"]},
            {"type": "direct", "tag": "direct"},
            {"type": "block", "tag": "block"},
        ]}
        mgr = _Mgr(cfg=src)
        with mock.patch("core.singbox_manager.get_singbox_manager",
                        return_value=mgr):
            res = self._run(mgr, link={}, proxy_config="pool")
        self.assertTrue(res["ok"], res)
        cfg = json.loads(mgr.saved[1])
        self.assertEqual([o["tag"] for o in cfg["outbounds"]],
                         ["a", "b", "auto", "proxy-out", "direct"])
        sel = cfg["outbounds"][3]
        self.assertEqual(sel, {"type": "selector", "tag": "proxy-out",
                               "outbounds": ["auto", "a", "b"],
                               "default": "auto"})
        self.assertEqual(res["proxies"], 2)

    def test_check_failure_is_reported_and_not_saved(self):
        mgr = _Mgr(check={"ok": False, "error": "FATAL bad"})
        res = self._run(mgr, proxy_link="vless://x")
        self.assertFalse(res["ok"])
        self.assertIn("FATAL bad", res["error"])
        self.assertIsNone(mgr.saved)
        self.assertNotIn("singbox", self.cm.data)

    def test_no_binary_saves_with_warning(self):
        mgr = _Mgr(check={"ok": False, "no_binary": True})
        res = self._run(mgr, proxy_link="vless://x")
        self.assertTrue(res["ok"])
        self.assertTrue(res["warning"])

    def test_input_validation(self):
        for kw, frag in ((dict(dns_listen="localhost"), "IP"),
                         (dict(dns_port=70000), "диапазон"),
                         (dict(dns_port="x"), "число"),
                         (dict(direct_dns="dns.google"), "не распознан"),
                         (dict(tun_address="nope"), "CIDR"),
                         (dict(front_dns="agh"), "front_dns")):
            with self.subTest(**kw):
                res = self._run(_Mgr(), proxy_link="vless://x", **kw)
                self.assertFalse(res["ok"])
                self.assertIn(frag, res["error"])

    def test_local_direct_dns_warns(self):
        res = self._run(_Mgr(), proxy_link="vless://x", direct_dns="local")
        self.assertTrue(res["ok"])
        self.assertTrue(any("петля" in w for w in res["warnings"]))

    def test_engine_build_forgets_external_mark(self):
        self.cm.data = {"singbox": {"fakeip_front": {
            "fi": {"front_dns": "external"}}}}
        mgr = _Mgr()
        with mock.patch("core.singbox_detector.get_singbox_detector") as det:
            det.return_value.detect_binary.return_value = {
                "version": "1.14.1", "installed": True}
            res = self._run(mgr, proxy_link="vless://x", front_dns="engine",
                            domains=["a.com"])
        self.assertTrue(res["ok"], res)
        self.assertEqual(self.cm.data["singbox"]["fakeip_front"], {})


class TestManagerExternalFront(unittest.TestCase):
    """п.4: SingboxManager не трогает DNS-перехват у конфига external."""

    def setUp(self):
        import tempfile
        from core import singbox_manager
        from tests.test_singbox_manager_lifecycle import FakePlatform
        self.sm = singbox_manager
        self.tmp = tempfile.mkdtemp(prefix="zg-sb-front-")
        self.platform = FakePlatform(self.tmp)
        self.binary = os.path.join(self.platform.binary_dir, "sing-box")
        open(self.binary, "w").close()
        self.mgr = singbox_manager.SingboxManager()
        self.cm = _FakeCM()
        self._ps = [
            mock.patch.object(self.mgr, "_platform",
                              return_value=self.platform),
            mock.patch.object(self.mgr, "_binary", return_value=self.binary),
            mock.patch("core.config_manager.get_config_manager",
                       return_value=self.cm),
            # iptables-платформа: именно там менеджер ставит REDIRECT :53
            mock.patch("core.singbox_platform.detect_singbox_platform",
                       return_value=_Plat(self.tmp, nft=False)),
        ]
        for p in self._ps:
            p.start()
        ext = _external(dns_port=1053)
        eng = build_fakeip_config(proxy_outbound=_vless(),
                                  proxied_domains=["a.com"],
                                  capture_dns=True, typed_dns=True)
        self.mgr.save_config("ext", text=render_conf(ext))
        self.mgr.save_config("eng", text=render_conf(eng))
        self.cm.data = {"singbox": {"fakeip_front": {
            "ext": {"front_dns": "external", "dns_listen": "127.0.0.1",
                    "dns_port": 1053}}}}

    def tearDown(self):
        import shutil
        for p in self._ps:
            p.stop()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _up(self, name):
        fake = mock.MagicMock()
        fake.pid = 4242
        fake.poll.return_value = None
        with mock.patch.object(self.sm, "_run", return_value=(0, "", "")), \
                mock.patch("subprocess.Popen", return_value=fake), \
                mock.patch("time.sleep"), \
                mock.patch("core.singbox_transparent.available",
                           return_value=True), \
                mock.patch("core.singbox_transparent.apply",
                           return_value={"ok": True}) as apply:
            r = self.mgr.up(name)
        return r, apply

    def test_dns_in_port_is_zero_for_external(self):
        self.assertEqual(self.mgr._config_dns_in_port("ext"), 0)
        self.assertEqual(self.mgr._config_dns_in_port("eng"), 1153)

    def test_up_external_does_not_capture(self):
        r, apply = self._up("ext")
        self.assertTrue(r["ok"], r)
        apply.assert_not_called()
        self.assertNotIn("transparent", self.cm.data["singbox"])

    def test_up_engine_still_captures(self):
        # Контроль: тот же путь для engine ставит dns-only REDIRECT.
        r, apply = self._up("eng")
        self.assertTrue(r["ok"], r)
        apply.assert_called_once()
        self.assertEqual(self.cm.data["singbox"]["transparent"]["mode"],
                         "dns-only")

    def test_down_external_leaves_foreign_capture(self):
        # Перехват от engine-конфига не снимается остановкой external.
        self.cm.data["singbox"]["transparent"] = {
            "mode": "dns-only", "dns_hijack_port": 1153}
        with mock.patch.object(self.sm, "_run", return_value=(1, "", "")), \
                mock.patch("core.singbox_transparent.remove") as rm:
            r = self.mgr.down("ext")
        self.assertTrue(r["ok"])
        rm.assert_not_called()
        self.assertEqual(self.cm.data["singbox"]["transparent"]["mode"],
                         "dns-only")

    def test_delete_forgets_mark(self):
        r = self.mgr.delete_config("ext")
        self.assertTrue(r["ok"])
        self.assertEqual(self.cm.data["singbox"]["fakeip_front"], {})


class TestFakeipApi(unittest.TestCase):
    """п.6: параметры фронт-DNS доходят до build_and_save, дефолты по режиму."""

    @classmethod
    def setUpClass(cls):
        from tests._wsgi_client import WSGIClient, build_test_app
        cls.client = WSGIClient(build_test_app())

    def _build(self, body):
        with mock.patch("core.singbox_fakeip.build_and_save",
                        return_value={"ok": True}) as bs:
            r = self.client.post_json("/api/singbox/fakeip/build", body)
        self.assertEqual(r["_status"], 200)
        return bs.call_args.kwargs

    def test_external_defaults(self):
        kw = self._build({"front_dns": "external", "proxy_link": "vless://x"})
        self.assertEqual(kw["front_dns"], "external")
        self.assertEqual(kw["dns_port"], 1053)
        self.assertEqual(kw["dns_listen"], "127.0.0.1")
        self.assertEqual(kw["direct_dns"], "https://1.1.1.1/dns-query")

    def test_external_explicit(self):
        kw = self._build({"front_dns": "external", "proxy_link": "vless://x",
                          "dns_listen": "10.0.0.1", "dns_port": 5300,
                          "direct_dns": "tls://1.1.1.1",
                          "tun_address": "172.20.0.1/30"})
        self.assertEqual((kw["dns_listen"], kw["dns_port"], kw["direct_dns"],
                          kw["tun_address"]),
                         ("10.0.0.1", 5300, "tls://1.1.1.1", "172.20.0.1/30"))

    def test_engine_defaults_unchanged(self):
        kw = self._build({"proxy_link": "vless://x", "domains": "a.com"})
        self.assertEqual(kw["front_dns"], "engine")
        self.assertEqual(kw["dns_port"], 1153)
        self.assertEqual(kw["direct_dns"], "local")

    def test_options_route_returns_build_options(self):
        from core import singbox_fakeip
        with mock.patch.object(singbox_fakeip, "build_options",
                               return_value={"ok": True, "front_dns": "engine"}):
            r = self.client.get_json("/api/singbox/fakeip/options")
        self.assertEqual(r["front_dns"], "engine")

    def test_build_options_defaults(self):
        from core import singbox_fakeip

        class _D:
            def detect_binary(self):
                return {"installed": False, "version": ""}

        class _M:
            def list_configs(self):
                return [{"name": "fi"}]

        class _H:
            def get_stats(self):
                return {}

            def list_names(self):
                return []

        cm = _FakeCM({"singbox": {"fakeip_front": {
            "fi": {"front_dns": "external"}}}})
        with mock.patch("core.singbox_detector.get_singbox_detector",
                        return_value=_D()), \
                mock.patch("core.singbox_manager.get_singbox_manager",
                           return_value=_M()), \
                mock.patch("core.hostlist_manager.get_hostlist_manager",
                           return_value=_H()), \
                mock.patch("core.singbox_platform.detect_singbox_platform",
                           return_value=_Plat("/nonexistent")), \
                mock.patch("core.config_manager.get_config_manager",
                           return_value=cm):
            o = singbox_fakeip.build_options()
        self.assertEqual(o["front_dns"], "engine")
        self.assertEqual(o["front_dns_modes"], ["engine", "external"])
        self.assertEqual(o["external_defaults"], {
            "dns_listen": "127.0.0.1", "dns_port": 1053,
            "direct_dns": "https://1.1.1.1/dns-query",
            "tun_address": "172.19.0.1/30", "stack": "system"})
        self.assertEqual(o["engine_defaults"],
                         {"dns_port": 1153, "direct_dns": "local"})
        self.assertEqual(o["fronts"], {"fi": {"front_dns": "external"}})


if __name__ == "__main__":
    unittest.main()
