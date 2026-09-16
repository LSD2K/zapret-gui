# tests/test_mihomo_routing.py
"""
Тесты оркестраторов маршрутизации mihomo (core/mihomo_routing.py): резолв
прокси (ссылка/конфиг), сборка+сохранение без бинаря (graceful), фолбэк стека
gvisor→system и rule-provider→DOMAIN-SUFFIX через мок `mihomo -t`.
"""

import unittest
from unittest import mock

from core import mihomo_routing as mr
from core.clash_yaml import parse_yaml


def _vless_proxy():
    return {"name": "srv", "type": "vless", "server": "vpn.example.com",
            "port": 443, "uuid": "u-1", "tls": True}


def _detector(installed=True, has_gvisor=True, version="1.18.0"):
    det = mock.MagicMock()
    det.detect_binary.return_value = {"installed": installed,
                                      "has_gvisor": has_gvisor,
                                      "version": version}
    return det


class _FakeManager:
    """Менеджер-заглушка: validate_via_binary решает по содержимому text."""

    def __init__(self, accept=lambda cfg: True):
        self.accept = accept
        self.saved = None

    def validate_via_binary(self, name, text=None):
        cfg = parse_yaml(text or "")
        ok = self.accept(cfg)
        return {"ok": ok, "stderr": "" if ok else "rejected", "returncode":
                0 if ok else 1}

    def save_config(self, name, text=""):
        self.saved = (name, text)
        return {"ok": True, "name": name, "warnings": []}


class TestResolveProxies(unittest.TestCase):

    def test_from_link(self):
        items = [{"type": "uri", "value": "vless://x"},
                 {"type": "uri", "value": "ss://y"}]
        with mock.patch("core.subscription_importer.extract_items",
                        return_value=items), \
             mock.patch("core.clash_yaml.uri_to_clash_proxy",
                        side_effect=[{"ok": True, "proxy": _vless_proxy()},
                                     {"ok": False, "error": "bad"}]):
            r = mr._resolve_proxies(proxy_link="vless://x\nss://y")
        self.assertTrue(r["ok"])
        self.assertEqual(len(r["proxies"]), 1)

    def test_link_no_valid(self):
        with mock.patch("core.subscription_importer.extract_items",
                        return_value=[]):
            r = mr._resolve_proxies(proxy_link="garbage")
        self.assertFalse(r["ok"])

    def test_from_config(self):
        cfg_text = ("proxies:\n  - {name: a, type: ss, server: 1.1.1.1, "
                    "port: 1, cipher: aes-128-gcm, password: p}\n")
        mgr = mock.MagicMock()
        mgr.get_config.return_value = {"ok": True, "text": cfg_text}
        with mock.patch("core.mihomo_manager.get_mihomo_manager",
                        return_value=mgr):
            r = mr._resolve_proxies(proxy_config="cfg")
        self.assertTrue(r["ok"])
        self.assertEqual(r["proxies"][0]["name"], "a")

    def test_none(self):
        self.assertFalse(mr._resolve_proxies()["ok"])

    def test_dedup_names(self):
        out = mr._dedup_names([{"name": "x", "type": "ss"},
                               {"name": "x", "type": "ss"},
                               {"type": "vless"}])
        names = [p["name"] for p in out]
        self.assertEqual(names, ["x", "x-2", "vless"])


class TestCollectTargets(unittest.TestCase):

    def test_all_dimensions(self):
        hm = mock.MagicMock()
        hm.get_hostlist.return_value = ["a.com", "b.com"]
        im = mock.MagicMock()
        im.get_ipset.return_value = ["5.5.5.5", "6.6.6.0/24"]
        # geosite→домены, geoip→CIDR, bare домен/cidr — через резолвер
        expand = {"domains": ["site.com", "gh.io"], "cidrs": ["1.2.3.0/24"],
                  "aliases_resolved": [{"kind": "geosite", "name": "github",
                                        "count": 2}],
                  "aliases_failed": []}
        with mock.patch("core.hostlist_manager.get_hostlist_manager",
                        return_value=hm), \
             mock.patch("core.named_lists.resolve",
                        return_value={"domains": ["c.com"],
                                      "cidrs": ["9.9.9.0/24"]}), \
             mock.patch("core.ipset_manager.get_ipset_manager",
                        return_value=im), \
             mock.patch("core.routing.alias_resolver.expand_domains",
                        return_value=expand):
            doms, cidrs, resolved, failed = mr._collect_targets(
                hostlists=["other"], lists=["id1"], ipsets=["ipset-base"],
                geosite=["github"], geoip=["ru"], domains=["x.com"],
                cidrs=["7.7.7.0/24"])
        self.assertEqual(set(doms), {"a.com", "b.com", "c.com",
                                     "site.com", "gh.io"})
        self.assertEqual(set(cidrs),
                         {"1.2.3.0/24", "9.9.9.0/24", "5.5.5.5", "6.6.6.0/24"})
        kinds = {r["kind"] for r in resolved}
        self.assertEqual(kinds, {"geosite", "hostlist", "list", "ipset"})
        self.assertEqual(failed, [])

    def test_geo_failure_reported(self):
        with mock.patch("core.routing.alias_resolver.expand_domains",
                        return_value={"domains": [], "cidrs": [],
                                      "aliases_resolved": [],
                                      "aliases_failed": [
                                          {"kind": "geoip", "name": "zz"}]}):
            doms, cidrs, resolved, failed = mr._collect_targets(geoip=["zz"])
        self.assertEqual(failed, [{"kind": "geoip", "name": "zz"}])


class TestBuildDomainRoute(unittest.TestCase):

    def _patches(self, mgr, installed=True, has_gvisor=True, nft=False,
                 version="1.18.0"):
        plat = mock.MagicMock()
        plat.get_firewall_backend.return_value = "nftables" if nft else "iptables"
        return [
            mock.patch("core.mihomo_detector.get_mihomo_detector",
                       return_value=_detector(installed, has_gvisor, version)),
            mock.patch("core.mihomo_manager.get_mihomo_manager",
                       return_value=mgr),
            mock.patch("core.proxy_tester._free_port", return_value=9099),
            mock.patch("core.mihomo_platform.detect_mihomo_platform",
                       return_value=plat),
            mock.patch.object(mr, "_resolve_proxies",
                              return_value={"ok": True,
                                            "proxies": [_vless_proxy()]}),
        ]

    def _run(self, mgr, **kw):
        ps = self._patches(mgr, **kw.pop("_env", {}))
        for p in ps:
            p.start()
        try:
            return mr.build_domain_route_and_save(**kw)
        finally:
            for p in ps:
                p.stop()

    def test_no_binary_graceful(self):
        mgr = _FakeManager()
        with mock.patch("core.mihomo_detector.get_mihomo_detector",
                        return_value=_detector(installed=False)), \
             mock.patch("core.mihomo_manager.get_mihomo_manager",
                        return_value=mgr), \
             mock.patch("core.proxy_tester._free_port", return_value=9099), \
             mock.patch("core.mihomo_platform.detect_mihomo_platform"), \
             mock.patch.object(mr, "_resolve_proxies",
                               return_value={"ok": True,
                                             "proxies": [_vless_proxy()]}):
            r = mr.build_domain_route_and_save(
                name="d", proxy_link="vless://x", domains=["youtube.com"])
        self.assertTrue(r["ok"])
        self.assertIn("не установлен", r["warning"])
        cfg = parse_yaml(mgr.saved[1])
        self.assertEqual(cfg["tun"]["stack"], "gvisor")
        self.assertIn("RULE-SET,proxied,PROXY", cfg["rules"])
        self.assertEqual(cfg["external-controller"], "127.0.0.1:9099")

    def test_gvisor_fallback_to_system(self):
        # mihomo -t отвергает gvisor, принимает system.
        mgr = _FakeManager(accept=lambda c: c.get("tun", {}).get("stack")
                           != "gvisor")
        r = self._run(mgr, name="d", proxy_link="vless://x",
                      domains=["youtube.com"])
        self.assertTrue(r["ok"])
        self.assertEqual(r["stack"], "system")

    def test_mips_stack_accepted_on_new_enough_mihomo(self):
        # `stack: mips` (metacubex/mipstack) — облегчённый стек для слабых
        # роутеров, добавлен в mihomo v1.19.31.
        mgr = _FakeManager()
        r = self._run(mgr, name="d", proxy_link="vless://x",
                      domains=["youtube.com"], stack="mips",
                      _env={"version": "1.19.31"})
        self.assertTrue(r["ok"])
        self.assertEqual(r["stack"], "mips")
        self.assertEqual(parse_yaml(mgr.saved[1])["tun"]["stack"], "mips")

    def test_mips_stack_ignored_on_old_mihomo(self):
        # На бинаре без mipstack незнакомое значение stack — не
        # игнорируемое поле, а «invalid tun stack» на ВЕСЬ конфиг.
        # Поэтому запрос молча вырождается в дефолтный стек.
        mgr = _FakeManager()
        r = self._run(mgr, name="d", proxy_link="vless://x",
                      domains=["youtube.com"], stack="mips",
                      _env={"version": "1.19.30"})
        self.assertTrue(r["ok"])
        self.assertEqual(r["stack"], "gvisor")

    def test_ruleset_fallback_to_domain_suffix(self):
        # Отвергаем любой конфиг с rule-providers (старая сборка).
        mgr = _FakeManager(accept=lambda c: "rule-providers" not in c)
        r = self._run(mgr, name="d", proxy_link="vless://x",
                      domains=["youtube.com"])
        self.assertTrue(r["ok"])
        self.assertFalse(r["ruleset"])
        cfg = parse_yaml(mgr.saved[1])
        self.assertIn("DOMAIN-SUFFIX,youtube.com,PROXY", cfg["rules"])

    def test_reject_all_fails(self):
        mgr = _FakeManager(accept=lambda c: False)
        r = self._run(mgr, name="d", proxy_link="vless://x",
                      domains=["youtube.com"])
        self.assertFalse(r["ok"])
        self.assertIn("отверг", r["error"])

    def test_requires_domains_or_route_all(self):
        mgr = _FakeManager()
        r = self._run(mgr, name="d", proxy_link="vless://x")
        self.assertFalse(r["ok"])

    def test_nft_enables_auto_redirect(self):
        mgr = _FakeManager()
        r = self._run(mgr, name="d", proxy_link="vless://x",
                      domains=["youtube.com"], _env={"nft": True})
        self.assertTrue(r["ok"])
        self.assertTrue(r["auto_redirect"])
        cfg = parse_yaml(mgr.saved[1])
        self.assertTrue(cfg["tun"]["auto-redirect"])


class TestBuildSourceRoute(unittest.TestCase):

    def _run(self, mgr, **kw):
        plat = mock.MagicMock()
        plat.get_firewall_backend.return_value = "iptables"
        with mock.patch("core.mihomo_detector.get_mihomo_detector",
                        return_value=_detector()), \
             mock.patch("core.mihomo_manager.get_mihomo_manager",
                        return_value=mgr), \
             mock.patch("core.proxy_tester._free_port", return_value=9099), \
             mock.patch("core.mihomo_platform.detect_mihomo_platform",
                        return_value=plat), \
             mock.patch.object(mr, "_resolve_proxies",
                               return_value={"ok": True,
                                             "proxies": [_vless_proxy()]}):
            return mr.build_source_route_and_save(**kw)

    def test_source_default_system_stack(self):
        mgr = _FakeManager()
        r = self._run(mgr, name="s", proxy_link="vless://x",
                      source_ips=["192.168.1.10"])
        self.assertTrue(r["ok"])
        self.assertEqual(r["stack"], "system")
        cfg = parse_yaml(mgr.saved[1])
        self.assertIn("SRC-IP-CIDR,192.168.1.10/32,PROXY", cfg["rules"])

    def test_requires_source_or_route_all(self):
        mgr = _FakeManager()
        r = self._run(mgr, name="s", proxy_link="vless://x")
        self.assertFalse(r["ok"])

    def test_route_all(self):
        mgr = _FakeManager()
        r = self._run(mgr, name="s", proxy_link="vless://x", route_all=True)
        self.assertTrue(r["ok"])
        cfg = parse_yaml(mgr.saved[1])
        self.assertEqual(cfg["rules"][-1], "MATCH,PROXY")


class TestStacks(unittest.TestCase):
    """
    Набор `tun.stack` сверен с `constant/tun.go` mihomo (StackTypeMapping).
    `mips` там появился в v1.19.31; UnmarshalText на незнакомом значении
    возвращает «invalid tun stack», то есть конфиг не принимается целиком —
    отсюда гейт по версии, а не «пусть попробует».
    """

    def test_mips_requires_11931(self):
        self.assertTrue(mr.mips_stack_supported("1.19.31"))
        self.assertTrue(mr.mips_stack_supported("v1.19.31"))
        self.assertTrue(mr.mips_stack_supported("1.20.0"))
        self.assertFalse(mr.mips_stack_supported("1.19.30"))
        self.assertFalse(mr.mips_stack_supported("1.18.0"))

    def test_unknown_version_is_not_supported(self):
        # Версию не прочитали — не предлагаем то, что может уронить конфиг.
        for v in ("", "unknown", None):
            self.assertFalse(mr.mips_stack_supported(v))

    def test_available_stacks(self):
        self.assertEqual(mr.available_stacks("1.19.30"),
                         ["gvisor", "system", "mixed"])
        self.assertEqual(mr.available_stacks("1.19.31"),
                         ["gvisor", "system", "mixed", "mips"])

    def test_pick_stack_rejects_garbage(self):
        self.assertEqual(mr._pick_stack("нет-такого", True, "gvisor"),
                         "gvisor")
        self.assertEqual(mr._pick_stack("mixed", True, "gvisor"), "mixed")


if __name__ == "__main__":
    unittest.main()
