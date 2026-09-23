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


if __name__ == "__main__":
    unittest.main()
