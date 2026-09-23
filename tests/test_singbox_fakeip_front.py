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
                self.assertEqual(cfg, case["config"])
                self.assertEqual(_sha(render_conf(cfg)), case["sha256"])

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


if __name__ == "__main__":
    unittest.main()
