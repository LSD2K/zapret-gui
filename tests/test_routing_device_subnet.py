# tests/test_routing_device_subnet.py
"""Источник device-правила — целая ПОДСЕТЬ (issue #333).

«Как добавить всю подсеть» упиралось в то, что при попытке указать
`192.168.0.1/24` роутер ложился: `ip rule from 192.168.0.0/24 lookup
<table>` уводит в туннель и трафик между клиентами LAN, и трафик самого
роутера (его LAN-адрес — внутри подсети), а в таблице туннеля из
маршрутов только default.

Проверяем: нормализацию ввода, исключения для локальных сетей и
собственных адресов роутера, их снятие и то, что одиночный IP работает
ровно как раньше.
"""

import unittest
from unittest import mock

from core.routing import device_rule
from core.routing.rules import DeviceRoutingRule
from core.unified.model import UnifiedRoute, _norm_device_ip


class TestDeviceSourceNormalization(unittest.TestCase):

    def test_plain_ip_kept_as_is(self):
        self.assertEqual(_norm_device_ip("192.168.1.50"), "192.168.1.50")

    def test_host_mask_is_dropped(self):
        self.assertEqual(_norm_device_ip("192.168.1.50/32"), "192.168.1.50")
        self.assertEqual(_norm_device_ip("fd00::1/128"), "fd00::1")

    def test_subnet_is_normalized_to_network(self):
        """192.168.0.1/24 — это вся сеть, и записана она должна быть так."""
        self.assertEqual(_norm_device_ip("192.168.0.1/24"), "192.168.0.0/24")

    def test_wildcards_are_rejected(self):
        for bad in ("192.168.0.*", "192.168.0.1-50", "не-адрес", "1.2.3"):
            with self.assertRaises(ValueError, msg=bad):
                _norm_device_ip(bad)

    def test_strict_save_reports_bad_address(self):
        with self.assertRaises(ValueError) as ctx:
            UnifiedRoute.from_dict(
                {"name": "lan", "method": "awg:awg0",
                 "devices": [{"ip": "192.168.0.*"}]},
                strict_devices=True)
        self.assertIn("192.168.0.*", str(ctx.exception))

    def test_lenient_load_keeps_the_rest_of_the_route(self):
        """Битый адрес в settings.json не должен уносить весь маршрут."""
        route = UnifiedRoute.from_dict(
            {"name": "lan", "method": "awg:awg0",
             "destination": {"domains": ["youtube.com"]},
             "devices": [{"ip": "192.168.0.*"}, {"ip": "192.168.0.0/24"}]})
        self.assertEqual([d["ip"] for d in route.devices], ["192.168.0.0/24"])
        self.assertEqual(route.destination.domains, ["youtube.com"])


class TestIsSubnet(unittest.TestCase):

    def test_single_addresses(self):
        self.assertFalse(device_rule._is_subnet("192.168.1.50/32"))
        self.assertFalse(device_rule._is_subnet("fd00::1/128"))

    def test_networks(self):
        self.assertTrue(device_rule._is_subnet("192.168.1.0/24"))
        self.assertTrue(device_rule._is_subnet("fd00::/64"))


class _FakeIp:
    """Подмена `_run` для device_rule: помнит все вызовы `ip`."""

    ROUTES = ("192.168.0.0/24 dev br0 proto kernel scope link src 192.168.0.1\n"
              "10.8.0.0/24 dev awg0 proto kernel scope link src 10.8.0.2\n"
              "default via 192.168.100.1 dev eth3\n")
    ADDRS = ("2: br0    inet 192.168.0.1/24 brd 192.168.0.255 scope global br0\n"
             "5: eth3    inet 192.168.100.37/24 scope global eth3\n")

    def __init__(self):
        self.calls = []

    def __call__(self, args, timeout=5):
        self.calls.append(list(args))
        if args[:2] == ["ip", "-4"] or args[:2] == ["ip", "-6"]:
            rest = args[2:]
            if rest[:2] == ["route", "show"] and "main" in rest:
                return 0, self.ROUTES if args[1] == "-4" else "", ""
            if rest[:1] == ["-o"] and "addr" in rest:
                return 0, self.ADDRS if args[1] == "-4" else "", ""
        return 0, "", ""

    def added(self):
        return [c for c in self.calls if "rule" in c and "add" in c]

    def deleted(self):
        return [c for c in self.calls if "rule" in c and "del" in c]


class TestSubnetExemptions(unittest.TestCase):

    def _apply(self, source_ip):
        fake = _FakeIp()
        rule = DeviceRoutingRule(target_iface="awg0", source_ip=source_ip,
                                 rule_id="device-test")
        mq = mock.Mock(return_value={"ok": True})
        ks = mock.Mock(return_value={"skipped": True})
        with mock.patch.object(device_rule, "_run", fake), \
             mock.patch.object(device_rule, "_iface_exists", return_value=True), \
             mock.patch.object(device_rule, "_ensure_table_default",
                               return_value=True), \
             mock.patch("core.routing.masquerade.ensure_for_iface", mq), \
             mock.patch("core.routing.killswitch.ensure", ks):
            res = device_rule.apply_device_rule(rule)
        return res, fake

    def test_single_ip_adds_only_the_main_rule(self):
        """Регрессия: одиночный IP работает как раньше, без исключений."""
        res, fake = self._apply("192.168.1.50")
        self.assertTrue(res["ok"], res)
        self.assertEqual(res.get("exemptions"), [])
        adds = fake.added()
        self.assertEqual(len(adds), 1)
        self.assertIn("192.168.1.50/32", adds[0])
        self.assertNotIn("main", adds[0])

    def test_subnet_exempts_local_networks_and_router_itself(self):
        res, fake = self._apply("192.168.0.1/24")
        self.assertTrue(res["ok"], res)
        adds = [" ".join(c) for c in fake.added()]

        # Локальные сети — мимо туннеля, в main.
        self.assertTrue(any("from 192.168.0.0/24 to 192.168.0.0/24"
                            " lookup main" in a for a in adds), adds)
        self.assertTrue(any("from 192.168.0.0/24 to 10.8.0.0/24"
                            " lookup main" in a for a in adds), adds)
        # Собственный адрес роутера из этой подсети — тоже в main.
        self.assertTrue(any("from 192.168.0.1/32 lookup main" in a
                            for a in adds), adds)
        # Адрес роутера ВНЕ подсети трогать незачем.
        self.assertFalse(any("192.168.100.37" in a for a in adds), adds)
        # И само правило на подсеть.
        self.assertTrue(any("from 192.168.0.0/24 lookup %d"
                            % device_rule._table_id_for("awg0") in a
                            for a in adds), adds)

    def test_exemption_priorities_are_checked_before_the_rule(self):
        self.assertLess(device_rule.LOCAL_EXEMPT_PRIORITY,
                        device_rule.DEVICE_PRIORITY)
        self.assertLess(device_rule.SELF_EXEMPT_PRIORITY,
                        device_rule.LOCAL_EXEMPT_PRIORITY)
        _res, fake = self._apply("192.168.0.0/24")
        for call in fake.added():
            line = " ".join(call)
            if "lookup main" in line and "to " in line:
                self.assertIn(str(device_rule.LOCAL_EXEMPT_PRIORITY), line)

    def test_removal_takes_exemptions_away(self):
        fake = _FakeIp()
        rule = DeviceRoutingRule(target_iface="awg0",
                                 source_ip="192.168.0.0/24",
                                 rule_id="device-test")
        with mock.patch.object(device_rule, "_run", fake), \
             mock.patch.object(device_rule, "_other_subnet_sources",
                               return_value=[]), \
             mock.patch("core.routing.masquerade.remove_if_unused",
                        mock.Mock(return_value={"ok": True})):
            res = device_rule.remove_device_rule(rule)
        self.assertTrue(res["ok"], res)
        dels = [" ".join(c) for c in fake.deleted()]
        self.assertTrue(any("from 192.168.0.0/24 to 192.168.0.0/24"
                            " lookup main" in d for d in dels), dels)
        self.assertTrue(any("from 192.168.0.1/32 lookup main" in d
                            for d in dels), dels)

    def test_shared_self_exemption_survives_other_subnet_rule(self):
        """Второе правило на ту же подсеть ещё живо — адрес роутера не трогаем."""
        fake = _FakeIp()
        rule = DeviceRoutingRule(target_iface="awg0",
                                 source_ip="192.168.0.0/24",
                                 rule_id="device-test")
        with mock.patch.object(device_rule, "_run", fake), \
             mock.patch.object(device_rule, "_other_subnet_sources",
                               return_value=["192.168.0.0/24"]), \
             mock.patch("core.routing.masquerade.remove_if_unused",
                        mock.Mock(return_value={"ok": True})):
            device_rule.remove_device_rule(rule)
        dels = [" ".join(c) for c in fake.deleted()]
        self.assertFalse(any("from 192.168.0.1/32 lookup main" in d
                            for d in dels), dels)


if __name__ == "__main__":
    unittest.main()
