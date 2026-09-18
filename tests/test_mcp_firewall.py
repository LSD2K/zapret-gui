# tests/test_mcp_firewall.py
"""
Правила перехвата из MCP: порты управления не уводятся в NFQUEUE.

Это сторож инварианта §5.5 контракта — «не рвать управление». Пакет,
отправленный в NFQUEUE, которую никто не читает (движок упал, ещё не
поднялся или стоит на другом номере очереди), просто исчезает. Если в
эту очередь уедет SSH или порт веб-интерфейса, роутер станет
недоступен — и отменить изменение будет нечем.

Дыра, которую здесь закрывают, не гипотетическая: ``nfqws.ports_tcp``
открыт на запись через ``config_set``, и последовательность
«config_set(ports_tcp="22,80,443") → firewall_apply» до S7 приводила
ровно к этому. Поэтому исключение живёт в ``core/firewall.py``
(действует для ЛЮБОГО применения правил), а не только в обёртке MCP.

Реальные iptables не дёргаем: тест, правящий firewall машины, на
которой его запустили, — это та же поломка, только своими руками.
"""

import unittest
from unittest import mock

import core.firewall as firewall_mod
from core.mcp import registry


CONTROL = {"control": True}


class TestStripManagementPorts(unittest.TestCase):
    """Чистая функция: что остаётся от спецификации портов."""

    def setUp(self):
        self.cfg = _Cfg(8080)

    def strip(self, spec):
        return firewall_mod.strip_management_ports(spec, self.cfg)

    def test_normal_ports_are_untouched(self):
        self.assertEqual(self.strip("80,443"), ("80,443", []))

    def test_ssh_is_removed(self):
        kept, dropped = self.strip("22,80,443")
        self.assertEqual(kept, "80,443")
        self.assertIn(22, dropped)

    def test_gui_port_is_removed(self):
        kept, dropped = self.strip("80,443,8080")
        self.assertEqual(kept, "80,443")
        self.assertIn(8080, dropped)

    def test_gui_port_is_read_from_config_not_hardcoded(self):
        self.cfg = _Cfg(9999)
        kept, dropped = self.strip("80,443,9999")
        self.assertEqual(kept, "80,443")
        self.assertIn(9999, dropped)
        # А дефолтный 8080, когда GUI живёт не на нём, трогать незачем.
        self.assertEqual(self.strip("8080")[0], "8080")

    def test_range_is_cut_not_dropped(self):
        # «Задел порт управления» не значит «выбросить весь диапазон»:
        # иначе защита превращалась бы в выключение перехвата.
        kept, dropped = self.strip("20:25")
        self.assertEqual(kept, "20:21,24:25")
        self.assertIn(22, dropped)
        self.assertIn(23, dropped)

    def test_everything_range(self):
        kept, _ = self.strip("1:65535")
        for port in ("22", "23", "233", "8080"):
            self.assertNotIn(port, kept.split(","))
        self.assertTrue(kept.startswith("1:21,"))

    def test_only_management_ports_leaves_nothing(self):
        self.assertEqual(self.strip("22,8080"), ("", [22, 8080]))

    def test_service_names_survive(self):
        # Имена служб iptables понимает, а мы их не переписываем.
        self.assertEqual(self.strip("http,https")[0], "http,https")


class TestApplyRulesGuard(unittest.TestCase):
    """Исключение работает внутри apply_rules — для любого вызывающего."""

    def setUp(self):
        self.fw = firewall_mod.FirewallManager()

    def _apply(self, ports_tcp):
        seen = {}

        def fake_iptables(qnum, tcp, udp, *rest):
            seen["tcp"] = tcp
            seen["udp"] = udp
            return True

        cfg = _Cfg(8080, ports_tcp=ports_tcp)
        with mock.patch.object(self.fw, "detect_fw_type",
                               return_value="iptables"), \
                mock.patch.object(self.fw, "_remove_rules_locked",
                                  return_value=True), \
                mock.patch.object(self.fw, "_apply_iptables",
                                  side_effect=fake_iptables), \
                mock.patch.object(self.fw, "_apply_sysctl_tuning"), \
                mock.patch.object(self.fw, "_ensure_persistence"), \
                mock.patch("core.config_manager.get_config_manager",
                           return_value=cfg):
            ok = self.fw.apply_rules()
        return ok, seen

    def test_ssh_and_gui_never_reach_the_rules(self):
        ok, seen = self._apply("22,80,443,8080")
        self.assertTrue(ok)
        self.assertEqual(seen["tcp"], "80,443")

    def test_normal_config_is_untouched(self):
        ok, seen = self._apply("80,443")
        self.assertTrue(ok)
        self.assertEqual(seen["tcp"], "80,443")

    def test_nothing_left_means_no_rules_at_all(self):
        # Применить «перехват ничего» нельзя: правила без портов ушли бы
        # в apply_iptables с пустой спецификацией.
        ok, seen = self._apply("22,8080")
        self.assertFalse(ok)
        self.assertEqual(seen, {})


class TestFirewallTools(unittest.TestCase):
    """Инструменты MCP: разрешение, дифф, снимок и честный hint."""

    def setUp(self):
        registry.load_tools()
        self.manager = _FakeFirewall()
        saved = firewall_mod.get_firewall_manager
        self.addCleanup(setattr, firewall_mod, "get_firewall_manager",
                        saved)
        firewall_mod.get_firewall_manager = lambda: self.manager

        self.cfg = _Cfg(8080, ports_tcp="80,443")
        import core.config_manager as cm
        saved_cfg = cm.get_config_manager
        self.addCleanup(setattr, cm, "get_config_manager", saved_cfg)
        cm.get_config_manager = lambda: self.cfg

    def data(self, name, perms=None):
        return registry.call(name, {},
                             CONTROL if perms is None
                             else perms)["structuredContent"]

    def test_not_listed_without_control(self):
        names = {spec.name for spec in registry.available_tools({})}
        self.assertNotIn("firewall_apply", names)
        self.assertNotIn("firewall_remove", names)

    def test_apply_reports_the_excluded_ports(self):
        self.cfg.values[("nfqws", "ports_tcp")] = "22,80,443"
        payload = self.data("firewall_apply")
        self.assertTrue(payload["ok"])
        self.assertIn(22, payload["excluded_ports"])
        self.assertIn("SSH", payload["note"])

    def test_apply_refuses_when_only_management_ports_remain(self):
        self.cfg.values[("nfqws", "ports_tcp")] = "22,8080"
        payload = self.data("firewall_apply")
        self.assertFalse(payload["ok"])
        self.assertEqual(self.manager.calls, [])
        self.assertIn("config_set", payload["hint"])
        self.assertIn(22, payload["protected_ports"])

    def test_apply_without_engine_says_the_queue_has_no_reader(self):
        import core.mcp.tools.firewall as tools

        saved = tools._engine_running
        self.addCleanup(setattr, tools, "_engine_running", saved)
        tools._engine_running = lambda: False
        payload = self.data("firewall_apply")
        self.assertIn("никто не читает", payload["hint"])

    def test_remove_says_traffic_goes_direct(self):
        self.manager.applied = True
        payload = self.data("firewall_remove")
        self.assertTrue(payload["ok"])
        self.assertFalse(payload["applied"])
        self.assertTrue(payload["changed"])
        self.assertIn("напрямую", payload["hint"])

    def test_missing_backend_is_an_answer_not_a_traceback(self):
        def boom(*a, **kw):
            raise OSError("ни iptables, ни nft нет")

        self.manager.apply_rules = boom
        answer = registry.call("firewall_apply", {}, CONTROL)
        self.assertTrue(answer["isError"])
        self.assertIn("OSError", answer["structuredContent"]["error"])


class _Cfg:
    """Конфиг ровно с теми ключами, которые читает firewall."""

    def __init__(self, gui_port, ports_tcp="80,443"):
        self.values = {
            ("nfqws", "ports_tcp"): ports_tcp,
            ("nfqws", "ports_udp"): "443",
            ("nfqws", "queue_num"): 300,
            ("nfqws", "disable_ipv6"): True,
        }
        self.gui_port = gui_port

    def get(self, *parts, **kw):
        return self.values.get(tuple(parts), kw.get("default"))

    def effective(self):
        return {"gui": {"port": self.gui_port}, "interfaces": {}}


class _FakeFirewall:
    def __init__(self):
        self.applied = False
        self.calls = []

    def apply_rules(self, *a, **kw):
        self.calls.append("apply")
        self.applied = True
        return True

    def remove_rules(self):
        self.calls.append("remove")
        self.applied = False
        return True

    def get_status(self):
        return {"type": "iptables", "applied": self.applied,
                "rules_count": 3 if self.applied else 0}


if __name__ == "__main__":
    unittest.main()
