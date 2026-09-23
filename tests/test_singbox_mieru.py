# tests/test_singbox_mieru.py
"""
Unit-тесты outbound'а `mieru` (только sing-box-extended): билдер
make_mieru_outbound, разбор ссылок mierus:// / mieru:// и то, что тип
известен валидатору и прочим спискам типов.

Логины/пароли/адреса выдуманные (203.0.113.0/24 это TEST-NET-3).
"""

import unittest

from core.singbox_config import (
    KNOWN_OUTBOUND_TYPES, make_mieru_outbound, pick_proxy_outbound,
    validate,
)
from core.singbox_subscription import mieru_to_outbound, uri_to_outbound
from core.subscription_importer import extract_items
from core.mcp import redact

USER, PASS, HOST = "tstUser1", "tstPass9", "203.0.113.10"


class TestMakeMieruOutbound(unittest.TestCase):

    def test_exact_schema(self):
        # Лишние поля sing-box-extended отвергает, схема ровно такая.
        ob = make_mieru_outbound("mieruTest", HOST, ["9000-9010"],
                                 USER, PASS, transport="TCP",
                                 multiplexing="MULTIPLEXING_LOW")
        self.assertEqual(ob, {
            "type": "mieru", "tag": "mieruTest",
            "server": HOST, "server_ports": ["9000-9010"],
            "transport": "TCP", "username": USER, "password": PASS,
            "multiplexing": "MULTIPLEXING_LOW",
        })

    def test_optional_fields_absent_by_default(self):
        ob = make_mieru_outbound("m", HOST, [9000], USER, PASS)
        self.assertEqual(ob["transport"], "TCP")
        self.assertNotIn("multiplexing", ob)
        self.assertNotIn("mtu", ob)

    def test_ports_normalized_to_strings(self):
        ob = make_mieru_outbound(
            "m", HOST, [9000, "9010-9020", " 9030 , 9040-9041 ",
                        "9050 - 9055", "9000"], USER, PASS)
        # Числа → строки, запятые разворачиваются, пробелы в диапазоне
        # убираются, дубль 9000 выкинут, порядок сохранён.
        self.assertEqual(ob["server_ports"],
                         ["9000", "9010-9020", "9030", "9040-9041",
                          "9050-9055"])

    def test_single_port_scalar(self):
        self.assertEqual(
            make_mieru_outbound("m", HOST, 9000, USER, PASS)["server_ports"],
            ["9000"])
        self.assertEqual(
            make_mieru_outbound("m", HOST, "9000-9001", USER,
                                PASS)["server_ports"],
            ["9000-9001"])

    def test_transport_and_multiplexing_case_insensitive(self):
        ob = make_mieru_outbound("m", HOST, ["9000"], USER, PASS,
                                 transport="udp",
                                 multiplexing="multiplexing_high")
        self.assertEqual(ob["transport"], "UDP")
        self.assertEqual(ob["multiplexing"], "MULTIPLEXING_HIGH")

    def test_mtu_passed_when_set(self):
        ob = make_mieru_outbound("m", HOST, ["9000"], USER, PASS,
                                 transport="UDP", mtu="1400")
        self.assertEqual(ob["mtu"], 1400)

    def test_bad_ports_rejected(self):
        for bad in ([], [""], ["abc"], ["0"], ["70000"], ["9010-9000"],
                    ["9000-"], ["-9000"]):
            with self.subTest(ports=bad):
                with self.assertRaises(ValueError):
                    make_mieru_outbound("m", HOST, bad, USER, PASS)

    def test_bad_transport_rejected(self):
        with self.assertRaises(ValueError):
            make_mieru_outbound("m", HOST, ["9000"], USER, PASS,
                                transport="QUIC")

    def test_bad_multiplexing_rejected(self):
        with self.assertRaises(ValueError):
            make_mieru_outbound("m", HOST, ["9000"], USER, PASS,
                                multiplexing="MULTIPLEXING_MAX")

    def test_bad_mtu_rejected(self):
        with self.assertRaises(ValueError):
            make_mieru_outbound("m", HOST, ["9000"], USER, PASS, mtu="big")

    def test_credentials_required(self):
        with self.assertRaises(ValueError):
            make_mieru_outbound("m", HOST, ["9000"], "", PASS)
        with self.assertRaises(ValueError):
            make_mieru_outbound("m", HOST, ["9000"], USER, "")


class TestMieruKnownType(unittest.TestCase):

    def _cfg(self):
        return {"outbounds": [
            {"type": "direct", "tag": "direct"},
            make_mieru_outbound("mieru-out", HOST, ["9000"], USER, PASS),
        ]}

    def test_in_known_outbound_types(self):
        self.assertIn("mieru", KNOWN_OUTBOUND_TYPES)

    def test_validate_does_not_warn(self):
        errs = validate(self._cfg())
        self.assertFalse([e for e in errs if "неизвестный тип" in e], errs)

    def test_pick_proxy_outbound(self):
        self.assertEqual(pick_proxy_outbound(self._cfg()), "mieru-out")


class TestMieruUri(unittest.TestCase):

    def test_full_link_with_profile(self):
        uri = ("mierus://%s:%s@%s?multiplexing=MULTIPLEXING_LOW"
               "&port=9000-9010&profile=mieruTest&protocol=TCP"
               % (USER, PASS, HOST))
        r = mieru_to_outbound(uri)
        self.assertTrue(r["ok"], msg=r.get("error"))
        self.assertEqual(r["tag"], "mieruTest")
        self.assertEqual(r["outbound"], {
            "type": "mieru", "tag": "mieruTest",
            "server": HOST, "server_ports": ["9000-9010"],
            "transport": "TCP", "username": USER, "password": PASS,
            "multiplexing": "MULTIPLEXING_LOW",
        })

    def test_link_without_profile_and_protocol(self):
        r = uri_to_outbound("mierus://%s:%s@%s?port=9010-9020"
                            % (USER, PASS, HOST))
        self.assertTrue(r["ok"], msg=r.get("error"))
        ob = r["outbound"]
        self.assertEqual(ob["tag"], "mieru-%s" % HOST.replace(".", "-"))
        self.assertEqual(ob["transport"], "TCP")          # дефолт
        self.assertEqual(ob["server_ports"], ["9010-9020"])
        self.assertNotIn("multiplexing", ob)

    def test_profile_sanitized_into_tag(self):
        r = uri_to_outbound("mierus://%s:%s@%s?port=9000&profile=My%%20Box"
                            % (USER, PASS, HOST))
        self.assertTrue(r["ok"], msg=r.get("error"))
        self.assertEqual(r["tag"], "My-Box")

    def test_udp_and_mtu(self):
        r = uri_to_outbound("mierus://%s:%s@%s?mtu=1400&port=9000"
                            "&protocol=UDP" % (USER, PASS, HOST))
        self.assertTrue(r["ok"], msg=r.get("error"))
        self.assertEqual(r["outbound"]["transport"], "UDP")
        self.assertEqual(r["outbound"]["mtu"], 1400)

    def test_repeated_and_comma_ports(self):
        r = uri_to_outbound("mierus://%s:%s@%s?port=9000&port=9010-9020"
                            "&port=9030,9040-9050&protocol=TCP"
                            % (USER, PASS, HOST))
        self.assertTrue(r["ok"], msg=r.get("error"))
        self.assertEqual(r["outbound"]["server_ports"],
                         ["9000", "9010-9020", "9030", "9040-9050"])

    def test_paired_protocols_keep_first_transport_ports(self):
        # В ссылке mieru i-й protocol относится к i-му port. transport у
        # outbound'а один, поэтому оставляем порты первого протокола.
        r = uri_to_outbound("mierus://%s:%s@%s?port=9000&port=9001-9002"
                            "&port=9003&protocol=TCP&protocol=UDP"
                            "&protocol=TCP" % (USER, PASS, HOST))
        self.assertTrue(r["ok"], msg=r.get("error"))
        self.assertEqual(r["outbound"]["transport"], "TCP")
        self.assertEqual(r["outbound"]["server_ports"], ["9000", "9003"])

    def test_mieru_scheme_is_synonym(self):
        a = uri_to_outbound("mieru://%s:%s@%s?port=9000&profile=x"
                            % (USER, PASS, HOST))
        b = uri_to_outbound("mierus://%s:%s@%s?port=9000&profile=x"
                            % (USER, PASS, HOST))
        self.assertTrue(a["ok"], msg=a.get("error"))
        self.assertEqual(a["outbound"], b["outbound"])

    def test_hostname_and_encoded_password(self):
        r = uri_to_outbound("mierus://%s:p%%40ss%%3Aword@mieru.example"
                            "?port=9000" % USER)
        self.assertTrue(r["ok"], msg=r.get("error"))
        self.assertEqual(r["outbound"]["server"], "mieru.example")
        self.assertEqual(r["outbound"]["password"], "p@ss:word")

    def test_bad_links(self):
        base = "mierus://%s:%s@%s" % (USER, PASS, HOST)
        cases = {
            "нет пароля":      "mierus://%s@%s?port=9000" % (USER, HOST),
            "нет логина":      "mierus://%s?port=9000" % HOST,
            "нет хоста":       "mierus://%s:%s@?port=9000" % (USER, PASS),
            "нет порта":       base + "?profile=x",
            "плохой порт":     base + "?port=99999",
            "плохой протокол": base + "?port=9000&protocol=QUIC",
            "плохой mux":      base + "?port=9000&multiplexing=MAX",
            "плохой mtu":      base + "?port=9000&mtu=big",
        }
        for name, uri in cases.items():
            with self.subTest(case=name):
                r = uri_to_outbound(uri)
                self.assertFalse(r["ok"], msg=r)
                self.assertTrue(r.get("error"))

    def test_error_style_for_importer(self):
        # «не <scheme>-URI» это сигнал импортеру «не наш URI»; ошибки разбора
        # нашей же схемы так начинаться не должны, иначе импорт их молча
        # проглотит вместо показа причины.
        self.assertEqual(mieru_to_outbound("vless://u@h:1")["error"],
                         "не mieru-URI")
        r = uri_to_outbound("mierus://%s:%s@%s" % (USER, PASS, HOST))
        self.assertFalse(r["ok"])
        self.assertFalse(r["error"].startswith("не "), r["error"])


class TestMieruInLists(unittest.TestCase):

    def test_extract_items_finds_mieru_links(self):
        text = ("vless://u@h.example:443#a\n"
                "mierus://%s:%s@%s?port=9000&profile=one\n"
                "mieru://%s:%s@%s?port=9001" % (USER, PASS, HOST,
                                                USER, PASS, HOST))
        schemes = [it["scheme"] for it in extract_items(text)
                   if it["type"] == "uri"]
        self.assertEqual(schemes, ["vless", "mierus", "mieru"])

    def test_redact_masks_mieru_credentials(self):
        out = redact.redact_text(
            "mierus://%s:%s@%s?port=9000" % (USER, PASS, HOST), force=True)
        self.assertNotIn(PASS, out)
        self.assertIn(HOST, out)


if __name__ == "__main__":
    unittest.main()
