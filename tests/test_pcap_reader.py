# tests/test_pcap_reader.py
"""
Разбор pcap в поля: байтами, без роутера и без tcpdump.

Почему тест байтовый. `core/pcap_reader.py` — чистая функция от
содержимого файла: ни одного побочного действия, ни одной зависимости.
Значит, его можно проверить целиком, собрав дамп руками, — и это
единственная часть снифера, которую вообще можно проверить в CI:
запустить tcpdump здесь нельзя, а «разобрали неправильно» выглядит для
модели точно так же, как «ничего не поймали».

Что стережём:

* **TTL, флаги и длина payload'а** — ради них снифер и заводится:
  короткий TTL у части пакетов означает, что fake-пакеты десинка
  действительно уходят;
* **SNI из ClientHello** — «имя ушло открытым текстом» это готовый
  ответ на вопрос «почему DPI это видит»;
* **обрезанный файл — норма, а не исключение**: tcpdump прибивают по
  таймеру, и последний пакет бывает недописан;
* **незнакомое — честно помечается**, а не молчит: пакет с неизвестным
  канальным уровнем приезжает с полем `error`.
"""

import struct
import unittest

from core import pcap_reader


def tls_client_hello(name: bytes) -> bytes:
    """Минимальный ClientHello с расширением server_name."""
    server_name = b"\x00" + struct.pack(">H", len(name)) + name
    name_list = struct.pack(">H", len(server_name)) + server_name
    extension = b"\x00\x00" + struct.pack(">H", len(name_list)) + name_list
    body = (
        b"\x03\x03"                      # client_version
        + b"\xAA" * 32                   # random
        + b"\x00"                        # session_id_len
        + struct.pack(">H", 2) + b"\x13\x01"   # cipher_suites
        + b"\x01\x00"                    # compression
        + struct.pack(">H", len(extension)) + extension
    )
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


def tcp(payload: bytes, *, sport=55555, dport=443, flags=0x18) -> bytes:
    return (struct.pack(">HH", sport, dport)
            + struct.pack(">II", 1, 2)
            + bytes([0x50, flags])
            + struct.pack(">HHH", 64240, 0, 0)
            + payload)


def ipv4(payload: bytes, *, src="192.168.1.10", dst="1.2.3.4", ttl=64,
         proto=6) -> bytes:
    import socket

    header = (bytes([0x45, 0x00])
              + struct.pack(">H", 20 + len(payload))
              + struct.pack(">HH", 0x1234, 0x4000)
              + bytes([ttl, proto])
              + b"\x00\x00"
              + socket.inet_aton(src) + socket.inet_aton(dst))
    return header + payload


def ethernet(payload: bytes) -> bytes:
    return b"\x11" * 6 + b"\x22" * 6 + b"\x08\x00" + payload


def pcap(frames, linktype=pcap_reader.LINKTYPE_ETHERNET,
         truncate_last=False) -> bytes:
    out = struct.pack("<IHHiIII", pcap_reader.MAGIC_LE, 2, 4, 0, 0,
                      65535, linktype)
    for index, frame in enumerate(frames):
        last = index == len(frames) - 1
        body = frame[:len(frame) // 2] if (last and truncate_last) else frame
        out += struct.pack("<IIII", 1700000000 + index, 500000,
                           len(frame), len(frame))
        out += body
    return out


class TestHeader(unittest.TestCase):

    def test_not_a_pcap(self):
        with self.assertRaises(pcap_reader.PcapError):
            pcap_reader.read_bytes(b"not a pcap file at all, honestly!!")

    def test_too_short(self):
        with self.assertRaises(pcap_reader.PcapError):
            pcap_reader.read_bytes(b"\x00" * 8)

    def test_linktype_is_named(self):
        report = pcap_reader.read_bytes(pcap([ethernet(ipv4(tcp(b"")))]))
        self.assertEqual(report["linktype_name"], "ethernet")


class TestPackets(unittest.TestCase):

    def parse(self, *frames, **kwargs):
        return pcap_reader.read_bytes(pcap(list(frames), **kwargs))

    def test_tcp_fields(self):
        report = self.parse(ethernet(ipv4(tcp(b"hello", flags=0x02),
                                           ttl=3)))
        packet = report["packets"][0]
        self.assertEqual(packet["src"], "192.168.1.10")
        self.assertEqual(packet["dst"], "1.2.3.4")
        # TTL — то, ради чего снифер и заводится.
        self.assertEqual(packet["ttl"], 3)
        self.assertEqual(packet["proto"], "tcp")
        self.assertEqual(packet["flags"], ["SYN"])
        self.assertEqual(packet["dport"], 443)
        self.assertEqual(packet["payload_len"], 5)

    def test_sni_is_extracted(self):
        report = self.parse(
            ethernet(ipv4(tcp(tls_client_hello(b"rutracker.org")))))
        packet = report["packets"][0]
        self.assertEqual(packet["l7"], "tls")
        self.assertEqual(packet["sni"], "rutracker.org")

    def test_tls_without_a_readable_name_says_why(self):
        # Ровно так выглядит разрезанный десинком ClientHello: первый
        # сегмент обрывается до расширения с именем. Это не ошибка
        # разбора, и путать одно с другим нельзя.
        cut = tls_client_hello(b"example.com")[:40]
        report = self.parse(ethernet(ipv4(tcp(cut))))
        packet = report["packets"][0]
        self.assertEqual(packet.get("sni", ""), "")
        self.assertIn("разрезан", packet.get("note", ""))

    def test_http_host(self):
        request = (b"GET /index.html HTTP/1.1\r\n"
                   b"Host: example.org\r\n\r\n")
        report = self.parse(ethernet(ipv4(tcp(request, dport=80))))
        packet = report["packets"][0]
        self.assertEqual(packet["l7"], "http")
        self.assertEqual(packet["host"], "example.org")
        self.assertEqual(packet["http_method"], "GET")

    def test_udp_and_icmp(self):
        udp = struct.pack(">HHHH", 40000, 53, 8, 0) + b"\x00" * 4
        report = self.parse(ethernet(ipv4(udp, proto=17)),
                            ethernet(ipv4(b"\x08\x00\x00\x00", proto=1)))
        self.assertEqual(report["packets"][0]["proto"], "udp")
        self.assertEqual(report["packets"][0]["dport"], 53)
        self.assertEqual(report["packets"][1]["proto"], "icmp")

    def test_raw_ip_linktype(self):
        # TUN-интерфейсы отдают дамп без канального заголовка.
        report = pcap_reader.read_bytes(
            pcap([ipv4(tcp(b""))], linktype=pcap_reader.LINKTYPE_RAW))
        self.assertEqual(report["packets"][0]["dst"], "1.2.3.4")

    def test_unknown_linktype_is_reported_not_raised(self):
        report = pcap_reader.read_bytes(pcap([b"\x00" * 40], linktype=999))
        self.assertIn("канальный уровень", report["packets"][0]["error"])

    def test_truncated_tail_is_dropped(self):
        report = self.parse(ethernet(ipv4(tcp(b"one"))),
                            ethernet(ipv4(tcp(b"two"))),
                            truncate_last=True)
        # Недописанный хвост просто не попадает в список — и это не
        # повод потерять то, что успели снять.
        self.assertEqual(len(report["packets"]), 1)

    def test_snapped_packet_is_flagged(self):
        frame = ethernet(ipv4(tcp(b"x" * 100)))
        data = struct.pack("<IHHiIII", pcap_reader.MAGIC_LE, 2, 4, 0, 0,
                           65535, pcap_reader.LINKTYPE_ETHERNET)
        cut = frame[:60]
        data += struct.pack("<IIII", 1700000000, 0, len(cut), len(frame))
        data += cut
        packet = pcap_reader.read_bytes(data)["packets"][0]
        # «SNI не найден» на снятом наполовину пакете может означать
        # «не доехал», а не «его не было».
        self.assertTrue(packet["snapped"])

    def test_limit_keeps_the_total_honest(self):
        frames = [ethernet(ipv4(tcp(b"x"))) for _ in range(5)]
        report = pcap_reader.read_bytes(pcap(frames), limit=2)
        self.assertEqual(len(report["packets"]), 2)
        self.assertEqual(report["total"], 5)
        self.assertTrue(report["truncated"])


class TestSniParser(unittest.TestCase):
    """`tls_sni` не падает ни на чём: сюда приезжают куски пакетов."""

    def test_garbage_returns_empty(self):
        for payload in (b"", b"\x16", b"\x16\x03\x01\xff\xff",
                        b"\x16" + b"\x00" * 200, b"\x17\x03\x03abcd",
                        tls_client_hello(b"a.com")[:20]):
            with self.subTest(payload=payload[:8]):
                self.assertIsInstance(pcap_reader.tls_sni(payload), str)


if __name__ == "__main__":
    unittest.main()
