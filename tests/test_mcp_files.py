# tests/test_mcp_files.py
"""
Файлы: граница записи, атомарность и путь назад.

Что здесь важно:

* **писать можно только внутрь ``mcp.shell.allow_write_paths``** — и
  проверяется это по РЕЗОЛВНУТОМУ пути: симлинк из разрешённого
  каталога наружу иначе провёл бы запись мимо границы;
* **собственные файлы GUI не правятся вовсе.** ``settings.json``,
  журнал MCP и снимки для отката — не «файлы на диске», а модель
  разрешений и путь назад; переписав их, модель выдала бы себе права
  и стёрла следы;
* **запись атомарна и не теряет права файла.** Атомарная запись
  создаёт новый файл: без явного ``chmod`` init-скрипт терял бы ``+x``
  и переставал запускаться при следующей загрузке;
* **прежняя версия попадает в аудит и возвращается ``mcp_undo_last``**
  — включая случай «файла не было»: там откат означает удаление
  созданного, а не запись пустоты;
* файл, который **нечем откатить** (слишком большой для снимка), на
  запись не принимается вовсе. Изменение без пути назад противоречит
  инварианту §5.4 контракта.
"""

import os
import unittest

from core.mcp import audit
from tests._shell_sandbox import Sandbox


FULL = {"shell_full": True}
RO = {"shell_readonly": True}


class TestRead(unittest.TestCase):
    """Чтение: окно, хвост, каталог, отсутствующий файл."""

    def setUp(self):
        self.box = Sandbox(self, RO)

    def test_window_and_tail(self):
        path = self.box.write("log.txt",
                              "".join("line%d\n" % i for i in range(1000)))
        head = self.box.data("file_read", {"path": path, "limit_kb": 1})
        self.assertTrue(head["ok"])
        self.assertTrue(head["truncated"])
        self.assertTrue(head["content"].startswith("line0"))

        more = self.box.data("file_read", {"path": path, "limit_kb": 1,
                                           "offset": head["next_offset"]})
        self.assertFalse(more["content"].startswith("line0"))

        tail = self.box.data("file_read", {"path": path, "limit_kb": 1,
                                           "tail": True})
        self.assertTrue(tail["content"].rstrip().endswith("line999"))

    def test_missing_file_is_an_answer_not_a_traceback(self):
        result = self.box.data("file_read",
                               {"path": self.box.path("nope")})
        self.assertFalse(result["ok"])
        self.assertFalse(result["exists"])
        self.assertIn("file_list", result["hint"])

    def test_directory_is_refused_with_a_pointer(self):
        result = self.box.data("file_read", {"path": self.box.dir})
        self.assertFalse(result["ok"])
        self.assertIn("file_list", result["hint"])

    def test_relative_path_is_refused(self):
        result = self.box.data("file_read", {"path": "etc/passwd"})
        self.assertFalse(result["ok"])
        self.assertIn("абсолютный", result["error"])

    def test_listing_gives_fields_not_a_string(self):
        self.box.write("a.txt", "x")
        os.mkdir(self.box.path("sub"))
        result = self.box.data("file_list", {"path": self.box.dir})
        self.assertTrue(result["ok"])
        by_name = {item["name"]: item for item in result["items"]}
        self.assertEqual(by_name["a.txt"]["type"], "file")
        self.assertEqual(by_name["a.txt"]["size"], 1)
        self.assertTrue(by_name["a.txt"]["mode"].startswith("-"))
        self.assertEqual(by_name["sub"]["type"], "dir")
        self.assertIn("modified", by_name["a.txt"])

    def test_listing_a_missing_directory_is_not_an_error(self):
        result = self.box.data("file_list", {"path": self.box.path("nope")})
        self.assertTrue(result["ok"])
        self.assertFalse(result["available"])
        self.assertEqual(result["items"], [])


class TestWriteBoundary(unittest.TestCase):
    """Куда писать нельзя."""

    def setUp(self):
        self.box = Sandbox(self, FULL)

    def test_write_outside_allowed_paths_is_refused(self):
        result = self.box.data("file_write",
                               {"path": "/etc/zapret-mcp-test",
                                "content": "x"}, FULL)
        self.assertFalse(result["ok"])
        self.assertIn("allow_write_paths", result["hint"])
        self.assertFalse(os.path.exists("/etc/zapret-mcp-test"))

    def test_symlink_out_of_the_sandbox_is_refused(self):
        # Проверка по резолвнутому пути, а не по написанному: иначе
        # симлинк — готовая дыра в границе записи.
        outside = os.path.join(self.box.dir, "..", "outside-target")
        link = self.box.path("escape")
        os.symlink(os.path.realpath(outside), link)
        result = self.box.data("file_write",
                               {"path": link, "content": "x"}, FULL)
        self.assertFalse(result["ok"])
        self.assertIn("resolved", result)

    def test_gui_own_files_are_protected(self):
        for name in ("settings.json", audit.JOURNAL_NAME,
                     audit.SNAPSHOT_NAME):
            with self.subTest(name=name):
                result = self.box.data(
                    "file_write", {"path": self.box.path(name),
                                   "content": "{}"}, FULL)
                self.assertFalse(result["ok"])
                self.assertIn("собственный файл GUI", result["error"])

    def test_write_needs_shell_full(self):
        self.box.permissions(shell_readonly=True)
        call = self.box.call("file_write",
                             {"path": self.box.path("x"), "content": "y"},
                             RO)
        self.assertTrue(call["isError"])
        self.assertIn("shell_full",
                      call["structuredContent"]["error"])
        self.assertFalse(os.path.exists(self.box.path("x")))

    def test_file_too_large_to_back_up_is_not_overwritten(self):
        import core.mcp.tools.files as files_mod

        path = self.box.write("big.bin", "x" * 4096)
        self.addCleanup(setattr, files_mod, "MAX_BACKUP_BYTES",
                        files_mod.MAX_BACKUP_BYTES)
        files_mod.MAX_BACKUP_BYTES = 1024
        result = self.box.data("file_write", {"path": path,
                                              "content": "small"}, FULL)
        self.assertFalse(result["ok"])
        self.assertEqual(self.box.read(path), "x" * 4096)


class TestWriteAndUndo(unittest.TestCase):
    """Запись, права, снимок и откат."""

    def setUp(self):
        self.box = Sandbox(self, FULL)

    def test_new_file_is_created_and_undo_removes_it(self):
        path = self.box.path("new.conf")
        result = self.box.data("file_write", {"path": path,
                                              "content": "hello\n"}, FULL)
        self.assertTrue(result["ok"])
        self.assertTrue(result["created"])
        self.assertEqual(self.box.read(path), "hello\n")

        undone = self.box.data("mcp_undo_last", {}, FULL)
        self.assertTrue(undone["reverted"])
        self.assertFalse(os.path.exists(path))

    def test_existing_file_is_restored_by_undo(self):
        path = self.box.write("keep.conf", "старое\n")
        self.box.data("file_write", {"path": path, "content": "новое\n"},
                      FULL)
        self.assertEqual(self.box.read(path), "новое\n")

        undone = self.box.data("mcp_undo_last", {}, FULL)
        self.assertTrue(undone["reverted"])
        self.assertEqual(self.box.read(path), "старое\n")

    def test_snapshot_is_written_to_disk(self):
        path = self.box.write("snap.conf", "было\n")
        result = self.box.data("file_write", {"path": path,
                                              "content": "стало\n"}, FULL)
        self.assertEqual(result["undo"]["kind"], audit.KIND_FILE)
        entry = audit.last_snapshot(audit.KIND_FILE)
        self.assertEqual(entry["target"], path)
        self.assertEqual(entry["before"]["content"], "было\n")

    def test_executable_bit_survives_the_write(self):
        # Атомарная запись создаёт НОВЫЙ файл: без сохранения прав
        # init-скрипт перестал бы запускаться при следующей загрузке.
        path = self.box.write("S99thing", "#!/bin/sh\necho old\n")
        os.chmod(path, 0o755)
        self.box.data("file_write",
                      {"path": path, "content": "#!/bin/sh\necho new\n"},
                      FULL)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o755)

    def test_mode_is_applied_to_a_new_file(self):
        path = self.box.path("script.sh")
        self.box.data("file_write", {"path": path, "content": "#!/bin/sh\n",
                                     "mode": "755"}, FULL)
        self.assertEqual(os.stat(path).st_mode & 0o777, 0o755)

    def test_write_is_atomic(self):
        # Временный файл не остаётся рядом, а содержимое меняется
        # целиком: читатель не видит полузаписанного файла.
        path = self.box.write("atomic.conf", "1" * 100)
        self.box.data("file_write", {"path": path, "content": "2" * 100},
                      FULL)
        self.assertEqual(self.box.read(path), "2" * 100)
        leftovers = [n for n in os.listdir(self.box.dir)
                     if n.startswith(".tmp-")]
        self.assertEqual(leftovers, [])

    def test_missing_parent_needs_create_dirs(self):
        path = self.box.path("deep/inner/file.txt")
        refused = self.box.data("file_write", {"path": path,
                                               "content": "x"}, FULL)
        self.assertFalse(refused["ok"])
        created = self.box.data("file_write", {"path": path, "content": "x",
                                               "create_dirs": True}, FULL)
        self.assertTrue(created["ok"])
        self.assertTrue(os.path.isfile(path))

    def test_undo_walks_back_one_change_at_a_time(self):
        first = self.box.write("chain.conf", "v1\n")
        self.box.data("file_write", {"path": first, "content": "v2\n"},
                      FULL)
        self.box.data("file_write", {"path": first, "content": "v3\n"},
                      FULL)
        self.box.data("mcp_undo_last", {}, FULL)
        self.assertEqual(self.box.read(first), "v2\n")
        self.box.data("mcp_undo_last", {}, FULL)
        self.assertEqual(self.box.read(first), "v1\n")


if __name__ == "__main__":
    unittest.main()
