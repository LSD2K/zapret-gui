# tests/test_mcp_secrets_mode.py
"""
Режим «без маскировки»: разрешение `secrets` и аргумент `raw`.

Маска спасает от утечки и мешает работать. Модель, прочитавшая конфиг с
`***` вместо ключа и записавшая его обратно, этот ключ **уничтожает** —
и узнаёт об этом последней. Поэтому режим есть, но он:

* **выключен по умолчанию** — как и все остальные разрешения;
* **включается только явно**: разрешение `secrets` И `raw: true` в
  конкретном вызове. Одного разрешения мало: ответ без маски — это
  решение на вызов, а не на сессию;
* **без разрешения даёт ОТКАЗ, а не тихую маскировку.** Это главное,
  что здесь стережётся: молча отдать замаскированное на явную просьбу
  «как есть» значит отдать модели испорченные данные, которые она
  запишет обратно;
* **журнал маскируется всегда.** Ответ уезжает модели и исчезает,
  а `mcp-audit.jsonl` остаётся на диске и переживает и вызов, и
  разрешение.
"""

import os
import shutil
import tempfile
import unittest

from core.mcp import audit
from core.mcp import permissions as perms_mod
from core.mcp import redact
from core.mcp import registry


SECRETS = {"secrets": True, "shell_readonly": True}
NO_SECRETS = {"shell_readonly": True}

TOKEN = "s3cr3t-token-value-0123456789"
FILE_TEXT = "api_key = %s\nhost = router.lan\n" % TOKEN


class TestSwitch(unittest.TestCase):
    """Сам переключатель: по умолчанию маскируем, в контексте — нет."""

    def test_off_by_default(self):
        self.assertFalse(redact.raw_mode())
        self.assertEqual(redact.redact({"token": "abc"}), {"token": "***"})

    def test_context_turns_it_off_and_back(self):
        with redact.unredacted():
            self.assertTrue(redact.raw_mode())
            self.assertEqual(redact.redact({"token": "abc"}),
                             {"token": "abc"})
        self.assertFalse(redact.raw_mode())
        self.assertEqual(redact.redact({"token": "abc"}), {"token": "***"})

    def test_context_survives_an_exception(self):
        try:
            with redact.unredacted():
                raise RuntimeError("boom")
        except RuntimeError:
            pass
        self.assertFalse(redact.raw_mode())

    def test_text_and_url_follow_the_same_switch(self):
        line = "Authorization: Bearer %s" % TOKEN
        url = "https://host/sub?token=%s" % TOKEN
        self.assertNotIn(TOKEN, redact.redact_text(line))
        self.assertNotIn(TOKEN, redact.shorten_url(url))
        with redact.unredacted():
            self.assertIn(TOKEN, redact.redact_text(line))
            self.assertIn(TOKEN, redact.shorten_url(url))

    def test_force_masks_even_in_raw_mode(self):
        # `force` — то, на чём держится журнал: он на диске, и секретам
        # там не место, о чём бы ни попросил клиент.
        with redact.unredacted():
            self.assertEqual(redact.redact({"token": "abc"}, force=True),
                             {"token": "***"})
            self.assertNotIn(
                TOKEN, redact.redact_text("token=%s" % TOKEN, force=True))


class TestFileRead(unittest.TestCase):
    """`file_read` — главный потребитель режима."""

    def setUp(self):
        registry.load_tools()
        self.dir = tempfile.mkdtemp(prefix="mcp-secrets-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.path = os.path.join(self.dir, "service.conf")
        with open(self.path, "w", encoding="utf-8") as f:
            f.write(FILE_TEXT)

    def read(self, perms, **args):
        answer = registry.call("file_read", dict(args, path=self.path),
                               perms)
        return answer["isError"], answer["structuredContent"]

    def test_masked_by_default(self):
        failed, payload = self.read(NO_SECRETS)
        self.assertFalse(failed)
        self.assertNotIn(TOKEN, payload["content"])
        self.assertTrue(payload["redacted"])
        # И прямо сказано, что записывать это обратно нельзя.
        self.assertIn("raw=true", payload["hint"])

    def test_raw_without_the_permission_is_refused(self):
        failed, payload = self.read(NO_SECRETS, raw=True)
        self.assertTrue(failed)
        self.assertEqual(payload["permission"], "secrets")
        self.assertNotIn(TOKEN, str(payload))

    def test_raw_with_the_permission_returns_everything(self):
        failed, payload = self.read(SECRETS, raw=True)
        self.assertFalse(failed)
        self.assertIn(TOKEN, payload["content"])
        self.assertFalse(payload["redacted"])

    def test_permission_alone_does_not_unmask(self):
        # Разрешение открывает возможность, а не режим: без `raw` ответ
        # маскируется, как и был.
        failed, payload = self.read(SECRETS)
        self.assertFalse(failed)
        self.assertNotIn(TOKEN, payload["content"])
        self.assertTrue(payload["redacted"])


class TestConfigGet(unittest.TestCase):

    def setUp(self):
        registry.load_tools()

    def test_raw_is_refused_without_the_permission(self):
        answer = registry.call("config_get", {"path": "gui", "raw": True},
                               {})
        self.assertTrue(answer["isError"])
        self.assertEqual(answer["structuredContent"]["permission"],
                         "secrets")

    def test_redacted_flag_tells_which_mode_it_was(self):
        payload = registry.call("config_get", {"path": "gui"},
                                {})["structuredContent"]
        self.assertTrue(payload["redacted"])


class TestWritableLeaves(unittest.TestCase):
    """`secrets` снимает запрет на секретные листья — и только на них."""

    def setUp(self):
        from core.config_manager import DEFAULT_CONFIG

        # Заводим временный лист в разрешённой секции: сегодня ни одной
        # настройки, похожей на секрет, в открытых на запись секциях
        # нет — а правило должно работать до того, как она появится.
        self.defaults = DEFAULT_CONFIG
        section = DEFAULT_CONFIG["nfqws"]
        section["test_api_token"] = ""
        section["test_log_path"] = "/tmp/x"
        self.addCleanup(section.pop, "test_api_token", None)
        self.addCleanup(section.pop, "test_log_path", None)

    def test_secret_leaf_is_closed_by_default(self):
        self.assertFalse(perms_mod.is_writable("nfqws.test_api_token"))
        reason = perms_mod.why_not_writable("nfqws.test_api_token")
        self.assertIn("secrets", reason)

    def test_secret_leaf_opens_with_the_permission(self):
        self.assertTrue(perms_mod.is_writable("nfqws.test_api_token",
                                              secrets=True))

    def test_path_like_leaf_stays_closed(self):
        # Расположение файла к секретам отношения не имеет: неверный
        # путь не ломает GUI громко, а тихо выключает часть логики.
        self.assertFalse(perms_mod.is_writable("nfqws.test_log_path"))
        self.assertFalse(perms_mod.is_writable("nfqws.test_log_path",
                                               secrets=True))

    def test_writable_paths_listing_matches_the_flag(self):
        without = {item["path"] for item in perms_mod.writable_paths()}
        with_secrets = {item["path"]
                        for item in perms_mod.writable_paths(secrets=True)}
        self.assertNotIn("nfqws.test_api_token", without)
        self.assertIn("nfqws.test_api_token", with_secrets)


class TestJournal(unittest.TestCase):
    """Журнал маскируется, даже когда ответ — нет."""

    def test_args_are_masked_in_raw_mode(self):
        with redact.unredacted():
            safe = audit._safe_args({"token": TOKEN,
                                     "command": "curl -H 'token=%s'"
                                                % TOKEN})
        self.assertEqual(safe["token"], "***")
        self.assertNotIn(TOKEN, safe["command"])


class TestPermissionModel(unittest.TestCase):

    def test_secrets_is_not_a_write_permission(self):
        # С одним `secrets` менять нечего — значит и `mcp_undo_last`
        # публиковать незачем.
        self.assertNotIn("secrets", perms_mod.WRITE_PERMISSIONS)
        self.assertFalse(perms_mod.allowed(perms_mod.ANY_WRITE_SCOPE,
                                           {"secrets": True}))

    def test_secrets_opens_no_tools(self):
        registry.load_tools()
        base = {spec.name for spec in registry.available_tools({})}
        with_secrets = {spec.name
                        for spec in registry.available_tools(
                            {"secrets": True})}
        self.assertEqual(base, with_secrets)

    def test_it_is_listed_and_described(self):
        keys = [item["key"] for item in perms_mod.describe({})]
        self.assertIn("secrets", keys)
        self.assertTrue(perms_mod.TITLES["secrets"])


if __name__ == "__main__":
    unittest.main()
