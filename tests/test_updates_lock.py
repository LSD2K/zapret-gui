# tests/test_updates_lock.py
"""
Замок обновлений updates.locked (debian-gw, docs/gw/spec-t4-updates.md).

При замке семь эндпоинтов установки/обновления/удаления отвечают 403
{"error": "locked", "message": ...} и не трогают установщики; без замка
ведут себя как раньше. GET /api/updates/lock отдаёт состояние вебке.
"""

import json
import shutil
import tempfile
import unittest
from unittest import mock

import core.config_manager as cm_mod
from core.config_manager import ConfigManager, DEFAULT_CONFIG
from api._updates_lock import LOCK_MESSAGE
from tests._wsgi_client import WSGIClient, build_test_app


# Все закрываемые эндпоинты по спеке (все POST).
LOCKED_ENDPOINTS = [
    "/api/gui/update",
    "/api/zapret/install",
    "/api/zapret/update",
    "/api/zapret/uninstall",
    "/api/singbox/install",
    "/api/singbox/install/local",
    "/api/singbox/uninstall",
]


class _Base(unittest.TestCase):
    """Временный settings.json и фейковые установщики."""

    locked = False

    @classmethod
    def setUpClass(cls):
        cls.client = WSGIClient(build_test_app())

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, True)
        cm = ConfigManager(config_dir=self.tmp)
        cm.load()
        if self.locked:
            cm.set("updates", "locked", True)
            cm.save()
        self.cm = cm
        p = mock.patch.object(cm_mod, "_config_manager", cm)
        p.start()
        self.addCleanup(p.stop)

        # Установщики: любой вызов фиксируется, сеть и диск не трогаются.
        self.gui = mock.MagicMock()
        self.gui.start_update.return_value = {"ok": True,
                                              "in_progress": True}
        self.zapret = mock.MagicMock()
        self.zapret.get_installed_version.return_value = {
            "installed": False, "version": ""}
        self.zapret.install.return_value = {"ok": True}
        self.zapret.update.return_value = {"ok": True}
        self.zapret.uninstall.return_value = {"ok": True, "removed": []}
        self.singbox = mock.MagicMock()
        self.singbox.install.return_value = {"ok": True, "version": "1.0"}
        self.singbox.uninstall.return_value = {"ok": True}
        self.upload = mock.MagicMock(return_value={"ok": True})

        for target, value in (
            ("core.gui_updater.get_gui_updater", lambda: self.gui),
            ("core.zapret_installer.get_zapret_installer",
             lambda: self.zapret),
            ("core.singbox_installer.get_singbox_installer",
             lambda: self.singbox),
            ("api._install_upload.handle_single_upload", self.upload),
        ):
            p = mock.patch(target, value)
            p.start()
            self.addCleanup(p.stop)

    def post(self, path, body=None):
        return self.client.request("POST", path, body=body or {})


class TestDefault(unittest.TestCase):

    def test_default_is_unlocked(self):
        self.assertEqual(DEFAULT_CONFIG["updates"], {"locked": False})


class TestLocked(_Base):

    locked = True

    def test_every_endpoint_is_403_with_contract_body(self):
        for path in LOCKED_ENDPOINTS:
            with self.subTest(path=path):
                code, headers, body = self.post(path, {"confirm": True})
                self.assertEqual(code, 403)
                self.assertIn("application/json",
                              headers.get("content-type", ""))
                self.assertEqual(body["error"], "locked")
                self.assertEqual(body["message"],
                                 "обновления на этом хосте делает gw-panel")
                self.assertIs(body["ok"], False)

    def test_installers_are_not_touched(self):
        for path in LOCKED_ENDPOINTS:
            self.post(path, {"confirm": True, "tag": "v1"})
        self.assertEqual(self.gui.mock_calls, [])
        self.assertEqual(self.zapret.mock_calls, [])
        self.assertEqual(self.singbox.mock_calls, [])
        self.upload.assert_not_called()

    def test_lock_is_checked_before_body_parsing(self):
        # Битое тело: замок всё равно отвечает 403, а не 400/500.
        for path in LOCKED_ENDPOINTS:
            with self.subTest(path=path):
                code, _, body = self.client.request(
                    "POST", path, body=b"{not json",
                    content_type="application/json")
                self.assertEqual(code, 403)
                self.assertEqual(body["error"], "locked")

    def test_lock_state_endpoint(self):
        r = self.client.get_json("/api/updates/lock")
        self.assertEqual(r["_status"], 200)
        self.assertIs(r["locked"], True)
        self.assertEqual(r["message"], LOCK_MESSAGE)

    def test_read_endpoints_stay_open(self):
        # Панель читает версии и прогресс: GET не закрываются.
        self.zapret.get_operation_status.return_value = {"in_progress": False}
        r = self.client.get_json("/api/zapret/installed")
        self.assertEqual(r["_status"], 200)
        r = self.client.get_json("/api/zapret/progress")
        self.assertEqual(r["_status"], 200)
        self.gui.get_operation_status.return_value = {"in_progress": False}
        r = self.client.get_json("/api/gui/progress")
        self.assertEqual(r["_status"], 200)

    def test_other_post_endpoints_are_not_locked(self):
        # Остановка nfqws2 не обновление: замок её не трогает.
        self.zapret.stop_nfqws.return_value = {"ok": True}
        code, _, _ = self.post("/api/zapret/stop")
        self.assertEqual(code, 200)
        self.zapret.stop_nfqws.assert_called_once()


class TestUnlocked(_Base):

    locked = False

    def test_no_endpoint_answers_locked(self):
        for path in LOCKED_ENDPOINTS:
            with self.subTest(path=path):
                code, _, body = self.post(path)
                self.assertNotEqual(code, 403)
                self.assertNotEqual(body.get("error"), "locked")

    def test_handlers_reach_installers(self):
        self.post("/api/gui/update", {"tag": "v1"})
        self.gui.start_update.assert_called_once_with(
            tag="v1", branch="", transport="")
        # Не установлен: install идёт дальше проверки, update отказывает 400.
        self.post("/api/zapret/update")
        self.zapret.get_installed_version.assert_called()
        code, _, _ = self.post("/api/zapret/uninstall")
        self.assertEqual(code, 400)      # без confirm, как раньше
        self.post("/api/singbox/install")
        self.singbox.install.assert_called_once()
        self.post("/api/singbox/install/local")
        self.upload.assert_called_once()
        self.post("/api/singbox/uninstall")
        self.singbox.uninstall.assert_called_once()

    def test_lock_state_endpoint(self):
        r = self.client.get_json("/api/updates/lock")
        self.assertEqual(r["_status"], 200)
        self.assertIs(r["locked"], False)
        self.assertEqual(r["message"], "")

    def test_put_config_turns_lock_on_and_persists(self):
        code, _, body = self.client.request(
            "PUT", "/api/config", body={"updates": {"locked": True}})
        self.assertEqual(code, 200)
        with open(self.cm.path, encoding="utf-8") as f:
            saved = json.load(f)
        self.assertIs(saved["updates"]["locked"], True)
        code, _, body = self.post("/api/zapret/update")
        self.assertEqual(code, 403)
        self.assertEqual(body["error"], "locked")

    def test_non_true_values_do_not_lock(self):
        # Замок включает только JSON true: строка или 1 не считаются.
        for value in ("true", 1, None):
            with self.subTest(value=value):
                self.cm.set("updates", "locked", value)
                code, _, _ = self.post("/api/singbox/uninstall")
                self.assertNotEqual(code, 403)


if __name__ == "__main__":
    unittest.main()
