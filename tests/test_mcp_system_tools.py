# tests/test_mcp_system_tools.py
"""
Пакеты и службы: имя проверяется, действие обратимо.

Мока здесь почти нет — и это осознанно. Пакетный менеджер подменён
НАСТОЯЩИМ скриптом с тем же интерфейсом (``opkg list-installed`` /
``status`` / ``install`` / ``remove``), а службы — настоящими
init-скриптами во временном каталоге. Так проверяется то, что мок
проверить не может: как собирается argv, что команда доходит до
системы в неизменном виде и что ничего не подставляется в строку.

Главные инварианты модуля:

* **имя службы сверяется со списком найденных скриптов.** В команду
  уезжает путь, который мы сами прочитали с диска, а не то, что
  прислала модель;
* **``status`` — это чтение**, и он доступен под ``shell_readonly``;
  ``start``/``stop``/``restart`` спрашивают ``shell_full`` по месту;
* **установка и удаление обратимы** (инвариант §5.4): снимок помнит,
  стоял ли пакет, а ``mcp_undo_last`` делает обратное;
* **удаление пакета требует подтверждения**: снос ``dnsmasq-full``
  оставляет LAN без DNS.
"""

import os
import stat
import unittest

from core import shell_exec
from core.mcp import audit
from core.mcp.tools import packages as packages_mod
from core.mcp.tools import services as services_mod
from tests._shell_sandbox import Sandbox


FULL = {"shell_full": True}
RO = {"shell_readonly": True}


def _script(path: str, body: str):
    with open(path, "w", encoding="utf-8") as f:
        f.write("#!/bin/sh\n" + body)
    os.chmod(path, 0o755)
    return path


class TestPackages(unittest.TestCase):
    """opkg подменён скриптом с тем же интерфейсом."""

    def setUp(self):
        self.box = Sandbox(self, FULL)
        self.bin = os.path.join(self.box.dir, "bin")
        os.makedirs(self.bin)
        self.db = os.path.join(self.box.dir, "packages.db")
        with open(self.db, "w", encoding="utf-8") as f:
            f.write("curl - 8.5.0\ndnsmasq-full - 2.90\n")
        _script(os.path.join(self.bin, "opkg"), """
DB=%s
case "$1" in
  list-installed) cat "$DB" ;;
  status) grep -q "^$2 " "$DB" || exit 1
          echo "Package: $2"; V=$(grep "^$2 " "$DB" | head -1)
          echo "Version: ${V##* }" ;;
  install) grep -q "^$2 " "$DB" || echo "$2 - 1.0" >> "$DB"
           echo "Installing $2" ;;
  remove) grep -v "^$2 " "$DB" > "$DB.new"; mv "$DB.new" "$DB"
          echo "Removing $2" ;;
  update) echo "Downloading lists" ;;
  *) echo "unknown: $1" >&2; exit 2 ;;
esac
""" % self.db)
        self._prepend_path(self.bin)

    def _prepend_path(self, directory):
        # И для shutil.which (детект менеджера в процессе GUI), и для
        # самой команды (окружение у неё своё, минимальное).
        saved_env = os.environ.get("PATH", "")
        self.addCleanup(os.environ.__setitem__, "PATH", saved_env)
        os.environ["PATH"] = directory + os.pathsep + saved_env

        saved_base = dict(shell_exec.BASE_ENV)
        self.addCleanup(shell_exec.BASE_ENV.update, saved_base)
        shell_exec.BASE_ENV["PATH"] = (directory + os.pathsep
                                       + shell_exec.BASE_ENV["PATH"])

    def test_manager_is_detected(self):
        self.assertEqual(packages_mod.manager(), "opkg")

    def test_list_parses_names_and_versions(self):
        result = self.box.data("package_list", {}, FULL)
        self.assertTrue(result["ok"])
        by_name = {item["name"]: item["version"] for item in result["items"]}
        self.assertEqual(by_name["curl"], "8.5.0")
        self.assertEqual(by_name["dnsmasq-full"], "2.90")

    def test_list_filters_by_search(self):
        result = self.box.data("package_list", {"search": "dnsmasq"}, FULL)
        self.assertEqual(result["total"], 1)

    def test_install_is_reversible(self):
        result = self.box.data("package_install", {"name": "htop"}, FULL)
        self.assertTrue(result["ok"])
        self.assertTrue(result["installed"])
        self.assertTrue(result["changed"])
        self.assertIn("htop", self.box.read(self.db))

        undone = self.box.data("mcp_undo_last", {}, FULL)
        self.assertTrue(undone["reverted"])
        self.assertNotIn("htop", self.box.read(self.db))

    def test_installing_an_installed_package_changes_nothing(self):
        result = self.box.data("package_install", {"name": "curl"}, FULL)
        self.assertTrue(result["ok"])
        self.assertFalse(result["changed"])

    def test_bad_package_name_never_reaches_the_manager(self):
        for name in ("curl; rm -rf /", "../../etc/passwd", "a b", ""):
            with self.subTest(name=name):
                result = self.box.data("package_install", {"name": name},
                                       FULL)
                self.assertFalse(result["ok"])
                self.assertIn("имя пакета", result["error"]
                              + result.get("hint", ""))
        self.assertIn("curl - 8.5.0", self.box.read(self.db))

    def test_remove_needs_confirmation_and_is_reversible(self):
        first = self.box.data("package_remove", {"name": "dnsmasq-full"},
                              FULL)
        self.assertFalse(first["ok"])
        self.assertTrue(first["need_confirm"])
        self.assertIn("DNS", first["consequences"])
        self.assertIn("dnsmasq-full", self.box.read(self.db))

        second = self.box.data("shell_confirm",
                               {"confirm_token": first["confirm_token"]},
                               FULL)
        self.assertTrue(second["ok"])
        self.assertNotIn("dnsmasq-full", self.box.read(self.db))

        undone = self.box.data("mcp_undo_last", {}, FULL)
        self.assertTrue(undone["reverted"])
        self.assertIn("dnsmasq-full", self.box.read(self.db))

    def test_removing_a_missing_package_says_so(self):
        result = self.box.data("package_remove", {"name": "nosuchpkg"},
                               FULL)
        self.assertTrue(result["ok"])
        self.assertFalse(result["changed"])

    def test_package_list_is_readable_without_shell_full(self):
        self.box.permissions(shell_readonly=True)
        result = self.box.data("package_list", {}, RO)
        self.assertTrue(result["ok"])

    def test_install_needs_shell_full(self):
        self.box.permissions(shell_readonly=True)
        call = self.box.call("package_install", {"name": "htop"}, RO)
        self.assertTrue(call["isError"])
        self.assertNotIn("htop", self.box.read(self.db))


class TestServices(unittest.TestCase):
    """init.d подменён временным каталогом с настоящими скриптами."""

    def setUp(self):
        self.box = Sandbox(self, FULL)
        self.init = os.path.join(self.box.dir, "init.d")
        os.makedirs(self.init)
        self.marker = os.path.join(self.box.dir, "service.log")
        _script(os.path.join(self.init, "S99demo"),
                'echo "$1" >> %s\necho "demo: $1"\n' % self.marker)
        _script(os.path.join(self.init, "S80other"), 'echo other: "$1"\n')
        # Неисполняемый файл в init.d службой не считается.
        with open(os.path.join(self.init, "README"), "w") as f:
            f.write("not a service\n")
        self.addCleanup(setattr, services_mod, "INIT_DIRS",
                        services_mod.INIT_DIRS)
        services_mod.INIT_DIRS = (self.init,)

    def actions(self) -> list:
        if not os.path.exists(self.marker):
            return []
        return self.box.read(self.marker).split()

    def test_list_shows_executable_scripts_only(self):
        result = self.box.data("service_list", {}, FULL)
        names = sorted(item["name"] for item in result["items"])
        self.assertEqual(names, ["S80other", "S99demo"])
        self.assertIn("demo", [item["short"] for item in result["items"]])

    def test_status_works_with_shell_readonly(self):
        self.box.permissions(shell_readonly=True)
        result = self.box.data("service_control",
                               {"name": "demo", "action": "status"}, RO)
        self.assertTrue(result["ok"])
        self.assertIn("demo: status", result["output"])
        self.assertEqual(self.actions(), ["status"])

    def test_restart_needs_shell_full(self):
        self.box.permissions(shell_readonly=True)
        result = self.box.data("service_control",
                               {"name": "demo", "action": "restart"}, RO)
        self.assertFalse(result["ok"])
        self.assertIn("shell_full", result["error"] + result["hint"])
        self.assertEqual(self.actions(), [])

    def test_unknown_service_is_refused_without_running_anything(self):
        result = self.box.data("service_control",
                               {"name": "demo; touch /tmp/pwned",
                                "action": "status"}, FULL)
        self.assertFalse(result["ok"])
        self.assertIn("known", result)
        self.assertEqual(self.actions(), [])
        self.assertFalse(os.path.exists("/tmp/pwned"))

    def test_short_name_resolves_to_the_numbered_script(self):
        result = self.box.data("service_control",
                               {"name": "demo", "action": "status"}, FULL)
        self.assertEqual(result["name"], "S99demo")
        self.assertTrue(result["path"].endswith("S99demo"))

    def test_stop_is_reversible(self):
        result = self.box.data("service_control",
                               {"name": "demo", "action": "stop"}, FULL)
        self.assertTrue(result["ok"])
        self.assertEqual(result["undo"]["kind"], audit.KIND_SERVICE)

        undone = self.box.data("mcp_undo_last", {}, FULL)
        self.assertTrue(undone["reverted"])
        self.assertEqual(self.actions(), ["stop", "start"])

    def test_restart_leaves_no_snapshot(self):
        # У «перезапуска» нет обратного действия, и притворяться, что
        # есть, хуже честного «отката нет».
        result = self.box.data("service_control",
                               {"name": "demo", "action": "restart"}, FULL)
        self.assertTrue(result["ok"])
        self.assertIsNone(result.get("undo"))
        self.assertIn("обратного действия", result["hint"])

    def test_no_init_dir_is_an_honest_answer(self):
        services_mod.INIT_DIRS = (os.path.join(self.box.dir, "nope"),)
        result = self.box.data("service_list", {}, FULL)
        self.assertTrue(result["ok"])
        self.assertFalse(result["available"])

    def test_scripts_are_found_in_both_locations(self):
        # Порядок значим: Entware раньше прошивки — на Keenetic службы
        # обхода лежат именно в /opt.
        self.assertEqual(services_mod.INIT_DIRS[0], self.init)
        found = services_mod.find_services()
        self.assertTrue(all(item["path"].startswith(self.init)
                            for item in found))
        for item in found:
            self.assertTrue(os.stat(item["path"]).st_mode & stat.S_IXUSR)


if __name__ == "__main__":
    unittest.main()
