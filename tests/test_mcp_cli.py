# tests/test_mcp_cli.py
"""
Подкоманда `zapret-gui mcp …` (`core/cli.py`).

Это отладка MCP по SSH: единственный способ посмотреть, что видит
модель, когда браузера под рукой нет. Проверяем то, что ломается
молча:

* `status` показывает состояние точки, а не падает на выключенном MCP;
* `tools` и `call` работают на подменённом реестре — то есть говорят
  ровно то, что в реестре, а не то, что собрано в этой сборке;
* `token rotate` **меняет токен и пишет его в конфиг** (иначе новый
  токен живёт до перезагрузки, а клиент настроен на него);
* `call` с неверным JSON объясняет, что не так, а не сыплет трассировкой:
  из shell чаще всего теряются кавычки;
* `mcp code` без S13 честно говорит, что самоправки в сборке нет.

Настройки — во временном каталоге: тест, дёргающий `token rotate` на
настоящем `settings.json`, оборвёт все подключённые клиенты того, кто
его запустил.
"""

import io
import json
import os
import shutil
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

from core import cli
from core.mcp import registry


def run(*argv):
    """Выполнить подкоманду и вернуть (код, напечатанное)."""
    args = cli.build_parser().parse_args(["mcp"] + list(argv))
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        code = cli._cmd_mcp(args)
    return code, buffer.getvalue()


class _CLIBase(unittest.TestCase):
    """Свой settings.json: `token rotate` пишет на диск по-настоящему."""

    def setUp(self):
        import core.config_manager as cm

        self.dir = tempfile.mkdtemp(prefix="mcp-cli-")
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        saved = cm._config_manager
        self.addCleanup(setattr, cm, "_config_manager", saved)
        cm._config_manager = cm.ConfigManager(config_dir=self.dir)
        cm._config_manager.load()
        self.cfg = cm._config_manager

    def add_tool(self, name="zz_cli_tool", scope="read", mutating=False,
                 handler=None):
        """Инструмент-времянка в настоящем реестре."""
        registry.load_tools()
        spec = registry.register_tool(
            name, handler or (lambda args: {"ok": True, "echo": args}),
            description="Probe tool for CLI tests. / Инструмент для тестов.",
            scope=scope, mutating=mutating,
            schema={"type": "object",
                    "properties": {"n": {"type": "integer"}}})
        self.addCleanup(registry._REGISTRY.pop, name, None)
        return spec


class TestStatus(_CLIBase):

    def test_disabled_server_is_reported_not_hidden(self):
        code, out = run("status")
        self.assertEqual(code, 0)
        self.assertIn("выключен", out)
        self.assertIn("не задан", out)

    def test_enabled_without_token_is_called_out(self):
        # Включённый флаг при пустом токене — это выключенный MCP, и
        # человек должен это прочитать, а не гадать над 401.
        self.cfg.set("mcp", "enabled", True)
        _, out = run("status")
        self.assertIn("ВНИМАНИЕ", out)

    def test_endpoint_uses_gui_host_and_port(self):
        self.cfg.set("gui", "host", "192.168.1.1")
        self.cfg.set("gui", "port", 8099)
        _, out = run("status")
        self.assertIn("http://192.168.1.1:8099/api/mcp", out)

    def test_wildcard_bind_does_not_print_0_0_0_0(self):
        self.cfg.set("gui", "host", "0.0.0.0")
        _, out = run("status")
        self.assertIn("<адрес роутера>", out)

    def test_permission_without_its_dependency_is_marked(self):
        # experiments без control/probes стоит, но не действует: без
        # пометки человек чинит то, что не сломано.
        self.cfg.set("mcp", "permissions", "experiments", True)
        _, out = run("status")
        self.assertIn("не действует", out)
        self.assertIn("control", out)

    def test_counts_tools(self):
        _, out = run("status")
        self.assertIn("инструментов:", out)

    def test_sse_state_is_visible(self):
        self.cfg.set("mcp", "transports", {"http": True, "sse": True})
        _, out = run("status")
        self.assertIn("sse=вкл", out)
        self.assertIn("открыто потоков", out)


class TestToken(_CLIBase):

    def test_show_without_token_explains_how_to_make_one(self):
        code, out = run("token", "show")
        self.assertEqual(code, 1)
        self.assertIn("token rotate", out)

    def test_show_prints_the_token_with_a_warning(self):
        self.cfg.set("mcp", "token", "b" * 64)
        code, out = run("token", "show")
        self.assertEqual(code, 0)
        self.assertIn("b" * 64, out)
        # Печать в терминал — осознанная, но об истории shell надо
        # предупредить.
        self.assertIn("истории shell", out)

    def test_rotate_changes_the_token(self):
        self.cfg.set("mcp", "token", "c" * 64)
        code, out = run("token", "rotate")
        self.assertEqual(code, 0)
        new = self.cfg.get("mcp", "token")
        self.assertEqual(len(new), 64)
        self.assertNotEqual(new, "c" * 64)
        self.assertIn(new, out)

    def test_rotate_writes_it_to_disk(self):
        # Токен, оставшийся только в памяти, живёт до перезагрузки — а
        # клиент уже настроен на него.
        run("token", "rotate")
        with open(os.path.join(self.dir, "settings.json"),
                  encoding="utf-8") as f:
            saved = json.load(f)
        self.assertEqual(saved["mcp"]["token"], self.cfg.get("mcp", "token"))

    def test_rotate_warns_that_clients_will_break(self):
        _, out = run("token", "rotate")
        self.assertIn("оборвутся", out)

    def test_unknown_action(self):
        code, out = run("token", "выдумать")
        self.assertEqual(code, 2)
        self.assertIn("show|rotate", out)


class TestTools(_CLIBase):

    def test_lists_a_registered_tool(self):
        self.add_tool()
        code, out = run("tools")
        self.assertEqual(code, 0)
        self.assertIn("zz_cli_tool", out)

    def test_hides_what_permissions_do_not_open(self):
        self.add_tool(name="zz_cli_closed", scope="control", mutating=True)
        _, out = run("tools")
        self.assertNotIn("zz_cli_closed", out)

    def test_shows_it_once_permission_is_granted(self):
        self.add_tool(name="zz_cli_open", scope="control", mutating=True)
        self.cfg.set("mcp", "permissions", "control", True)
        _, out = run("tools")
        self.assertIn("zz_cli_open", out)

    def test_json_output_is_the_wire_format(self):
        self.add_tool(name="zz_cli_json")
        _, out = run("tools", "--json")
        names = {item["name"] for item in json.loads(out)}
        self.assertIn("zz_cli_json", names)


class TestCall(_CLIBase):

    def test_call_prints_structured_result(self):
        self.add_tool(name="zz_cli_call")
        code, out = run("call", "zz_cli_call", '{"n": 5}')
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["echo"], {"n": 5})

    def test_call_without_arguments_uses_empty_object(self):
        self.add_tool(name="zz_cli_bare")
        code, out = run("call", "zz_cli_bare")
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["echo"], {})

    def test_failing_tool_is_exit_code_one(self):
        self.add_tool(name="zz_cli_fail",
                      handler=lambda args: {"ok": False, "error": "нет"})
        code, out = run("call", "zz_cli_fail")
        self.assertEqual(code, 1)
        self.assertIn("нет", out)

    def test_denied_tool_names_the_permission(self):
        self.add_tool(name="zz_cli_denied", scope="control", mutating=True)
        code, out = run("call", "zz_cli_denied")
        self.assertEqual(code, 1)
        self.assertIn("control", out)

    def test_bad_json_is_explained_not_traced(self):
        # Самая частая ошибка из shell — потерянные кавычки.
        code, out = run("call", "zz_cli_x", "{n: 5}")
        self.assertEqual(code, 2)
        self.assertIn("не разобраны как JSON", out)
        self.assertIn("{n: 5}", out)

    def test_non_object_arguments_are_refused(self):
        code, out = run("call", "zz_cli_x", "[1,2]")
        self.assertEqual(code, 2)
        self.assertIn("объектом JSON", out)

    def test_arguments_off_schema_are_refused_with_reason(self):
        self.add_tool(name="zz_cli_schema")
        code, out = run("call", "zz_cli_schema", '{"n": "пять"}')
        self.assertEqual(code, 2)
        self.assertIn("n", out)

    def test_unknown_tool_lists_what_exists(self):
        code, out = run("call", "zz_нет_такого")
        self.assertEqual(code, 1)
        self.assertIn("не найден", out)

    def test_without_tool_name(self):
        code, out = run("call")
        self.assertEqual(code, 2)
        self.assertIn("Укажите инструмент", out)


class TestAudit(_CLIBase):

    def test_empty_journal_says_so(self):
        code, out = run("audit")
        self.assertEqual(code, 0)
        self.assertIn("Журнал пуст", out)

    def test_shows_calls_after_one(self):
        self.add_tool(name="zz_cli_audited")
        run("call", "zz_cli_audited")
        code, out = run("audit", )
        self.assertEqual(code, 0)
        self.assertIn("zz_cli_audited", out)

    def test_limit_is_respected(self):
        self.add_tool(name="zz_cli_many")
        for _ in range(4):
            run("call", "zz_cli_many")
        args = cli.build_parser().parse_args(["mcp", "audit", "--limit", "2"])
        buffer = io.StringIO()
        with redirect_stdout(buffer):
            cli._cmd_mcp(args)
        self.assertIn("Показано записей: 2", buffer.getvalue())


class TestCode(_CLIBase):
    """`mcp code …` — только если самоправка в сборке есть."""

    def test_missing_module_is_said_plainly(self):
        with mock.patch.dict("sys.modules", {"core.code_editor": None}):
            code, out = run("code", "list")
        self.assertEqual(code, 1)
        self.assertIn("недоступна", out)

    def test_empty_history(self):
        with mock.patch("core.code_editor.history", return_value=[]):
            code, out = run("code", "list")
        self.assertEqual(code, 0)
        self.assertIn("Снимков нет", out)

    def test_history_is_printed(self):
        item = {"snapshot_id": "snap-1", "created": "2026-09-19 10:00:00",
                "state": "committed", "files": ["core/foo.py"]}
        with mock.patch("core.code_editor.history", return_value=[item]), \
                mock.patch("core.code_editor.last_open_snapshot",
                           return_value=None):
            _, out = run("code", "list")
        self.assertIn("snap-1", out)
        self.assertIn("core/foo.py", out)

    def test_unknown_action(self):
        code, out = run("code", "выдумать")
        self.assertEqual(code, 2)
        self.assertIn("list|diff|rollback", out)


class TestStdioWiring(_CLIBase):
    """`--stdio` и действие `stdio` — одна и та же дверь."""

    def test_flag_selects_the_bridge(self):
        args = cli.build_parser().parse_args(["mcp", "--stdio"])
        with mock.patch("core.mcp.stdio.serve", return_value=0) as serve:
            self.assertEqual(cli._cmd_mcp(args), 0)
        self.assertTrue(serve.called)

    def test_action_selects_the_bridge_too(self):
        args = cli.build_parser().parse_args(["mcp", "stdio"])
        with mock.patch("core.mcp.stdio.serve", return_value=0) as serve:
            cli._cmd_mcp(args)
        self.assertTrue(serve.called)

    def test_proxy_flags_reach_the_bridge(self):
        args = cli.build_parser().parse_args(
            ["mcp", "stdio", "--url", "http://router", "--token", "z" * 8])
        with mock.patch("core.mcp.stdio.serve", return_value=0) as serve:
            cli._cmd_mcp(args)
        self.assertEqual(serve.call_args.kwargs["url"], "http://router")
        self.assertEqual(serve.call_args.kwargs["token"], "z" * 8)


class TestParser(unittest.TestCase):

    def test_mcp_is_a_cli_command(self):
        self.assertIn("mcp", cli.COMMANDS)
        self.assertIn("mcp", cli._DISPATCH)

    def test_action_defaults_to_status(self):
        args = cli.build_parser().parse_args(["mcp"])
        self.assertEqual(args.action, "status")

    def test_unknown_action_is_rejected_by_argparse(self):
        with self.assertRaises(SystemExit):
            cli.build_parser().parse_args(["mcp", "frobnicate"])

    def test_rest_keeps_json_argument(self):
        args = cli.build_parser().parse_args(
            ["mcp", "call", "strategy_list", '{"limit": 5}'])
        self.assertEqual(args.rest, ["strategy_list", '{"limit": 5}'])


if __name__ == "__main__":
    unittest.main()
