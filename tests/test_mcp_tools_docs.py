"""Сторож: реестр MCP-инструментов синхронен с документацией.

Реестр растёт (93 инструмента за пятнадцать сессий), а документация —
нет: инструмент добавляется декоратором `@tool` в `core/mcp/tools/*.py`
и уезжает модели в тот же прогон, ничего при этом не требуя. Через
полгода такого реестр и документация расходятся молча, и первым это
замечает пользователь, у которого модель делает не то.

Поэтому здесь два разных требования, и они не дублируют друг друга:

* `.claude/skills/mcp/SKILL.md` — справочник для того, кто правит код:
  инструмент обязан быть **строкой таблицы** с scope, признаком
  мутации, файлом и сигнатурой. Сверяется не только наличие имени, но и
  **scope с mutating**: разъехавшийся scope в таблице хуже отсутствия
  строки — по нему принимают решения;
* `README.md` — текст для человека, который решает, что включать:
  инструмент обязан быть **упомянут** в разделе «Управление через ИИ
  (MCP)», в группе своего разрешения.

Починка: добавили инструмент — добавьте строку в таблицу скила и имя в
README. Это дешевле, чем разбираться потом, что именно умеет модель.
"""

import os
import re
import sys
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

from core.mcp import permissions as perms_mod  # noqa: E402
from core.mcp import registry  # noqa: E402


SKILL = os.path.join(REPO_ROOT, ".claude", "skills", "mcp", "SKILL.md")
README = os.path.join(REPO_ROOT, "README.md")

# Строка таблицы скила:
# | `имя` | scope | да/нет | `tools/файл.py` | сигнатура | описание |
ROW_RE = re.compile(
    r"^\|\s*`(?P<name>[a-z][a-z0-9_]*)`\s*\|"
    r"\s*(?P<scope>[a-z_]+)\s*\|"
    r"\s*(?P<mut>\*\*да\*\*|да|нет)\s*\|"
    r"\s*`(?P<file>[^`]+)`\s*\|",
    re.M)

# Заголовок раздела README, в котором обязаны быть все инструменты.
README_SECTION = "## Управление через ИИ (MCP)"


def _read(path):
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


class TestMcpToolsDocumented(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        registry.load_tools()
        cls.tools = {t.name: t for t in registry.all_tools()}
        cls.skill = _read(SKILL)
        cls.rows = {m.group("name"): m.groupdict()
                    for m in ROW_RE.finditer(cls.skill)}
        readme = _read(README)
        start = readme.index(README_SECTION)
        # Раздел — до следующего заголовка первого уровня «## ».
        rest = readme[start + len(README_SECTION):]
        end = rest.find("\n## ")
        cls.readme_section = rest if end < 0 else rest[:end]

    def test_registry_is_not_empty(self):
        """Реестр вообще загрузился — иначе сторож стережёт пустоту."""
        self.assertGreater(len(self.tools), 50,
                           "инструменты не загрузились: %d" % len(self.tools))

    def test_every_tool_has_a_skill_row(self):
        """Каждый инструмент — строка таблицы в скиле."""
        missing = sorted(set(self.tools) - set(self.rows))
        self.assertEqual(
            missing, [],
            "нет строки в .claude/skills/mcp/SKILL.md: %s"
            % ", ".join(missing))

    def test_skill_table_has_no_ghosts(self):
        """В таблице нет инструментов, которых уже нет в реестре."""
        ghosts = sorted(set(self.rows) - set(self.tools))
        self.assertEqual(
            ghosts, [],
            "в таблице скила описан несуществующий инструмент: %s"
            % ", ".join(ghosts))

    def test_skill_row_matches_scope_and_mutating(self):
        """Scope и признак мутации в таблице равны объявленным в коде."""
        wrong = []
        for name, spec in sorted(self.tools.items()):
            row = self.rows.get(name)
            if not row:
                continue  # ловит отдельный тест
            scope = spec.scope or perms_mod.READ_SCOPE
            if row["scope"] != scope:
                wrong.append("%s: в таблице scope=%s, в коде %s"
                             % (name, row["scope"], scope))
            mutating = row["mut"] != "нет"
            if mutating != spec.mutating:
                wrong.append("%s: в таблице mutating=%s, в коде %s"
                             % (name, mutating, spec.mutating))
        self.assertEqual(wrong, [], "; ".join(wrong))

    def test_skill_row_points_at_the_real_module(self):
        """Файл в таблице — тот модуль, где инструмент объявлен."""
        wrong = []
        for name, spec in sorted(self.tools.items()):
            row = self.rows.get(name)
            if not row:
                continue
            # core.mcp.tools.lists → tools/lists.py
            expected = "tools/%s.py" % spec.module.rsplit(".", 1)[-1]
            if row["file"] != expected:
                wrong.append("%s: в таблице %s, объявлен в %s"
                             % (name, row["file"], expected))
        self.assertEqual(wrong, [], "; ".join(wrong))

    def test_every_tool_is_mentioned_in_readme(self):
        """Каждый инструмент назван в пользовательском разделе README."""
        missing = sorted(name for name in self.tools
                         if "`%s`" % name not in self.readme_section)
        self.assertEqual(
            missing, [],
            "не упомянуты в разделе «Управление через ИИ (MCP)» "
            "файла README.md: %s" % ", ".join(missing))

    def test_readme_names_every_permission(self):
        """Все одиннадцать разрешений названы в README — включать-то их."""
        missing = [p for p in perms_mod.PERMISSIONS
                   if "`%s`" % p not in self.readme_section]
        self.assertEqual(missing, [],
                         "разрешения не описаны в README: %s"
                         % ", ".join(missing))

    def test_skill_documents_every_permission(self):
        """И в скиле тоже — он источник правды для правящего код."""
        missing = [p for p in perms_mod.PERMISSIONS
                   if "`%s`" % p not in self.skill]
        self.assertEqual(missing, [],
                         "разрешения не описаны в скиле: %s"
                         % ", ".join(missing))

    def test_readme_warns_about_the_risks(self):
        """Раздел README обязан назвать риски, а не только возможности.

        Пункт задания S16: «README пишется для человека, который боится
        это включать». Тест стережёт не формулировки, а то, что три
        неприятные темы вообще упомянуты.
        """
        for needle, why in (
                ("Bearer", "не сказано, как передаётся токен"),
                ("TLS", "не сказано, что токен уезжает открытым текстом"),
                ("root", "не сказано, что shell_full — это root")):
            self.assertIn(needle, self.readme_section, why)


if __name__ == "__main__":
    unittest.main()
