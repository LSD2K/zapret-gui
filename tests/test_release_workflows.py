"""Сторож: «latest» в Releases принадлежит релизу GUI, и только ему.

В одном репозитории публикуются две разные вещи:

  * релизы самого GUI — тэг `vX.Y.Z`, внутри пакеты `zapret-gui-*.ipk/.apk`
    и `zapret-gui-linux.tar.gz`;
  * наши сборки сторонних бинарников — тэги `awg-bin-*`, `usque-bin-*`,
    `singbox-bin-*`, `opera-bin-*`, `tgproto-bin-*`, внутри только
    `amneziawg-go`, `usque`, `sing-box` и т.п. плюс `manifest.json`.

GitHub считает «latest» самый свежий по дате non-draft/non-prerelease релиз.
Бинарные сборки выходят чаще GUI, поэтому без `make_latest: "false"` они
перехватывают «latest» — и все ссылки вида

    https://github.com/avatarDD/zapret-gui/releases/latest/download/zapret-gui-openwrt.apk

(README, команды установки в одну строку, бейдж версии) начинают вести на
релиз, где пакетов GUI нет вовсе. Пользователь получает HTTP 404, а следом
невнятное «./zapret-gui-openwrt.apk (no such package)» от apk — issue #305.

Тест падает, если новый workflow сборки бинарников забыл `make_latest`, или
если релиз GUI перестал его требовать. Поиск бинарных workflow — по факту
публикации релиза, а не по списку имён: список устареет на первом же новом
движке.
"""

import os
import re
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WORKFLOW_DIR = os.path.join(REPO_ROOT, ".github", "workflows")

# Workflow релиза самого GUI — единственный, кому «latest» разрешён.
GUI_RELEASE_WORKFLOW = "release.yml"

# Публикация релиза — по ней и опознаём workflow, который вообще создаёт
# Release. Способов два: action softprops/action-gh-release и gh CLI
# (`gh release create`). Второй появился в release.yml после того, как
# codeload.github.com отдал 429 на скачивании самих actions и релиз
# v0.24.16 не вышел вовсе: gh предустановлен на раннере и не скачивается.
PUBLISH_RE = re.compile(
    r"uses:\s*softprops/action-gh-release@|gh release create", re.M)

# Заявка «этот релиз — latest»: у action это `make_latest:` с не-false
# значением, у gh CLI — флаг `--latest` (именно без `=false`).
CLAIMS_LATEST_RE = re.compile(
    r"^\s*make_latest:\s*(?!['\"]?false)|--latest(?![=\w])", re.M)

# Отказ от latest: `make_latest: "false"` / `make_latest: false` /
# `--latest=false`.
DISCLAIMS_LATEST_RE = re.compile(
    r"^\s*make_latest:\s*['\"]?false['\"]?\s*$|--latest=false", re.M)

# Пререлиз в «latest» не попадает по определению — с него спроса нет.
PRERELEASE_TRUE_RE = re.compile(r"^\s*prerelease:\s*true\s*$", re.M)


def _workflows():
    if not os.path.isdir(WORKFLOW_DIR):
        return {}
    out = {}
    for name in sorted(os.listdir(WORKFLOW_DIR)):
        if not name.endswith((".yml", ".yaml")):
            continue
        path = os.path.join(WORKFLOW_DIR, name)
        with open(path, encoding="utf-8") as f:
            out[name] = f.read()
    return out


class TestReleaseWorkflows(unittest.TestCase):

    def setUp(self):
        self.workflows = _workflows()
        self.assertTrue(self.workflows,
                        "не найдено ни одного workflow в .github/workflows")

    def test_gui_release_workflow_exists(self):
        self.assertIn(GUI_RELEASE_WORKFLOW, self.workflows)
        self.assertRegex(
            self.workflows[GUI_RELEASE_WORKFLOW], PUBLISH_RE,
            "release.yml больше не публикует Release — тест надо обновить")

    def test_binary_workflows_do_not_claim_latest(self):
        """Сборки бинарников не перехватывают «latest» у релиза GUI."""
        checked = []
        for name, text in self.workflows.items():
            if name == GUI_RELEASE_WORKFLOW:
                continue
            if not PUBLISH_RE.search(text):
                continue          # workflow вообще не создаёт релиз
            if PRERELEASE_TRUE_RE.search(text):
                continue          # пререлиз «latest» не станет
            checked.append(name)
            self.assertRegex(
                text, DISCLAIMS_LATEST_RE,
                "%s публикует НЕ-пререлиз, не отказавшись от «latest» "
                "(`make_latest: \"false\"` или `--latest=false`). Такой "
                "релиз перехватит «latest» у vX.Y.Z, и ссылки "
                "/releases/latest/download/zapret-gui-*.apk отдадут 404 "
                "(issue #305)." % name)

        self.assertTrue(
            checked,
            "не найдено ни одного workflow сборки бинарников — "
            "проверка перестала что-либо проверять")

    def test_gui_release_claims_latest(self):
        """У релиза GUI «latest» заявлен явно.

        `--latest=false` в release.yml допустим — но только в ветке для
        пререлиза; безусловная заявка на latest обязана быть рядом, иначе
        «latest» не будет указывать ни на один релиз с пакетами GUI.
        """
        text = self.workflows[GUI_RELEASE_WORKFLOW]
        self.assertRegex(
            text, CLAIMS_LATEST_RE,
            "release.yml должен явно заявлять «latest» (make_latest: или "
            "--latest): на него завязаны все ссылки на пакеты в README")


class TestGhNeedsRepoWithoutCheckout(unittest.TestCase):
    """Сторож: gh-команды в job'е без checkout'а знают, какой это репозиторий.

    Публикация v0.24.17 упала на `gh release view` с «failed to run git:
    fatal: not a git repository». Причина: job публикации намеренно живёт
    без `actions/checkout` (каждый action тянется с codeload.github.com, и
    именно на этом не вышел v0.24.16), а `gh release`/`gh pr`/`gh issue`
    без явного репозитория определяют его по git remote рабочего каталога.
    Нет каталога — нет репозитория — нет релиза.

    Лечится либо `GH_REPO` в env job'а, либо `--repo` у каждой команды.
    `gh api` сюда не входит: там репозиторий уже стоит в пути запроса.
    """

    # Команды gh, которым нужен репозиторий (в отличие от `gh api`).
    GH_REPO_SCOPED_RE = re.compile(
        r"\bgh (release|pr|issue|run|workflow|label|cache|variable|secret)\b")

    def _jobs(self):
        try:
            import yaml
        except ImportError:                     # pragma: no cover
            self.skipTest("нет PyYAML")
        for name, text in _workflows().items():
            data = yaml.safe_load(text) or {}
            top_env = data.get("env") or {}
            for job_name, job in (data.get("jobs") or {}).items():
                yield name, job_name, job, top_env

    def test_gh_without_checkout_names_the_repo(self):
        checked = []
        for wf, job_name, job, top_env in self._jobs():
            steps = job.get("steps") or []
            if any("checkout" in str(s.get("uses") or "") for s in steps):
                continue                        # каталог — git-репозиторий
            runs = [str(s.get("run") or "") for s in steps]
            scoped = [r for r in runs if self.GH_REPO_SCOPED_RE.search(r)]
            if not scoped:
                continue
            checked.append("%s:%s" % (wf, job_name))
            env = dict(top_env)
            env.update(job.get("env") or {})
            if "GH_REPO" in env:
                continue                        # задан на весь job
            for run in scoped:
                for line in run.splitlines():
                    if not self.GH_REPO_SCOPED_RE.search(line):
                        continue
                    self.assertIn(
                        "--repo", line,
                        "%s: job «%s» без checkout'а зовёт gh без --repo и "
                        "без GH_REPO в env — команда упадёт с «not a git "
                        "repository»:\n    %s"
                        % (wf, job_name, line.strip()))

        self.assertTrue(
            checked,
            "не найдено ни одного job'а без checkout'а с gh-командами — "
            "проверка перестала что-либо проверять")

    def test_gui_release_job_has_gh_repo(self):
        """Точечно про публикацию релиза GUI — там это уже стоило релиза."""
        try:
            import yaml
        except ImportError:                     # pragma: no cover
            self.skipTest("нет PyYAML")
        data = yaml.safe_load(_workflows()[GUI_RELEASE_WORKFLOW])
        job = (data.get("jobs") or {}).get("release") or {}
        env = job.get("env") or {}
        self.assertIn(
            "GH_REPO", env,
            "в job'е публикации релиза нет GH_REPO: без checkout'а gh не "
            "определит репозиторий и релиз не опубликуется")


if __name__ == "__main__":
    unittest.main()
