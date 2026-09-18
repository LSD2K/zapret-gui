# tests/test_mcp_hints.py
"""
Правила-подсказки «почему не сработало»: данные, а не цепочка `if`.

Цифра «0% успеха» сама по себе модели бесполезна: по ней нельзя выбрать
следующий шаг. Подсказка выбирает его за неё — но только если правило
действительно срабатывает на той строке лога, ради которой заведено.
Поэтому здесь эталонные строки из реальных логов nfqws2 и эталонные
наборы измерений, а не проверка «функция что-то вернула».

Список правил дополняет S11, и дополняет его **данными**
(`HINT_RULES`), не кодом. Тест стережёт и это: у каждого правила должны
быть id, текст и ссылка на раздел справочника — подсказка без адреса
отправляет модель искать наугад.
"""

import unittest

from core.strategy_experiment import (HINT_RULES, _METRIC_RULES, hints_for,
                                      known_hint_ids)


def ids(log_lines=None, metrics=None):
    return [hint["id"] for hint in hints_for(log_lines or [], metrics or {})]


# Измерения варианта, который применился и всё измерил удачно: от него
# отталкиваются метрические правила.
HEALTHY = {
    "validation": {"available": True, "ok": True},
    "started_nfqws": True,
    "applied_attempted": True,
    "ok_count": 2,
    "target_count": 2,
    "fixed_count": 2,
    "broken_count": 0,
}


class TestLogRules(unittest.TestCase):
    """Строка лога → подсказка из таблицы задания S10."""

    def test_rawsend_permission_points_at_postnat(self):
        log = ["ERROR rawsend: sendto: Operation not permitted"]
        hints = hints_for(log, HEALTHY)
        self.assertIn("rawsend_eperm", [h["id"] for h in hints])
        text = next(h for h in hints if h["id"] == "rawsend_eperm")
        self.assertIn("POSTNAT", text["hint"])
        self.assertIn("desync_mark_postnat", text["hint"])

    def test_lua_nil_call_points_at_the_function_list(self):
        log = ["ERROR lua: attempt to call a nil value (global 'fake_tls2')"]
        hints = hints_for(log, HEALTHY)
        self.assertIn("lua_nil_call", [h["id"] for h in hints])
        self.assertIn("lua_functions_list",
                      next(h["hint"] for h in hints
                           if h["id"] == "lua_nil_call"))

    def test_missing_hostlist_and_blob_are_recognised(self):
        self.assertIn("hostlist_missing",
                      ids(["WARNING failed to register hostlist "
                           "/opt/zapret2/lists/yt.txt"], HEALTHY))
        self.assertIn("blob_missing",
                      ids(["ERROR failed to load blob tls_google"], HEALTHY))

    def test_queue_bind_failure_is_recognised(self):
        self.assertIn("queue_bind_failed",
                      ids(["ERROR cannot bind to queue 200"], HEALTHY))

    def test_case_does_not_matter(self):
        # Регистр строки лога зависит от версии движка, а подсказка — нет.
        self.assertIn("rawsend_eperm",
                      ids(["RAWSEND: SENDTO: OPERATION NOT PERMITTED"],
                          HEALTHY))

    def test_a_rule_fires_once_per_variant(self):
        # Эту строку движок печатает на КАЖДЫЙ фейковый пакет: пять
        # одинаковых подсказок — это пять раз занятый контекст модели.
        log = ["rawsend: sendto: Operation not permitted"] * 5
        self.assertEqual(ids(log, HEALTHY).count("rawsend_eperm"), 1)

    def test_clean_log_and_healthy_metrics_give_nothing(self):
        # Подсказка «на всякий случай» хуже её отсутствия: модель начнёт
        # чинить работающее.
        self.assertEqual(ids(["INFO nfqws2 started"], HEALTHY), [])


class TestMetricRules(unittest.TestCase):
    """Измерения без единой строки лога — тоже повод для подсказки."""

    def test_zero_success_with_valid_dry_run_points_at_nfqueue(self):
        metrics = dict(HEALTHY, ok_count=0, fixed_count=0)
        hints = hints_for([], metrics)
        self.assertIn("zero_everywhere", [h["id"] for h in hints])
        self.assertIn("firewall_status",
                      next(h["hint"] for h in hints
                           if h["id"] == "zero_everywhere"))

    def test_engine_that_did_not_start_points_at_user_and_rights(self):
        metrics = dict(HEALTHY, started_nfqws=False, ok_count=0)
        hints = hints_for([], metrics)
        self.assertIn("engine_did_not_start", [h["id"] for h in hints])
        self.assertIn("--user",
                      next(h["hint"] for h in hints
                           if h["id"] == "engine_did_not_start"))

    def test_failed_dry_run_is_not_blamed_on_nfqueue(self):
        # Вариант, отвергнутый валидацией, до движка не доезжал вовсе —
        # советовать проверять правила перехвата здесь значит послать
        # модель чинить исправное.
        metrics = dict(HEALTHY, ok_count=0, started_nfqws=False,
                       applied_attempted=False,
                       validation={"available": True, "ok": False})
        got = ids([], metrics)
        self.assertIn("dry_run_failed", got)
        self.assertNotIn("zero_everywhere", got)
        self.assertNotIn("engine_did_not_start", got)

    def test_missing_binary_is_not_a_failed_validation(self):
        # На dev-машине бинарника нет: `available: false` — это «не
        # проверяли», а не «проверили и не прошло».
        metrics = dict(HEALTHY, validation={"available": False,
                                            "ok": False})
        self.assertNotIn("dry_run_failed", ids([], metrics))

    def test_broken_targets_are_called_out(self):
        metrics = dict(HEALTHY, broken_count=1)
        hints = hints_for([], metrics)
        self.assertIn("worse_than_baseline", [h["id"] for h in hints])


class TestRuleTable(unittest.TestCase):
    """Сама таблица: правила остаются данными и остаются полными."""

    def test_every_rule_has_id_text_and_reference(self):
        for rule in HINT_RULES:
            with self.subTest(rule=rule.get("id")):
                self.assertTrue(rule.get("id"))
                self.assertTrue(rule.get("hint"))
                # Подсказка без адреса отправляет модель искать наугад.
                self.assertTrue(rule.get("ref"))
                self.assertIn(rule.get("when"), ("log", "metric"))

    def test_ids_are_unique(self):
        self.assertEqual(len(known_hint_ids()), len(set(known_hint_ids())))

    def test_every_metric_rule_has_a_predicate(self):
        # Правило, у которого нет предиката, молча не срабатывает
        # никогда — худший вид поломки: таблица выглядит полной.
        for rule in HINT_RULES:
            if rule["when"] == "metric":
                with self.subTest(rule=rule["id"]):
                    self.assertIn(rule.get("rule"), _METRIC_RULES)

    def test_log_rules_carry_lowercase_patterns(self):
        # Сравнение идёт по строке, приведённой к нижнему регистру:
        # заглавная буква в самом правиле означала бы правило, которое
        # не срабатывает никогда.
        for rule in HINT_RULES:
            if rule["when"] == "log":
                with self.subTest(rule=rule["id"]):
                    self.assertTrue(rule.get("patterns"))
                    for part in rule["patterns"]:
                        self.assertEqual(part, part.lower())

    def test_log_rule_needs_all_its_parts_in_ONE_line(self):
        # «rawsend» из одной строки и «not permitted» из другой — это
        # две разные беды, и склеивать их в одну подсказку нельзя.
        split = ["ERROR rawsend: sendto: connection refused",
                 "WARNING something else not permitted"]
        self.assertNotIn("rawsend_eperm", ids(split, HEALTHY))

    def test_hints_survive_empty_input(self):
        self.assertEqual(hints_for(None, None), [])


if __name__ == "__main__":
    unittest.main()
