import unittest

from pii_gate.config import parse
from pii_gate.engine import Engine


def run(sql, cfg=None):
    rep = Engine(cfg).scan_text(sql)
    return sorted({f.rule for f in rep.blocking}), sorted({f.rule for f in rep.warnings})


class CoreColumnTests(unittest.TestCase):
    def test_core_column_blocks_anywhere(self):
        self.assertEqual(run("SELECT national_id FROM customers"), (["sql-pii"], []))
        self.assertEqual(run("select c.birth_date, c.city from dbo.customers c"), (["sql-pii"], []))
        self.assertEqual(run("SELECT [Birth_Date] FROM [dbo].[Orders]"), (["sql-pii"], []))

    def test_partial_substring_is_fine(self):
        self.assertEqual(run("SELECT customer_count, dob_flag FROM stats"), ([], []))


class ContextColumnTests(unittest.TestCase):
    def test_outside_person_table_is_a_warning(self):
        self.assertEqual(run("SELECT name, email, phone FROM suppliers"), ([], ["sql-pii-context"]))

    def test_inside_person_table_blocks(self):
        self.assertEqual(run("SELECT name, email FROM patients"), (["sql-pii"], []))
        self.assertEqual(run("SELECT p.first_name FROM dbo.patients p JOIN visits v ON v.pid = p.id"), (["sql-pii"], []))
        self.assertEqual(run("SELECT e.email FROM employees e"), (["sql-pii"], []))


class StarTests(unittest.TestCase):
    def test_star_on_person_table(self):
        self.assertEqual(run("SELECT * FROM patients"), (["sql-star"], []))
        self.assertEqual(run("SELECT p.* FROM patients p"), (["sql-star"], []))

    def test_star_elsewhere(self):
        self.assertEqual(run("SELECT * FROM orders"), ([], []))


class WrapperTests(unittest.TestCase):
    def test_non_revealing_wrappers_pass(self):
        sql = ("SELECT COUNT(national_id), COUNT(DISTINCT email), LEN(phone), LEFT(first_name, 1), "
               "SUBSTRING(last_name, 1, 1), YEAR(birth_date), DATEPART(year, birth_date), "
               "phone IS NOT NULL FROM patients WHERE phone IS NOT NULL GROUP BY YEAR(birth_date)")
        self.assertEqual(run(sql), ([], []))

    def test_revealing_wrappers_block(self):
        self.assertEqual(run("SELECT SUBSTRING(national_id, 1, 3) FROM patients"), (["sql-pii"], []))
        self.assertEqual(run("SELECT UPPER(email) FROM patients"), (["sql-pii"], []))
        self.assertEqual(run("SELECT MONTH(birth_date), DAY(birth_date) FROM patients"), (["sql-pii"], []))


class ParsingTests(unittest.TestCase):
    def test_comments_and_strings_are_ignored(self):
        self.assertEqual(run("SELECT id -- national_id\nFROM visits"), ([], []))
        self.assertEqual(run("SELECT 'national_id' AS label FROM visits"), ([], []))

    def test_subquery(self):
        self.assertEqual(run("SELECT v.id FROM visits v WHERE v.pid IN (SELECT national_id FROM patients)"),
                         (["sql-pii"], []))

    def test_prose_with_select_from(self):
        self.assertEqual(run("please select from the menu"), ([], []))
        self.assertEqual(run("no sql here, just email text"), ([], []))


class ConfigTests(unittest.TestCase):
    def test_ignore_extra_columns_and_tables(self):
        cfg = parse({"sql": {"ignore_columns": ["name"], "extra_pii_columns": ["protocol_no"],
                             "extra_person_tables": ["donor"]}})
        self.assertEqual(run("SELECT name FROM suppliers", cfg), ([], []))
        self.assertEqual(run("SELECT protocol_no FROM visits", cfg), (["sql-pii"], []))
        self.assertEqual(run("SELECT email FROM donors", cfg), (["sql-pii"], []))

    def test_rule_levels(self):
        cfg = parse({"rules": {"sql-pii": "warn", "sql-pii-context": "block"}})
        self.assertEqual(run("SELECT national_id FROM customers", cfg), ([], ["sql-pii"]))
        self.assertEqual(run("SELECT phone FROM suppliers", cfg), (["sql-pii-context"], []))
        cfg = parse({"rules": {"sql-pii": "off", "sql-star": "off"}})
        self.assertEqual(run("SELECT *, national_id FROM patients", cfg), ([], []))


if __name__ == "__main__":
    unittest.main()
