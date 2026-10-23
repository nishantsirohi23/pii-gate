import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from pii_gate import cli

import _synthetic as syn


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.cwd = os.getcwd()
        os.chdir(self.tmp.name)
        self._env = os.environ.pop("PII_GATE_CONFIG", None)

    def tearDown(self):
        os.chdir(self.cwd)
        if self._env is not None:
            os.environ["PII_GATE_CONFIG"] = self._env
        self.tmp.cleanup()

    def test_check(self):
        code, out, _ = run(["check", f"customer {syn.TCKN_A}"])
        self.assertEqual(code, 1)
        self.assertIn("BLOCK  tckn", out)
        self.assertNotIn(syn.TCKN_A, out)
        self.assertEqual(run(["check", "hello world"])[:2], (0, "clean\n"))
        self.assertEqual(run(["check", "--command", "git push"])[0], 1)
        self.assertEqual(run(["check", "git push"])[0], 0)  # exfil rules only apply to commands
        code, out, _ = run(["check", "SELECT phone FROM suppliers"])
        self.assertEqual(code, 0)
        self.assertIn("warn   sql-pii-context", out)

    def test_scan_files_and_allow_paths(self):
        Path("src").mkdir()
        Path("src", "a.py").write_text(f"X = '{syn.IBAN_TR}'\n", encoding="utf-8")
        Path("src", "b.bin").write_bytes(b"\x00\x01" + syn.TCKN_A.encode())
        Path("tests").mkdir()
        Path("tests", "fx.json").write_text(json.dumps({"id": syn.TCKN_B}), encoding="utf-8")
        Path("pkg.egg-info").mkdir()
        Path("pkg.egg-info", "PKG-INFO").write_text(syn.TCKN_A, encoding="utf-8")
        code, out, _ = run(["scan", "."])
        self.assertEqual(code, 1)
        self.assertIn("BLOCK iban", out)
        self.assertIn("BLOCK tckn", out)
        self.assertNotIn("b.bin", out)
        self.assertNotIn("egg-info", out)
        Path(".pii-gate.json").write_text(json.dumps({"allow_paths": ["tests/*"]}), encoding="utf-8")
        code, out, _ = run(["scan", "."])
        self.assertEqual(code, 1)
        self.assertNotIn("tckn", out)
        Path("src", "a.py").write_text("X = 1\n", encoding="utf-8")
        self.assertEqual(run(["scan", "."])[0], 0)

    def test_status_and_version(self):
        code, out, _ = run(["status"])
        self.assertEqual(code, 0)
        self.assertIn("config: defaults", out)
        self.assertIn("codex", out)
        with self.assertRaises(SystemExit) as ctx:
            run(["--version"])
        self.assertEqual(ctx.exception.code, 0)

    def test_config_error_exit_code(self):
        Path(".pii-gate.json").write_text('{"rules": {"tckn": "sometimes"}}', encoding="utf-8")
        code, _, err = run(["check", "x"])
        self.assertEqual(code, 2)
        self.assertIn("config error", err)


if __name__ == "__main__":
    unittest.main()
