import json
import tempfile
import unittest
from pathlib import Path

from pii_gate import installer


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = self.tmp.name
        self.proj = str(Path(self.tmp.name) / "proj")
        Path(self.proj).mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def read(self, path):
        return json.loads(Path(path).read_text(encoding="utf-8"))

    def test_codex_user_install_is_idempotent(self):
        path = installer.install("codex", home=self.home, python="/usr/bin/python3")
        self.assertEqual(path, Path(self.home) / ".codex" / "hooks.json")
        data = self.read(path)
        pre = data["hooks"]["PreToolUse"]
        self.assertEqual(len(pre), 1)
        self.assertEqual(pre[0]["matcher"], ".*")
        self.assertEqual(pre[0]["hooks"][0]["command"], '"/usr/bin/python3" -m pii_gate hook')
        self.assertEqual(pre[0]["hooks"][0]["timeout"], installer.TIMEOUT)
        self.assertEqual(len(data["hooks"]["UserPromptSubmit"]), 1)
        installer.install("codex", home=self.home, python="/usr/bin/python3")
        self.assertEqual(len(self.read(path)["hooks"]["PreToolUse"]), 1)

    def test_claude_project_install_keeps_other_settings(self):
        path = Path(self.proj) / ".claude" / "settings.json"
        path.parent.mkdir()
        path.write_text(json.dumps({"permissions": {"allow": ["Bash(ls *)"]},
                                    "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
                                        {"type": "command", "command": "echo other"}]}]}}), encoding="utf-8")
        installer.install("claude", project=True, cwd=self.proj, python="py")
        data = self.read(path)
        self.assertEqual(data["permissions"], {"allow": ["Bash(ls *)"]})
        self.assertEqual(len(data["hooks"]["PreToolUse"]), 2)
        self.assertNotIn("matcher", data["hooks"]["PreToolUse"][1])
        self.assertEqual(data["hooks"]["PreToolUse"][1]["hooks"][0]["command"], '"py" -m pii_gate hook')

    def test_uninstall_removes_only_ours(self):
        path = Path(self.home) / ".claude" / "settings.json"
        path.parent.mkdir()
        path.write_text(json.dumps({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
            {"type": "command", "command": "echo other"}]}]}}), encoding="utf-8")
        installer.install("claude", home=self.home, python="py")
        installer.uninstall("claude", home=self.home)
        data = self.read(path)
        self.assertEqual(len(data["hooks"]["PreToolUse"]), 1)
        self.assertNotIn("UserPromptSubmit", data["hooks"])
        installer.install("codex", home=self.home, python="py")
        installer.uninstall("codex", home=self.home)
        self.assertEqual(self.read(Path(self.home) / ".codex" / "hooks.json"), {})

    def test_uninstall_missing_file_is_noop(self):
        installer.uninstall("codex", home=self.home)
        self.assertFalse((Path(self.home) / ".codex" / "hooks.json").exists())

    def test_status(self):
        installer.install("codex", home=self.home, python="py")
        lines = installer.status(cwd=self.proj, home=self.home)
        self.assertEqual(len(lines), 4)
        self.assertIn("installed (PreToolUse, UserPromptSubmit)", lines[0])
        self.assertTrue(all("missing" in line for line in lines[1:]))

    def test_bad_agent(self):
        with self.assertRaises(ValueError):
            installer.install("gemini", home=self.home)


if __name__ == "__main__":
    unittest.main()
