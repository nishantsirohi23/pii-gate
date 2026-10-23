import json
import os
import tempfile
import unittest
from pathlib import Path

from pii_gate import config


class ParseTests(unittest.TestCase):
    def test_defaults(self):
        cfg = config.Config()
        self.assertEqual(cfg.level("tckn"), "block")
        self.assertEqual(cfg.level("email"), "warn")
        self.assertEqual(cfg.level("unknown-future-rule"), "block")
        self.assertFalse(cfg.fail_open)

    def test_overrides(self):
        cfg = config.parse({"rules": {"email": "block", "git-push": "off"}, "allow_values": ["x"],
                            "allow_paths": ["tests/*"], "email_allow_domains": ["corp.example"],
                            "scan_prompts": False, "fail_open": True, "log": False})
        self.assertEqual(cfg.level("email"), "block")
        self.assertEqual(cfg.level("git-push"), "off")
        self.assertEqual(cfg.allow_values, {"x"})
        self.assertFalse(cfg.scan_prompts)
        self.assertTrue(cfg.fail_open)

    def test_errors(self):
        with self.assertRaises(config.ConfigError):
            config.parse({"rules": {"nope": "block"}})
        with self.assertRaises(config.ConfigError):
            config.parse({"rules": {"tckn": "maybe"}})
        with self.assertRaises(config.ConfigError):
            config.parse({"allow_values": "not-a-list"})
        with self.assertRaises(config.ConfigError):
            config.parse({"fail_open": "yes"})
        with self.assertRaises(config.ConfigError):
            config.parse([])


class LoadTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name) / "home"
        self.proj = Path(self.tmp.name) / "proj"
        self.home.mkdir()
        self.proj.mkdir()
        self._env = os.environ.pop(config.ENV_VAR, None)

    def tearDown(self):
        if self._env is not None:
            os.environ[config.ENV_VAR] = self._env
        else:
            os.environ.pop(config.ENV_VAR, None)
        self.tmp.cleanup()

    def test_order_env_project_home(self):
        (self.home / ".pii-gate.json").write_text(json.dumps({"rules": {"email": "block"}}), encoding="utf-8")
        self.assertEqual(config.load(cwd=str(self.proj), home=str(self.home)).level("email"), "block")
        (self.proj / ".pii-gate.json").write_text(json.dumps({"rules": {"email": "off"}}), encoding="utf-8")
        self.assertEqual(config.load(cwd=str(self.proj), home=str(self.home)).level("email"), "off")
        env_file = Path(self.tmp.name) / "env.json"
        env_file.write_text(json.dumps({"rules": {"email": "warn"}}), encoding="utf-8")
        os.environ[config.ENV_VAR] = str(env_file)
        self.assertEqual(config.load(cwd=str(self.proj), home=str(self.home)).level("email"), "warn")

    def test_no_file_means_defaults(self):
        cfg = config.load(cwd=str(self.proj), home=str(self.home))
        self.assertEqual(cfg.source, "defaults")

    def test_broken_json_is_a_config_error(self):
        (self.proj / ".pii-gate.json").write_text("{not json", encoding="utf-8")
        with self.assertRaises(config.ConfigError):
            config.load(cwd=str(self.proj), home=str(self.home))


if __name__ == "__main__":
    unittest.main()
