"""Command line: hook, check, scan, install, uninstall, status."""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path
from typing import Iterable, List, Optional

from . import __version__, hook, installer
from .config import ConfigError, load
from .engine import Engine, describe

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "__pycache__", ".venv", "venv", ".tox", ".mypy_cache"}
MAX_BYTES = 5 * 1024 * 1024


def _print(text: str = "") -> None:
    sys.stdout.write(text + "\n")


def _is_text(data: bytes) -> bool:
    return b"\x00" not in data[:8192]


def _iter_files(roots: Iterable[str]) -> Iterable[Path]:
    for root in roots:
        p = Path(root)
        if p.is_file():
            yield p
            continue
        for dirpath, dirnames, filenames in os.walk(p):
            dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.endswith(".egg-info")]
            for name in filenames:
                yield Path(dirpath) / name


def cmd_check(args) -> int:
    cfg = load(cwd=os.getcwd())
    engine = Engine(cfg)
    text = sys.stdin.read() if args.stdin else " ".join(args.text)
    rep = engine.scan_command(text) if args.command else engine.scan_text(text)
    for line in describe(rep.blocking):
        _print("BLOCK  " + line)
    for line in describe(rep.warnings):
        _print("warn   " + line)
    if not rep.blocking and not rep.warnings:
        _print("clean")
    return 1 if rep.blocked else 0


def _scan_text_lines(engine: Engine, label: str, text: str) -> int:
    blocked = 0
    for n, line in enumerate(text.splitlines(), 1):
        rep = engine.scan_text(line)
        for f in rep.blocking:
            _print(f'{label}:{n}: BLOCK {f.rule} ({f.note}, "{f.sample}")')
            blocked += 1
        for f in rep.warnings:
            _print(f'{label}:{n}: warn  {f.rule} ({f.note}, "{f.sample}")')
    return blocked


def cmd_scan(args) -> int:
    cwd = os.getcwd()
    cfg = load(cwd=cwd)
    engine = Engine(cfg)
    blocked = 0
    if args.staged:
        diff = subprocess.run(["git", "diff", "--cached", "-U0", "--no-color"], capture_output=True,
                              text=True, encoding="utf-8", errors="replace", check=False)
        if diff.returncode != 0:
            sys.stderr.write(diff.stderr)
            return 2
        current = ""
        for line in diff.stdout.splitlines():
            if line.startswith("+++ "):
                current = line[4:]
                current = current[2:] if current.startswith("b/") else current
            elif line.startswith("+") and not line.startswith("+++"):
                if engine.path_allowed(current, cwd):
                    continue
                blocked += _scan_text_lines(engine, current, line[1:])
    else:
        for path in _iter_files(args.paths or ["."]):
            rel = str(path)
            if engine.path_allowed(rel, cwd) or engine.path_allowed(str(path.resolve()), cwd):
                continue
            try:
                if path.stat().st_size > MAX_BYTES:
                    continue
                data = path.read_bytes()
            except OSError:
                continue
            if not _is_text(data):
                continue
            blocked += _scan_text_lines(engine, rel, data.decode("utf-8", errors="replace"))
    _print(f"{'BLOCKED' if blocked else 'clean'}: {blocked} blocking finding(s)")
    return 1 if blocked else 0


def cmd_install(args) -> int:
    agents = ["codex", "claude"] if args.agent == "all" else [args.agent]
    for agent in agents:
        path = installer.install(agent, project=args.project)
        _print(f"{agent}: hook written to {path}")
        if agent == "codex":
            _print("        run `codex`, then `/hooks` to review and trust the new hook (Codex skips untrusted hooks)")
    return 0


def cmd_uninstall(args) -> int:
    agents = ["codex", "claude"] if args.agent == "all" else [args.agent]
    for agent in agents:
        path = installer.uninstall(agent, project=args.project)
        _print(f"{agent}: pii-gate entries removed from {path}")
    return 0


def cmd_status(args) -> int:
    try:
        cfg = load(cwd=os.getcwd())
        _print(f"config: {cfg.source}")
        _print("rules : " + ", ".join(f"{r}={cfg.level(r)}" for r in sorted(cfg.levels)))
    except ConfigError as exc:
        _print(f"config: ERROR {exc}")
    for line in installer.status():
        _print(line)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pii-gate", description="Fail-closed personal-data gate for AI coding agents.")
    p.add_argument("--version", action="version", version=f"pii-gate {__version__}")
    sub = p.add_subparsers(dest="cmd")
    sub.required = True

    h = sub.add_parser("hook", help="run as a Codex CLI / Claude Code hook (reads JSON on stdin)")
    h.add_argument("--fail-open", action="store_true", help="allow on internal errors (default: block)")
    h.set_defaults(func=lambda a: hook.main(fail_open=True if a.fail_open else None))

    c = sub.add_parser("check", help="check a piece of text; exit 1 if it would be blocked")
    c.add_argument("text", nargs="*")
    c.add_argument("--stdin", action="store_true", help="read the text from stdin")
    c.add_argument("--command", action="store_true", help="treat the text as a shell command (exfil/tamper rules too)")
    c.set_defaults(func=cmd_check)

    s = sub.add_parser("scan", help="scan files (or --staged git changes); exit 1 on blocking findings")
    s.add_argument("paths", nargs="*")
    s.add_argument("--staged", action="store_true", help="scan lines added in the git index (pre-commit)")
    s.set_defaults(func=cmd_scan)

    for name, fn in (("install", cmd_install), ("uninstall", cmd_uninstall)):
        i = sub.add_parser(name, help=f"{name} the hook for codex, claude or all")
        i.add_argument("agent", choices=["codex", "claude", "all"])
        i.add_argument("--project", action="store_true", help="write into ./.codex or ./.claude instead of your home")
        i.set_defaults(func=fn)

    st = sub.add_parser("status", help="show active config and where the hook is installed")
    st.set_defaults(func=cmd_status)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except ConfigError as exc:
        sys.stderr.write(f"pii-gate config error: {exc}\n")
        return 2
