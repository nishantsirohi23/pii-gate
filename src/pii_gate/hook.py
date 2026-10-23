"""Hook entry point shared by Codex CLI and Claude Code.

Both agents send one JSON object on stdin and treat exit code 2 as "block, and show stderr as the
reason". Exit 0 with no output means "no objection". Anything unexpected (bad JSON, a bug in a
detector, an unreadable config) blocks too, unless fail_open is set: a gate that fails open is not a gate.
"""
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from typing import Any, List, Optional, Tuple

from . import log as decision_log
from .config import Config, ConfigError, load
from .detectors import Finding
from .engine import Engine, Report, describe
from .exfil import tamper_path

PATH_KEYS = ("file_path", "path", "notebook_path", "filePath")
SHELL_TOOLS = ("Bash", "PowerShell", "shell", "exec_command")
_PATCH_FILE = re.compile(r"^\*\*\* (?:Add|Update|Delete|Move to) File: (.+)$", re.M)


@dataclass
class Outcome:
    exit_code: int
    stderr: str = ""
    counts: Optional[dict] = None


def _strings(value: Any, out: List[str]) -> None:
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            _strings(v, out)
    elif isinstance(value, list):
        for v in value:
            _strings(v, out)


def _added_lines(patch: str) -> str:
    return "\n".join(line[1:] for line in patch.splitlines()
                     if line.startswith("+") and not line.startswith("+++"))


def _agent(payload: dict) -> str:
    if "turn_id" in payload or "model" in payload:
        return "codex"
    if "prompt_id" in payload or "scratchpad_dir" in payload:
        return "claude"
    return "agent"


def _reason(event: str, tool: str, rep: Report) -> str:
    head = f"pii-gate blocked this {tool or event} call." if event == "PreToolUse" else "pii-gate blocked this prompt."
    lines = ["  - " + line for line in describe(rep.blocking)]
    tail = ("Personal data, secrets and outbound transfers must not leave this machine. Remove them. "
            "If this is synthetic test data, the user can allow it in .pii-gate.json (allow_values, allow_paths); "
            "the agent may not edit that file.")
    return "\n".join([head, *lines, tail])


def evaluate(payload: dict, cfg: Config) -> Tuple[Report, str, str]:
    """Returns (report, event, tool). Pure: no I/O."""
    engine = Engine(cfg)
    event = str(payload.get("hook_event_name", ""))
    tool = str(payload.get("tool_name", ""))
    cwd = payload.get("cwd")
    if event == "UserPromptSubmit":
        if not cfg.scan_prompts:
            return Report(), event, tool
        return engine.scan_text(str(payload.get("prompt", "")), sql=False), event, tool
    if event != "PreToolUse":
        return Report(), event, tool
    tool_input = payload.get("tool_input", {})
    if not isinstance(tool_input, dict):
        tool_input = {"value": tool_input}
    findings: List[Finding] = []

    # 1. Shell commands: full rule set including exfiltration and tamper rules.
    if tool in SHELL_TOOLS:
        findings += engine.findings(str(tool_input.get("command", "")), command=True)
        return engine.report(findings), event, tool

    # 2. File writes: what the agent writes, not what already exists. Honour allow_paths.
    paths = [str(tool_input[k]) for k in PATH_KEYS if isinstance(tool_input.get(k), str)]
    if tool == "apply_patch":
        patch = str(tool_input.get("command", tool_input.get("input", "")))
        paths = _PATCH_FILE.findall(patch)
        texts = [_added_lines(patch)]
    elif tool == "Edit":
        texts = [str(tool_input.get("new_string", ""))]
    elif tool == "MultiEdit":
        texts = [str(e.get("new_string", "")) for e in tool_input.get("edits", []) if isinstance(e, dict)]
    elif tool == "Write":
        texts = [str(tool_input.get("content", ""))]
    elif tool == "NotebookEdit":
        texts = [str(tool_input.get("new_source", ""))]
    else:
        texts = []
        _strings(tool_input, texts)
    for p in paths:
        if tamper_path(p):
            findings.append(Finding("tamper", 0, 0, p.replace("\\", "/").split("/")[-1],
                                    "write to the gate's own configuration"))
    if paths and all(engine.path_allowed(p, cwd) for p in paths):
        return engine.report(findings), event, tool
    for text in texts:
        findings += engine.findings(text)
    return engine.report(findings), event, tool


def run(stdin_text: str, cfg: Optional[Config] = None, home: Optional[str] = None,
        fail_open: Optional[bool] = None) -> Outcome:
    try:
        payload = json.loads(stdin_text)
        if not isinstance(payload, dict):
            raise ValueError("hook payload must be a JSON object")
        if cfg is None:
            cfg = load(cwd=payload.get("cwd"), home=home)
        rep, event, tool = evaluate(payload, cfg)
        if cfg.log and (rep.blocking or rep.warnings):
            decision = "DENY" if rep.blocked else "ALLOW-WARN"
            decision_log.write(_agent(payload), event, tool, decision,
                               {**rep.counts(rep.warnings), **rep.counts()}, home=home)
        if rep.blocked:
            return Outcome(2, _reason(event, tool, rep), rep.counts())
        return Outcome(0)
    except Exception as exc:  # noqa: BLE001 - fail closed on anything
        open_ = fail_open if fail_open is not None else (cfg.fail_open if cfg else False)
        kind = "config error" if isinstance(exc, ConfigError) else "internal error"
        msg = f"pii-gate {kind}: {exc}. " + ("Allowing (fail_open)." if open_ else "Blocking to stay safe.")
        return Outcome(0 if open_ else 2, msg)


def main(fail_open: Optional[bool] = None) -> int:
    data = sys.stdin.read()
    out = run(data, fail_open=fail_open)
    if out.stderr:
        sys.stderr.write(out.stderr + "\n")
    return out.exit_code
