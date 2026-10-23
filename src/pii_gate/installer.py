"""Writes the hook entries into Codex CLI and Claude Code configuration files."""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Dict, List, Optional

MARKER = "pii_gate"
TIMEOUT = 20


def hook_command(python: Optional[str] = None) -> str:
    exe = python or sys.executable
    return f'"{exe}" -m pii_gate hook'


def target(agent: str, project: bool, cwd: Optional[str] = None, home: Optional[str] = None) -> Path:
    base = Path(cwd or Path.cwd()) if project else Path(home or Path.home())
    if agent == "codex":
        return base / ".codex" / "hooks.json"
    if agent == "claude":
        return base / ".claude" / "settings.json"
    raise ValueError("agent must be 'codex' or 'claude'")


def _entry(agent: str, command: str) -> Dict:
    handler = {"type": "command", "command": command, "timeout": TIMEOUT}
    if agent == "codex":
        handler["statusMessage"] = "pii-gate"
        pre = {"matcher": ".*", "hooks": [handler]}
    else:
        pre = {"hooks": [handler]}
    return {"PreToolUse": [pre], "UserPromptSubmit": [{"hooks": [dict(handler)]}]}


def _has_marker(group: Dict) -> bool:
    return any(MARKER in str(h.get("command", "")) for h in group.get("hooks", []) if isinstance(h, dict))


def _read(path: Path) -> Dict:
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8-sig") or "{}")
    if not isinstance(data, dict):
        raise ValueError(f"{path}: expected a JSON object")
    return data


def install(agent: str, project: bool = False, cwd: Optional[str] = None, home: Optional[str] = None,
            python: Optional[str] = None) -> Path:
    path = target(agent, project, cwd, home)
    data = _read(path)
    hooks = data.setdefault("hooks", {})
    for event, groups in _entry(agent, hook_command(python)).items():
        existing = hooks.setdefault(event, [])
        if not any(_has_marker(g) for g in existing if isinstance(g, dict)):
            existing.extend(groups)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path


def uninstall(agent: str, project: bool = False, cwd: Optional[str] = None, home: Optional[str] = None) -> Path:
    path = target(agent, project, cwd, home)
    if not path.is_file():
        return path
    data = _read(path)
    hooks = data.get("hooks", {})
    for event in list(hooks):
        hooks[event] = [g for g in hooks[event] if not (isinstance(g, dict) and _has_marker(g))]
        if not hooks[event]:
            del hooks[event]
    if not hooks:
        data.pop("hooks", None)
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return path


def status(cwd: Optional[str] = None, home: Optional[str] = None) -> List[str]:
    lines = []
    for agent in ("codex", "claude"):
        for project in (False, True):
            path = target(agent, project, cwd, home)
            state = "missing"
            if path.is_file():
                try:
                    hooks = _read(path).get("hooks", {})
                    found = [e for e, groups in hooks.items()
                             if any(_has_marker(g) for g in groups if isinstance(g, dict))]
                    state = "installed (" + ", ".join(found) + ")" if found else "present, no pii-gate entry"
                except ValueError as exc:
                    state = f"unreadable: {exc}"
            lines.append(f"{agent:6} {'project' if project else 'user   '} {path}: {state}")
    return lines
