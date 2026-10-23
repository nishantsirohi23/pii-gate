"""Exfiltration and tamper rules for shell commands and file paths."""
from __future__ import annotations

import os
import re
from typing import Iterator

from .detectors import Finding

_GIT_PUSH = re.compile(r"\bgit(?:\.exe)?\b(?:\s+-[Cc]\s+\S+|\s+--?[\w-]+(?:=\S+)?)*\s+push\b", re.I)
_OUTBOUND = re.compile(
    r"(?<![\w.-])(?:curl|wget|Invoke-WebRequest|iwr|Invoke-RestMethod|irm)(?:\.exe)?\b", re.I)
_UPLOAD_FLAG = re.compile(
    r"(?:^|\s)(?:-d|-F|-T|--data(?:-binary|-raw|-urlencode)?|--form|--upload-file|--json"
    r"|--post-data|--post-file|--body-file|-InFile|-Body|-Method\s+(?:Post|Put|Patch))(?=\s|=|$)", re.I)
_ALWAYS_UPLOAD = re.compile(
    r"(?<![\w.-])(?:scp|sftp|rsync|rclone|Start-BitsTransfer)(?:\.exe)?\b"
    r"|\baws\s+s3\s+(?:cp|sync|mv)\b|\bgsutil\s+(?:cp|rsync)\b|\baz\s+storage\s+blob\s+upload\b"
    r"|\|\s*(?:nc|ncat|netcat|socat|ssh)\b|\b(?:nc|ncat|netcat|socat)\b[^|&;]*<", re.I)
_CODE_HTTP = re.compile(
    r"requests\.(?:post|put|patch)\s*\(|urllib\.request\.urlopen\s*\([^)]*\bdata\s*="
    r"|http\.client\.HTTPS?Connection|fetch\s*\([^)]*method\s*:\s*[\"'](?:POST|PUT|PATCH)"
    r"|Net\.WebClient|\bUploadString\b|\bUploadFile\b", re.I)

_GATE_PATHS = re.compile(
    r"\.pii-gate(?:\.json)?(?![\w-])|\.codex[\\/]+(?:hooks\.json|config\.toml)"
    r"|\.claude[\\/]+settings(?:\.local)?\.json", re.I)
_WRITE_TOKENS = re.compile(
    r">|\b(?:tee|sed\s+-i|rm|del|erase|mv|move|cp|copy|truncate|Set-Content|Out-File|Add-Content"
    r"|Remove-Item|Move-Item|Copy-Item|Clear-Content|ren|rename|python[23]?\s+-c|node\s+-e)\b", re.I)
_BYPASS = re.compile(
    r"PII_GATE_\w+\s*=|--dangerously-bypass-hook-trust|\bhooks\s*=\s*false|--no-verify|core\.hooksPath", re.I)


def find_git_push(command: str) -> Iterator[Finding]:
    for m in _GIT_PUSH.finditer(command):
        yield Finding("git-push", m.start(), m.end(), "git push", "the agent must not publish; you push")


def find_exfil(command: str, has_sensitive: bool) -> Iterator[Finding]:
    """Outbound transfer. Downloads are fine; uploads, or any outbound call that carries sensitive data, are not."""
    m = _ALWAYS_UPLOAD.search(command)
    if m:
        yield Finding("exfil", m.start(), m.end(), mask_cmd(m.group()), "file transfer command")
        return
    m = _CODE_HTTP.search(command)
    if m:
        yield Finding("exfil", m.start(), m.end(), mask_cmd(m.group()), "HTTP upload in code")
        return
    m = _OUTBOUND.search(command)
    if m and (has_sensitive or _UPLOAD_FLAG.search(command)):
        why = "outbound call carrying sensitive data" if has_sensitive else "upload flag"
        yield Finding("exfil", m.start(), m.end(), mask_cmd(m.group()), f"{m.group().strip()} with {why}")


def find_tamper(command: str) -> Iterator[Finding]:
    m = _BYPASS.search(command)
    if m:
        yield Finding("tamper", m.start(), m.end(), mask_cmd(m.group()), "attempt to bypass the gate or git hooks")
        return
    m = _GATE_PATHS.search(command)
    if m and _WRITE_TOKENS.search(command):
        yield Finding("tamper", m.start(), m.end(), mask_cmd(m.group()), "write to the gate's own configuration")


def tamper_path(path: str) -> bool:
    """True if a file path belongs to the gate or the agents' hook configuration."""
    norm = path.replace("\\", "/")
    return os.path.basename(norm) == ".pii-gate.json" or "/.pii-gate/" in norm or bool(_GATE_PATHS.search(norm))


def mask_cmd(token: str) -> str:
    token = token.strip()
    return token[:12] if len(token) <= 12 else token[:12] + "..."
