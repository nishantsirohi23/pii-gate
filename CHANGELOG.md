# Changelog

## 0.1.0 (2026-10-23)

First release.

- Hook for Codex CLI and Claude Code (`PreToolUse`, `UserPromptSubmit`), exit-code-2 protocol, fail closed.
- Detectors: Turkish national ID (checksum), IBAN (mod-97, country lengths), payment cards (Luhn),
  e-mail, phone, secrets (private keys, AWS, OpenAI/Anthropic, GitHub, Slack, Google, JWT, clear-text assignments).
- Shell rules: uploads and outbound calls carrying sensitive data, `git push`, tamper protection for the
  gate's own configuration and hook settings.
- Two-tier SQL gate: core columns, context columns, person tables, non-revealing wrappers.
- `.pii-gate.json` configuration with rule levels, allow lists, e-mail domains and SQL extensions.
- CLI: `check`, `scan` (files and `--staged`), `install`, `uninstall`, `status`.
- Decision log with counts only.
