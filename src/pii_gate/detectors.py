"""Pattern detectors for personal data and secrets.

Every detector yields Finding objects. A Finding never carries the matched value,
only a masked sample (first character + "***"), so findings are safe to log and
safe to show to the agent.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Iterable, Iterator


@dataclass(frozen=True)
class Finding:
    rule: str
    start: int
    end: int
    sample: str
    note: str = ""


def mask(value: str) -> str:
    value = value.strip()
    return (value[0] + "***") if value else "***"


# Values published as test data in countless docs and SDKs. They identify nobody.
WELL_KNOWN_TEST_VALUES = frozenset({
    "10000000146",                       # the canonical TCKN test number
    "4111111111111111", "4242424242424242", "5555555555554444",
    "378282246310005", "6011111111111117", "4000000000000002",
    "TR330006100519786457841326",        # example IBANs from the IBAN registry docs
    "GB82WEST12345698765432", "DE89370400440532013000",
})

# RFC 2606 / RFC 6761 reserved names plus GitHub's no-reply relay.
RESERVED_EMAIL_SUFFIXES = (
    "@example.com", "@example.net", "@example.org", ".example.com", ".example.net",
    ".example.org", ".example", ".invalid", ".localhost", ".test",
    "@users.noreply.github.com",
)

# --------------------------------------------------------------------------- TCKN
_TCKN = re.compile(r"(?<!\d)\d{11}(?!\d)")


def tckn_valid(s: str) -> bool:
    """Turkish national identity number: 11 digits, two check digits."""
    if len(s) != 11 or not s.isdigit() or s[0] == "0":
        return False
    d = [int(c) for c in s]
    odd = d[0] + d[2] + d[4] + d[6] + d[8]
    even = d[1] + d[3] + d[5] + d[7]
    if (odd * 7 - even) % 10 != d[9]:
        return False
    return sum(d[:10]) % 10 == d[10]


def find_tckn(text: str, allow: Iterable[str] = ()) -> Iterator[Finding]:
    for m in _TCKN.finditer(text):
        s = m.group()
        if s in WELL_KNOWN_TEST_VALUES or s in allow or not tckn_valid(s):
            continue
        yield Finding("tckn", m.start(), m.end(), mask(s), "Turkish national ID, checksum valid")


# --------------------------------------------------------------------------- IBAN
_IBAN = re.compile(r"(?<![A-Z0-9])[A-Z]{2}\d{2}(?: ?[A-Z0-9]){11,30}(?![A-Z0-9])")
IBAN_LENGTHS = {
    "AE": 23, "AT": 20, "AZ": 28, "BE": 16, "BG": 22, "CH": 21, "CY": 28, "CZ": 24,
    "DE": 22, "DK": 18, "EE": 20, "EG": 29, "ES": 24, "FI": 18, "FR": 27, "GB": 22,
    "GE": 22, "GR": 27, "HR": 21, "HU": 28, "IE": 22, "IL": 23, "IS": 26, "IT": 27,
    "KW": 30, "KZ": 20, "LT": 20, "LU": 20, "LV": 21, "MT": 31, "NL": 18, "NO": 15,
    "PL": 28, "PT": 25, "QA": 29, "RO": 24, "SA": 24, "SE": 24, "SK": 24, "TR": 26,
}


def iban_valid(compact: str) -> bool:
    cc = compact[:2]
    if not cc.isalpha() or not compact[2:4].isdigit():
        return False
    if cc in IBAN_LENGTHS and len(compact) != IBAN_LENGTHS[cc]:
        return False
    if not 15 <= len(compact) <= 34:
        return False
    rearranged = compact[4:] + compact[:4]
    try:
        number = "".join(str(int(ch, 36)) for ch in rearranged)
    except ValueError:
        return False
    return int(number) % 97 == 1


def find_iban(text: str, allow: Iterable[str] = ()) -> Iterator[Finding]:
    for m in _IBAN.finditer(text):
        compact = m.group().replace(" ", "")
        if compact in WELL_KNOWN_TEST_VALUES or compact in allow or not iban_valid(compact):
            continue
        yield Finding("iban", m.start(), m.end(), mask(compact), f"IBAN ({compact[:2]}), checksum valid")


# --------------------------------------------------------------------------- cards
_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")


def luhn_valid(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def find_card(text: str, allow: Iterable[str] = ()) -> Iterator[Finding]:
    for m in _CARD.finditer(text):
        digits = re.sub(r"[ -]", "", m.group())
        if not 13 <= len(digits) <= 19 or digits[0] not in "3456":
            continue
        if len(set(digits)) == 1 or not luhn_valid(digits):
            continue
        if digits in WELL_KNOWN_TEST_VALUES or digits in allow:
            continue
        yield Finding("card", m.start(), m.end(), mask(digits), "payment card number, Luhn valid")


# --------------------------------------------------------------------------- e-mail
_EMAIL = re.compile(r"(?<![\w.+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![\w.-])")


def find_email(text: str, allow: Iterable[str] = (), allow_domains: Iterable[str] = ()) -> Iterator[Finding]:
    domains = tuple("@" + d.lower().lstrip("@") for d in allow_domains)
    for m in _EMAIL.finditer(text):
        value = m.group()
        low = value.lower()
        if value in allow or low.endswith(RESERVED_EMAIL_SUFFIXES) or (domains and low.endswith(domains)):
            continue
        yield Finding("email", m.start(), m.end(), mask(value), "e-mail address")


# --------------------------------------------------------------------------- phone
_PHONE = re.compile(
    r"(?<![\w+.-])(?:"
    r"(?:\+\d{1,3}[\s.-]?)?\(?0?5\d{2}\)?[\s.-]?\d{3}[\s.-]?\d{2}[\s.-]?\d{2}"   # Turkish mobile
    r"|\+\d{1,3}[\s.-]?\(?\d{1,4}\)?(?:[\s.-]?\d{2,4}){2,4}"                     # international
    r")(?![\w-])"
)


def find_phone(text: str, allow: Iterable[str] = ()) -> Iterator[Finding]:
    for m in _PHONE.finditer(text):
        value = m.group()
        digits = re.sub(r"\D", "", value)
        if len(digits) < 10 or value in allow or digits in allow:
            continue
        yield Finding("phone", m.start(), m.end(), mask(digits), "phone number")


# --------------------------------------------------------------------------- secrets
_SECRET_PATTERNS = (
    ("private key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("AWS access key", re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA)[0-9A-Z]{16}(?![A-Z0-9])")),
    ("OpenAI/Anthropic-style key", re.compile(r"(?<![\w-])sk-(?:ant-|proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}")),
    ("GitHub token", re.compile(r"(?<!\w)(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,})")),
    ("Slack token", re.compile(r"(?<!\w)xox[abpr]-[A-Za-z0-9-]{10,}")),
    ("Google API key", re.compile(r"(?<![\w-])AIza[0-9A-Za-z_-]{35}(?![\w-])")),
    ("JWT", re.compile(r"(?<![\w-])eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
)
_PLACEHOLDER = re.compile(r"xxx|\.\.\.|<|>|\$\{|\{\{|your[_-]|change[_-]?me|example|placeholder|dummy|redacted", re.I)
_ASSIGN = re.compile(
    r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)"
    r"\s*[:=]\s*[\"']?(?P<value>[^\s\"'`,;)]{8,})"
)
_CODE_VALUE = re.compile(r"[(){}$%]|os\.environ|getenv|process\.env|input\(|None|null|true|false", re.I)


def find_secrets(text: str, allow: Iterable[str] = ()) -> Iterator[Finding]:
    for label, pattern in _SECRET_PATTERNS:
        for m in pattern.finditer(text):
            value = m.group()
            if value in allow or (label != "private key" and _PLACEHOLDER.search(value)):
                continue
            yield Finding("secret", m.start(), m.end(), mask(value), label)
    for m in _ASSIGN.finditer(text):
        value = m.group("value")
        if value in allow or _PLACEHOLDER.search(value) or _CODE_VALUE.search(value):
            continue
        yield Finding("secret-assign", m.start("value"), m.end("value"), mask(value), "credential assigned in clear text")


def find_pii(text: str, allow: Iterable[str] = (), allow_domains: Iterable[str] = ()) -> Iterator[Finding]:
    yield from find_tckn(text, allow)
    yield from find_iban(text, allow)
    yield from find_card(text, allow)
    yield from find_email(text, allow, allow_domains)
    yield from find_phone(text, allow)
