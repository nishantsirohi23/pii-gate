"""Synthetic test values. Generated from arbitrary digits; they belong to nobody.

Each helper computes the real check digits so that the detectors' checksum logic is exercised.
"""


def tckn(prefix9: str) -> str:
    d = [int(c) for c in prefix9]
    assert len(d) == 9 and d[0] != 0
    d10 = ((d[0] + d[2] + d[4] + d[6] + d[8]) * 7 - (d[1] + d[3] + d[5] + d[7])) % 10
    d11 = (sum(d) + d10) % 10
    return prefix9 + str(d10) + str(d11)


def iban(country: str, bban: str) -> str:
    rearranged = bban + country + "00"
    number = int("".join(str(int(ch, 36)) for ch in rearranged))
    check = 98 - number % 97
    return f"{country}{check:02d}{bban}"


def card(prefix: str) -> str:
    total = 0
    for i, ch in enumerate(reversed(prefix)):
        d = int(ch)
        if i % 2 == 0:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return prefix + str((10 - total % 10) % 10)


TCKN_A = tckn("123456789")
TCKN_B = tckn("987654321")
IBAN_TR = iban("TR", "0001200912345678901234")
IBAN_GB = iban("GB", "NWBK60161331926820")
CARD_VISA = card("453957876362148")
CARD_MC = card("540112345678901")
AWS_KEY = "AKIAIOSFODNN7QWERTYUX"[:20]
OPENAI_KEY = "sk-proj-" + "a1B2c3D4e5F6g7H8i9J0k1L2"
GITHUB_TOKEN = "ghp_" + "A" * 36
PRIVATE_KEY = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
