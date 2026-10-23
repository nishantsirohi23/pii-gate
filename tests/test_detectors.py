import unittest

from pii_gate import detectors as d

import _synthetic as syn


def rules(findings):
    return [f.rule for f in findings]


class TcknTests(unittest.TestCase):
    def test_valid_number_is_found(self):
        found = list(d.find_tckn(f"customer {syn.TCKN_A} called"))
        self.assertEqual(rules(found), ["tckn"])
        self.assertNotIn(syn.TCKN_A, found[0].sample)
        self.assertEqual(found[0].sample, syn.TCKN_A[0] + "***")

    def test_bad_checksum_is_ignored(self):
        broken = syn.TCKN_A[:-1] + str((int(syn.TCKN_A[-1]) + 1) % 10)
        self.assertEqual(list(d.find_tckn(broken)), [])

    def test_leading_zero_and_embedded_digits_are_ignored(self):
        self.assertEqual(list(d.find_tckn("0" + syn.TCKN_A[1:])), [])
        self.assertEqual(list(d.find_tckn("9" + syn.TCKN_A)), [])  # 12 digits

    def test_well_known_test_number_and_allowlist(self):
        self.assertEqual(list(d.find_tckn("10000000146")), [])
        self.assertEqual(list(d.find_tckn(syn.TCKN_A, allow={syn.TCKN_A})), [])

    def test_two_numbers_two_findings(self):
        self.assertEqual(len(list(d.find_tckn(f"{syn.TCKN_A} and {syn.TCKN_B}"))), 2)


class IbanTests(unittest.TestCase):
    def test_compact_and_spaced(self):
        spaced = " ".join(syn.IBAN_TR[i:i + 4] for i in range(0, len(syn.IBAN_TR), 4))
        self.assertEqual(rules(d.find_iban("iban: " + syn.IBAN_TR)), ["iban"])
        self.assertEqual(rules(d.find_iban("iban: " + spaced)), ["iban"])
        self.assertEqual(rules(d.find_iban(syn.IBAN_GB)), ["iban"])

    def test_bad_check_digits(self):
        broken = syn.IBAN_TR[:2] + "00" + syn.IBAN_TR[4:]
        self.assertEqual(list(d.find_iban(broken)), [])

    def test_wrong_length_for_country(self):
        self.assertEqual(list(d.find_iban(syn.iban("TR", "000120091234567890123"))), [])

    def test_registry_examples_are_not_personal(self):
        self.assertEqual(list(d.find_iban("GB82 WEST 1234 5698 7654 32")), [])


class CardTests(unittest.TestCase):
    def test_luhn_valid_with_separators(self):
        self.assertEqual(rules(d.find_card(syn.CARD_VISA)), ["card"])
        grouped = " ".join(syn.CARD_VISA[i:i + 4] for i in range(0, 16, 4))
        self.assertEqual(rules(d.find_card(grouped)), ["card"])
        self.assertEqual(rules(d.find_card(syn.CARD_MC.replace(" ", "-"))), ["card"])

    def test_luhn_invalid_and_bad_prefix(self):
        broken = syn.CARD_VISA[:-1] + str((int(syn.CARD_VISA[-1]) + 1) % 10)
        self.assertEqual(list(d.find_card(broken)), [])
        self.assertEqual(list(d.find_card("1" + syn.CARD_VISA[1:])), [])

    def test_published_test_cards(self):
        self.assertEqual(list(d.find_card("4111 1111 1111 1111")), [])


class EmailTests(unittest.TestCase):
    def test_found_and_masked(self):
        found = list(d.find_email("mail ayse.k@somecompany.com.tr now"))
        self.assertEqual(rules(found), ["email"])
        self.assertEqual(found[0].sample, "a***")

    def test_reserved_and_allowed_domains(self):
        self.assertEqual(list(d.find_email("bob@example.com x@foo.test y@users.noreply.github.com")), [])
        self.assertEqual(list(d.find_email("ops@mycorp.io", allow_domains=["mycorp.io"])), [])


class PhoneTests(unittest.TestCase):
    def test_turkish_and_international(self):
        for text in ("+90 532 123 45 67", "0532 123 45 67", "5321234567", "+1 212 555 0199", "+44 20 7946 0958"):
            self.assertEqual(rules(d.find_phone(text)), ["phone"], text)

    def test_not_phones(self):
        for text in ("2024-10-23", "order 12345", "v1.2.3", "port 8080"):
            self.assertEqual(list(d.find_phone(text)), [], text)


class SecretTests(unittest.TestCase):
    def test_token_formats_block(self):
        for text in (syn.AWS_KEY, syn.OPENAI_KEY, syn.GITHUB_TOKEN, syn.PRIVATE_KEY):
            found = list(d.find_secrets(text))
            self.assertEqual(rules(found), ["secret"], text)
            self.assertTrue(found[0].sample.endswith("***"))

    def test_documentation_placeholders_pass(self):
        self.assertEqual(list(d.find_secrets("AKIAIOSFODNN7EXAMPLE sk-proj-xxxxxxxxxxxxxxxxxxxxxxxx")), [])

    def test_clear_text_assignment_is_a_warning_rule(self):
        self.assertEqual(rules(d.find_secrets('password = "hunter2hunter2"')), ["secret-assign"])
        self.assertEqual(rules(d.find_secrets("API_KEY=9f8e7d6c5b4a3f2e1d")), ["secret-assign"])

    def test_code_and_placeholders_are_not_assignments(self):
        for text in ('password = os.environ["PW"]', "password = input()", "api_key: <your-key>",
                     "password: ${DB_PASSWORD}", "secret = getenv('S')"):
            self.assertEqual(list(d.find_secrets(text)), [], text)


class MaskTests(unittest.TestCase):
    def test_mask_never_leaks(self):
        self.assertEqual(d.mask("  secretvalue "), "s***")
        self.assertEqual(d.mask(""), "***")


if __name__ == "__main__":
    unittest.main()
