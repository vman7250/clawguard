import unittest

from scripts.sync_advisories import normalize_version


class NormalizeVersionTests(unittest.TestCase):
    def test_normalizes_whitespace_and_optional_v_prefix(self):
        self.assertEqual(normalize_version(" \tv2026.8.1-rc.2\n"), "2026.8.1-rc.2")

    def test_extracts_version_from_release_label_with_unicode_text(self):
        self.assertEqual(normalize_version("发布版本 2026.8.1"), "2026.8.1")

    def test_accepts_unicode_decimal_digits(self):
        self.assertEqual(normalize_version("v２０２６.８.１"), "２０２６.８.１")

    def test_rejects_empty_incomplete_and_non_string_values(self):
        for value in ("", "   ", "2026.8", "202.8.1", None, 20260801, b"2026.8.1"):
            with self.subTest(value=value):
                self.assertIsNone(normalize_version(value))


if __name__ == "__main__":
    unittest.main()
