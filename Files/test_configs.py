import base64
import json
import unittest

from app import filter_for_protocols, rename_remark
from sort import classify, split_configs


class ProtocolTests(unittest.TestCase):
    def test_supported_protocols(self):
        cases = {
            "vmess://x": "vmess",
            "vless://x": "vless",
            "trojan://x": "trojan",
            "ss://x": "ss",
            "ssr://x": "ssr",
            "tuic://x": "tuic",
            "hy2://x": "hy2",
            "hysteria://x": "hy2",
            "hysteria2://x": "hy2",
            "warp://x": "extra",
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(classify(value), expected)

    def test_ssr_is_not_ss(self):
        self.assertEqual(classify("ssr://example"), "ssr")
        self.assertEqual(classify("ss://example"), "ss")


class FilteringTests(unittest.TestCase):
    def test_filter_and_dedupe(self):
        data = [
            "#source",
            "vless://one",
            "vless://one",
            "hysteria2://two",
            "garbage",
        ]
        result, garbage = filter_for_protocols(
            data,
            ["vless", "hysteria2", "hy2"],
        )
        self.assertEqual(result, ["#source", "vless://one", "hysteria2://two"])
        self.assertEqual(garbage, 1)

    def test_control_characters_are_rejected(self):
        result, garbage = filter_for_protocols(
            ["#clean", "#bad\x00comment", "vless://ok"],
            ["vless"],
        )
        self.assertEqual(result, ["#clean", "vless://ok"])
        self.assertEqual(garbage, 1)


class RenameTests(unittest.TestCase):
    def test_vmess_remark(self):
        payload = {"v": "2", "ps": "old", "add": "example.com"}
        encoded = base64.b64encode(json.dumps(payload).encode()).decode()
        result = rename_remark(f"vmess://{encoded}", "new")
        decoded = json.loads(base64.b64decode(result[8:]).decode())
        self.assertEqual(decoded["ps"], "new")

    def test_url_remark(self):
        self.assertEqual(
            rename_remark("vless://token@example.com:443", "new name"),
            "vless://token@example.com:443#new%20name",
        )


class SplitTests(unittest.TestCase):
    def test_split_counts(self):
        buckets = split_configs(
            ["vless://a", "hysteria2://b", "ssr://c", "#comment"]
        )
        self.assertEqual(len(buckets["vless"]), 1)
        self.assertEqual(len(buckets["hy2"]), 1)
        self.assertEqual(len(buckets["ssr"]), 1)


if __name__ == "__main__":
    unittest.main()
