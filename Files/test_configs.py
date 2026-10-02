import base64
import json
import unittest

import app
from app import country_emoji, filter_for_protocols, rename_remark, server_remark
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

    def test_duplicate_remarks_are_deduplicated(self):
        result, _ = filter_for_protocols(
            [
                "vless://token@example.com:443?security=tls#one",
                "vless://token@example.com:443?security=tls#two",
            ],
            ["vless"],
        )
        self.assertEqual(len(result), 1)


class HealthTests(unittest.TestCase):
    def test_validation_limits_are_bounded(self):
        self.assertLessEqual(app.PROTOCOL_TEST_TIMEOUT, 8)
        self.assertGreaterEqual(app.PROTOCOL_TEST_WORKERS, 16)
        self.assertLessEqual(app.PROTOCOL_VALIDATION_MAX_RUNTIME, 900)

    def test_protocol_validator_rejects_unsupported_schemes(self):
        for scheme in ("ssr", "warp"):
            with self.subTest(scheme=scheme):
                with self.assertRaises(app.UnsupportedProtocol):
                    app._run_protocol_test(f"{scheme}://example")

    def test_singbox_outbound_parsing(self):
        cases = (
            ("vless://uuid@example.com:443?security=tls&sni=example.com&type=ws&path=%2Fws", "vless"),
            ("trojan://password@example.com:443?security=tls&sni=example.com", "trojan"),
            ("ss://YWVzLTI1Ni1nY206cGFzc3dvcmQ@example.com:443", "shadowsocks"),
        )
        for value, expected in cases:
            with self.subTest(value=value):
                outbound = app._singbox_outbound(value)
                self.assertEqual(outbound["type"], expected)

    def test_singbox_hysteria2_outbound_parsing(self):
        outbound = app._singbox_outbound(
            "hysteria2://password@example.com:443/?sni=example.com"
        )
        self.assertEqual(outbound["type"], "hysteria2")
        self.assertEqual(outbound["server"], "example.com")
        self.assertEqual(outbound["server_port"], 443)

    def test_transport_and_tls_options(self):
        query = {"security": ["tls"], "sni": ["example.com"], "alpn": ["h2,http/1.1"], "type": ["ws"], "path": ["/proxy"], "host": ["cdn.example.com"]}
        self.assertEqual(app._tls_options(query)["server_name"], "example.com")
        self.assertEqual(app._tls_options(query)["alpn"], ["h2", "http/1.1"])
        self.assertEqual(app._transport_options(query), {"type": "ws", "path": "/proxy", "headers": {"Host": "cdn.example.com"}})

    def test_reality_gets_default_utls(self):
        query = {"security": ["reality"], "sni": ["example.com"], "pbk": ["public-key"], "sid": ["1234"]}
        tls = app._tls_options(query)
        self.assertEqual(tls["utls"]["fingerprint"], "chrome")
        self.assertEqual(tls["reality"]["public_key"], "public-key")

    def test_unsupported_xray_vision_udp_flow_is_skipped(self):
        value = "vless://uuid@example.com:443?security=tls&flow=xtls-rprx-vision-udp443"
        with self.assertRaises(app.UnsupportedProtocol):
            app._singbox_outbound(value)


class RenameTests(unittest.TestCase):
    def test_country_emoji(self):
        self.assertEqual(country_emoji("DE"), "🇩🇪")
        self.assertEqual(country_emoji("US"), "🇺🇸")
        self.assertEqual(country_emoji("XX"), "🌐")
        self.assertEqual(country_emoji(""), "🌐")

    def test_server_remark(self):
        self.assertEqual(
            server_remark("Germany", "DE", 42.5),
            "🇩🇪 Germany • 42.5ms • mrdevmohamed",
        )

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
