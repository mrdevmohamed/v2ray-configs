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

    def test_xray_xhttp_outbound(self):
        value = "vless://uuid@example.com:443?security=tls&sni=example.com&fp=chrome&type=xhttp&path=%2Fproxy&mode=stream-one&host=cdn.example.com"
        outbound = app._xray_outbound(value, 10880)
        self.assertEqual(outbound["outbounds"][0]["protocol"], "vless")
        stream = outbound["outbounds"][0]["streamSettings"]
        self.assertEqual(stream["network"], "xhttp")
        self.assertEqual(stream["xhttpSettings"]["mode"], "stream-one")
        self.assertEqual(stream["xhttpSettings"]["path"], "/proxy")
        self.assertEqual(stream["xhttpSettings"]["host"], "cdn.example.com")

    def test_xray_reality_outbound(self):
        value = "vless://uuid@example.com:443?security=reality&sni=example.com&fp=chrome&pbk=public-key&sid=1234"
        outbound = app._xray_outbound(value, 10881)
        stream = outbound["outbounds"][0]["streamSettings"]
        self.assertEqual(stream["security"], "reality")
        self.assertEqual(stream["realitySettings"]["publicKey"], "public-key")
        self.assertEqual(stream["realitySettings"]["shortId"], "1234")

    def test_xray_trojan_reality_outbound(self):
        value = "trojan://password@example.com:443?security=reality&sni=example.com&fp=chrome&pbk=public-key&sid=1234&type=grpc&serviceName=proxy"
        outbound = app._xray_outbound(value, 10882)
        proxy = outbound["outbounds"][0]
        self.assertEqual(proxy["protocol"], "trojan")
        self.assertEqual(proxy["settings"]["servers"][0]["password"], "password")
        self.assertEqual(proxy["streamSettings"]["network"], "grpc")

    def test_xray_reality_rejects_websocket(self):
        value = "trojan://password@example.com:443?security=reality&type=ws&path=%2F"
        with self.assertRaises(app.UnsupportedProtocol):
            app._xray_outbound(value, 10883)

    def test_invalid_engine_inputs_are_skipped_early(self):
        with self.assertRaises(app.UnsupportedProtocol):
            app._run_protocol_test("trojan://password@example.com:443?security=tls&fp=unsafe")
        with self.assertRaises(ValueError):
            app._run_protocol_test("ss://bad@example.com:not-a-port")

    def test_invalid_shadowsocks_methods_are_rejected(self):
        with self.assertRaises(app.UnsupportedProtocol):
            app._singbox_outbound("ss://chacha20-poly1305:password@example.com:443")

    def test_reality_requires_public_key(self):
        with self.assertRaises(app.UnsupportedProtocol):
            app._run_protocol_test("vless://uuid@example.com:443?security=reality&sni=example.com&fp=chrome")

    def test_invalid_percent_escape_is_rejected(self):
        with self.assertRaises(ValueError):
            app._run_protocol_test("trojan://password@example.com:443?security=tls&path=%")


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


def _vmess(**overrides):
    obj = {"v": "2", "ps": "name", "add": "example.com", "port": "443",
           "id": "11111111-1111-1111-1111-111111111111", "net": "ws", "tls": "tls",
           "path": "/ws", "host": "cdn.example.com"}
    obj.update(overrides)
    return "vmess://" + base64.b64encode(json.dumps(obj).encode()).decode()


class RegressionTests(unittest.TestCase):
    """One test per bug fixed in the review."""

    def test_vmess_endpoint_is_read_from_payload(self):
        # Previously urlsplit() saw the base64 blob as the host and no port, so every
        # vmess config was rejected with "invalid server port".
        self.assertEqual(app._endpoint(_vmess()), ("example.com", 443))
        self.assertEqual(app._endpoint(_vmess(port=8443)), ("example.com", 8443))

    def test_vmess_outbound(self):
        outbound = app._singbox_outbound(_vmess())
        self.assertEqual(outbound["type"], "vmess")
        self.assertEqual(outbound["server_port"], 443)
        self.assertEqual(outbound["tls"]["server_name"], "cdn.example.com")
        self.assertEqual(outbound["transport"]["type"], "ws")

    def test_vmess_without_tls_does_not_enable_tls_because_of_sni(self):
        outbound = app._singbox_outbound(_vmess(tls="", sni="example.com", net="tcp"))
        self.assertNotIn("tls", outbound)

    def test_malformed_vmess_raises_value_error_not_type_error(self):
        # TypeError/AttributeError used to escape validate_configs and abort the run.
        no_port = _vmess()
        obj = json.loads(base64.b64decode(no_port[8:]))
        obj.pop("port")
        broken = "vmess://" + base64.b64encode(json.dumps(obj).encode()).decode()
        with self.assertRaises(ValueError):
            app._singbox_outbound(broken)
        not_a_dict = "vmess://" + base64.b64encode(b"[1, 2]").decode()
        with self.assertRaises(ValueError):
            app._singbox_outbound(not_a_dict)
        self.assertEqual(app.canonical_config_key(not_a_dict), not_a_dict)  # no crash

    def test_vmess_duplicates_ignore_remark_and_port_type(self):
        result, _ = filter_for_protocols(
            [_vmess(ps="a", port="443"), _vmess(ps="b", port=443)], ["vmess"])
        self.assertEqual(len(result), 1)

    def test_shadowsocks_urlsafe_and_legacy(self):
        creds = base64.urlsafe_b64encode(b"aes-256-gcm:pa>ss?word").decode().rstrip("=")
        method, password, host, port, _ = app._parse_shadowsocks(f"ss://{creds}@example.com:8388#x")
        self.assertEqual((method, password, host, port), ("aes-256-gcm", "pa>ss?word", "example.com", 8388))

        legacy = base64.b64encode(b"aes-256-gcm:secret@example.com:8388").decode()
        method, password, host, port, _ = app._parse_shadowsocks(f"ss://{legacy}#x")
        self.assertEqual((method, password, host, port), ("aes-256-gcm", "secret", "example.com", 8388))

    def test_shadowsocks_plugin_is_unsupported(self):
        with self.assertRaises(app.UnsupportedProtocol):
            app._singbox_outbound("ss://aes-256-gcm:pw@example.com:443?plugin=v2ray-plugin")

    def test_tls_none_wins_over_sni(self):
        self.assertIsNone(app._tls_options({"security": ["none"], "sni": ["example.com"]}))

    def test_trojan_defaults_to_tls(self):
        outbound = app._singbox_outbound("trojan://pw@example.com:443")
        self.assertTrue(outbound["tls"]["enabled"])

    def test_hysteria2_user_password_auth(self):
        outbound = app._singbox_outbound("hy2://user:pass@example.com:443")
        self.assertEqual(outbound["password"], "user:pass")

    def test_unsupported_transport_is_unsupported_not_failure(self):
        with self.assertRaises(app.UnsupportedProtocol):
            app._singbox_outbound("vless://uuid@example.com:443?type=kcp")

    def test_xray_raw_network_is_normalised(self):
        config = app._xray_outbound(
            "vless://uuid@example.com:443?security=reality&pbk=k&type=raw", 12345)
        self.assertEqual(config["outbounds"][0]["streamSettings"]["network"], "tcp")

    def test_decode_base64_handles_urlsafe_and_whitespace(self):
        plain = "vless://a@b.example:1?x=~~~~#n"
        encoded = base64.urlsafe_b64encode(plain.encode()).decode().rstrip("=")
        wrapped = "\n".join(encoded[i:i + 20] for i in range(0, len(encoded), 20)) + "\n"
        self.assertEqual(app.decode_base64(wrapped), plain)
        self.assertEqual(app.decode_base64("not base64 at all !!"), "")

    def test_filter_does_not_split_on_unicode_line_separators(self):
        line = "vless://id@example.com:443#re\u2028mark"
        result, garbage = filter_for_protocols([line], ["vless"])
        self.assertEqual(result, [line])
        self.assertEqual(garbage, 0)

    def test_duplicate_comments_are_collapsed(self):
        result, _ = filter_for_protocols(["#a", "#a", "vless://x"], ["vless"])
        self.assertEqual(result, ["#a", "vless://x"])

    def test_country_code_cannot_escape_the_output_directory(self):
        self.assertEqual(app._sanitize_country_code("../../etc"), "XX")
        self.assertEqual(app._sanitize_country_code("de"), "DE")
        self.assertEqual(app._sanitize_country_code(None), "XX")

    def test_ssr_remark_roundtrip(self):
        inner = "example.com:443:origin:aes-256-cfb:plain:" + \
            base64.urlsafe_b64encode(b"pw").decode().rstrip("=") + "/?remarks=b2xk"
        line = "ssr://" + base64.urlsafe_b64encode(inner.encode()).decode().rstrip("=")
        renamed = rename_remark(line, "new")
        decoded = app._b64decode_loose(renamed[6:]).decode()
        remark = decoded.split("remarks=")[1].split("&")[0]
        self.assertEqual(app._b64decode_loose(remark).decode(), "new")

    def test_vmess_remark_ignores_fragment(self):
        renamed = rename_remark(_vmess() + "#fragment", "new")
        self.assertEqual(json.loads(base64.b64decode(renamed[8:]))["ps"], "new")


class SortRegressionTests(unittest.TestCase):
    def test_classify_is_case_insensitive(self):
        self.assertEqual(classify("VLESS://x"), "vless")
        self.assertEqual(classify("SSR://x"), "ssr")
        self.assertEqual(classify("Ss://x"), "ss")


if __name__ == "__main__":
    unittest.main()
