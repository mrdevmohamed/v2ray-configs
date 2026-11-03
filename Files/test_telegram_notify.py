import base64
import json
import unittest
from unittest.mock import Mock, patch

import requests

from telegram_notify import (
    build_messages,
    find_new_servers,
    matching_servers,
    send_telegram_messages,
)


def vmess_config(port=80, net="ws", remark="name"):
    payload = {
        "v": "2",
        "ps": remark,
        "add": "vmess.example.com",
        "port": str(port),
        "id": "11111111-1111-1111-1111-111111111111",
        "net": net,
        "tls": "",
        "path": "/ws",
        "host": "cdn.example.com",
    }
    encoded = base64.b64encode(json.dumps(payload).encode()).decode()
    return "vmess://" + encoded


def metric(config, port=80, latency=50, host="example.com"):
    return {
        "host": host,
        "port": port,
        "latency_ms": latency,
        "country": "Test Country",
        "country_code": "TC",
        "config": config,
    }


class MatchingTests(unittest.TestCase):
    def test_only_port_80_vless_and_vmess_websocket_are_selected(self):
        rows = [
            metric(vmess_config(), latency=60, host="vmess.example.com"),
            metric(
                "vless://uuid@example.com:80?type=ws&path=%2Fws#vless",
                latency=30,
            ),
            metric("vless://uuid@example.com:443?type=ws", port=443),
            metric("vless://uuid@example.com:80?type=tcp"),
            metric(vmess_config(net="tcp"), host="vmess.example.com"),
            metric("trojan://password@example.com:80?type=ws"),
        ]

        selected = matching_servers(rows)
        self.assertEqual([item["protocol"] for item in selected], ["vless", "vmess"])
        self.assertEqual([item["latency_ms"] for item in selected], [30, 60])

    def test_vless_accepts_network_ws_alias(self):
        selected = matching_servers([
            metric("vless://uuid@example.com:80?network=ws")
        ])
        self.assertEqual(len(selected), 1)

    def test_metrics_port_must_match_uri_port(self):
        selected = matching_servers([
            metric("vless://uuid@example.com:80?type=ws", port=8080)
        ])
        self.assertEqual(selected, [])

    def test_duplicates_ignore_remarks(self):
        selected = matching_servers([
            metric("vless://uuid@example.com:80?type=ws#first"),
            metric("vless://uuid@example.com:80?type=ws#second"),
        ])
        self.assertEqual(len(selected), 1)

    def test_new_server_detection_ignores_vmess_display_remark(self):
        old = [metric(vmess_config(remark="old name"), host="vmess.example.com")]
        current = [
            metric(vmess_config(remark="new latency name"), host="vmess.example.com")
        ]
        self.assertEqual(find_new_servers(current, old), [])

    def test_only_new_matching_servers_are_returned(self):
        existing = "vless://uuid@example.com:80?type=ws#old"
        new_vmess = vmess_config()
        previous = [metric(existing)]
        current = [
            metric(existing.replace("#old", "#updated")),
            metric(new_vmess, host="vmess.example.com"),
        ]

        added = find_new_servers(current, previous)
        self.assertEqual(len(added), 1)
        self.assertEqual(added[0]["protocol"], "vmess")


class MessageTests(unittest.TestCase):
    def test_messages_are_chunked_below_the_limit(self):
        servers = [
            {
                **metric(
                    f"vless://uuid{i}@example.com:80?type=ws&path=%2Fsome-long-path-{i}",
                    latency=20 + i,
                ),
                "protocol": "vless",
            }
            for i in range(8)
        ]
        messages = build_messages(servers, max_length=500)
        self.assertGreater(len(messages), 1)
        for message in messages:
            self.assertLessEqual(len(message.encode("utf-16-le")) // 2, 500)
        self.assertTrue(all("vless://" in message for message in messages))

    def test_empty_server_list_produces_no_messages(self):
        self.assertEqual(build_messages([]), [])


class TelegramTests(unittest.TestCase):
    @patch("telegram_notify.requests.post")
    def test_sends_plain_text_with_preview_disabled(self, post):
        response = Mock()
        response.json.return_value = {"ok": True}
        post.return_value = response

        count = send_telegram_messages("bot-token", "12345", ["hello"])
        self.assertEqual(count, 1)
        post.assert_called_once()
        self.assertEqual(post.call_args.kwargs["json"]["chat_id"], "12345")
        self.assertEqual(post.call_args.kwargs["json"]["text"], "hello")
        self.assertTrue(post.call_args.kwargs["json"]["disable_web_page_preview"])

    @patch("telegram_notify.requests.post")
    def test_delivery_errors_never_include_the_bot_token(self, post):
        token = "123456:secret-token"
        post.side_effect = requests.RequestException(
            f"request failed at https://api.telegram.org/bot{token}/sendMessage"
        )

        with self.assertRaises(RuntimeError) as raised:
            send_telegram_messages(token, "12345", ["hello"])
        self.assertNotIn(token, str(raised.exception))


if __name__ == "__main__":
    unittest.main()
