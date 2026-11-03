import base64
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import requests

from telegram_notify import (
    build_message_batches,
    build_messages,
    load_notification_state,
    matching_servers,
    notify_new_servers,
    send_telegram_message,
    _state_key,
)


def vmess_config(port=80, net="ws", remark="name"):
    payload = {
        "v": "2", "ps": remark, "add": "vmess.example.com", "port": str(port),
        "id": "11111111-1111-1111-1111-111111111111", "net": net,
        "tls": "", "path": "/ws", "host": "cdn.example.com",
    }
    return "vmess://" + base64.b64encode(json.dumps(payload).encode()).decode()


def metric(config, port=80, latency=50, host="example.com"):
    return {
        "host": host, "port": port, "latency_ms": latency,
        "country": "Test Country", "country_code": "TC", "config": config,
    }


class MatchingTests(unittest.TestCase):
    def test_only_port_80_vless_and_vmess_websocket_are_selected(self):
        rows = [
            metric(vmess_config(), latency=60, host="vmess.example.com"),
            metric("vless://uuid@example.com:80?type=ws&path=%2Fws#vless", latency=30),
            metric("vless://uuid@example.com:443?type=ws", port=443),
            metric("vless://uuid@example.com:80?type=tcp"),
            metric(vmess_config(net="tcp"), host="vmess.example.com"),
            metric("trojan://password@example.com:80?type=ws"),
        ]
        selected = matching_servers(rows)
        self.assertEqual([s["protocol"] for s in selected], ["vless", "vmess"])
        self.assertEqual([s["latency_ms"] for s in selected], [30, 60])

    def test_vless_accepts_network_ws_alias(self):
        self.assertEqual(
            len(matching_servers([metric("vless://uuid@example.com:80?network=ws")])),
            1,
        )

    def test_metrics_port_must_match_uri_port(self):
        self.assertEqual(
            matching_servers([metric("vless://uuid@example.com:80?type=ws", port=8080)]),
            [],
        )

    def test_duplicates_ignore_uri_remarks(self):
        rows = [
            metric("vless://uuid@example.com:80?type=ws#first"),
            metric("vless://uuid@example.com:80?type=ws#second"),
        ]
        self.assertEqual(len(matching_servers(rows)), 1)

    def test_vmess_state_key_ignores_display_name(self):
        self.assertEqual(
            _state_key(vmess_config(remark="old")),
            _state_key(vmess_config(remark="new")),
        )


class MessageTests(unittest.TestCase):
    def test_messages_are_chunked_below_the_limit(self):
        servers = [
            {**metric(f"vless://uuid{i}@example.com:80?type=ws&path=%2Fpath-{i}", latency=20+i),
             "protocol": "vless"}
            for i in range(8)
        ]
        messages = build_messages(servers, max_length=500)
        self.assertGreater(len(messages), 1)
        for message in messages:
            self.assertLessEqual(len(message.encode("utf-16-le")) // 2, 500)
        self.assertTrue(all("vless://" in message for message in messages))

    def test_batches_keep_their_server_records(self):
        servers = [
            {**metric(f"vless://uuid{i}@example.com:80?type=ws"), "protocol": "vless"}
            for i in range(2)
        ]
        self.assertEqual(sum(len(records) for _, records in build_message_batches(servers)), 2)

    def test_empty_input_has_no_messages(self):
        self.assertEqual(build_messages([]), [])


class StateAndDeliveryTests(unittest.TestCase):
    def test_successfully_notified_server_is_not_sent_again(self):
        config = "vless://uuid@example.com:80?type=ws#first"
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "telegram-notified.json"
            with patch("telegram_notify.send_telegram_message") as send:
                pending, skipped = notify_new_servers([metric(config)], state_path, "token", "123")
                self.assertEqual((pending, skipped), (1, False))
                pending, skipped = notify_new_servers(
                    [metric(config.replace("#first", "#updated"))],
                    state_path, "token", "123",
                )
                self.assertEqual((pending, skipped), (0, False))
                send.assert_called_once()
            self.assertEqual(load_notification_state(state_path), {_state_key(config)})

    def test_missing_secrets_do_not_mark_new_servers_as_sent(self):
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "telegram-notified.json"
            pending, skipped = notify_new_servers(
                [metric("vless://uuid@example.com:80?type=ws")], state_path
            )
            self.assertEqual((pending, skipped), (1, True))
            self.assertEqual(load_notification_state(state_path), set())

    def test_partial_delivery_checkpoints_only_successful_messages(self):
        rows = [
            metric("vless://uuid1@example.com:80?type=ws"),
            metric("vless://uuid2@example.com:80?type=ws"),
        ]
        records = [{**row, "protocol": "vless"} for row in rows]
        fake_batches = [("first", [records[0]]), ("second", [records[1]])]
        with tempfile.TemporaryDirectory() as directory:
            state_path = Path(directory) / "telegram-notified.json"
            with patch("telegram_notify.build_message_batches", return_value=fake_batches):
                with patch("telegram_notify.send_telegram_message", side_effect=[None, RuntimeError("send failed")]):
                    with self.assertRaises(RuntimeError):
                        notify_new_servers(rows, state_path, "token", "123")
            self.assertEqual(
                load_notification_state(state_path),
                {_state_key(rows[0]["config"])},
            )

    @patch("telegram_notify.requests.post")
    def test_send_uses_plain_text_and_disables_preview(self, post):
        response = Mock()
        response.json.return_value = {"ok": True}
        post.return_value = response
        send_telegram_message("bot-token", "12345", "hello")
        post.assert_called_once()
        self.assertEqual(post.call_args.kwargs["json"]["chat_id"], "12345")
        self.assertEqual(post.call_args.kwargs["json"]["text"], "hello")
        self.assertTrue(post.call_args.kwargs["json"]["disable_web_page_preview"])

    @patch("telegram_notify.requests.post")
    def test_delivery_error_does_not_expose_bot_token(self, post):
        token = "123456:secret-token"
        post.side_effect = requests.RequestException(f"failed URL https://api.telegram.org/bot{token}/sendMessage")
        with self.assertRaises(RuntimeError) as raised:
            send_telegram_message(token, "12345", "hello")
        self.assertNotIn(token, str(raised.exception))


if __name__ == "__main__":
    unittest.main()
