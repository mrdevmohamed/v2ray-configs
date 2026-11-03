#!/usr/bin/env python3
"""Send newly discovered port-80 VLESS/VMess WebSocket servers to Telegram."""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import sys
import urllib.parse
from pathlib import Path
from typing import Any

import requests

TELEGRAM_API = "https://api.telegram.org"
MESSAGE_LIMIT = 3900
MESSAGE_TITLE = "New port-80 WebSocket servers (VLESS / VMess)"


def _decode_vmess(config: str) -> dict[str, Any]:
    payload = config.split("://", 1)[1].split("#", 1)[0].strip()
    payload = urllib.parse.unquote(payload).replace("-", "+").replace("_", "/")
    payload += "=" * (-len(payload) % 4)
    try:
        decoded = base64.b64decode(payload, validate=True).decode("utf-8")
        value = json.loads(decoded)
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ValueError("invalid VMess payload") from exc
    if not isinstance(value, dict):
        raise ValueError("VMess payload must be a JSON object")
    return value


def _config_details(config: str) -> tuple[str, str, str, int]:
    scheme, separator, _ = config.partition("://")
    protocol = scheme.lower()
    if not separator or protocol not in {"vless", "vmess"}:
        raise ValueError("unsupported protocol")

    if protocol == "vmess":
        payload = _decode_vmess(config)
        host = str(payload.get("add") or "")
        try:
            port = int(payload.get("port"))
        except (TypeError, ValueError):
            raise ValueError("invalid VMess port") from None
        transport = str(payload.get("net") or "tcp").strip().lower()
    else:
        parsed = urllib.parse.urlsplit(config)
        host = parsed.hostname or ""
        try:
            port = parsed.port
        except ValueError:
            raise ValueError("invalid VLESS port") from None
        if port is None:
            raise ValueError("missing VLESS port")
        query = {
            key.lower(): values
            for key, values in urllib.parse.parse_qs(
                parsed.query, keep_blank_values=True
            ).items()
        }
        transport_values = query.get("type") or query.get("network") or []
        transport = str(
            transport_values[0] if transport_values else "tcp"
        ).strip().lower()

    if not host or not 1 <= port <= 65535:
        raise ValueError("invalid server endpoint")
    return protocol, transport, host, port


def _config_identity(config: str) -> str:
    """Ignore URI fragments and the VMess display name when deduplicating."""
    try:
        protocol, _, _, _ = _config_details(config)
        if protocol == "vmess":
            payload = _decode_vmess(config)
            payload.pop("ps", None)
            return "vmess://" + json.dumps(
                payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            )
        parsed = urllib.parse.urlsplit(config)
        return urllib.parse.urlunsplit(
            (protocol, parsed.netloc, parsed.path, parsed.query, "")
        )
    except (ValueError, TypeError, KeyError):
        return config.strip().split("#", 1)[0]


def matching_servers(metrics: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Select only port-80 VLESS/VMess servers using WebSocket transport."""
    selected: list[dict[str, Any]] = []
    seen: set[str] = set()

    for item in metrics:
        if not isinstance(item, dict):
            continue
        config = item.get("config")
        if not isinstance(config, str) or not config.strip():
            continue
        try:
            protocol, transport, host, uri_port = _config_details(config)
            metric_port = int(item.get("port", uri_port))
        except (TypeError, ValueError):
            continue

        if protocol not in {"vless", "vmess"}:
            continue
        if transport != "ws" or uri_port != 80 or metric_port != 80:
            continue

        identity = _config_identity(config)
        if identity in seen:
            continue
        seen.add(identity)

        server = dict(item)
        server["protocol"] = protocol
        server["host"] = str(item.get("host") or host)
        server["port"] = 80
        selected.append(server)

    protocol_order = {"vless": 0, "vmess": 1}

    def sort_key(server: dict[str, Any]) -> tuple[Any, ...]:
        try:
            latency = float(server.get("latency_ms"))
        except (TypeError, ValueError):
            latency = float("inf")
        return (
            protocol_order[server["protocol"]],
            latency,
            str(server.get("country_code") or "XX"),
            str(server.get("host") or ""),
        )

    return sorted(selected, key=sort_key)


def find_new_servers(
    current_metrics: list[dict[str, Any]],
    previous_metrics: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return matching configs not present in the previous metrics snapshot."""
    previous_ids = {
        _config_identity(server["config"])
        for server in matching_servers(previous_metrics)
    }
    return [
        server
        for server in matching_servers(current_metrics)
        if _config_identity(server["config"]) not in previous_ids
    ]


def _telegram_length(value: str) -> int:
    return len(value.encode("utf-16-le")) // 2


def _server_block(server: dict[str, Any]) -> str:
    country = str(server.get("country") or "Unknown").replace("\r", " ").replace("\n", " ")
    country_code = str(server.get("country_code") or "XX").replace("\r", " ").replace("\n", " ")
    host = str(server.get("host") or "unknown").replace("\r", " ").replace("\n", " ")
    try:
        latency = f"{float(server.get('latency_ms')):.1f} ms"
    except (TypeError, ValueError):
        latency = "latency unavailable"
    config = str(server["config"]).replace("\r", " ").replace("\n", " ")
    return f"{country} [{country_code}] | {host}:80 | {latency}\n{config}\n"


def build_messages(
    servers: list[dict[str, Any]], max_length: int = MESSAGE_LIMIT
) -> list[str]:
    """Build Telegram-safe messages without splitting a configuration URI."""
    if not servers:
        return []
    if max_length <= _telegram_length(MESSAGE_TITLE) + 80:
        raise ValueError("message limit is too small")

    grouped = {
        protocol: [server for server in servers if server.get("protocol") == protocol]
        for protocol in ("vless", "vmess")
    }
    messages: list[str] = []
    current = MESSAGE_TITLE
    current_protocol: str | None = None

    for protocol in ("vless", "vmess"):
        group = grouped[protocol]
        for server in group:
            section = ""
            if current_protocol != protocol:
                section = f"\n{protocol.upper()} ({len(group)})\n"
            block = _server_block(server)

            if _telegram_length(current + section + block) > max_length:
                if current == MESSAGE_TITLE:
                    raise ValueError("a single server entry exceeds Telegram's message limit")
                messages.append(current.rstrip())
                current = MESSAGE_TITLE
                current_protocol = None
                section = f"\n{protocol.upper()} ({len(group)}; continued)\n"

            if _telegram_length(current + section + block) > max_length:
                raise ValueError("a single server entry exceeds Telegram's message limit")

            current += section + block
            current_protocol = protocol

    if current != MESSAGE_TITLE:
        messages.append(current.rstrip())
    return messages


def send_telegram_messages(
    bot_token: str, chat_id: str, messages: list[str], timeout: int = 20
) -> int:
    """Send messages without exposing the bot token in raised errors."""
    for index, message in enumerate(messages, start=1):
        url = f"{TELEGRAM_API}/bot{bot_token}/sendMessage"
        try:
            response = requests.post(
                url,
                json={
                    "chat_id": chat_id,
                    "text": message,
                    "disable_web_page_preview": True,
                },
                timeout=timeout,
            )
            response.raise_for_status()
            payload = response.json()
        except (requests.RequestException, ValueError, AttributeError):
            raise RuntimeError(
                f"Telegram delivery failed for message {index}/{len(messages)}."
            ) from None

        if not isinstance(payload, dict) or payload.get("ok") is not True:
            error_code = payload.get("error_code") if isinstance(payload, dict) else None
            suffix = f" (API error {error_code})" if error_code else ""
            raise RuntimeError(
                f"Telegram rejected message {index}/{len(messages)}{suffix}."
            )
    return len(messages)


def _read_metrics(path: str | Path) -> list[dict[str, Any]]:
    with open(path, encoding="utf-8") as stream:
        payload = json.load(stream)
    if not isinstance(payload, list):
        raise ValueError(f"metrics file must contain a JSON array: {path}")
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metrics", default="server-metrics.json")
    parser.add_argument("--previous", help="metrics snapshot from before this run")
    args = parser.parse_args(argv)

    try:
        current_metrics = _read_metrics(args.metrics)
        previous_metrics = (
            _read_metrics(args.previous)
            if args.previous and Path(args.previous).is_file()
            else []
        )
        new_servers = find_new_servers(current_metrics, previous_metrics)

        if not new_servers:
            print("Telegram: no new port-80 VLESS/VMess WebSocket servers.")
            return 0

        bot_token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
        chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
        if not bot_token or not chat_id:
            print(
                f"Telegram notification skipped: found {len(new_servers)} matching "
                "server(s), but TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID are not configured."
            )
            return 0

        messages = build_messages(new_servers)
        sent = send_telegram_messages(bot_token, chat_id, messages)
        print(
            f"Telegram: sent {len(new_servers)} new port-80 VLESS/VMess "
            f"WebSocket server(s) in {sent} message(s)."
        )
        return 0
    except (OSError, json.JSONDecodeError, ValueError, RuntimeError) as exc:
        print(f"Telegram notification error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
