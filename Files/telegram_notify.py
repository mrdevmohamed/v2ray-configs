#!/usr/bin/env python3
"""Send new port-80 VLESS/VMess WebSocket servers to Telegram."""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import html
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
        value = json.loads(base64.b64decode(payload, validate=True).decode("utf-8"))
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
        query = {key.lower(): values for key, values in urllib.parse.parse_qs(
            parsed.query, keep_blank_values=True
        ).items()}
        values = query.get("type") or query.get("network") or []
        transport = str(values[0] if values else "tcp").strip().lower()

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


def _state_key(config: str) -> str:
    """Store a digest rather than a URI containing credentials."""
    return hashlib.sha256(_config_identity(config).encode("utf-8")).hexdigest()


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
        if protocol not in {"vless", "vmess"} or transport != "ws":
            continue
        if uri_port != 80 or metric_port != 80:
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

    order = {"vless": 0, "vmess": 1}

    def sort_key(server: dict[str, Any]) -> tuple[Any, ...]:
        try:
            latency = float(server.get("latency_ms"))
        except (TypeError, ValueError):
            latency = float("inf")
        return (
            order[server["protocol"]],
            latency,
            str(server.get("country_code") or "XX"),
            str(server.get("host") or ""),
        )

    return sorted(selected, key=sort_key)


def load_notification_state(path: str | Path) -> set[str]:
    state_path = Path(path)
    if not state_path.is_file():
        return set()
    with state_path.open(encoding="utf-8") as stream:
        payload = json.load(stream)
    if (
        not isinstance(payload, dict)
        or payload.get("version") != 1
        or not isinstance(payload.get("notified"), list)
        or any(not isinstance(value, str) for value in payload["notified"])
    ):
        raise ValueError(f"invalid Telegram notification state: {state_path}")
    return set(payload["notified"])


def write_notification_state(path: str | Path, notified: set[str]) -> None:
    """Atomically save fingerprints of successfully delivered configs."""
    state_path = Path(path)
    state_path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = state_path.with_name(state_path.name + ".tmp")
    with temporary_path.open("w", encoding="utf-8", newline="\n") as stream:
        json.dump(
            {"version": 1, "notified": sorted(notified)},
            stream,
            ensure_ascii=True,
            indent=2,
        )
        stream.write("\n")
    os.replace(temporary_path, state_path)


def _telegram_length(value: str) -> int:
    return len(value.encode("utf-16-le")) // 2


def _html_text(value: Any) -> str:
    """Escape dynamic server metadata and URI text for Telegram HTML mode."""
    return html.escape(str(value), quote=False).replace("\r", " ").replace("\n", " ")


def _server_block(server: dict[str, Any], number: int) -> str:
    country = _html_text(server.get("country") or "Unknown")
    code = _html_text(server.get("country_code") or "XX")
    host = _html_text(server.get("host") or "unknown")
    try:
        latency = f"{float(server.get('latency_ms')):.1f} ms"
    except (TypeError, ValueError):
        latency = "latency unavailable"
    config = _html_text(server["config"])
    return (
        f"<b>{number}. {country} [{code}]</b>\n"
        f"<code>{host}:80</code>  |  <b>{latency}</b>\n"
        f"<code>{config}</code>\n"
    )


def _message_header() -> str:
    return (
        "<b>🛰️ New WebSocket Servers</b>\n"
        "<code>Port 80</code>  |  <b>VLESS + VMess</b>\n"
        "<i>Validated configurations, sorted by latency</i>\n"
    )


def build_message_batches(
    servers: list[dict[str, Any]], max_length: int = MESSAGE_LIMIT
) -> list[tuple[str, list[dict[str, Any]]]]:
    """Build Telegram HTML messages and retain each message's server records."""
    if not servers:
        return []
    if max_length <= _telegram_length(_message_header()) + 80:
        raise ValueError("message limit is too small")

    grouped = {
        protocol: [server for server in servers if server.get("protocol") == protocol]
        for protocol in ("vless", "vmess")
    }
    batches: list[tuple[str, list[dict[str, Any]]]] = []
    current = _message_header()
    current_protocol: str | None = None
    current_servers: list[dict[str, Any]] = []

    for protocol in ("vless", "vmess"):
        group = grouped[protocol]
        for index, server in enumerate(group, start=1):
            section = (
                f"\n<b>{protocol.upper()} • {len(group)} server(s)</b>\n"
                if current_protocol != protocol else ""
            )
            block = _server_block(server, index)
            if _telegram_length(current + section + block) > max_length:
                if not current_servers:
                    raise ValueError("a single server entry exceeds Telegram's message limit")
                batches.append((current.rstrip(), current_servers))
                current = _message_header()
                current_protocol = None
                current_servers = []
                section = f"\n<b>{protocol.upper()} • continued</b>\n"
            if _telegram_length(current + section + block) > max_length:
                raise ValueError("a single server entry exceeds Telegram's message limit")
            current += section + block
            current_protocol = protocol
            current_servers.append(server)

    if current_servers:
        batches.append((current.rstrip(), current_servers))
    return batches


def build_messages(
    servers: list[dict[str, Any]], max_length: int = MESSAGE_LIMIT
) -> list[str]:
    return [message for message, _ in build_message_batches(servers, max_length)]


def send_telegram_message(
    bot_token: str, chat_id: str, message: str, index: int = 1, total: int = 1
) -> None:
    """Send one message without exposing the bot token in raised errors."""
    url = f"{TELEGRAM_API}/bot{bot_token}/sendMessage"
    try:
        response = requests.post(
            url,
            json={
                "chat_id": chat_id,
                "text": message,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
            },
            timeout=20,
        )
        response.raise_for_status()
        payload = response.json()
    except (requests.RequestException, ValueError, AttributeError):
        raise RuntimeError(f"Telegram delivery failed for message {index}/{total}.") from None
    if not isinstance(payload, dict) or payload.get("ok") is not True:
        error_code = payload.get("error_code") if isinstance(payload, dict) else None
        suffix = f" (API error {error_code})" if error_code else ""
        raise RuntimeError(f"Telegram rejected message {index}/{total}{suffix}.")


def notify_new_servers(
    metrics: list[dict[str, Any]],
    state_path: str | Path,
    bot_token: str = "",
    chat_id: str = "",
) -> tuple[int, bool]:
    """Send only unnotified matches and checkpoint after every successful message."""
    current = matching_servers(metrics)
    current_keys = {_state_key(server["config"]) for server in current}
    previously_notified = load_notification_state(state_path)
    active_notified = previously_notified.intersection(current_keys)
    pending = [server for server in current if _state_key(server["config"]) not in active_notified]

    if not pending:
        if active_notified != previously_notified:
            write_notification_state(state_path, active_notified)
        return 0, False

    if not bot_token or not chat_id:
        if active_notified != previously_notified:
            write_notification_state(state_path, active_notified)
        return len(pending), True

    batches = build_message_batches(pending)
    for index, (message, batch_servers) in enumerate(batches, start=1):
        send_telegram_message(bot_token, chat_id, message, index, len(batches))
        active_notified.update(_state_key(server["config"]) for server in batch_servers)
        write_notification_state(state_path, active_notified)

    return len(pending), False


def _read_metrics(path: str | Path) -> list[dict[str, Any]]:
    with open(path, encoding="utf-8") as stream:
        payload = json.load(stream)
    if not isinstance(payload, list):
        raise ValueError(f"metrics file must contain a JSON array: {path}")
    return payload


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--metrics", default="server-metrics.json")
    parser.add_argument("--state", default=".github/telegram-notified.json")
    args = parser.parse_args(argv)

    try:
        metrics = _read_metrics(args.metrics)
        pending, skipped = notify_new_servers(
            metrics,
            args.state,
            os.environ.get("TELEGRAM_BOT_TOKEN", "").strip(),
            os.environ.get("TELEGRAM_CHAT_ID", "").strip(),
        )
        if pending == 0:
            print("Telegram: no new port-80 VLESS/VMess WebSocket servers.")
        elif skipped:
            print(
                f"Telegram skipped: {pending} matching server(s), but "
                "TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID are not configured."
            )
        else:
            print(f"Telegram: sent {pending} new port-80 VLESS/VMess WebSocket server(s).")
        return 0
    except (OSError, json.JSONDecodeError, ValueError, RuntimeError) as exc:
        print(f"Telegram notification error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
