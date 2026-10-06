"""Collect public V2Ray/Xray/sing-box subscription sources, validate the configs
through a real proxy connection, and publish merged / split / per-country files.

External requirements (only needed when the health check is enabled):
    * ``sing-box``  (env SING_BOX_BINARY, or on PATH)
    * ``xray``      (env XRAY_BINARY, or on PATH) - only for XHTTP / REALITY configs
    * ``curl``      (on PATH)

Environment variables:
    HEALTH_CHECK=0                      skip validation and just merge/rename
    PROTOCOL_TEST_TIMEOUT / _WORKERS    per-config timeout (s) / parallel tests
    PROTOCOL_VALIDATION_MAX_RUNTIME     global validation budget (s)
    PROTOCOL_STARTUP_TIMEOUT            time allowed for an engine to open its port
    PROTOCOL_TEST_URL                   URL fetched through each proxy
"""

import base64
import binascii
import json
import os
import re
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.parse
from collections import Counter
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from contextlib import contextmanager
from pathlib import Path

import pybase64
import requests


def _env_int(*names, default):
    """First valid integer among the given env vars, else ``default``."""
    for name in names:
        raw = os.environ.get(name)
        if raw:
            try:
                return int(raw)
            except ValueError:
                print(f"WARNING: ignoring non-integer {name}={raw!r}")
    return default


# --- HTTP / source fetching -------------------------------------------------
TIMEOUT = 15  # seconds, per HTTP request
MAX_SOURCE_BYTES = 10 * 1024 * 1024
FETCH_ATTEMPTS = 3
SOURCE_FETCH_WORKERS = 8
MIN_CONFIGS_EXPECTED = 1

# --- Validation -------------------------------------------------------------
HEALTH_CHECK_ENABLED = os.environ.get("HEALTH_CHECK", "1").strip().lower() not in {"0", "false", "no", "off"}
PROTOCOL_TEST_TIMEOUT = _env_int("PROTOCOL_VALIDATION_TIMEOUT", "PROTOCOL_TEST_TIMEOUT", default=8)
PROTOCOL_TEST_WORKERS = _env_int("PROTOCOL_VALIDATION_WORKERS", "PROTOCOL_TEST_WORKERS", default=32)
PROTOCOL_VALIDATION_MAX_RUNTIME = _env_int("PROTOCOL_VALIDATION_MAX_RUNTIME", default=900)
PROTOCOL_STARTUP_TIMEOUT = _env_int("PROTOCOL_STARTUP_TIMEOUT", default=5)
PROTOCOL_TEST_URL = os.environ.get("PROTOCOL_TEST_URL", "https://www.gstatic.com/generate_204")
SING_BOX_BINARY = os.environ.get("SING_BOX_BINARY") or shutil.which("sing-box") or ""
XRAY_BINARY = os.environ.get("XRAY_BINARY") or shutil.which("xray") or ""
CURL_BINARY = shutil.which("curl") or ""
MIN_HEALTHY_CONFIGS_EXPECTED = 1

# --- GeoIP ------------------------------------------------------------------
GEOIP_BATCH_SIZE = 100
GEOIP_DNS_WORKERS = 16

# --- Branding / output ------------------------------------------------------
BRAND = "mrdevmohamed"
SUPPORT_URL = f"https://github.com/{BRAND}/v2ray-configs"
MAX_CONFIGS_PER_FILE = 1000

# NOTE: these are cosmetic values shown by some clients (traffic used / quota /
# expiry). They are not real usage numbers.
SUBSCRIPTION_USERINFO = "upload=29; download=12; total=10737418240000000; expire=2546249531"

fixed_text = f"#{BRAND}\n"

PROTOCOLS = ["vmess", "vless", "trojan", "ss", "ssr", "hy2", "hysteria2", "tuic", "warp://"]

# Each source may be plain text or base64; the format is auto-detected.
SOURCES = [
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/app/sub.txt",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mtn/sub_1.txt",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mtn/sub_2.txt",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mtn/sub_3.txt",
    "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mtn/sub_4.txt",
    "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/mixed",
    "https://raw.githubusercontent.com/itsyebekhe/PSG/main/subscriptions/xray/mix",
    "https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/refs/heads/main/mix/sub.html",
    "https://raw.githubusercontent.com/Rayan-Config/C-Sub/refs/heads/main/configs/proxy.txt",
    "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.txt",
   "https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Configs_base64_Sub.txt",
   "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/V2Ray-Config-By-EbraSha-All-Type.txt",
   "https://github.com/Delta-Kronecker/V2ray-Config/raw/refs/heads/main/config/all_configs.txt"
]

_URI_LINE = re.compile(r"^\s*(?:vmess|vless|trojan|ssr?|tuic|hy2|hysteria2?|warp)://", re.IGNORECASE | re.MULTILINE)
_B64_URLSAFE_TO_STD = bytes.maketrans(b"-_", b"+/")


# ---------------------------------------------------------------------------
# Base64 helpers
# ---------------------------------------------------------------------------
def _b64decode_loose(value):
    """Decode standard or URL-safe base64 with optional/missing padding.

    Raises ``ValueError`` (binascii.Error is a subclass) on invalid input
    instead of silently dropping bad characters.
    """
    value = urllib.parse.unquote(value.strip()).replace("-", "+").replace("_", "/").rstrip("=")
    value += "=" * (-len(value) % 4)
    return base64.b64decode(value, validate=True)


def decode_base64(encoded):
    """Decode a base64 subscription body. Returns "" unless it looks like URI text."""
    if isinstance(encoded, str):
        encoded = encoded.encode("utf-8")
    cleaned = re.sub(rb"\s+", b"", encoded or b"")
    if not cleaned:
        return ""
    cleaned = cleaned.translate(_B64_URLSAFE_TO_STD).rstrip(b"=")
    cleaned += b"=" * (-len(cleaned) % 4)
    try:
        decoded = pybase64.b64decode(cleaned).decode("utf-8")  # strict UTF-8
    except (UnicodeDecodeError, binascii.Error, ValueError):
        return ""
    if "://" not in decoded:
        return ""
    allowed = sum(1 for c in decoded if c.isprintable() or c in "\n\r\t")
    if allowed / len(decoded) < 0.95:
        return ""
    return decoded


# ---------------------------------------------------------------------------
# Fetching
# ---------------------------------------------------------------------------
def _download(url):
    """Return the body of ``url`` as bytes, or None (after a warning) on failure."""
    last_error = None
    for attempt in range(1, FETCH_ATTEMPTS + 1):
        try:
            with requests.get(url, timeout=TIMEOUT, stream=True) as response:
                response.raise_for_status()
                declared = response.headers.get("Content-Length", "")
                if declared.isdigit() and int(declared) > MAX_SOURCE_BYTES:
                    print(f"WARNING: source too large, skipping {url}")
                    return None
                chunks, total = [], 0
                for chunk in response.iter_content(chunk_size=65536):
                    total += len(chunk)
                    if total > MAX_SOURCE_BYTES:
                        print(f"WARNING: source too large, skipping {url}")
                        return None
                    chunks.append(chunk)
                return b"".join(chunks)
        except requests.RequestException as exc:
            last_error = exc
            status = getattr(getattr(exc, "response", None), "status_code", None)
            if status is not None and status < 500:
                break  # 4xx will not fix itself
            if attempt < FETCH_ATTEMPTS:
                time.sleep(attempt)
    print(f"WARNING: failed to fetch {url}: {last_error}")
    return None


def _load_source(url):
    """Fetch one source and return its text (plain or base64-decoded), or ""."""
    raw = _download(url)
    if raw is None:
        return ""
    text = raw.decode("utf-8-sig", errors="replace")
    if _URI_LINE.search(text):
        return text
    decoded = decode_base64(raw)
    if not decoded:
        print(f"WARNING: no supported configs found, skipping {url}")
    return decoded


def fetch_sources(urls):
    """Fetch all sources in parallel; order is preserved, failures are dropped."""
    urls = list(urls)
    if not urls:
        return []
    with ThreadPoolExecutor(max_workers=min(SOURCE_FETCH_WORKERS, len(urls))) as executor:
        return [text for text in executor.map(_load_source, urls) if text]


# Backwards-compatible names (both formats are now auto-detected).
decode_links = fetch_sources
decode_dir_links = fetch_sources


# ---------------------------------------------------------------------------
# Filtering / de-duplication
# ---------------------------------------------------------------------------
def filter_for_protocols(data, protocols):
    # Build case-insensitive "protocol://" prefixes ("warp://" already has suffix)
    prefixes = tuple((p if p.endswith("://") else p + "://").lower() for p in protocols)
    filtered_data = []
    seen_configs = set()
    seen_comments = set()
    garbage_count = 0

    for content in data:
        if not content or not content.strip():
            continue
        # split("\n"), not splitlines(): splitlines() also breaks on U+2028, \x0b, \x85...
        # which can appear inside a remark and would cut a config in half.
        for raw_line in content.split("\n"):
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith("#"):
                if not all(ord(c) >= 32 or c in "\t\r\n" for c in line):
                    garbage_count += 1
                    continue
                if line not in seen_comments:
                    seen_comments.add(line)
                    filtered_data.append(line)
                continue
            # Skip non-printable / binary lines
            if any(ord(c) < 32 or ord(c) == 127 for c in line):
                garbage_count += 1
                continue
            if "://" not in line or not line.lower().startswith(prefixes):
                garbage_count += 1
                continue
            dedupe_key = canonical_config_key(line)
            if dedupe_key not in seen_configs:
                filtered_data.append(line)
                seen_configs.add(dedupe_key)
    return filtered_data, garbage_count


def canonical_config_key(config_line):
    """Return a config identity without the human-readable remark."""
    line = config_line.strip()
    if line.startswith("#") or "://" not in line:
        return line

    scheme, _, rest = line.partition("://")
    scheme = scheme.lower()
    try:
        if scheme == "vmess":
            obj = _decode_vmess(line)
            # str() so port 443 and "443" produce the same key
            normalized = {k: str(v) for k, v in obj.items() if k != "ps"}
            return "vmess://" + json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        if scheme == "ssr":
            decoded = _b64decode_loose(rest.split("#", 1)[0]).decode("utf-8")
            decoded = re.sub(r"([?&]remarks=)[^&]*", r"\1", decoded)
            return "ssr://" + decoded

        parsed = urllib.parse.urlsplit(line)
        return urllib.parse.urlunsplit((scheme, parsed.netloc, parsed.path, parsed.query, ""))
    except (ValueError, UnicodeError, binascii.Error, AttributeError, TypeError):
        return line.split("#", 1)[0]


# ---------------------------------------------------------------------------
# URI parsing helpers
# ---------------------------------------------------------------------------
class UnsupportedProtocol(ValueError):
    """A config URI is intentionally outside the protocol validator's scope."""


def _query(parsed):
    return urllib.parse.parse_qs(parsed.query, keep_blank_values=True)


def _first(query, key, default=None):
    values = query.get(key)
    return values[0] if values else default


def _has_invalid_percent_escape(value):
    return bool(re.search(r"%(?![0-9A-Fa-f]{2})", value or ""))


def _parse_port(value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ValueError("invalid server port") from None
    if not 1 <= port <= 65535:
        raise ValueError("invalid server port")
    return port


def _uri_port(parsed):
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid server port") from exc
    return _parse_port(port)


def _decode_vmess(line):
    payload = line.split("://", 1)[1].split("#", 1)[0]
    obj = json.loads(_b64decode_loose(payload).decode("utf-8"))
    if not isinstance(obj, dict):
        raise ValueError("vmess payload is not a JSON object")
    return obj


def _parse_shadowsocks(line):
    """Parse SIP002 (``ss://base64(method:pw)@host:port``, or plain ``method:pw@``)
    and legacy (``ss://base64(method:pw@host:port)``) URIs.

    Returns ``(method, password, host, port, query)``.
    """
    body = line.split("://", 1)[1].split("#", 1)[0]
    main_part, _, raw_query = body.partition("?")
    query = urllib.parse.parse_qs(raw_query, keep_blank_values=True)
    parsed = urllib.parse.urlsplit("ss://" + main_part)

    if "@" in parsed.netloc:
        host = parsed.hostname
        port = _uri_port(parsed)
        userinfo = parsed.netloc.rpartition("@")[0]
        if ":" in userinfo:
            method, password = (urllib.parse.unquote(x) for x in userinfo.split(":", 1))
        else:
            try:
                decoded = _b64decode_loose(userinfo).decode("utf-8")
            except (UnicodeDecodeError, ValueError) as exc:
                raise ValueError("invalid Shadowsocks credentials encoding") from exc
            method, _, password = decoded.partition(":")
    else:  # legacy: everything is base64
        try:
            decoded = _b64decode_loose(main_part.rstrip("/")).decode("utf-8")
        except (UnicodeDecodeError, ValueError) as exc:
            raise ValueError("invalid Shadowsocks credentials encoding") from exc
        creds, at, hostport = decoded.rpartition("@")
        method, colon, password = creds.partition(":")
        host, colon2, port_text = hostport.rpartition(":")
        if not (at and colon and colon2):
            raise ValueError("invalid Shadowsocks credentials encoding")
        host = host.strip("[]")
        port = _parse_port(port_text)

    if not method or not host:
        raise ValueError("missing server or credentials")
    return method, password, host, port, query


def _endpoint(config_line):
    """Return ``(host, port)`` for any supported URI, including vmess/ss payloads."""
    line = config_line.strip()
    scheme = line.split("://", 1)[0].lower() if "://" in line else ""
    if scheme == "vmess":
        obj = _decode_vmess(line)
        return obj.get("add"), _parse_port(obj.get("port"))
    if scheme == "ss":
        _, _, host, port, _ = _parse_shadowsocks(line)
        return host, port
    parsed = urllib.parse.urlsplit(line)
    return parsed.hostname, _uri_port(parsed)


# ---------------------------------------------------------------------------
# sing-box / Xray config builders
# ---------------------------------------------------------------------------
def _tls_options(query):
    security = (_first(query, "security", "") or "").lower()
    if security == "none":
        return None
    if security not in {"tls", "reality"} and not _first(query, "sni"):
        return None
    tls = {"enabled": True}
    server_name = _first(query, "sni") or _first(query, "serverName")
    if server_name:
        tls["server_name"] = server_name
    if _first(query, "alpn"):
        tls["alpn"] = [x for x in _first(query, "alpn").split(",") if x]
    if _first(query, "fp"):
        tls["utls"] = {"enabled": True, "fingerprint": _first(query, "fp")}
    if security == "reality" or _first(query, "pbk"):
        tls["utls"] = tls.get("utls") or {"enabled": True, "fingerprint": "chrome"}
        reality = {"enabled": True}
        if _first(query, "pbk"):
            reality["public_key"] = _first(query, "pbk")
        if _first(query, "sid"):
            reality["short_id"] = _first(query, "sid")
        tls["reality"] = reality
    if _first(query, "insecure") in {"1", "true"} or _first(query, "allowInsecure") in {"1", "true"}:
        tls["insecure"] = True
    return tls


def _transport_options(query):
    transport = (_first(query, "type") or _first(query, "network") or "tcp").lower()
    if transport in {"tcp", "raw", "none"}:
        return None
    if transport == "ws":
        result = {"type": "ws"}
        if _first(query, "path"):
            result["path"] = _first(query, "path")
        if _first(query, "host"):
            result["headers"] = {"Host": _first(query, "host")}
        return result
    if transport in {"grpc", "gun"}:
        result = {"type": "grpc"}
        if _first(query, "serviceName"):
            result["service_name"] = _first(query, "serviceName")
        return result
    if transport in {"httpupgrade", "http-upgrade"}:
        result = {"type": "httpupgrade"}
        if _first(query, "path"):
            result["path"] = _first(query, "path")
        if _first(query, "host"):
            result["host"] = _first(query, "host")
        return result
    if transport == "xhttp":
        raise UnsupportedProtocol("xhttp requires the Xray transport engine")
    raise UnsupportedProtocol(f"unsupported transport: {transport}")


def _singbox_vmess_outbound(line):
    obj = _decode_vmess(line)
    host, port = _endpoint(line)
    uuid = obj.get("id")
    if not host or not uuid:
        raise ValueError("missing server or uuid")
    outbound = {"type": "vmess", "server": host, "server_port": port,
                "uuid": str(uuid), "security": obj.get("scy") or "auto"}
    try:
        alter_id = int(obj.get("aid") or 0)
    except (TypeError, ValueError):
        alter_id = 0
    if alter_id:
        outbound["alter_id"] = alter_id

    net = str(obj.get("net") or "tcp").lower()
    tls_on = str(obj.get("tls", "")).lower() in {"tls", "true", "1"}
    q = {"security": ["tls" if tls_on else "none"]}
    for key in ("sni", "alpn", "fp"):
        if obj.get(key):
            q[key] = [str(obj[key])]
    if tls_on and "sni" not in q and obj.get("host"):
        q["sni"] = [str(obj["host"])]
    if str(obj.get("allowInsecure", "")).lower() in {"1", "true"}:
        q["insecure"] = ["1"]

    if net == "tcp":
        if str(obj.get("type") or "none").lower() not in {"none", ""}:
            raise UnsupportedProtocol("vmess TCP header obfuscation is not supported")
    else:
        q["type"] = [net]
        if obj.get("path"):
            q["path"] = [str(obj["path"])]
        if obj.get("host"):
            q["host"] = [str(obj["host"])]
        if net == "grpc" and obj.get("path"):
            q["serviceName"] = [str(obj["path"]).lstrip("/")]

    tls = _tls_options(q)
    if tls:
        outbound["tls"] = tls
    transport_options = _transport_options(q)
    if transport_options:
        outbound["transport"] = transport_options
    return outbound


def _singbox_outbound(config_line):
    line = config_line.strip()
    scheme = line.split("://", 1)[0].lower() if "://" in line else ""
    if scheme in {"ssr", "warp"}:
        raise UnsupportedProtocol(f"{scheme.upper()} is unsupported by protocol validation")
    if scheme == "vmess":
        return _singbox_vmess_outbound(line)

    if scheme == "ss":
        method, password, host, port, query = _parse_shadowsocks(line)
        if _first(query, "plugin"):
            raise UnsupportedProtocol("Shadowsocks plugins are not supported by protocol validation")
        if method == "chacha20-poly1305":
            raise UnsupportedProtocol("legacy chacha20-poly1305 is not supported by sing-box; use chacha20-ietf-poly1305")
        return {"type": "shadowsocks", "server": host, "server_port": port,
                "method": method, "password": password}

    parsed = urllib.parse.urlsplit(line)
    query = _query(parsed)
    host = parsed.hostname
    port = _uri_port(parsed)

    if scheme in {"vless", "trojan"}:
        if not host or not parsed.username:
            raise ValueError("missing server or credentials")
        key = "uuid" if scheme == "vless" else "password"
        outbound = {"type": scheme, "server": host, "server_port": port,
                    key: urllib.parse.unquote(parsed.username)}
        if scheme == "vless":
            if (_first(query, "encryption", "none") or "none").lower() != "none":
                raise UnsupportedProtocol("VLESS encryption other than 'none' is not supported")
            flow = _first(query, "flow")
            if flow:
                if flow == "xtls-rprx-vision-udp443":
                    raise UnsupportedProtocol("sing-box does not support xtls-rprx-vision-udp443")
                outbound["flow"] = flow
        tls = _tls_options(query)
        if tls is None and scheme == "trojan" and (_first(query, "security", "") or "").lower() != "none":
            tls = {"enabled": True}  # Trojan is TLS by definition
        if tls:
            outbound["tls"] = tls
        transport = _transport_options(query)
        if transport:
            outbound["transport"] = transport
        return outbound

    if scheme in {"hy2", "hysteria2"}:
        if not host or not parsed.username:
            raise ValueError("missing server or password")
        # "user:pass@" is a single auth string for Hysteria2
        password = urllib.parse.unquote(parsed.username)
        if parsed.password:
            password += ":" + urllib.parse.unquote(parsed.password)
        outbound = {"type": "hysteria2", "server": host, "server_port": port, "password": password}
        outbound["tls"] = _tls_options(query) or {"enabled": True}
        if _first(query, "obfs") == "salamander":
            outbound["obfs"] = {"type": "salamander", "password": _first(query, "obfs-password", "")}
        return outbound

    if scheme == "tuic":
        if not host or not parsed.username:
            raise ValueError("missing server or credentials")
        outbound = {"type": "tuic", "server": host, "server_port": port,
                    "uuid": urllib.parse.unquote(parsed.username),
                    "password": urllib.parse.unquote(parsed.password or "")}
        for key in ("congestion_control", "udp_relay_mode"):
            if _first(query, key):
                outbound[key] = _first(query, key)
        outbound["tls"] = _tls_options(query) or {"enabled": True}
        return outbound

    raise UnsupportedProtocol(f"unsupported protocol: {scheme or 'unknown'}")


def _xray_xhttp_settings(query):
    """Build Xray's engine-specific XHTTP settings from a VLESS URI."""
    settings = {}
    extra = _first(query, "extra")
    if extra:
        try:
            parsed_extra = json.loads(urllib.parse.unquote(extra))
            if isinstance(parsed_extra, dict):
                settings.update(parsed_extra)
        except (TypeError, ValueError):
            pass  # malformed "extra" is ignored; the base settings still apply

    for key in ("host", "path", "mode"):
        value = _first(query, key)
        if value:
            settings[key] = value

    padding = _first(query, "x_padding_bytes") or _first(query, "xPaddingBytes")
    if padding:
        settings["xPaddingBytes"] = padding

    return settings


def _xray_outbound(config_line, socks_port):
    """Build an Xray config for transports/security unsupported by sing-box."""
    parsed = urllib.parse.urlsplit(config_line.strip())
    scheme = parsed.scheme.lower()
    query = _query(parsed)
    host = parsed.hostname
    port = _uri_port(parsed)
    if not host or not parsed.username:
        raise ValueError("missing server, port, or credentials")

    if scheme not in {"vless", "trojan"}:
        raise UnsupportedProtocol(f"Xray engine is only used for VLESS/Trojan, got {scheme or 'unknown'}")

    flow = _first(query, "flow")
    if scheme == "vless":
        user = {"id": urllib.parse.unquote(parsed.username), "encryption": "none"}
        if flow:
            user["flow"] = flow
        settings = {"vnext": [{"address": host, "port": port, "users": [user]}]}
    else:
        settings = {"servers": [{"address": host, "port": port,
                                  "password": urllib.parse.unquote(parsed.username)}]}

    network = (_first(query, "type") or _first(query, "network") or "tcp").lower()
    if network in {"raw", "none"}:
        network = "tcp"  # Xray has no "none" network
    stream = {
        "network": network,
        "security": (_first(query, "security") or "none").lower(),
    }
    security = stream["security"]
    server_name = _first(query, "sni") or _first(query, "serverName")
    alpn = _first(query, "alpn")
    fingerprint = _first(query, "fp") or "chrome"

    if security == "tls":
        tls = {"fingerprint": fingerprint}
        if server_name:
            tls["serverName"] = server_name
        if alpn:
            tls["alpn"] = [x for x in alpn.split(",") if x]
        if _first(query, "insecure") in {"1", "true"} or _first(query, "allowInsecure") in {"1", "true"}:
            tls["allowInsecure"] = True
        stream["tlsSettings"] = tls
    elif security == "reality":
        reality = {"fingerprint": fingerprint}
        if server_name:
            reality["serverName"] = server_name
        if _first(query, "pbk"):
            reality["publicKey"] = _first(query, "pbk")
        if _first(query, "sid"):
            reality["shortId"] = _first(query, "sid")
        if _first(query, "spiderX"):
            reality["spiderX"] = _first(query, "spiderX")
        stream["realitySettings"] = reality

    if network == "xhttp":
        stream["xhttpSettings"] = _xray_xhttp_settings(query)
    elif network == "ws":
        ws = {}
        if _first(query, "path"):
            ws["path"] = _first(query, "path")
        if _first(query, "host"):
            ws["headers"] = {"Host": _first(query, "host")}
        stream["wsSettings"] = ws
    elif network == "grpc":
        grpc = {}
        if _first(query, "serviceName"):
            grpc["serviceName"] = _first(query, "serviceName")
        elif _first(query, "path"):
            grpc["serviceName"] = _first(query, "path").lstrip("/")
        stream["grpcSettings"] = grpc
    elif network != "tcp":
        raise UnsupportedProtocol(f"unsupported Xray transport: {network}")

    if security == "reality" and network not in {"tcp", "grpc", "xhttp"}:
        raise UnsupportedProtocol("Xray REALITY supports only raw, grpc, or xhttp transports")

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": socks_port, "protocol": "socks",
                      "settings": {"udp": True}}],
        "outbounds": [{
            "protocol": scheme,
            "settings": settings,
            "streamSettings": stream,
        }],
    }


def _singbox_config(outbound, socks_port):
    outbound = dict(outbound)
    outbound["tag"] = "proxy"
    return {
        "log": {"disabled": True},
        "inbounds": [{"type": "socks", "tag": "validator-in", "listen": "127.0.0.1", "listen_port": socks_port}],
        "outbounds": [outbound],
        "route": {"final": "proxy"},
    }


# ---------------------------------------------------------------------------
# Real-connection validation
# ---------------------------------------------------------------------------
_PORT_LOCK = threading.Lock()
_RESERVED_PORTS = set()


def _free_local_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@contextmanager
def _reserved_local_port():
    """Yield a free local port that no other worker thread is currently using.

    Without this, two threads can be handed the same port (it is released before the
    engine binds it), and a test could end up measuring a *different* config's proxy.
    """
    with _PORT_LOCK:
        for _ in range(100):
            port = _free_local_port()
            if port not in _RESERVED_PORTS:
                _RESERVED_PORTS.add(port)
                break
        else:
            raise RuntimeError("could not find a free local port")
    try:
        yield port
    finally:
        with _PORT_LOCK:
            _RESERVED_PORTS.discard(port)


def _run_protocol_test(config_line):
    line = config_line.strip()
    scheme = line.split("://", 1)[0].lower() if "://" in line else ""
    if scheme in {"ssr", "warp"}:
        raise UnsupportedProtocol(f"{scheme.upper()} is unsupported by protocol validation")

    parsed = urllib.parse.urlsplit(line)
    # vmess/ss payloads are base64, not percent-encoded
    if scheme not in {"vmess", "ss"} and (
        _has_invalid_percent_escape(parsed.path) or _has_invalid_percent_escape(parsed.query)
    ):
        raise ValueError("invalid percent-escape in URI")
    host, port = _endpoint(line)  # raises ValueError on a bad/missing port
    if not host:
        raise ValueError("missing server host")

    query = {} if scheme == "vmess" else _query(parsed)
    transport = (_first(query, "type") or _first(query, "network") or "tcp").lower()
    security = (_first(query, "security") or "").lower()
    fingerprint = (_first(query, "fp") or "").lower()
    if fingerprint == "unsafe":
        raise UnsupportedProtocol("unsafe uTLS fingerprint is not supported by protocol validation")
    if transport == "http":
        raise UnsupportedProtocol("HTTP transport is not supported by the protocol validator")
    if transport == "tcp@soskeynets":
        raise UnsupportedProtocol("invalid tcp transport variant")
    if security == "reality" and not _first(query, "pbk"):
        raise UnsupportedProtocol("REALITY public key (pbk) is required")

    # Build the engine config first: every cheap/offline rejection happens before we
    # require any external binary.
    if transport == "xhttp" or security == "reality":
        engine, binary = "xray", XRAY_BINARY
        engine_config = _xray_outbound(line, 0)
        outbound = None
    else:
        engine, binary = "sing-box", SING_BOX_BINARY
        outbound = _singbox_outbound(line)
        engine_config = None

    if not binary:
        raise RuntimeError(f"{engine} is not available")
    if not CURL_BINARY:
        raise RuntimeError("curl is not available")

    with _reserved_local_port() as socks_port, tempfile.TemporaryDirectory(prefix="protocol-test-") as temp_dir:
        if engine == "xray":
            config = engine_config
            config["inbounds"][0]["port"] = socks_port
        else:
            config = _singbox_config(outbound, socks_port)
        config_path = Path(temp_dir) / "config.json"
        config_path.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")
        stderr_path = Path(temp_dir) / "engine.stderr"  # a file, not a pipe: a full pipe would block the engine
        process = None
        try:
            with open(stderr_path, "wb") as stderr_file:
                process = subprocess.Popen(
                    [binary, "run", "-c", str(config_path)], cwd=temp_dir,
                    stdout=subprocess.DEVNULL, stderr=stderr_file, start_new_session=True,
                )
            deadline = time.monotonic() + PROTOCOL_STARTUP_TIMEOUT
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    tail = stderr_path.read_text(encoding="utf-8", errors="replace")[-1000:]
                    raise RuntimeError(f"{engine} exited during startup: {tail}")
                try:
                    with socket.create_connection(("127.0.0.1", socks_port), timeout=0.1):
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                raise RuntimeError(f"{engine} local SOCKS inbound did not start")
            if process.poll() is not None:  # port answered, but not because of *our* process
                raise RuntimeError(f"{engine} exited right after startup")

            started = time.perf_counter()
            curl = subprocess.run(
                [CURL_BINARY, "--silent", "--show-error", "--fail",
                 "--socks5-hostname", f"127.0.0.1:{socks_port}",
                 "--connect-timeout", str(PROTOCOL_TEST_TIMEOUT), "--max-time", str(PROTOCOL_TEST_TIMEOUT),
                 "-o", "/dev/null", "-w", "%{http_code}", PROTOCOL_TEST_URL],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                timeout=PROTOCOL_TEST_TIMEOUT + 2, check=False,
            )
            latency_ms = round((time.perf_counter() - started) * 1000, 1)
            if curl.returncode != 0:
                return None
            try:
                status = int(curl.stdout.strip())
            except ValueError:
                return None
            if not 200 <= status < 400:
                return None
            return {
                "config": line,
                "host": host,
                "port": port,
                "latency_ms": latency_ms,
                "test_method": "protocol-https",
                "engine": engine,
                "http_status": status,
            }
        finally:
            if process is not None and process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=1)


def validate_configs(configs):
    """Validate configs through a real proxy connection and HTTPS request."""
    if not (SING_BOX_BINARY or XRAY_BINARY):
        raise RuntimeError("Neither sing-box nor xray was found. Install one (or set SING_BOX_BINARY / "
                           "XRAY_BINARY), or run with HEALTH_CHECK=0 to skip validation.")
    if not CURL_BINARY:
        raise RuntimeError("curl was not found on PATH; it is required for validation.")

    healthy = []
    unsupported = Counter()
    failures = Counter()
    deadline = time.monotonic() + PROTOCOL_VALIDATION_MAX_RUNTIME
    executor = ThreadPoolExecutor(max_workers=PROTOCOL_TEST_WORKERS)
    pending = set()
    try:
        futures = {executor.submit(_run_protocol_test, config): config for config in configs}
        pending = set(futures)
        while pending and time.monotonic() < deadline:
            completed, pending = wait(pending, timeout=deadline - time.monotonic(), return_when=FIRST_COMPLETED)
            for future in completed:
                config = futures[future]
                try:
                    result = future.result()
                except UnsupportedProtocol:
                    unsupported[config.split("://", 1)[0].lower()] += 1
                    continue
                except Exception as exc:  # noqa: BLE001 - one bad config must never abort the whole run
                    message = (str(exc).splitlines() or [""])[0][:100]
                    failures[f"{type(exc).__name__}: {message}"] += 1
                    continue
                if result:
                    healthy.append(result)
    finally:
        for future in pending:
            future.cancel()
        executor.shutdown(wait=False, cancel_futures=True)

    healthy.sort(key=lambda item: item["latency_ms"])
    validated = len(configs) - len(pending)
    print(f"Protocol validation: {len(healthy)}/{validated} completed configs passed real HTTPS tests")
    if pending:
        print(f"Protocol validation stopped at the {PROTOCOL_VALIDATION_MAX_RUNTIME}s runtime limit; "
              f"{len(pending)} configs were not started/completed.")
    if unsupported:
        print("Unsupported by protocol validator: " + ", ".join(f"{k}={v}" for k, v in sorted(unsupported.items())))
    if failures:
        print("Most common validation errors:")
        for reason, count in failures.most_common(8):
            print(f"  {count:>5} x {reason}")
    return healthy


# ---------------------------------------------------------------------------
# GeoIP / country files
# ---------------------------------------------------------------------------
def _sanitize_country_code(code):
    """Country codes come from a third-party API and end up in file names."""
    code = str(code or "").upper()
    return code if re.fullmatch(r"[A-Z]{2}", code) else "XX"


def _resolve_ip(host):
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, host)
            return host
        except OSError:
            pass
    for family in (socket.AF_INET, socket.AF_UNSPEC):  # prefer IPv4
        try:
            infos = socket.getaddrinfo(host, None, family=family, type=socket.SOCK_STREAM)
        except (OSError, UnicodeError):
            continue
        if infos:
            return infos[0][4][0]
    return None


def lookup_countries(hosts):
    """Resolve public IPs/hosts to country metadata in batches."""
    unique_hosts = [h for h in dict.fromkeys(hosts) if isinstance(h, str) and h]
    results = {}

    with ThreadPoolExecutor(max_workers=GEOIP_DNS_WORKERS) as executor:
        resolved = dict(zip(unique_hosts, executor.map(_resolve_ip, unique_hosts)))

    for start in range(0, len(unique_hosts), GEOIP_BATCH_SIZE):
        host_to_ip = {}
        for host in unique_hosts[start:start + GEOIP_BATCH_SIZE]:
            ip = resolved.get(host)
            if ip:
                host_to_ip.setdefault(ip, []).append(host)
        if not host_to_ip:
            continue
        try:
            response = requests.post("https://countries.dev/ip", json=list(host_to_ip), timeout=10)
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, list):
                payload = [payload]
            for item in payload:
                if not isinstance(item, dict):
                    continue
                ip = item.get("ip")
                country = item.get("country") or {}
                if ip and isinstance(country, dict):
                    location = {
                        "country": country.get("name") or "Unknown",
                        "country_code": _sanitize_country_code(
                            country.get("alpha2Code") or item.get("countryCode")
                        ),
                    }
                    for host in host_to_ip.get(ip, []):
                        results[host] = location
        except (requests.RequestException, ValueError, TypeError, AttributeError) as exc:
            print(f"WARNING: GeoIP lookup failed: {exc}")
    return results


def country_emoji(country_code):
    """Convert an ISO 3166-1 alpha-2 country code to its flag emoji."""
    code = (country_code or "").upper()
    if len(code) != 2 or not code.isalpha() or code == "XX":
        return "🌐"
    return "".join(chr(127397 + ord(char)) for char in code)


def server_remark(country, country_code, latency_ms):
    """Build a readable server name containing country, flag, latency, and brand."""
    country_name = country or "Unknown"
    flag = country_emoji(country_code)
    latency = f"{latency_ms:g}ms" if isinstance(latency_ms, (int, float)) else "N/A"
    return f"{flag} {country_name} • {latency} • {BRAND}"


def _atomic_write_text(path, text):
    """Write via a temp file + rename so readers never see a half-written file."""
    path = Path(path)
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    os.replace(tmp, path)


def _b64_text(text):
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def write_country_files(healthy_configs, output_folder):
    """Write healthy configurations grouped by server country."""
    country_dir = output_folder / "By-Country"
    country_dir.mkdir(parents=True, exist_ok=True)

    geo = lookup_countries([item["host"] for item in healthy_configs])
    grouped = {}
    for item in healthy_configs:
        location = geo.get(item["host"], {"country": "Unknown", "country_code": "XX"})
        item["country"] = location["country"]
        item["country_code"] = location["country_code"]
        item["config"] = rename_remark(
            item["config"],
            new_remark=server_remark(item["country"], item["country_code"], item["latency_ms"]),
        )
        grouped.setdefault(location["country_code"], []).append(item)

    # Only touch the old files once the new data is ready.
    for stale in country_dir.glob("*.txt"):
        stale.unlink()
    for country_code, items in sorted(grouped.items()):
        items.sort(key=lambda item: item["latency_ms"])
        _atomic_write_text(country_dir / f"{country_code}.txt", "".join(f"{i['config']}\n" for i in items))

    print(f"Country classification: {len(grouped)} countries")
    return grouped


def write_server_metrics(healthy_configs, output_folder):
    """Write machine-readable health/latency metadata."""
    metrics = [
        {
            "host": item["host"],
            "port": item["port"],
            "latency_ms": item["latency_ms"],
            "country": item.get("country", "Unknown"),
            "country_code": item.get("country_code", "XX"),
            "test_method": item.get("test_method", "tcp"),
            "speed_avg": item.get("speed_avg", 0),
            "speed_max": item.get("speed_max", 0),
            "config": item["config"],
        }
        for item in healthy_configs
    ]
    _atomic_write_text(output_folder / "server-metrics.json", json.dumps(metrics, ensure_ascii=False, indent=2))


# ---------------------------------------------------------------------------
# Remarks
# ---------------------------------------------------------------------------
def rename_remark(config_line, new_remark=BRAND):
    """Rename the remark of a single config line to ``new_remark``."""
    line = config_line.strip()

    # Leave comment / empty lines untouched
    if not line or line.startswith("#"):
        return config_line

    lowered = line.lower()
    if lowered.startswith("vmess://"):
        try:
            config_obj = _decode_vmess(line)
            config_obj["ps"] = new_remark
            encoded = base64.b64encode(json.dumps(config_obj, ensure_ascii=False).encode("utf-8")).decode("ascii")
            return f"vmess://{encoded}"
        except (ValueError, UnicodeError):
            return config_line

    if lowered.startswith("ssr://"):
        try:
            decoded = _b64decode_loose(line[len("ssr://"):].split("#", 1)[0]).decode("utf-8")
            encoded_remark = base64.urlsafe_b64encode(new_remark.encode("utf-8")).decode("ascii").rstrip("=")
            if re.search(r"[?&]remarks=", decoded):
                decoded = re.sub(r"([?&])remarks=[^&]*", rf"\1remarks={encoded_remark}", decoded, count=1)
            elif "?" in decoded:
                decoded += f"&remarks={encoded_remark}"
            else:
                decoded = decoded.rstrip("/") + f"/?remarks={encoded_remark}"
            return "ssr://" + base64.urlsafe_b64encode(decoded.encode("utf-8")).decode("ascii").rstrip("=")
        except (ValueError, UnicodeError):
            return config_line

    encoded_remark = urllib.parse.quote(new_remark, safe="")
    base_url = line[:line.rfind("#")] if "#" in line else line
    return f"{base_url}#{encoded_remark}"


def rename_all_remarks(configs, new_remark=BRAND):
    return [rename_remark(line, new_remark) for line in configs]


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
def ensure_directories_exist():
    output_folder = Path(__file__).resolve().parent.parent
    base64_folder = output_folder / "Base64"
    base64_folder.mkdir(parents=True, exist_ok=True)
    return output_folder, base64_folder


def _remove_stale_outputs(output_folder, base64_folder, num_files):
    """Delete Sub<N> files beyond the current count (and legacy base64 names).

    Matches ``Sub<digits>.txt`` exactly so unrelated files such as ``Subscriptions.txt``
    are never touched.
    """
    for folder, pattern in ((output_folder, r"Sub(\d+)\.txt"), (base64_folder, r"Sub(\d+)_base64\.txt")):
        for path in folder.iterdir():
            match = re.fullmatch(pattern, path.name)
            if match and int(match.group(1)) > num_files:
                path.unlink()
    for path in base64_folder.glob("Config list*_base64.txt"):
        path.unlink()


def main():
    output_folder, base64_folder = ensure_directories_exist()
    output_filename = output_folder / "All_Configs_Sub.txt"
    main_base64_filename = output_folder / "All_Configs_base64_Sub.txt"

    print("Starting to fetch and process configs...")
    print(f"Fetching {len(SOURCES)} sources...")
    sources = fetch_sources(SOURCES)
    print(f"Loaded {len(sources)}/{len(SOURCES)} sources")

    print("Combining and filtering configs...")
    merged_configs, garbage_count = filter_for_protocols(sources, PROTOCOLS)
    real_configs = [c for c in merged_configs if not c.startswith("#")]
    print(f"Found {len(real_configs)} unique configs after filtering")
    print(f"Skipped {garbage_count} garbage/invalid lines during filtering")

    if len(real_configs) < MIN_CONFIGS_EXPECTED:
        raise RuntimeError("No valid configurations were obtained from any source. Refusing to publish empty output files.")

    if HEALTH_CHECK_ENABLED:
        print("Testing configs with protocol-level engine validation...")
        healthy = validate_configs(real_configs)
        if len(healthy) < MIN_HEALTHY_CONFIGS_EXPECTED:
            raise RuntimeError("No reachable servers were found. Refusing to publish an empty health-filtered dataset.")
        country_groups = write_country_files(healthy, output_folder)
        write_server_metrics(healthy, output_folder)
        healthy.sort(key=lambda item: (item.get("country_code", "XX"), item["latency_ms"]))
        merged_configs = [item["config"] for item in healthy]
        print(f"Keeping {len(merged_configs)} reachable configs")
        print(f"Countries found: {', '.join(sorted(country_groups))}")
    else:
        print(f"Renaming remarks to {BRAND}...")
        # Source comment lines are dropped: they can carry foreign #profile-* directives.
        merged_configs = rename_all_remarks(real_configs, new_remark=BRAND)

    print("Writing main config files...")
    main_text = fixed_text + "".join(f"{config}\n" for config in merged_configs)
    _atomic_write_text(output_filename, main_text)
    _atomic_write_text(main_base64_filename, _b64_text(main_text))
    print(f"Main config file created: {output_filename}")
    print(f"Base64 config file created: {main_base64_filename}")

    num_files = (len(merged_configs) + MAX_CONFIGS_PER_FILE - 1) // MAX_CONFIGS_PER_FILE
    print(f"Splitting into {num_files} files with max {MAX_CONFIGS_PER_FILE} configs each")

    for i in range(num_files):
        profile_title = f"🆓 Git:{BRAND} | Sub{i + 1} 🔥"
        header = (
            f"#profile-title: base64:{_b64_text(profile_title)}\n"
            "#profile-update-interval: 1\n"
            f"#subscription-userinfo: {SUBSCRIPTION_USERINFO}\n"
            f"#support-url: {SUPPORT_URL}\n"
            f"#profile-web-page-url: {SUPPORT_URL}\n"
        )
        chunk = merged_configs[i * MAX_CONFIGS_PER_FILE:(i + 1) * MAX_CONFIGS_PER_FILE]
        text = header + "".join(f"{config}\n" for config in chunk)
        _atomic_write_text(output_folder / f"Sub{i + 1}.txt", text)
        _atomic_write_text(base64_folder / f"Sub{i + 1}_base64.txt", _b64_text(text))
        print(f"Created: Sub{i + 1}.txt and Sub{i + 1}_base64.txt")

    # Clean up only after the new files are safely in place.
    _remove_stale_outputs(output_folder, base64_folder, num_files)

    print("\nProcess completed successfully!")
    print(f"Total configs processed: {len(merged_configs)}")
    print("Files created:")
    print("  - All_Configs_Sub.txt")
    print("  - All_Configs_base64_Sub.txt")
    print(f"  - {num_files} split files (Sub1.txt to Sub{num_files}.txt)")
    print(f"  - {num_files} base64 split files (Sub1_base64.txt to Sub{num_files}_base64.txt)")


if __name__ == "__main__":
    main()
