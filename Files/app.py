import pybase64
import base64
import requests
import binascii
import json
import re
import urllib.parse
import socket
import time
import os
import subprocess
import tempfile
import shutil
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path

# Define a fixed timeout for HTTP requests
TIMEOUT = 15  # seconds
MAX_SOURCE_BYTES = 10 * 1024 * 1024
MIN_CONFIGS_EXPECTED = 1
HEALTH_CHECK_ENABLED = True
PROTOCOL_TEST_TIMEOUT = int(os.environ.get("PROTOCOL_VALIDATION_TIMEOUT", os.environ.get("PROTOCOL_TEST_TIMEOUT", "8")))
PROTOCOL_TEST_WORKERS = int(os.environ.get("PROTOCOL_VALIDATION_WORKERS", os.environ.get("PROTOCOL_TEST_WORKERS", "32")))
PROTOCOL_VALIDATION_MAX_RUNTIME = int(os.environ.get("PROTOCOL_VALIDATION_MAX_RUNTIME", "900"))
PROTOCOL_TEST_URL = os.environ.get("PROTOCOL_TEST_URL", "https://www.gstatic.com/generate_204")
SING_BOX_BINARY = os.environ.get("SING_BOX_BINARY") or shutil.which("sing-box") or ""
XRAY_BINARY = os.environ.get("XRAY_BINARY") or shutil.which("xray") or ""
GEOIP_BATCH_SIZE = 100
MIN_HEALTHY_CONFIGS_EXPECTED = 1

# Unifed branding
BRAND = "mrdevmohamed"
SUPPORT_URL = f"https://github.com/{BRAND}/v2ray-configs"

# Define the fixed text for the initial configuration
fixed_text = f"""#{BRAND}
"""

# Base64 decoding function: strict UTF-8 only, validate printable + URI-like
def decode_base64(encoded):
    try:
        if isinstance(encoded, str):
            encoded = encoded.encode("utf-8")
        if not encoded or not encoded.strip():
            return ""
        padded = encoded + b"=" * (-len(encoded) % 4)
        decoded = pybase64.b64decode(padded).decode("utf-8")  # strict
    except (UnicodeDecodeError, binascii.Error, ValueError):
        return ""
    if "://" not in decoded:
        return ""
    total = len(decoded)
    if total == 0:
        return ""
    allowed = sum(1 for c in decoded if c.isprintable() or c in "\n\r\t")
    if allowed / total < 0.95:
        return ""
    return decoded


def decode_links(links):
    decoded_data = []
    for link in links:
        try:
            response = requests.get(link, timeout=TIMEOUT)
            response.raise_for_status()
            encoded_bytes = response.content
            if len(encoded_bytes) > MAX_SOURCE_BYTES:
                print(f"WARNING: source too large, skipping {link}")
                continue
            decoded_text = decode_base64(encoded_bytes)
            if decoded_text:
                decoded_data.append(decoded_text)
            else:
                print(f"WARNING: source is not valid supported base64 content, skipping {link}")
        except requests.RequestException as e:
            print(f"WARNING: failed to fetch base64 source {link}: {e}")
    return decoded_data


def decode_dir_links(dir_links):
    decoded_dir_links = []
    for link in dir_links:
        try:
            response = requests.get(link, timeout=TIMEOUT)
            response.raise_for_status()
            if len(response.content) > MAX_SOURCE_BYTES:
                print(f"WARNING: source too large, skipping {link}")
                continue
            decoded_text = response.text
            if decoded_text:
                decoded_dir_links.append(decoded_text)
            else:
                print(f"WARNING: empty direct source, skipping {link}")
        except requests.RequestException as e:
            print(f"WARNING: failed to fetch direct source {link}: {e}")
    return decoded_dir_links

def filter_for_protocols(data, protocols):
    # Build case-insensitive "protocol://" prefixes ("warp://" already has suffix)
    prefixes = tuple(
        (p if p.endswith("://") else p + "://").lower() for p in protocols
    )
    filtered_data = []
    seen_configs = set()
    garbage_count = 0

    for content in data:
        if not content or not content.strip():
            continue
        lines = content.strip().splitlines()
        for raw_line in lines:
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith('#'):
                if not all(ord(c) >= 32 or c in "\t\r\n" for c in line):
                    garbage_count += 1
                    continue
                filtered_data.append(line)
                continue
            # Skip non-printable / binary lines
            if any(ord(c) < 32 or ord(c) == 127 for c in line):
                garbage_count += 1
                continue
            # Skip lines that don't look like URIs
            if "://" not in line:
                garbage_count += 1
                continue
            lowered = line.lower()
            if not any(lowered.startswith(prefix) for prefix in prefixes):
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

    try:
        scheme = line.split("://", 1)[0].lower()
        if scheme == "vmess":
            encoded = line.split("://", 1)[1].split("#", 1)[0]
            decoded = base64.b64decode(encoded + "=" * (-len(encoded) % 4)).decode("utf-8")
            obj = json.loads(decoded)
            obj.pop("ps", None)
            return "vmess://" + json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        if scheme == "ssr":
            encoded = line.split("://", 1)[1].split("#", 1)[0]
            decoded = base64.b64decode(encoded + "=" * (-len(encoded) % 4)).decode("utf-8")
            decoded = re.sub(r"([?&]remarks=)[^&]*", r"\1", decoded)
            return "ssr://" + decoded

        parsed = urllib.parse.urlsplit(line)
        return urllib.parse.urlunsplit((parsed.scheme.lower(), parsed.netloc, parsed.path, parsed.query, ""))
    except (ValueError, UnicodeError, binascii.Error, json.JSONDecodeError):
        return line.split("#", 1)[0]


class UnsupportedProtocol(ValueError):
    """A config URI is intentionally outside the protocol validator's scope."""


def _query(parsed):
    return urllib.parse.parse_qs(parsed.query, keep_blank_values=True)


def _first(query, key, default=None):
    values = query.get(key)
    return values[0] if values else default


def _has_invalid_percent_escape(value):
    return bool(re.search(r"%(?![0-9A-Fa-f]{2})", value or ""))


def _tls_options(query):
    security = _first(query, "security", "")
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
    if _first(query, "insecure") == "1" or _first(query, "allowInsecure") == "1":
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
    raise ValueError(f"unsupported transport: {transport}")


def _decode_vmess(line):
    payload = line.split("://", 1)[1].split("#", 1)[0]
    return json.loads(base64.b64decode(payload + "=" * (-len(payload) % 4)).decode("utf-8"))


def _singbox_outbound(config_line):
    line = config_line.strip()
    scheme = line.split("://", 1)[0].lower() if "://" in line else ""
    if scheme in {"ssr", "warp"}:
        raise UnsupportedProtocol(f"{scheme.upper()} is unsupported by protocol validation")
    parsed = urllib.parse.urlsplit(line)
    query = _query(parsed)
    host = parsed.hostname
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid server port") from exc
    if scheme == "vmess":
        obj = _decode_vmess(line)
        host = obj.get("add") or obj.get("host")
        port = int(obj.get("port"))
        outbound = {"type": "vmess", "server": host, "server_port": port,
                    "uuid": obj.get("id"), "security": obj.get("scy", "auto")}
        q = {k: [str(v)] for k, v in obj.items() if v is not None}
        if obj.get("tls") in {"tls", True, "1"}:
            q["security"] = ["tls"]
        if obj.get("sni"):
            q["sni"] = [str(obj["sni"])]
        if obj.get("alpn"):
            q["alpn"] = [str(obj["alpn"])]
        if obj.get("fp"):
            q["fp"] = [str(obj["fp"])]
        transport = obj.get("net", "tcp")
        if transport != "tcp":
            q["type"] = [transport]
            if obj.get("path"):
                q["path"] = [str(obj["path"])]
            if obj.get("host"):
                q["host"] = [str(obj["host"])]
            if transport == "grpc" and obj.get("path"):
                q["serviceName"] = [str(obj["path"]).lstrip("/")]
        tls = _tls_options(q)
        if tls:
            outbound["tls"] = tls
        transport_options = _transport_options(q)
        if transport_options:
            outbound["transport"] = transport_options
        return outbound
    if scheme in {"vless", "trojan"}:
        if not host or not port or not parsed.username:
            raise ValueError("missing server, port, or credentials")
        key = "uuid" if scheme == "vless" else "password"
        outbound = {"type": scheme, "server": host, "server_port": port,
                    key: urllib.parse.unquote(parsed.username)}
        if scheme == "vless" and _first(query, "flow"):
            flow = _first(query, "flow")
            if flow == "xtls-rprx-vision-udp443":
                raise UnsupportedProtocol("sing-box does not support xtls-rprx-vision-udp443")
            outbound["flow"] = flow
        tls = _tls_options(query)
        if tls:
            outbound["tls"] = tls
        transport = _transport_options(query)
        if transport:
            outbound["transport"] = transport
        return outbound
    if scheme == "ss":
        if parsed.username and parsed.password:
            method = urllib.parse.unquote(parsed.username)
            password = urllib.parse.unquote(parsed.password)
        else:
            payload = parsed.netloc.split("@", 1)[0]
            try:
                decoded = base64.b64decode(payload + "=" * (-len(payload) % 4)).decode("utf-8")
                method, password = decoded.split(":", 1)
            except (UnicodeDecodeError, ValueError, binascii.Error) as exc:
                raise ValueError("invalid Shadowsocks credentials encoding") from exc
        if not host or not port:
            raise ValueError("missing server or port")
        if method == "chacha20-poly1305":
            raise UnsupportedProtocol("legacy chacha20-poly1305 is not supported by sing-box; use chacha20-ietf-poly1305")
        return {"type": "shadowsocks", "server": host, "server_port": port,
                "method": method, "password": password}
    if scheme in {"hy2", "hysteria2"}:
        if not host or not port or not parsed.username:
            raise ValueError("missing server, port, or password")
        outbound = {"type": "hysteria2", "server": host, "server_port": port,
                    "password": urllib.parse.unquote(parsed.username)}
        outbound["tls"] = _tls_options(query) or {"enabled": True}
        if _first(query, "obfs") == "salamander":
            outbound["obfs"] = {"type": "salamander", "password": _first(query, "obfs-password", "")}
        return outbound
    if scheme == "tuic":
        if not host or not port or not parsed.username:
            raise ValueError("missing server, port, or credentials")
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
            decoded = urllib.parse.unquote(extra)
            parsed_extra = json.loads(decoded)
            if isinstance(parsed_extra, dict):
                settings.update(parsed_extra)
        except (TypeError, ValueError, json.JSONDecodeError):
            pass

    for key in ("host", "path", "mode"):
        value = _first(query, key)
        if value:
            settings[key] = value

    padding = _first(query, "x_padding_bytes") or _first(query, "xPaddingBytes")
    if padding:
        settings["xPaddingBytes"] = padding

    return settings


def _xray_outbound(config_line, socks_port):
    """Build an Xray outbound for transports/security unsupported by sing-box."""
    parsed = urllib.parse.urlsplit(config_line)
    scheme = parsed.scheme.lower()
    query = _query(parsed)
    host = parsed.hostname
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid server port") from exc
    if not host or not port or not parsed.username:
        raise ValueError("missing server, port, or credentials")

    if scheme not in {"vless", "trojan"}:
        raise UnsupportedProtocol(f"Xray engine is only used for VLESS/Trojan, got {scheme or 'unknown'}")

    flow = _first(query, "flow")
    if scheme == "vless":
        user = {"id": urllib.parse.unquote(parsed.username), "encryption": "none"}
        if flow:
            user["flow"] = flow
        settings = {"vnext": [{"address": host, "port": port, "users": [user]}]}
        protocol = "vless"
    else:
        settings = {"servers": [{"address": host, "port": port,
                                  "password": urllib.parse.unquote(parsed.username)}]}
        protocol = "trojan"

    stream = {
        "network": (_first(query, "type") or _first(query, "network") or "tcp").lower(),
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
        if _first(query, "insecure") == "1" or _first(query, "allowInsecure") == "1":
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

    if stream["network"] == "xhttp":
        stream["xhttpSettings"] = _xray_xhttp_settings(query)
    elif stream["network"] == "ws":
        ws = {}
        if _first(query, "path"):
            ws["path"] = _first(query, "path")
        if _first(query, "host"):
            ws["headers"] = {"Host": _first(query, "host")}
        stream["wsSettings"] = ws
    elif stream["network"] == "grpc":
        grpc = {}
        if _first(query, "serviceName"):
            grpc["serviceName"] = _first(query, "serviceName")
        elif _first(query, "path"):
            grpc["serviceName"] = _first(query, "path").lstrip("/")
        stream["grpcSettings"] = grpc
    elif stream["network"] not in {"tcp", "raw", "none"}:
        raise UnsupportedProtocol(f"unsupported Xray transport: {stream['network']}")

    if security == "reality" and stream["network"] not in {"tcp", "raw", "grpc", "xhttp"}:
        raise UnsupportedProtocol("Xray REALITY supports only raw, grpc, or xhttp transports")

    return {
        "log": {"loglevel": "warning"},
        "inbounds": [{"listen": "127.0.0.1", "port": socks_port, "protocol": "socks",
                      "settings": {"udp": True}}],
        "outbounds": [{
            "protocol": protocol,
            "settings": settings,
            "streamSettings": stream,
        }],
    }


def _free_local_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def _singbox_config(outbound, socks_port):
    outbound = dict(outbound)
    outbound["tag"] = "proxy"
    return {
        "log": {"disabled": True},
        "inbounds": [{"type": "socks", "tag": "validator-in", "listen": "127.0.0.1", "listen_port": socks_port}],
        "outbounds": [outbound],
        "route": {"final": "proxy"},
    }


def _run_protocol_test(config_line):
    scheme = config_line.split("://", 1)[0].lower() if "://" in config_line else ""
    if scheme in {"ssr", "warp"}:
        raise UnsupportedProtocol(f"{scheme.upper()} is unsupported by protocol validation")
    if not SING_BOX_BINARY:
        raise RuntimeError("sing-box is not available")
    query = _query(urllib.parse.urlsplit(config_line))
    parsed = urllib.parse.urlsplit(config_line)
    if _has_invalid_percent_escape(parsed.path) or _has_invalid_percent_escape(parsed.query):
        raise ValueError("invalid percent-escape in URI")
    if not parsed.hostname:
        raise ValueError("missing server host")
    try:
        parsed_port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid server port") from exc
    if not parsed_port or not 1 <= parsed_port <= 65535:
        raise ValueError("invalid server port")
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
    if transport == "xhttp" or security == "reality":
        if not XRAY_BINARY:
            raise RuntimeError("xray is required to validate XHTTP/REALITY configs")
        binary, engine = XRAY_BINARY, "xray"
        socks_port = _free_local_port()
        config = _xray_outbound(config_line, socks_port)
    else:
        binary, engine = SING_BOX_BINARY, "sing-box"
        outbound = _singbox_outbound(config_line)
        socks_port = _free_local_port()
        config = _singbox_config(outbound, socks_port)
    with tempfile.TemporaryDirectory(prefix="protocol-test-") as temp_dir:
        config_path = Path(temp_dir) / "config.json"
        config_path.write_text(json.dumps(config, ensure_ascii=False), encoding="utf-8")
        process = None
        try:
            process = subprocess.Popen([binary, "run", "-c", str(config_path)], cwd=temp_dir, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True, start_new_session=True)
            deadline = time.monotonic() + min(3, PROTOCOL_TEST_TIMEOUT)
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    stderr = (process.stderr.read() if process.stderr else "")[-1000:]
                    raise RuntimeError(f"{engine} exited during startup: {stderr}")
                try:
                    with socket.create_connection(("127.0.0.1", socks_port), timeout=0.1):
                        break
                except OSError:
                    time.sleep(0.05)
            else:
                raise RuntimeError(f"{engine} local SOCKS inbound did not start")
            started = time.perf_counter()
            curl = subprocess.run(["curl", "--silent", "--show-error", "--fail", "--socks5-hostname", f"127.0.0.1:{socks_port}", "--connect-timeout", str(PROTOCOL_TEST_TIMEOUT), "--max-time", str(PROTOCOL_TEST_TIMEOUT), "-o", "/dev/null", "-w", "%{http_code}", PROTOCOL_TEST_URL], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=PROTOCOL_TEST_TIMEOUT + 2, check=False)
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
                "config": config_line,
                "host": urllib.parse.urlsplit(config_line).hostname,
                "port": urllib.parse.urlsplit(config_line).port,
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
    healthy = []
    unsupported = {"ssr": 0, "warp": 0}
    deadline = time.monotonic() + PROTOCOL_VALIDATION_MAX_RUNTIME
    executor = ThreadPoolExecutor(max_workers=PROTOCOL_TEST_WORKERS)
    pending = set()
    try:
        futures = {executor.submit(_run_protocol_test, config): config for config in configs}
        pending = set(futures)
        while pending and time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            completed, pending = wait(pending, timeout=remaining, return_when=FIRST_COMPLETED)
            for future in completed:
                config = futures[future]
                try:
                    result = future.result()
                except UnsupportedProtocol:
                    scheme = config.split("://", 1)[0].lower()
                    unsupported[scheme] = unsupported.get(scheme, 0) + 1
                    continue
                except (OSError, RuntimeError, ValueError, json.JSONDecodeError, binascii.Error, subprocess.TimeoutExpired) as exc:
                    print(f"Protocol validation failed for {config[:80]}: {exc}")
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
        print(f"Protocol validation stopped at the {PROTOCOL_VALIDATION_MAX_RUNTIME}s runtime limit; {len(pending)} configs were not started/completed.")
    print(f"Unsupported by protocol validator: SSR={unsupported['ssr']}, WARP={unsupported['warp']}")
    return healthy

def lookup_countries(hosts):
    """Resolve public IPs/hosts to country metadata in batches."""
    unique_hosts = list(dict.fromkeys(hosts))
    results = {}
    for start in range(0, len(unique_hosts), GEOIP_BATCH_SIZE):
        batch = unique_hosts[start:start + GEOIP_BATCH_SIZE]
        host_to_ip = {}
        ip_batch = []
        for host in batch:
            try:
                ip = host
                socket.inet_pton(socket.AF_INET, host)
            except OSError:
                try:
                    ip = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)[0][4][0]
                except OSError:
                    continue
            host_to_ip.setdefault(ip, []).append(host)
            ip_batch.append(ip)
        if not ip_batch:
            continue
        try:
            response = requests.post(
                "https://countries.dev/ip",
                json=list(dict.fromkeys(ip_batch)),
                timeout=10,
            )
            response.raise_for_status()
            payload = response.json()
            if not isinstance(payload, list):
                payload = [payload]
            for item in payload:
                ip = item.get("ip")
                country = item.get("country") or {}
                if ip and isinstance(country, dict):
                    location = {
                        "country": country.get("name") or "Unknown",
                        "country_code": country.get("alpha2Code") or item.get("countryCode") or "XX",
                    }
                    for host in host_to_ip.get(ip, []):
                        results[host] = location
        except (requests.RequestException, ValueError, TypeError) as exc:
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


def write_country_files(healthy_configs, output_folder):
    """Write healthy configurations grouped by server country."""
    country_dir = output_folder / "By-Country"
    country_dir.mkdir(parents=True, exist_ok=True)
    for stale in country_dir.glob("*.txt"):
        stale.unlink()

    geo = lookup_countries([item["host"] for item in healthy_configs])
    grouped = {}
    for item in healthy_configs:
        location = geo.get(item["host"], {"country": "Unknown", "country_code": "XX"})
        item["country"] = location["country"]
        item["country_code"] = location["country_code"]
        item["config"] = rename_remark(
            item["config"],
            new_remark=server_remark(
                item["country"], item["country_code"], item["latency_ms"]
            ),
        )
        grouped.setdefault(location["country_code"], []).append(item)

    for country_code, items in sorted(grouped.items()):
        path = country_dir / f"{country_code}.txt"
        items.sort(key=lambda item: item["latency_ms"])
        with open(path, "w", encoding="utf-8") as f:
            for item in items:
                f.write(item["config"] + "\n")

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
    with open(output_folder / "server-metrics.json", "w", encoding="utf-8") as f:
        json.dump(metrics, f, ensure_ascii=False, indent=2)

# Rename the remark of a single v2ray config line to new_remark
def rename_remark(config_line, new_remark=BRAND):
    line = config_line.strip()

    # Leave comment / empty lines untouched
    if not line or line.startswith('#'):
        return config_line


    if line.startswith('vmess://'):
        try:
            encoded = line[len('vmess://'):]
            padding = '=' * (-len(encoded) % 4)
            decoded_json = base64.b64decode(encoded + padding).decode('utf-8')
            config_obj = json.loads(decoded_json)
            config_obj['ps'] = new_remark
            new_encoded = base64.b64encode(
                json.dumps(config_obj, ensure_ascii=False).encode('utf-8')
            ).decode('utf-8')
            return f'vmess://{new_encoded}'
        except Exception:
            return config_line

    if line.startswith('ssr://'):
        try:
            encoded = line[len('ssr://'):]
            padding = '=' * (-len(encoded) % 4)
            decoded = base64.b64decode(encoded + padding).decode('utf-8')

            encoded_remark = base64.b64encode(
                new_remark.encode('utf-8')
            ).decode('utf-8').rstrip('=')

            if 'remarks=' in decoded:
                decoded = re.sub(r'remarks=[^&]*', f'remarks={encoded_remark}', decoded)
            elif '?' in decoded:
                decoded += f'&remarks={encoded_remark}'
            else:
                decoded += f'/?remarks={encoded_remark}'

            new_encoded = base64.b64encode(
                decoded.encode('utf-8')
            ).decode('utf-8')
            return f'ssr://{new_encoded}'
        except Exception:
            return config_line

    encoded_remark = urllib.parse.quote(new_remark, safe='')
    if '#' in line:
        base_url = line[:line.rfind('#')]
        return f'{base_url}#{encoded_remark}'
    else:
        return f'{line}#{encoded_remark}'

# Apply rename_remark to every config line in the list
def rename_all_remarks(configs, new_remark=BRAND):
    return [rename_remark(line, new_remark) for line in configs]

# Create necessary directories if they don't exist
def ensure_directories_exist():
    output_folder = Path(__file__).resolve().parent.parent
    base64_folder = output_folder / "Base64"
    output_folder.mkdir(parents=True, exist_ok=True)
    base64_folder.mkdir(parents=True, exist_ok=True)

    return output_folder, base64_folder

# Main function to process links and write output files
def main():
    output_folder, base64_folder = ensure_directories_exist()
    output_folder = Path(output_folder)
    base64_folder = Path(base64_folder)

    output_filename = output_folder / "All_Configs_Sub.txt"
    main_base64_filename = output_folder / "All_Configs_base64_Sub.txt"

    print("Starting to fetch and process configs...")

    protocols = ["vmess", "vless", "trojan", "ss", "ssr", "hy2", "hysteria2", "tuic", "warp://"]
    links = [
        "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/app/sub.txt",
        "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mtn/sub_1.txt",
        "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mtn/sub_2.txt",
        "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mtn/sub_3.txt",
        "https://raw.githubusercontent.com/mahsanet/MahsaFreeConfig/refs/heads/main/mtn/sub_4.txt",
        "https://raw.githubusercontent.com/Surfboardv2ray/TGParse/main/splitted/mixed"
    ]
    dir_links = [
        "https://raw.githubusercontent.com/itsyebekhe/PSG/main/lite/subscriptions/xray/normal/mix",
        "https://raw.githubusercontent.com/arshiacomplus/v2rayExtractor/refs/heads/main/mix/sub.html",
        "https://raw.githubusercontent.com/Rayan-Config/C-Sub/refs/heads/main/configs/proxy.txt",
        "https://raw.githubusercontent.com/mahdibland/ShadowsocksAggregator/master/Eternity.txt",
        "https://raw.githubusercontent.com/Everyday-VPN/Everyday-VPN/main/subscription/main.txt",
        "https://raw.githubusercontent.com/MahsaNetConfigTopic/config/refs/heads/main/xray_final.txt",
    ]

    print("Fetching base64 encoded configs...")
    decoded_links = decode_links(links)
    print(f"Decoded {len(decoded_links)} base64 sources")

    print("Fetching direct text configs...")
    decoded_dir_links = decode_dir_links(dir_links)
    print(f"Decoded {len(decoded_dir_links)} direct text sources")

    print("Combining and filtering configs...")
    combined_data = decoded_links + decoded_dir_links
    merged_configs, garbage_count = filter_for_protocols(combined_data, protocols)
    print(f"Found {len(merged_configs)} unique configs after filtering")
    print(f"Skipped {garbage_count} garbage/invalid lines during filtering")

    real_configs = [c for c in merged_configs if not c.startswith('#')]
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

    print("Cleaning old generated files after successful validation...")
    for stale in (output_filename, main_base64_filename):
        if stale.exists():
            stale.unlink()
    for stale in output_folder.glob("Sub*.txt"):
        stale.unlink()
    for pattern in ("Sub*_base64.txt", "Config list*_base64.txt"):
        for stale in base64_folder.glob(pattern):
            stale.unlink()

    if not HEALTH_CHECK_ENABLED:
        print(f"Renaming remarks to {BRAND}...")
        merged_configs = rename_all_remarks(merged_configs, new_remark=BRAND)
        print("Remarks renamed successfully")

    print("Writing main config file...")
    output_filename = output_folder / "All_Configs_Sub.txt"
    with open(output_filename, "w", encoding="utf-8") as f:
        f.write(fixed_text)
        for config in merged_configs:
            f.write(config + "\n")
    print(f"Main config file created: {output_filename}")

    print("Creating base64 version...")
    with open(output_filename, "r", encoding="utf-8") as f:
        main_config_data = f.read()

    main_base64_filename = output_folder / "All_Configs_base64_Sub.txt"
    with open(main_base64_filename, "w", encoding="utf-8") as f:
        encoded_main_config = base64.b64encode(main_config_data.encode()).decode()
        f.write(encoded_main_config)
    print(f"Base64 config file created: {main_base64_filename}")

    print("Creating split files...")
    with open(output_filename, "r", encoding="utf-8") as f:
        lines = f.readlines()

    config_lines = [line for line in lines if not line.startswith('#')]
    max_configs_per_file = 1000
    num_files = (len(config_lines) + max_configs_per_file - 1) // max_configs_per_file
    print(f"Splitting into {num_files} files with max {max_configs_per_file} configs each")

    for i in range(num_files):
        profile_title = f"🆓 Git:{BRAND} | Sub{i+1} 🔥"
        encoded_title = base64.b64encode(profile_title.encode()).decode()
        custom_fixed_text = f"""#profile-title: base64:{encoded_title}
#profile-update-interval: 1
#subscription-userinfo: upload=29; download=12; total=10737418240000000; expire=2546249531
#support-url: {SUPPORT_URL}
#profile-web-page-url: {SUPPORT_URL}
"""

        input_filename = output_folder / f"Sub{i + 1}.txt"
        with open(input_filename, "w", encoding="utf-8") as f:
            f.write(custom_fixed_text)
            start_index = i * max_configs_per_file
            end_index = min((i + 1) * max_configs_per_file, len(config_lines))
            for line in config_lines[start_index:end_index]:
                f.write(line)
        print(f"Created: Sub{i + 1}.txt")

        with open(input_filename, "r", encoding="utf-8") as input_file:
            config_data = input_file.read()

        base64_output_filename = base64_folder / f"Sub{i + 1}_base64.txt"
        with open(base64_output_filename, "w", encoding="utf-8") as output_file:
            encoded_config = base64.b64encode(config_data.encode()).decode()
            output_file.write(encoded_config)
        print(f"Created: Sub{i + 1}_base64.txt")

    print(f"\nProcess completed successfully!")
    print(f"Total configs processed: {len(merged_configs)}")
    print(f"Files created:")
    print(f"  - All_Configs_Sub.txt")
    print(f"  - All_Configs_base64_Sub.txt")
    print(f"  - {num_files} split files (Sub1.txt to Sub{num_files}.txt)")
    print(f"  - {num_files} base64 split files (Sub1_base64.txt to Sub{num_files}_base64.txt)")

if __name__ == "__main__":
    main()
