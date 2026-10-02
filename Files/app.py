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
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Define a fixed timeout for HTTP requests
TIMEOUT = 15  # seconds
MAX_SOURCE_BYTES = 10 * 1024 * 1024
MIN_CONFIGS_EXPECTED = 1
HEALTH_CHECK_ENABLED = True
HEALTH_CHECK_TIMEOUT = 4
HEALTH_CHECK_WORKERS = 128
LITESPEEDTEST_BINARY = os.environ.get("LITESPEEDTEST_BINARY", "")
LITESPEEDTEST_TIMEOUT = int(os.environ.get("LITESPEEDTEST_TIMEOUT", "20"))
LITESPEEDTEST_CONCURRENCY = int(os.environ.get("LITESPEEDTEST_CONCURRENCY", "16"))
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


def extract_endpoint(config_line):
    """Extract (host, port) from supported URI formats for a TCP health check."""
    line = config_line.strip()
    try:
        scheme, payload = line.split("://", 1)
        scheme = scheme.lower()

        if scheme == "vmess":
            encoded = payload.split("#", 1)[0]
            obj = json.loads(base64.b64decode(encoded + "=" * (-len(encoded) % 4)).decode("utf-8"))
            host = obj.get("add") or obj.get("host")
            port = int(obj.get("port"))
            return host, port

        if scheme == "ssr":
            encoded = payload.split("#", 1)[0]
            decoded = base64.b64decode(encoded + "=" * (-len(encoded) % 4)).decode("utf-8")
            parts = decoded.split(":")
            host, port = parts[0], int(parts[1])
            return host, port

        parsed = urllib.parse.urlsplit(line)
        if parsed.hostname and parsed.port:
            return parsed.hostname, parsed.port
    except (ValueError, TypeError, KeyError, UnicodeError, binascii.Error, json.JSONDecodeError):
        pass
    return None


def check_endpoint(config_line):
    endpoint = extract_endpoint(config_line)
    if not endpoint:
        return None
    host, port = endpoint
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=HEALTH_CHECK_TIMEOUT):
            latency_ms = round((time.perf_counter() - started) * 1000, 1)
            return {"config": config_line, "host": host, "port": port, "latency_ms": latency_ms}
    except (OSError, socket.gaierror):
        return None


def health_check_configs(configs):
    """Keep only configs whose server accepts a TCP connection."""
    healthy = []
    checked = 0
    with ThreadPoolExecutor(max_workers=HEALTH_CHECK_WORKERS) as executor:
        futures = [executor.submit(check_endpoint, config) for config in configs]
        for future in as_completed(futures):
            checked += 1
            result = future.result()
            if result:
                healthy.append(result)
    healthy.sort(key=lambda item: item["latency_ms"])
    print(f"Health check: {len(healthy)}/{checked} endpoints reachable")
    return healthy


def validate_configs(configs):
    """Validate every config, using LiteSpeedTest where supported.

    Protocols not understood by LiteSpeedTest are retained in a separate
    fallback set and validated with the existing TCP endpoint check.
    """
    if not LITESPEEDTEST_BINARY:
        print("WARNING: LiteSpeedTest binary is not configured; using TCP health checks")
        return health_check_configs(configs)

    litespeed_healthy, unsupported = run_litespeedtest(configs)
    fallback_healthy = health_check_configs(unsupported) if unsupported else []

    healthy = []
    for item in litespeed_healthy + fallback_healthy:
        endpoint = extract_endpoint(item["config"])
        if not endpoint:
            continue
        item["host"], item["port"] = endpoint
        item.setdefault("test_method", "tcp")
        healthy.append(item)

    healthy.sort(key=lambda item: item["latency_ms"])
    print(f"Validation: {len(healthy)}/{len(configs)} configs passed")
    return healthy


LITESPEEDTEST_SUPPORTED_SCHEMES = {"vmess", "vless", "trojan", "ss", "ssr"}


def litespeedtest_supported(config_line):
    """Return whether LiteSpeedTest can parse this config URI."""
    if "://" not in config_line:
        return False
    scheme = config_line.split("://", 1)[0].lower()
    return scheme in LITESPEEDTEST_SUPPORTED_SCHEMES


def run_litespeedtest(configs, binary_path=None):
    """Validate supported configs with LiteSpeedTest and return its metrics.

    LiteSpeedTest v0.15.0 parses VMess, VLESS, Trojan, SS and SSR links.
    The repository also contains HY2/TUIC/WARP, so those are deliberately
    left for the existing TCP fallback instead of being silently dropped.
    """
    binary = binary_path or LITESPEEDTEST_BINARY
    if not binary:
        raise RuntimeError("LITESPEEDTEST_BINARY is not configured")

    supported = [config for config in configs if litespeedtest_supported(config)]
    unsupported = [config for config in configs if not litespeedtest_supported(config)]
    if not supported:
        return [], unsupported

    with tempfile.TemporaryDirectory(prefix="litespeedtest-") as temp_dir:
        temp_path = Path(temp_dir)
        input_path = temp_path / "configs.txt"
        config_path = temp_path / "config.json"
        output_path = temp_path / "output.json"

        input_path.write_text("\n".join(supported) + "\n", encoding="utf-8")
        config_path.write_text(
            json.dumps(
                {
                    "group": BRAND,
                    "speedtestMode": "pingonly",
                    "pingMethod": "googleping",
                    "sortMethod": "ping",
                    "concurrency": LITESPEEDTEST_CONCURRENCY,
                    "testMode": 2,
                    "subscription": str(input_path),
                    "timeout": LITESPEEDTEST_TIMEOUT,
                    "language": "en",
                    "unique": True,
                    "outputMode": 3,
                }
            ),
            encoding="utf-8",
        )

        completed = subprocess.run(
            [binary, "--config", str(config_path), "--test", str(input_path)],
            cwd=temp_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=max(LITESPEEDTEST_TIMEOUT * 2, 60) * max(1, len(supported) // max(LITESPEEDTEST_CONCURRENCY, 1) + 1),
            check=False,
        )
        if not output_path.exists():
            raise RuntimeError(
                "LiteSpeedTest did not produce output.json. "
                f"exit={completed.returncode}; output={completed.stdout[-2000:]}"
            )

        payload = json.loads(output_path.read_text(encoding="utf-8"))
        nodes = payload.get("nodes", []) if isinstance(payload, dict) else []
        by_config = {}
        for node in nodes:
            link = node.get("Link") or node.get("link")
            if not link:
                continue
            ping_raw = node.get("Ping") or node.get("ping") or "0"
            try:
                latency_ms = float(str(ping_raw).replace("ms", ""))
            except ValueError:
                latency_ms = 0.0
            by_config[link] = {
                "config": link,
                "latency_ms": round(latency_ms, 1),
                "litespeedtest_ok": bool(node.get("IsOk", node.get("isOk", False))) and latency_ms > 0,
                "speed_avg": node.get("AvgSpeed", node.get("avgSpeed", 0)),
                "speed_max": node.get("MaxSpeed", node.get("maxSpeed", 0)),
                "test_method": "litespeedtest",
            }

        healthy = [
            by_config[config]
            for config in supported
            if config in by_config and by_config[config]["litespeedtest_ok"]
        ]
        healthy.sort(key=lambda item: item["latency_ms"])
        print(
            f"LiteSpeedTest: {len(healthy)}/{len(supported)} supported configs passed; "
            f"{len(unsupported)} configs require TCP fallback"
        )
        return healthy, unsupported


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
        print("Testing configs with LiteSpeedTest where supported...")
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
