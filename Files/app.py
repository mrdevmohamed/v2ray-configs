import pybase64
import base64
import requests
import binascii
import json
import re
import urllib.parse
from pathlib import Path

# Define a fixed timeout for HTTP requests
TIMEOUT = 15  # seconds
MAX_SOURCE_BYTES = 10 * 1024 * 1024
MIN_CONFIGS_EXPECTED = 1

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
            if line not in seen_configs:
                filtered_data.append(line)
                seen_configs.add(line)
    return filtered_data, garbage_count

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

    print("Cleaning existing files...")
    output_filename = output_folder / "All_Configs_Sub.txt"
    main_base64_filename = output_folder / "All_Configs_base64_Sub.txt"

    if output_filename.exists():
        output_filename.unlink()
        print(f"Removed: {output_filename}")
    if main_base64_filename.exists():
        main_base64_filename.unlink()
        print(f"Removed: {main_base64_filename}")

    for stale in output_folder.glob("Sub*.txt"):
        stale.unlink()
        print(f"Removed: {stale}")
    for pattern in ("Sub*_base64.txt", "Config list*_base64.txt"):
        for stale in base64_folder.glob(pattern):
            stale.unlink()
            print(f"Removed: {stale}")

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
