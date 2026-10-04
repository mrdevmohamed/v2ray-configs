"""Split All_Configs_Sub.txt by protocol into plaintext per-protocol files.

Reads ../All_Configs_Sub.txt relative to this script's location (not cwd).
Falls back to HTTP fetch with a warning if the local file is missing.

Outputs (one config URI per line, plaintext, NOT base64):
    Splitted-By-Protocol/vmess.txt, vless.txt, trojan.txt,
    ss.txt, ssr.txt, tuic.txt, hy2.txt, extra.txt
"""

from __future__ import annotations

import os
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
LOCAL_INPUT = REPO_ROOT / "All_Configs_Sub.txt"
OUTPUT_DIR = REPO_ROOT / "Splitted-By-Protocol"

FALLBACK_URL = (
    "https://raw.githubusercontent.com/mrdevmohamed/"
    "v2ray-configs/main/All_Configs_Sub.txt"
)

# protocol key -> output filename
OUTPUT_FILES = {
    "vmess": "vmess.txt",
    "vless": "vless.txt",
    "trojan": "trojan.txt",
    "ssr": "ssr.txt",
    "ss": "ss.txt",
    "tuic": "tuic.txt",
    "hy2": "hy2.txt",
    "extra": "extra.txt",
}

# URI scheme prefix -> protocol bucket. Exact "scheme://" prefixes, so "ssr://"
# can never be mistaken for "ss://".
_PREFIXES = (
    ("vmess://", "vmess"),
    ("vless://", "vless"),
    ("trojan://", "trojan"),
    ("ssr://", "ssr"),
    ("ss://", "ss"),
    ("tuic://", "tuic"),
    ("hy2://", "hy2"),
    ("hysteria2://", "hy2"),
    ("hysteria://", "hy2"),
    ("warp://", "extra"),
)


def classify(line: str) -> str | None:
    """Return protocol bucket key for a config line, or None to skip.

    Matching is case-insensitive, consistent with app.py's filter (which accepts
    e.g. ``VLESS://``); otherwise such lines would be silently dropped here.
    """
    s = line.strip()
    if not s or s.startswith("#"):
        return None
    lowered = s.lower()
    for prefix, key in _PREFIXES:
        if lowered.startswith(prefix):
            return key
    return None


def load_lines(input_path: Path | None = None) -> list[str]:
    """Load config lines, preferring the local file, HTTP fallback."""
    src = Path(input_path) if input_path else LOCAL_INPUT
    if src.exists():
        with open(src, encoding="utf-8-sig") as f:
            return f.read().splitlines()
    print(f"WARNING: local file not found: {src}, falling back to HTTP.")
    import requests

    resp = requests.get(FALLBACK_URL, timeout=30)
    resp.raise_for_status()
    return resp.content.decode("utf-8-sig", errors="replace").splitlines()


def split_configs(lines: list[str]) -> dict[str, list[str]]:
    """Single-pass classification into per-protocol buckets."""
    buckets: dict[str, list[str]] = {k: [] for k in OUTPUT_FILES}
    for line in lines:
        key = classify(line)
        if key is not None:
            buckets[key].append(line.strip())
    return buckets


def write_buckets(buckets: dict[str, list[str]], out_dir: Path | None = None) -> None:
    """Create/overwrite output files, one URI per line (plaintext).

    Each file is written to a temp name and renamed, so an interrupted run
    never leaves a truncated file behind.
    """
    dest = Path(out_dir) if out_dir else OUTPUT_DIR
    dest.mkdir(parents=True, exist_ok=True)
    for key, filename in OUTPUT_FILES.items():
        target = dest / filename
        tmp = target.with_name(filename + ".tmp")
        with open(tmp, "w", encoding="utf-8", newline="\n") as f:
            for config in buckets.get(key, []):
                f.write(config + "\n")
        os.replace(tmp, target)


def main(input_path: Path | None = None, out_dir: Path | None = None) -> dict[str, int]:
    lines = load_lines(input_path)
    buckets = split_configs(lines)
    write_buckets(buckets, out_dir)
    counts = {k: len(v) for k, v in buckets.items()}
    skipped = len(lines) - sum(counts.values())
    print("Split summary:")
    for key in OUTPUT_FILES:
        print(f"  {key}: {counts[key]} -> {OUTPUT_FILES[key]}")
    print(f"  skipped (blank/comment/unknown): {skipped}")
    print(f"  total input lines: {len(lines)}")
    return counts


if __name__ == "__main__":
    main()
