# V2Ray Configs

Automated collection of V2Ray/Xray-compatible configuration URIs, aggregated from public upstream sources and refreshed every **5 minutes**.

> **Important:** This repository validates configuration syntax and content. It does **not** guarantee that a configuration is currently online, fast, secure, or suitable for a particular network. Use configurations only when you are authorized to do so and comply with the applicable laws and service terms.

## Features

- **Automatic refresh** every 5 minutes via GitHub Actions.
- **Multi-protocol support** for VMess, VLESS, Trojan, Shadowsocks, ShadowsocksR, Hysteria2, and TUIC.
- **Deduplication and filtering** of collected configuration URIs.
- **Base64 subscription output** for clients that support Base64 subscriptions.
- **Protocol-specific subscriptions** for clients that need a single protocol.
- **Dynamic 1000-config packs** generated according to the current dataset size.
- **Automated validation tests** run before the configuration pipeline.
- **No registration or application account** is required to download the generated files.

## Supported Protocols

| Protocol | Output |
| --- | --- |
| VMess | `vmess.txt` |
| VLESS | `vless.txt` |
| Trojan | `trojan.txt` |
| Shadowsocks | `ss.txt` |
| ShadowsocksR | `ssr.txt` |
| Hysteria2 | `hy2.txt` |
| TUIC | `tuic.txt` |

The protocol files are generated automatically. A protocol file may be empty when no valid configurations for that protocol are available from the current upstream sources.

## Subscription Links

### All Configurations

Plain-text subscription containing the complete deduplicated dataset:

```text
https://raw.githubusercontent.com/mrdevmohamed/v2ray-configs/main/All_Configs_Sub.txt
```

### Base64 Subscription

Base64-encoded version of the complete subscription:

```text
https://raw.githubusercontent.com/mrdevmohamed/v2ray-configs/main/All_Configs_base64_Sub.txt
```

## Protocol-Specific Subscriptions

| Protocol | Subscription |
| --- | --- |
| VLESS | `https://raw.githubusercontent.com/mrdevmohamed/v2ray-configs/main/Splitted-By-Protocol/vless.txt` |
| VMess | `https://raw.githubusercontent.com/mrdevmohamed/v2ray-configs/main/Splitted-By-Protocol/vmess.txt` |
| Trojan | `https://raw.githubusercontent.com/mrdevmohamed/v2ray-configs/main/Splitted-By-Protocol/trojan.txt` |
| Shadowsocks | `https://raw.githubusercontent.com/mrdevmohamed/v2ray-configs/main/Splitted-By-Protocol/ss.txt` |
| ShadowsocksR | `https://raw.githubusercontent.com/mrdevmohamed/v2ray-configs/main/Splitted-By-Protocol/ssr.txt` |
| Hysteria2 | `https://raw.githubusercontent.com/mrdevmohamed/v2ray-configs/main/Splitted-By-Protocol/hy2.txt` |
| TUIC | `https://raw.githubusercontent.com/mrdevmohamed/v2ray-configs/main/Splitted-By-Protocol/tuic.txt` |

## 1000-Config Packs

The complete dataset is also divided into files containing **up to 1,000 configuration URIs per file**.

The number of packs is dynamic and changes automatically with the generated dataset.

Examples:

```text
https://raw.githubusercontent.com/mrdevmohamed/v2ray-configs/main/Sub1.txt
https://raw.githubusercontent.com/mrdevmohamed/v2ray-configs/main/Sub2.txt
```

Each pack includes subscription metadata headers in addition to its configuration URIs.

## How It Works

```text
Public upstream sources
        ↓
Fetch / decode
        ↓
Validate and filter
        ↓
Deduplicate
        ↓
Generate combined subscriptions
        ↓
Generate Base64 subscriptions
        ↓
Split into 1000-config packs
        ↓
Split by protocol
        ↓
Commit generated files
```

The workflow runs the tests before generating and publishing the updated files. Failed or invalid upstream sources are skipped when possible; the pipeline refuses to publish an empty configuration set.

## Repository Structure

```text
.
├── Files/
│   ├── app.py
│   ├── sort.py
│   ├── test_configs.py
│   └── requirements.txt
├── .github/
│   └── workflows/
│       └── main.yml
├── All_Configs_Sub.txt
├── All_Configs_base64_Sub.txt
├── Sub*.txt
├── Base64/
│   └── Sub*_base64.txt
└── Splitted-By-Protocol/
    ├── vmess.txt
    ├── vless.txt
    ├── trojan.txt
    ├── ss.txt
    ├── ssr.txt
    ├── hy2.txt
    ├── tuic.txt
    └── extra.txt
```

## Development

Requirements:

- Python 3.11+
- `requests`
- `pybase64`

Install dependencies:

```bash
python -m pip install -r Files/requirements.txt
```

Run the pipeline locally:

```bash
python Files/app.py
python Files/sort.py
```

Run the test suite:

```bash
python -m unittest discover -s Files -p 'test_*.py' -v
```

Compile-check the Python files:

```bash
python -m py_compile Files/app.py Files/sort.py Files/test_configs.py
```

## Automation

The GitHub Actions workflow:

1. Runs on pushes to `main`.
2. Can be started manually with `workflow_dispatch`.
3. Runs automatically every 5 minutes.
4. Installs the pinned dependency ranges from `Files/requirements.txt`.
5. Runs the unit tests.
6. Generates and sorts the subscriptions.
7. Commits generated output changes back to the repository.

Concurrent scheduled runs are prevented from publishing overlapping updates.

## Data Quality

This project performs automated data hygiene, including:

- supported-protocol detection;
- duplicate removal;
- invalid/garbage-line filtering;
- Base64 decoding validation;
- URL/config remark normalization;
- protocol-specific classification;
- split-file count validation through tests.

These checks are **format and data-quality checks**, not live endpoint health checks. A syntactically valid URI can still be expired, unreachable, rate-limited, or otherwise unusable.

## Disclaimer

This repository is an automated aggregator of publicly available configuration data. The maintainers do not guarantee the availability, performance, security, legality, or privacy properties of any individual configuration or upstream source.

Users are responsible for evaluating and using configurations in accordance with applicable laws, network policies, and the terms of the services they access.

## License

See [`LICENSE`](./LICENSE).

---

<div align="center">

[![GitHub last commit](https://img.shields.io/github/last-commit/mrdevmohamed/v2ray-configs.svg?style=for-the-badge)](https://github.com/mrdevmohamed/v2ray-configs)
[![Update Configs](https://img.shields.io/github/actions/workflow/status/mrdevmohamed/v2ray-configs/main.yml?style=for-the-badge&label=Auto%20Update)](https://github.com/mrdevmohamed/v2ray-configs/actions/workflows/main.yml)
[![Repo Size](https://img.shields.io/github/repo-size/mrdevmohamed/v2ray-configs.svg?style=for-the-badge)](https://github.com/mrdevmohamed/v2ray-configs)
[![License](https://img.shields.io/badge/License-GPLv3-blue.svg?style=for-the-badge)](./LICENSE)

</div>
