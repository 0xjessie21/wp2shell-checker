<div align="center">

```
██╗    ██╗██████╗ ██████╗ ███████╗██╗  ██╗███████╗██╗     ██╗
██║    ██║██╔══██╗╚════██╗██╔════╝██║  ██║██╔════╝██║     ██║
██║ █╗ ██║██████╔╝ █████╔╝███████╗███████║█████╗  ██║     ██║
██║███╗██║██╔═══╝ ██╔═══╝ ╚════██║██╔══██║██╔══╝  ██║     ██║
╚███╔███╔╝██║     ███████╗███████║██║  ██║███████╗███████╗███████╗
 ╚══╝╚══╝ ╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
```

### 🔍 Checker detector for the WordPress Core REST Batch API pre-auth RCE

[![Python](https://img.shields.io/badge/python-3.7%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Severity](https://img.shields.io/badge/CVSS-9.8%20CRITICAL-red?logo=hackthebox&logoColor=white)](#)
[![Status](https://img.shields.io/badge/mode-non--destructive-brightgreen)](#)
[![Scope](https://img.shields.io/badge/use-authorized%20testing%20only-yellow)](#warning-disclaimer--read-before-use)
[![License](https://img.shields.io/badge/license-MIT-lightgrey)](#license)
[![Made With](https://img.shields.io/badge/made%20with-%E2%9D%A4%EF%B8%8F%20%26%20Python-informational)](#)

<br/>

> 🛡️ **Created by [`0xjessie21`](https://github.com/0xjessie21) — Cybersecurity ILCS**

</div>

---

## 📌 Overview

| | |
|---|---|
| 🎯 **Signature** | wp2shell / WP Core REST Batch API Desync |
| 🔥 **Severity** | `9.8 CRITICAL` — `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| ☠️ **Affected versions** | WordPress `6.9.0–6.9.4` and `7.0.0–7.0.1` |
| ✅ **Fixed in** | `6.9.5`, `7.0.2` |
| 🔓 **Preconditions** | None — unauthenticated, no plugins, default config |
| 🟢 **Mode** | Non-destructive / read-only probe |

---

## 📸 Evidence

> Screenshot of the tool detecting a vulnerable WordPress instance in an authorized internal VAPT engagement.

<div align="center">

![Evidence](./evidence.png)

</div>

---

## ⚠️ Disclaimer — Read Before Use

> **This tool is strictly for authorized security testing and defensive verification purposes only.**

| | |
|---|---|
| ✅ | Use **only** against WordPress instances you **own**, or have **explicit written authorization** to test (e.g. an approved internal VAPT scope). |
| ✅ | This probe is designed to be **non-destructive** — it targets a non-existent category ID (`0`) and stops at the permission-check layer, so no data is ever created, modified, or deleted. |
| ❌ | **Do not** modify the payload (e.g. change the category ID to a real one, or point it at other REST routes) to attempt actual exploitation. Doing so turns this from a *detector* into a *weaponized exploit* — which this tool is explicitly **not** built for and does not support. |
| ❌ | **Do not** publish, redistribute, or run this against systems outside your authorized scope. Unauthorized use against third-party systems may violate the **ITE Law (UU ITE)** in Indonesia and equivalent computer-misuse laws elsewhere. |
| ❌ | Provided **as-is, with no warranty**. The author and any associated organization accept **no liability** for misuse, damage, or legal consequences arising from use of this tool. |

> 📋 By using this tool you agree that you are solely responsible for ensuring your use complies with applicable law and your organization’s authorization policies.

---

## 🧠 How It Works

WordPress Core’s REST Batch API (`/wp-json/batch/v1`) keeps three parallel arrays in sync while resolving a batch of sub-requests. An intentionally malformed sub-request **desynchronizes** them — causing every subsequent sub-request to be dispatched using the **wrong handler and permission callback**.

This tool sends one crafted batch request and inspects the **response codes only**, never crossing into a state-changing operation.

| # | 📨 Sub-request | 🎯 Purpose |
|---|---|---|
| 0 | `POST http://:` | 💥 Intentionally malformed — triggers the index desync |
| 1 | `DELETE /wp/v2/categories/0` | 🔬 Safe “sensor” — category ID `0` never exists |
| 2 | `POST /wp/v2/block-renderer/core/paragraph` | 📡 Reference handler used to detect the leak |

**🧪 Verdict logic**

| Result | Verdict |
|---|---|
| ❌ `block_cannot_read` | **VULNERABLE** — permission check leaked from block-renderer handler |
| ✅ `rest_term_invalid` | **PATCHED** — categories handler responded correctly |
| ❓ no marker found | **INCONCLUSIVE** — WAF, API disabled, or non-WordPress |

Additionally, the tool performs **passive WAF/CDN fingerprinting** 🔎 from response headers:

> `Cloudflare` · `Sucuri` · `Akamai` · `AWS CloudFront` · `Imperva` · `Fastly` · `F5 BIG-IP` · `Wordfence`

---

## 🚀 Usage

```bash
# Basic scan
./wp2shell_checker.py https://your-site.com

# Multiple targets in one run
./wp2shell_checker.py https://site1.com https://site2.com https://site3.com

# Custom timeout
./wp2shell_checker.py https://your-site.com --timeout 20

# Show full raw request/response (payload, headers, body)
./wp2shell_checker.py https://your-site.com --raw

# Disable colors/animation (for logging to a file)
./wp2shell_checker.py https://your-site.com --no-color > scan_report.txt
```

<details>
<summary><strong>🚩 All flags</strong></summary>

<br/>

| 🏷️ Flag | 📝 Description |
|---|---|
| `targets` | One or more base URLs to scan **(required)** |
| `--query-param` | Force the `?rest_route=/batch/v1` form instead of auto-detecting |
| `--timeout N` | Request timeout in seconds (default: `10`) |
| `--no-color` | Disable ANSI colors and scan animation |
| `--raw` | Print full raw request/response payload and headers |

</details>

### ⚙️ Requirements

- 🐍 Python **3.7+**
- 📦 No external dependencies — standard library only

---

## 🔧 Remediation

If a target comes back **VULNERABLE** ❌:

1. ⬆️ **Update WordPress immediately** to `7.0.2` (or `6.9.5` on the 6.9 branch). Confirm the update actually applied.
2. 🔒 If an immediate update isn’t possible, apply a temporary mitigation:
   - Install **Disable WP REST API** plugin to block unauthenticated REST access.
   - Block `/wp-json/batch/v1` **and** `?rest_route=/batch/v1` at your WAF/reverse proxy — both forms must be blocked.
   - Deploy a must-use plugin requiring authentication for the batch route.
3. 📁 Inventory **every** WordPress instance in scope — staging and campaign sites are the ones that get missed.

---

## 📚 References

| 🔗 | |
|---|---|
| 🌐 | [wp2shell.com](https://wp2shell.com) — original checker & advisory, Searchlight Cyber |
| 📄 | [Hadrian Security — Technical Breakdown](https://hadrian.io/blog/wp2shell-a-pre-authentication-rce-in-wordpress-cores-rest-batch-api) |

---

## 📜 License

This project is licensed under the MIT License — see the [LICENSE](./LICENSE) file for details.

<div align="center">

---

🔐 **Cybersecurity ILCS** · built for internal defensive use

![Visitors](https://visitor-badge.laobi.icu/badge?page_id=0xjessie21.wp2shell)

</div>
