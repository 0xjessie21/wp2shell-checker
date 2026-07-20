#!/usr/bin/env python3
"""
wp2shell Detector — Non-Destructive Probe
==========================================
Detects the pre-auth RCE vulnerability in WordPress Core's REST Batch API
(WP 6.9.0-6.9.4 and 7.0.0-7.0.1), based on the public technical analysis
by Hadrian Security:
https://hadrian.io/blog/wp2shell-a-pre-authentication-rce-in-wordpress-cores-rest-batch-api

How it works:
- Sends a single batch request containing 3 sub-requests:
  1. First sub-request is intentionally malformed to trigger index desync
  2. DELETE to /wp/v2/categories/0 (an ID that never exists -> safe, deletes nothing)
  3. POST to /wp/v2/block-renderer/core/paragraph (reference endpoint for verification)
- If the server is VULNERABLE: sub-request #2 receives the permission
  error belonging to the block-renderer handler ("block_cannot_read") ->
  indicating the request was evaluated against the wrong handler (desync).
- If the server is PATCHED: sub-request #2 returns the normal error
  ("rest_term_invalid") matching the correct categories handler.

This probe does NOT perform any destructive action:
- No credentials are sent (unauthenticated request)
- Category ID 0 never exists, so nothing is actually deleted
- Even on the vulnerable path, the request stops at the permission check
  (read-permission), never reaching the delete logic

IMPORTANT: Only use this against assets you are authorized to test
(e.g. domains owned by Pelindo/ILCS or within an approved VAPT scope).
"""

import argparse
import json
import random
import sys
import time
import urllib.request
import urllib.error


PROBE_PAYLOAD = {
    "validation": "normal",
    "requests": [
        {"method": "POST", "path": "http://:"},
        {"method": "DELETE", "path": "/wp/v2/categories/0"},
        {"method": "POST", "path": "/wp/v2/block-renderer/core/paragraph"},
    ],
}

VULNERABLE_MARKER = "block_cannot_read"
PATCHED_MARKER = "rest_term_invalid"

CVE_REF = "wp2shell / WP Core REST Batch API Desync"
CVSS_REF = "9.8 CRITICAL (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)"


class C:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    ITALIC = "\033[3m"
    BLINK = "\033[5m"
    GREEN = "\033[32m"
    BR_GREEN = "\033[92m"
    RED = "\033[31m"
    BR_RED = "\033[91m"
    YELLOW = "\033[33m"
    BR_YELLOW = "\033[93m"
    CYAN = "\033[36m"
    BR_CYAN = "\033[96m"
    MAGENTA = "\033[35m"
    WHITE = "\033[37m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLACK = "\033[40m"


VERDICT_STYLE = {
    "VULNERABLE": (C.BG_RED + C.WHITE + C.BOLD, "CRITICAL", C.BR_RED),
    "PATCHED / NOT VULNERABLE": (C.BG_GREEN + C.WHITE + C.BOLD, "SECURE", C.BR_GREEN),
    "INCONCLUSIVE": (C.BG_YELLOW + C.WHITE + C.BOLD, "UNKNOWN", C.BR_YELLOW),
    "UNKNOWN": (C.BG_YELLOW + C.WHITE + C.BOLD, "UNKNOWN", C.BR_YELLOW),
}

BANNER = r"""
██╗    ██╗██████╗ ██████╗ ███████╗██╗  ██╗███████╗██╗     ██╗
██║    ██║██╔══██╗╚════██╗██╔════╝██║  ██║██╔════╝██║     ██║
██║ █╗ ██║██████╔╝ █████╔╝███████╗███████║█████╗  ██║     ██║
██║███╗██║██╔═══╝ ██╔═══╝ ╚════██║██╔══██║██╔══╝  ██║     ██║
╚███╔███╔╝██║     ███████╗███████║██║  ██║███████╗███████╗███████╗
 ╚══╝╚══╝ ╚═╝     ╚══════╝╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
"""

WAF_SIGNATURES = [
    ("Cloudflare", ["cf-ray", "cf-cache-status", "__cfduid", "cf-request-id"], ["cloudflare"]),
    ("Sucuri", ["x-sucuri-id", "x-sucuri-cache"], ["sucuri"]),
    ("Akamai", ["akamai-x-cache", "x-akamai-transformed"], ["akamaighost"]),
    ("AWS WAF / CloudFront", ["x-amz-cf-id", "x-amz-cf-pop"], ["cloudfront"]),
    ("Imperva / Incapsula", ["x-iinfo", "x-cdn"], ["incap_ses", "visid_incap"]),
    ("Fastly", ["x-served-by", "x-fastly-request-id"], ["fastly"]),
    ("F5 BIG-IP ASM", ["x-waf-event-info"], ["big-ip", "bigipserver"]),
    ("Wordfence", [], ["wordfence"]),
    ("Generic WAF/Proxy", ["x-waf-status", "x-protected-by", "x-firewall"], []),
]


def detect_waf(response_headers, raw_body=""):
    headers_lower = {k.lower(): str(v).lower() for k, v in response_headers.items()}
    haystack = " ".join(headers_lower.values()) + " " + " ".join(headers_lower.keys()) + " " + raw_body.lower()

    for name, header_keys, body_markers in WAF_SIGNATURES:
        for hk in header_keys:
            if hk in headers_lower:
                return name, True
        for marker in body_markers:
            if marker in haystack:
                return name, True

    server = headers_lower.get("server", "")
    if any(x in server for x in ["cloudflare", "sucuri", "akamai", "cloudfront"]):
        return server, True

    return None, False
STATUS_ICON = {
    2: ("[OK]", C.GREEN),
    3: ("[->]", C.CYAN),
    4: ("[XX]", C.YELLOW),
    5: ("[!!]", C.RED),
}


def _icon_for_status(status):
    if not isinstance(status, int):
        return "[??]", C.DIM
    return STATUS_ICON.get(status // 100, ("[??]", C.DIM))


def hr(char="─", width=68, color=C.DIM):
    print(f"{color}{char * width}{C.RESET}")


def dhr(color=C.BR_GREEN):
    print(f"{color}{'═' * 68}{C.RESET}")


def section(title, color=C.BR_CYAN, icon="◈"):
    pad = max(0, 60 - len(title))
    print(f"\n{color}{C.BOLD}{icon} {title} {'─' * pad}{C.RESET}")


def type_out(text, delay=0.0015, color=""):
    for ch in text:
        sys.stdout.write(f"{color}{ch}{C.RESET}")
        sys.stdout.flush()
        time.sleep(delay)
    print()


def scan_animation(label, steps=28, delay=0.02):
    glyphs = "01"
    for i in range(steps + 1):
        filled = "▓" * i
        empty = "░" * (steps - i)
        pct = int(i / steps * 100)
        noise = "".join(random.choice(glyphs) for _ in range(6))
        sys.stdout.write(
            f"\r{C.BR_GREEN}[{filled}{C.DIM}{empty}{C.RESET}{C.BR_GREEN}] "
            f"{pct:3d}%  {C.DIM}{noise}{C.RESET}  {C.BR_GREEN}{label}{C.RESET}"
        )
        sys.stdout.flush()
        time.sleep(delay)
    sys.stdout.write("\r" + " " * 100 + "\r")
    sys.stdout.flush()


def print_banner():
    print(f"{C.BR_GREEN}{C.BOLD}{BANNER}{C.RESET}")
    dhr()
    print(f"{C.DIM}  target ..... {C.RESET}{C.BR_CYAN}WordPress Core REST Batch API{C.RESET}")
    print(f"{C.DIM}  signature .. {C.RESET}{CVE_REF}")
    print(f"{C.DIM}  severity ... {C.RESET}{C.BR_RED}{C.BOLD}{CVSS_REF}{C.RESET}")
    print(f"{C.DIM}  mode ....... {C.RESET}{C.BR_GREEN}non-destructive / read-only probe{C.RESET}")
    print(f"{C.DIM}  created by . {C.RESET}{C.BR_YELLOW}{C.BOLD}0xjessie21{C.RESET}{C.DIM} — Cybersecurity ILCS{C.RESET}")
    dhr()


def print_verdict_banner(verdict):
    style, tag, accent = VERDICT_STYLE.get(verdict, (C.BG_YELLOW + C.WHITE + C.BOLD, "UNKNOWN", C.BR_YELLOW))
    print()
    print(f"{style}  ⚠ THREAT LEVEL: {tag}  {C.RESET}")
    print(f"{accent}{C.BOLD}  » {verdict}{C.RESET}")


def _send_probe(endpoint: str, timeout: int):
    data = json.dumps(PROBE_PAYLOAD).encode("utf-8")
    req = urllib.request.Request(
        endpoint,
        data=data,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "wp2shell-internal-checker/1.0",
        },
        method="POST",
    )

    request_headers = dict(req.header_items())

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            status = resp.status
            response_headers = dict(resp.getheaders())
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        status = e.code
        response_headers = dict(e.headers.items()) if e.headers else {}
    except Exception as e:
        return None, str(e)

    return {
        "http_status": status,
        "request_headers": request_headers,
        "response_headers": response_headers,
        "raw_response": body,
    }, None


def check_target(base_url: str, timeout: int = 10, force_query_param: bool = False):
    base_url = base_url.rstrip("/")

    if force_query_param:
        candidates = [f"{base_url}/?rest_route=/batch/v1"]
    else:
        candidates = [
            f"{base_url}/wp-json/batch/v1",
            f"{base_url}/?rest_route=/batch/v1",
        ]

    last_error = None
    for endpoint in candidates:
        data, error = _send_probe(endpoint, timeout)

        if data is None:
            last_error = error
            continue

        if data["http_status"] == 404 and endpoint != candidates[-1]:
            continue

        result = {
            "target": base_url,
            "endpoint": endpoint,
            "http_status": data["http_status"],
            "verdict": "UNKNOWN",
            "detail": None,
            "request_payload": PROBE_PAYLOAD,
            "request_headers": data["request_headers"],
            "response_headers": data["response_headers"],
            "raw_response": data["raw_response"],
        }

        try:
            result["parsed_response"] = json.loads(data["raw_response"])
        except json.JSONDecodeError:
            result["parsed_response"] = None

        body = data["raw_response"]
        if VULNERABLE_MARKER in body:
            result["verdict"] = "VULNERABLE"
            result["detail"] = f"Found marker '{VULNERABLE_MARKER}' — indicates index desync (wp2shell)."
        elif PATCHED_MARKER in body:
            result["verdict"] = "PATCHED / NOT VULNERABLE"
            result["detail"] = f"Found marker '{PATCHED_MARKER}' — response matches the correct handler."
        else:
            result["verdict"] = "INCONCLUSIVE"
            result["detail"] = "No marker found (batch API may be disabled, blocked by a WAF, or this WP version does not support batch/v1)."

        return result

    return {
        "target": base_url,
        "endpoint": candidates[-1],
        "status": "ERROR",
        "detail": last_error or "All endpoint forms failed or returned 404.",
    }


def print_subrequest_table(payload, parsed_response):
    requests = payload.get("requests", [])

    if isinstance(parsed_response, dict) and "responses" in parsed_response:
        responses = parsed_response["responses"]
    elif isinstance(parsed_response, list):
        responses = parsed_response
    else:
        responses = []

    print(f"  {C.DIM}ID  METHOD  PATH{' ' * 31}STATUS  RESPONSE CODE{C.RESET}")
    hr("┈", 68, C.DIM)

    for i, sub_req in enumerate(requests):
        method = sub_req.get("method", "?")
        path = sub_req.get("path", "?")
        path_display = (path[:33] + "…") if len(path) > 34 else path

        entry = responses[i] if i < len(responses) else {}
        if not isinstance(entry, dict):
            entry = {}

        # A batch sub-response is normally {"status": int, "body": {...}, "headers": {...}}.
        # Some error entries put the WP_Error fields directly at the top level instead.
        status = entry.get("status")
        body = entry.get("body", entry)
        if not isinstance(body, dict):
            body = {}

        code = body.get("code", "-")
        if status is None:
            data = body.get("data")
            if isinstance(data, dict):
                status = data.get("status")

        icon, color = _icon_for_status(status)
        status_display = str(status) if status is not None else "-"

        flag = ""
        if code == VULNERABLE_MARKER:
            flag = f"  {C.BG_RED}{C.WHITE}{C.BOLD} ANOMALY: HANDLER HIJACK {C.RESET}"
        elif code == PATCHED_MARKER:
            flag = f"  {C.GREEN}✓ nominal{C.RESET}"

        print(f"  {i:<3} {method:<6}  {path_display:<34} {color}{icon}{C.RESET} {status_display:<5} {C.DIM}{code}{C.RESET}{flag}")

    hr("┈", 68, C.DIM)


def print_header_summary(headers, keys_of_interest):
    shown = {k: v for k, v in headers.items() if k in keys_of_interest}
    if not shown:
        print(f"  {C.DIM}(no notable headers exposed){C.RESET}")
        return
    for k, v in shown.items():
        print(f"  {C.DIM}▸{C.RESET} {C.BR_CYAN}{k}{C.RESET}: {v}")


def print_result(res, show_raw=False, animate=True):
    dhr(C.DIM)
    print(f"{C.BOLD}{C.BR_CYAN}◉ TARGET{C.RESET}   : {res['target']}")
    print(f"{C.BOLD}{C.BR_CYAN}◉ ENDPOINT{C.RESET} : {res['endpoint']}")
    if "http_status" in res:
        print(f"{C.BOLD}{C.BR_CYAN}◉ HTTP{C.RESET}     : {res['http_status']}")

    print_verdict_banner(res["verdict"])
    print(f"  {C.DIM}{C.ITALIC}{res.get('detail')}{C.RESET}")

    if res.get("status") == "ERROR":
        print(f"\n  {C.RED}✗ Probe failed: {res.get('detail')}{C.RESET}")
        dhr(C.DIM)
        return

    section("SUB-REQUEST BREAKDOWN", C.BR_CYAN, "◈")
    if res.get("parsed_response") is not None:
        print_subrequest_table(res["request_payload"], res["parsed_response"])
    else:
        print(f"  {C.YELLOW}Response was not valid JSON — rerun with --raw for full body.{C.RESET}")

    section("SERVER FINGERPRINT", C.BR_CYAN, "◈")
    print_header_summary(res["response_headers"], {"Server", "X-Powered-By", "Date", "Content-Type"})

    waf_name, waf_detected = detect_waf(res["response_headers"], res.get("raw_response", ""))
    print()
    if waf_detected:
        print(f"  {C.BG_GREEN}{C.WHITE}{C.BOLD} WAF DETECTED {C.RESET}  {C.BR_GREEN}{waf_name}{C.RESET}")
    else:
        print(f"  {C.BG_YELLOW}{C.WHITE}{C.BOLD} NO WAF SIGNATURE {C.RESET}  {C.DIM}no known WAF/CDN headers observed — passive check only, not conclusive{C.RESET}")

    if show_raw:
        section("RAW REQUEST PAYLOAD", C.MAGENTA, "◆")
        print(json.dumps(res["request_payload"], indent=2))

        section("RAW REQUEST HEADERS", C.MAGENTA, "◆")
        for k, v in res["request_headers"].items():
            print(f"  {C.DIM}{k}:{C.RESET} {v}")

        section("RAW RESPONSE HEADERS", C.MAGENTA, "◆")
        for k, v in res["response_headers"].items():
            print(f"  {C.DIM}{k}:{C.RESET} {v}")

        section("RAW RESPONSE BODY", C.MAGENTA, "◆")
        if res.get("parsed_response") is not None:
            print(json.dumps(res["parsed_response"], indent=2))
        else:
            print(res["raw_response"])

    dhr(C.DIM)


def print_summary(results):
    print(f"\n{C.BOLD}{C.BR_GREEN}◉ SCAN SUMMARY{C.RESET}")
    dhr()
    vuln_count = sum(1 for r in results if r.get("verdict") == "VULNERABLE")
    ok_count = sum(1 for r in results if r.get("verdict") == "PATCHED / NOT VULNERABLE")
    other_count = len(results) - vuln_count - ok_count

    for r in results:
        style, tag, accent = VERDICT_STYLE.get(r.get("verdict", "UNKNOWN"), (C.BG_YELLOW + C.WHITE + C.BOLD, "UNKNOWN", C.BR_YELLOW))
        print(f"  {style} {tag:<8} {C.RESET}  {r['target']:<38} {accent}{r.get('verdict')}{C.RESET}")

    dhr()
    print(f"  {C.BR_RED}{C.BOLD}{vuln_count} critical{C.RESET}  ·  "
          f"{C.BR_GREEN}{C.BOLD}{ok_count} secure{C.RESET}  ·  "
          f"{C.BR_YELLOW}{C.BOLD}{other_count} inconclusive{C.RESET}")
    dhr()


def main():
    parser = argparse.ArgumentParser(description="Non-destructive wp2shell detector")
    parser.add_argument("targets", nargs="+", help="Base URL of the WordPress site (e.g. https://example.com)")
    parser.add_argument("--query-param", action="store_true",
                         help="Skip auto-detection and force the ?rest_route=/batch/v1 form (by default the script tries /wp-json/batch/v1 first and falls back automatically on a 404)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout (seconds)")
    parser.add_argument("--no-color", action="store_true", help="Disable ANSI colors/animation")
    parser.add_argument("--raw", action="store_true", help="Also show full raw payload, headers, and response body")
    args = parser.parse_args()

    if args.no_color:
        for attr in vars(C):
            if not attr.startswith("_"):
                setattr(C, attr, "")

    print_banner()

    results = []
    for target in args.targets:
        print(f"\n{C.BR_GREEN}➤ initiating probe:{C.RESET} {C.BOLD}{target}{C.RESET}")
        if not args.no_color:
            scan_animation("analyzing batch/v1 dispatch...", steps=28, delay=0.014)
        res = check_target(target, timeout=args.timeout, force_query_param=args.query_param)
        results.append(res)
        print_result(res, show_raw=args.raw, animate=not args.no_color)

    print_summary(results)
    sys.exit(0)


if __name__ == "__main__":
    main()
