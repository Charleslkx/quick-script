#!/usr/bin/env python3
"""Convert VLESS subscription links to Quantumult X server lines."""

from __future__ import annotations

import argparse
import base64
import re
import sys
import urllib.parse
import urllib.request


VLESS_PATTERN = re.compile(r"vless://[^\s]+", re.IGNORECASE)
TRUE_VALUES = {"1", "true", "yes", "on"}


def read_source(source: str | None) -> str:
    if not source or source == "-":
        return sys.stdin.read()

    parsed = urllib.parse.urlparse(source)
    if parsed.scheme.lower() == "vless":
        return source
    if parsed.scheme in {"http", "https"}:
        request = urllib.request.Request(
            source,
            headers={"User-Agent": "quick-script-vless-converter/1.0"},
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            return response.read().decode("utf-8", errors="replace")

    with open(source, "r", encoding="utf-8") as file:
        return file.read()


def maybe_decode_base64(text: str) -> str:
    compact = "".join(text.split())
    if not compact or "vless://" in text.lower():
        return text

    if not re.fullmatch(r"[A-Za-z0-9+/=_-]+", compact):
        return text

    normalized = compact.replace("-", "+").replace("_", "/")
    normalized += "=" * (-len(normalized) % 4)
    try:
        decoded = base64.b64decode(normalized, validate=False)
    except ValueError:
        return text

    decoded_text = decoded.decode("utf-8", errors="replace")
    if "vless://" in decoded_text.lower():
        return decoded_text
    return text


def extract_vless_links(text: str) -> list[str]:
    decoded_text = maybe_decode_base64(text)
    links = []
    for match in VLESS_PATTERN.finditer(decoded_text):
        links.append(match.group(0).strip().rstrip(",;"))
    return links


def first_param(params: dict[str, list[str]], *names: str) -> str:
    for name in names:
        values = params.get(name)
        if values and values[0] != "":
            return values[0]
    return ""


def is_true(value: str) -> bool:
    return value.strip().lower() in TRUE_VALUES


def quote_qx_value(value: str) -> str:
    return value.replace(",", "%2C")


def build_vless_line(link: str) -> str:
    parsed = urllib.parse.urlparse(link)
    if parsed.scheme.lower() != "vless":
        raise ValueError(f"not a vless link: {link}")
    if not parsed.username:
        raise ValueError(f"missing UUID: {link}")
    if not parsed.hostname:
        raise ValueError(f"missing host: {link}")
    if not parsed.port:
        raise ValueError(f"missing port: {link}")

    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"

    uuid = urllib.parse.unquote(parsed.username)
    tag = urllib.parse.unquote(parsed.fragment) if parsed.fragment else f"{parsed.hostname}:{parsed.port}"
    network = first_param(params, "type", "network").lower()
    security = first_param(params, "security", "tls").lower()
    sni = first_param(params, "sni", "peer", "servername")
    obfs_host = first_param(params, "host")
    path = first_param(params, "path", "serviceName")
    flow = first_param(params, "flow")
    public_key = first_param(params, "pbk", "publicKey", "reality-base64-pubkey")
    short_id = first_param(params, "sid", "shortId", "reality-hex-shortid")

    fields = [
        f"vless={host}:{parsed.port}",
        "method=none",
        f"password={quote_qx_value(uuid)}",
    ]

    if network == "ws":
        fields.append("obfs=wss" if security in {"tls", "reality"} else "obfs=ws")
        if obfs_host or sni:
            fields.append(f"obfs-host={quote_qx_value(obfs_host or sni)}")
        if path:
            fields.append(f"obfs-uri={quote_qx_value(urllib.parse.unquote(path))}")
    elif network == "http":
        fields.append("obfs=http")
        if obfs_host or sni:
            fields.append(f"obfs-host={quote_qx_value(obfs_host or sni)}")
        if path:
            fields.append(f"obfs-uri={quote_qx_value(urllib.parse.unquote(path))}")
    elif security in {"tls", "reality"}:
        fields.append("obfs=over-tls")
        if sni:
            fields.append(f"obfs-host={quote_qx_value(sni)}")

    if public_key:
        fields.append(f"reality-base64-pubkey={quote_qx_value(public_key)}")
    if short_id:
        fields.append(f"reality-hex-shortid={quote_qx_value(short_id)}")
    if flow:
        fields.append(f"vless-flow={quote_qx_value(flow)}")

    allow_insecure = first_param(params, "allowInsecure", "allow_insecure", "skip-cert-verify")
    if is_true(allow_insecure):
        fields.append("tls-verification=false")

    udp = first_param(params, "udp", "udp-relay")
    fields.append(f"udp-relay={'true' if is_true(udp) else 'false'}")
    fields.append(f"tag={quote_qx_value(tag)}")
    return ", ".join(fields)


def convert(source_text: str) -> list[str]:
    lines = []
    for link in extract_vless_links(source_text):
        lines.append(build_vless_line(link))
    return lines


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Convert VLESS links or subscriptions to Quantumult X server lines.",
    )
    parser.add_argument(
        "source",
        nargs="?",
        help="Subscription URL, local file path, or '-' for stdin.",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Write converted Quantumult X lines to this file.",
    )
    parser.add_argument(
        "--with-section",
        action="store_true",
        help="Wrap output in a [server_local] section.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    source_text = read_source(args.source)
    lines = convert(source_text)
    if not lines:
        print("No VLESS links found.", file=sys.stderr)
        return 1

    output_lines = ["[server_local]", *lines] if args.with_section else lines
    output_text = "\n".join(output_lines) + "\n"
    if args.output:
        with open(args.output, "w", encoding="utf-8") as file:
            file.write(output_text)
    else:
        sys.stdout.write(output_text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
