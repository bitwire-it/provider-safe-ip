#!/usr/bin/env python3
"""Cloudflare edge ranges (OPT-IN / shared CDN).

  https://www.cloudflare.com/ips-v4
  https://www.cloudflare.com/ips-v6

Cloudflare's edge proxies third-party sites -- including abusive ones -- so
excluding these could blind a blocklist. This list is OPT-IN only and is NOT
part of all-safe.txt. Consumers who terminate/trust Cloudflare in front of
their own infra can opt in.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common as common  # noqa: E402

NAME = "cloudflare"
SAFE = False  # shared CDN edge -- opt-in only
V4_URL = "https://www.cloudflare.com/ips-v4"
V6_URL = "https://www.cloudflare.com/ips-v6"


def transform(v4_text, v6_text):
    """Pure: two newline-delimited blobs -> list[ip_network]."""
    lines = []
    for text in (v4_text, v6_text):
        for raw in text.splitlines():
            line = raw.strip()
            if line and not line.startswith("#"):
                lines.append(line)
    return common.to_networks(lines)


def fetch():
    return common.fetch_text(V4_URL), common.fetch_text(V6_URL)


def build():
    v4_text, v6_text = fetch()
    return [(NAME, SAFE, transform(v4_text, v6_text))]


def main():
    for name, _safe, nets in build():
        count = common.write_list(name, nets)
        print(f"{name}: {count} CIDRs")


if __name__ == "__main__":
    main()
