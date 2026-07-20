#!/usr/bin/env python3
"""Fastly edge ranges (OPT-IN / shared CDN).

  https://api.fastly.com/public-ip-list

Like Cloudflare, Fastly's edge fronts third-party customer sites, so this is
OPT-IN only and NOT part of all-safe.txt.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common as common  # noqa: E402

NAME = "fastly"
SAFE = False  # shared CDN edge -- opt-in only
URL = "https://api.fastly.com/public-ip-list"


def transform(payload):
    """Pure: {addresses, ipv6_addresses} -> list[ip_network]."""
    strings = []
    for key in ("addresses", "ipv6_addresses"):
        value = payload.get(key)
        if isinstance(value, list):
            strings.extend(v for v in value if isinstance(v, str))
    return common.to_networks(strings)


def fetch():
    return common.fetch_json(URL)


def build():
    return [(NAME, SAFE, transform(fetch()))]


def main():
    for name, _safe, nets in build():
        count = common.write_list(name, nets)
        print(f"{name}: {count} CIDRs")


if __name__ == "__main__":
    main()
