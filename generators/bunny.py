#!/usr/bin/env python3
"""bunny.net CDN edge addresses.

  https://api.bunny.net/system/edgeserverlist

A flat JSON array of bare edge IPs (read as /32s). Same call as Cloudflare and
Fastly: a shared CDN edge that fronts third-party customer sites, including
abusive ones, so it is OPT-IN and stays out of all-safe.txt. Opt in only if you
specifically trust bunny.net edges in front of your own infrastructure.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common as common  # noqa: E402

NAME = "bunny"
SAFE = False  # shared CDN edge
URL = "https://api.bunny.net/system/edgeserverlist"


def transform(payload):
    """Pure: ["1.2.3.4", ...] -> list[ip_network]."""
    if not isinstance(payload, list):
        return []
    return common.to_networks(payload)


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
