#!/usr/bin/env python3
"""DuckDuckGo's crawler ranges, published for bot verification.

  https://duckduckgo.com/duckduckbot.json

DuckDuckBot is DuckDuckGo's own crawler; the file is DuckDuckGo's published
list of the addresses it crawls from (mostly single /32s on Azure assigned to
DuckDuckGo). Scheduled crawler traffic only -- no third-party workloads.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common as common  # noqa: E402

NAME = "duckduckbot"
SAFE = True
URL = "https://duckduckgo.com/duckduckbot.json"


def transform(payload):
    """Pure: ipranges payload -> list[ip_network]."""
    return common.to_networks(common.extract_prefix_entries(payload))


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
