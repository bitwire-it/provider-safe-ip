#!/usr/bin/env python3
"""Bingbot's ranges, published by Microsoft for crawler verification.

  https://www.bing.com/toolbox/bingbot.json

Microsoft's own search crawler (which also feeds Copilot and other Bing-backed
products). These are Azure addresses assigned to the crawler fleet, published by
Microsoft as bingbot's own -- not an Azure service tag, so no customer compute
comes with them. The M365 endpoints feed does not include them, so this is
additive rather than a duplicate of microsoft365.txt.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common as common  # noqa: E402

NAME = "bingbot"
SAFE = True
URL = "https://www.bing.com/toolbox/bingbot.json"


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
