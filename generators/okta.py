#!/usr/bin/env python3
"""Okta's service cell ranges.

  https://s3.amazonaws.com/okta-ip-ranges/ip_ranges.json

The file Okta documents for allowlisting. It is keyed by cell (us_cell_1,
emea_cell_2, ...), each with an "ip_ranges" array; we take every cell, because a
tenant can live in any of them and an SSO login that a blocklist drops locks
people out of everything.

Safe: these are Okta's own auth service and hook-sender addresses -- Okta runs
no customer compute on them.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common as common  # noqa: E402

NAME = "okta"
SAFE = True
URL = "https://s3.amazonaws.com/okta-ip-ranges/ip_ranges.json"


def transform(payload):
    """Pure: {cell: {"ip_ranges": [...]}} -> list[ip_network]."""
    strings = []
    for cell in payload.values():
        if not isinstance(cell, dict):
            continue
        ranges = cell.get("ip_ranges")
        if not isinstance(ranges, list):
            continue
        for item in ranges:
            if isinstance(item, str):
                strings.append(item)
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
