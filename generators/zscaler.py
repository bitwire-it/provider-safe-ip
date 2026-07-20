#!/usr/bin/env python3
"""Zscaler ZEN / cloud enforcement node ranges (OPT-IN / shared egress proxy).

  https://config.zscaler.com/api/zscaler.net/cenr/json

IMPORTANT: although these are Zscaler-owned IPs, ZEN nodes are an *egress
proxy* -- they carry many organizations' outbound (customer/third-party)
traffic. Blanket-excluding them would let abuse that happens to egress through
Zscaler pass a blocklist. That is exactly the "third-party workloads" case the
project's core principle says never to put in the default list.

So this is provided as OPT-IN only (NOT in all-safe.txt). Opt in only if you
specifically trust Zscaler egress in your threat model.

The CENR payload nests {continent: {city: [{"range": ...}, ...]}} and also a
top-level "svpnIPs" list. We collect both, parsing defensively.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common as common  # noqa: E402

NAME = "zscaler"
SAFE = False  # egress proxy carrying customer traffic -- opt-in only
URL = "https://config.zscaler.com/api/zscaler.net/cenr/json"


def _collect_ranges(node, out):
    """Recursively gather every value stored under a "range" key."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "range" and isinstance(value, str):
                out.append(value)
            else:
                _collect_ranges(value, out)
    elif isinstance(node, list):
        for value in node:
            _collect_ranges(value, out)


def transform(payload):
    """Pure: CENR payload -> list[ip_network]. Collects nested "range" values
    plus the flat "svpnIPs" host list; non-IP strings are dropped."""
    strings = []
    _collect_ranges(payload, strings)
    svpn = payload.get("svpnIPs")
    if isinstance(svpn, list):
        strings.extend(v for v in svpn if isinstance(v, str))
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
