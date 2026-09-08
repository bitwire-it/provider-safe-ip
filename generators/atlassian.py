#!/usr/bin/env python3
"""Atlassian Cloud ranges (Jira, Confluence, Bitbucket, Trello, Opsgenie, ...).

  https://ip-ranges.atlassian.com/

Each item carries a `cidr` plus `product`, `direction`, `region` and `perimeter`
tags. We publish every item -- but as OPT-IN, not safe.

Why opt-in: the tags show one shared egress pool. The same prefixes are tagged
`forge` (Atlassian's app platform, where *third-party* app code runs and makes
outbound calls) and `bitbucket` (whose egress includes Pipelines build runners).
That is third-party workload sharing provider addresses -- the Zscaler case, and
exactly what all-safe.txt is supposed to keep out. The addresses really are
Atlassian's, so if you want Jira/Confluence webhooks and Atlassian connectors to
survive your blocklist, opt in deliberately.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common as common  # noqa: E402

NAME = "atlassian"
SAFE = False  # shared with Forge apps / Pipelines -- see docstring
URL = "https://ip-ranges.atlassian.com/"


def transform(payload):
    """Pure: {"items": [{"cidr": ...}, ...]} -> list[ip_network]."""
    strings = []
    for item in payload.get("items", []):
        if not isinstance(item, dict):
            continue
        value = item.get("cidr")
        if isinstance(value, str):
            strings.append(value)
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
