#!/usr/bin/env python3
"""Microsoft 365 service ranges from the official Office endpoints service.

  https://endpoints.office.com/endpoints/worldwide?clientrequestid=<uuid4>

We collect the "ips" arrays from every endpoint set. This is M365 (Exchange
Online, SharePoint, Teams, etc.) ONLY -- we deliberately do NOT ingest Azure
service tags, which describe customer-controlled Azure ranges.
"""

import os
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common as common  # noqa: E402

NAME = "microsoft365"
SAFE = True
BASE_URL = "https://endpoints.office.com/endpoints/worldwide"


def transform(endpoints):
    """Pure: list-of-endpoint-dicts -> list[ip_network]. Entries without an
    "ips" key (URL-only endpoints) are skipped."""
    strings = []
    for entry in endpoints:
        if not isinstance(entry, dict):
            continue
        ips = entry.get("ips")
        if not isinstance(ips, list):
            continue
        for ip in ips:
            if isinstance(ip, str):
                strings.append(ip)
    return common.to_networks(strings)


def fetch():
    url = f"{BASE_URL}?clientrequestid={uuid.uuid4()}"
    return common.fetch_json(url)


def build():
    return [(NAME, SAFE, transform(fetch()))]


def main():
    for name, _safe, nets in build():
        count = common.write_list(name, nets)
        print(f"{name}: {count} CIDRs")


if __name__ == "__main__":
    main()
