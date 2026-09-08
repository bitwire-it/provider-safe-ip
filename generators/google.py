#!/usr/bin/env python3
"""Google's own service ranges: goog.json MINUS cloud.json.

  goog.json  = every range Google announces (own services + GCP)
  cloud.json = GCP customer ranges (customer compute -- must stay OUT)

goog - cloud therefore leaves Google's own services (Search, Gmail front-ends,
crawlers, etc.). The subtraction is done with CIDR containment
(address_exclude), so a partial carve like 8.8.8.0/24 - 8.8.8.128/25 correctly
yields 8.8.8.0/25.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common as common  # noqa: E402

NAME = "google"
SAFE = True
GOOG_URL = "https://www.gstatic.com/ipranges/goog.json"
CLOUD_URL = "https://www.gstatic.com/ipranges/cloud.json"


def extract_prefixes(payload):
    """Pull ipv4Prefix / ipv6Prefix strings out of a gstatic ipranges payload."""
    return common.extract_prefix_entries(payload)


def transform(goog_payload, cloud_payload):
    """Pure: (goog, cloud) payloads -> list[ip_network] of goog minus cloud."""
    goog = common.to_networks(extract_prefixes(goog_payload))
    cloud = common.to_networks(extract_prefixes(cloud_payload))
    return common.subtract_dual(goog, cloud)


def fetch():
    return common.fetch_json(GOOG_URL), common.fetch_json(CLOUD_URL)


def build():
    goog_payload, cloud_payload = fetch()
    return [(NAME, SAFE, transform(goog_payload, cloud_payload))]


def main():
    for name, _safe, nets in build():
        count = common.write_list(name, nets)
        print(f"{name}: {count} CIDRs")


if __name__ == "__main__":
    main()
