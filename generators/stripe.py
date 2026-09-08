#!/usr/bin/env python3
"""Stripe's own service addresses.

  https://stripe.com/files/ips/ips_api.json       {"API": ["13.112.224.240", ...]}
  https://stripe.com/files/ips/ips_webhooks.json  {"WEBHOOKS": [...]}

Stripe publishes these for firewall allowlisting: the addresses its API answers
on, and the addresses its webhook senders originate from. Bare IPs (no mask);
ip_network() reads them as /32s.

Safe: Stripe's own infrastructure, no customer workloads. Payment webhooks that
a blocklist silently drops are a genuinely expensive failure mode, which is
what this feed prevents.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common as common  # noqa: E402

NAME = "stripe"
SAFE = True
API_URL = "https://stripe.com/files/ips/ips_api.json"
WEBHOOKS_URL = "https://stripe.com/files/ips/ips_webhooks.json"


def extract_lists(payload):
    """Pull every string out of every top-level array (keys are API/WEBHOOKS)."""
    out = []
    for value in payload.values():
        if not isinstance(value, list):
            continue
        for item in value:
            if isinstance(item, str):
                out.append(item)
    return out


def transform(api_payload, webhooks_payload):
    """Pure: two Stripe payloads -> list[ip_network]."""
    return common.to_networks(
        extract_lists(api_payload) + extract_lists(webhooks_payload)
    )


def fetch():
    return common.fetch_json(API_URL), common.fetch_json(WEBHOOKS_URL)


def build():
    return [(NAME, SAFE, transform(*fetch()))]


def main():
    for name, _safe, nets in build():
        count = common.write_list(name, nets)
        print(f"{name}: {count} CIDRs")


if __name__ == "__main__":
    main()
