#!/usr/bin/env python3
"""Datadog's own service ranges.

  https://ip-ranges.datadoghq.com/

Keyed by function (api, agents, apm, logs, webhooks, synthetics, ...), each with
prefixes_ipv4 / prefixes_ipv6 arrays.

Included: everything Datadog runs itself -- the intake endpoints your agents ship
to, the webhook senders, and the Synthetics probe sources. Synthetics probes are
the same shape as the Route 53 health checkers this project already treats as
safe: Datadog-owned hosts probing endpoints on a customer's instruction.

Excluded: `synthetics-private-locations`. Private locations are workers a
customer runs inside their *own* network, so those addresses are not Datadog
infrastructure at all.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common as common  # noqa: E402

NAME = "datadog"
SAFE = True
URL = "https://ip-ranges.datadoghq.com/"

# Customer-run workers, not Datadog infrastructure.
EXCLUDE_KEYS = ("synthetics-private-locations",)


def transform(payload):
    """Pure: ip-ranges payload -> list[ip_network]. Non-dict sections (version,
    modified) and excluded keys are skipped."""
    strings = []
    for key, section in payload.items():
        if key in EXCLUDE_KEYS or not isinstance(section, dict):
            continue
        for family in ("prefixes_ipv4", "prefixes_ipv6"):
            values = section.get(family)
            if not isinstance(values, list):
                continue
            for item in values:
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
