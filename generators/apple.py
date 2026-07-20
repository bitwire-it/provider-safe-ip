#!/usr/bin/env python3
"""Apple's service ranges.

Apple owns the entire 17.0.0.0/8 legacy Class A block and uses it for its own
services (apple.com, iCloud, App Store, push, etc.). There is no per-service
machine-readable feed, so the whole /8 is hardcoded -- it is exclusively
Apple's own infrastructure.

Ref: ARIN WHOIS for 17.0.0.0/8 (Apple Inc., NET-17-0-0-0-1).
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common as common  # noqa: E402

NAME = "apple"
SAFE = True

# Apple Inc. owns all of 17.0.0.0/8 (ARIN NET-17-0-0-0-1).
APPLE_RANGES = ["17.0.0.0/8"]


def transform(ranges):
    """Pure: list[str] -> list[ip_network]."""
    return common.to_networks(ranges)


def build():
    return [(NAME, SAFE, transform(APPLE_RANGES))]


def main():
    for name, _safe, nets in build():
        count = common.write_list(name, nets)
        print(f"{name}: {count} CIDRs")


if __name__ == "__main__":
    main()
