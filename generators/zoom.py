#!/usr/bin/env python3
"""Zoom's own service ranges from Zoom's published firewall list.

  https://assets.zoom.us/docs/ipranges/Zoom.txt

This is the aggregate list Zoom documents for firewall/proxy allowlisting. The
ranges are Zoom's own meeting/media/web infrastructure (not customer compute),
so they are safe to exclude. The file is one CIDR per line; we still parse
defensively in case comment or blank lines appear.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common as common  # noqa: E402

NAME = "zoom"
SAFE = True
URL = "https://assets.zoom.us/docs/ipranges/Zoom.txt"


def transform(text):
    """Pure: newline-delimited text -> list[ip_network]. Non-CIDR lines skipped."""
    lines = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        lines.append(line)
    return common.to_networks(lines)


def fetch():
    return common.fetch_text(URL)


def build():
    return [(NAME, SAFE, transform(fetch()))]


def main():
    for name, _safe, nets in build():
        count = common.write_list(name, nets)
        print(f"{name}: {count} CIDRs")


if __name__ == "__main__":
    main()
