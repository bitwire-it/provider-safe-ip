#!/usr/bin/env python3
"""Telegram's own service ranges from Telegram's published CIDR list.

  https://core.telegram.org/resources/cidr.txt

Telegram publishes this plain-text file for firewall allowlisting; it covers
Telegram's own datacenters -- the apps, the Bot API, and the servers that call
your registered bot webhook. Telegram runs no customer compute on it, so the
whole list is the provider's own infrastructure.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common as common  # noqa: E402

NAME = "telegram"
SAFE = True
URL = "https://core.telegram.org/resources/cidr.txt"


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
