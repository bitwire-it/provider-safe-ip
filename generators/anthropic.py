#!/usr/bin/env python3
"""Anthropic's published bot ranges.

  https://claude.com/crawling/bots.json

Anthropic publishes a single file, in Google's ipranges shape, covering *all* of
its crawlers and agents together: ClaudeBot (training crawler), Claude-SearchBot
and Claude-User (pages fetched because a Claude user asked for them).

Because the file does not separate them, we cannot split the scheduled crawler
from the user-triggered fetcher the way OpenAI's per-bot files allow. A range
that carries user-chosen fetches is the same gray zone as an egress proxy --
the addresses are Anthropic's, but who they talk to is decided by third
parties -- so the whole list is published as OPT-IN and stays out of
all-safe.txt. Opt in if you want Claude to be able to read your site.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common as common  # noqa: E402

NAME = "anthropic"
SAFE = False  # mixed crawler + user-triggered agent fetches (see docstring)
URL = "https://claude.com/crawling/bots.json"


def transform(payload):
    """Pure: ipranges payload -> list[ip_network]."""
    return common.to_networks(common.extract_prefix_entries(payload))


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
