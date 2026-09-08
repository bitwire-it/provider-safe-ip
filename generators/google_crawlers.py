#!/usr/bin/env python3
"""Google's crawler ranges, published for bot verification.

  https://developers.google.com/static/crawling/ipranges/common-crawlers.json
      Googlebot and friends.
  https://developers.google.com/static/crawling/ipranges/special-crawlers.json
      AdsBot, APIs-Google, Google-Safety, ...

Both are Google's own fleets, so both are SAFE. They overlap goog.json (and
therefore usually lists/google.txt) heavily, but goog.json - cloud.json can carve
out a crawler prefix that also appears in cloud.json, so publishing the crawler
feeds explicitly guarantees Googlebot is never dropped -- collapse_addresses
merges the duplicates in all-safe.txt anyway.

NOT ingested: `user-triggered-fetchers.json`. Those fetches happen because a user
asked a Google product to pull a URL, and they leave from shared App Engine
(`*.gae.googleusercontent.com`) space -- customer-controlled workloads live on
the same ranges, which is exactly what this project keeps out. Google's own
user-triggered ranges (`user-triggered-fetchers-google.json`) are the same
third-party-intent gray zone as ChatGPT-User; they are already inside goog.json
if you want them.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common as common  # noqa: E402

NAME = "google-crawlers"
SAFE = True
BASE = "https://developers.google.com/static/crawling/ipranges"
COMMON_URL = f"{BASE}/common-crawlers.json"
SPECIAL_URL = f"{BASE}/special-crawlers.json"


def transform(common_payload, special_payload):
    """Pure: two ipranges payloads -> list[ip_network]."""
    strings = common.extract_prefix_entries(common_payload)
    strings += common.extract_prefix_entries(special_payload)
    return common.to_networks(strings)


def fetch():
    return common.fetch_json(COMMON_URL), common.fetch_json(SPECIAL_URL)


def build():
    return [(NAME, SAFE, transform(*fetch()))]


def main():
    for name, _safe, nets in build():
        count = common.write_list(name, nets)
        print(f"{name}: {count} CIDRs")


if __name__ == "__main__":
    main()
