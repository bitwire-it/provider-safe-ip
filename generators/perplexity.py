#!/usr/bin/env python3
"""Perplexity's published bot ranges.

  https://www.perplexity.com/perplexitybot.json    PerplexityBot   (crawler)
  https://www.perplexity.com/perplexity-user.json  Perplexity-User (user-triggered)

Same split as OpenAI: the scheduled crawler is Perplexity's own traffic and is
SAFE, while Perplexity-User fetches a page because a user asked a question, so
third parties choose the target and it is OPT-IN.

The .com URLs are the ones Perplexity documents; they redirect to www.perplexity.ai,
which urllib follows.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common as common  # noqa: E402

CRAWLER_NAME = "perplexity"
USER_NAME = "perplexity-user-fetchers"

BOT_URL = "https://www.perplexity.com/perplexitybot.json"
USER_URL = "https://www.perplexity.com/perplexity-user.json"


def transform(bot, user):
    """Pure: two ipranges payloads -> {name: list[ip_network]}."""
    return {
        CRAWLER_NAME: common.to_networks(common.extract_prefix_entries(bot)),
        USER_NAME: common.to_networks(common.extract_prefix_entries(user)),
    }


def fetch():
    return common.fetch_json(BOT_URL), common.fetch_json(USER_URL)


def build():
    products = transform(*fetch())
    return [
        (CRAWLER_NAME, True, products[CRAWLER_NAME]),
        (USER_NAME, False, products[USER_NAME]),
    ]


def main():
    for name, _safe, nets in build():
        count = common.write_list(name, nets)
        print(f"{name}: {count} CIDRs")


if __name__ == "__main__":
    main()
