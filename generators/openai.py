#!/usr/bin/env python3
"""OpenAI's published bot ranges.

OpenAI publishes one JSON file per bot, in Google's ipranges shape:

  https://openai.com/gptbot.json        GPTBot        (training crawler)
  https://openai.com/searchbot.json     OAI-SearchBot (ChatGPT search index)
  https://openai.com/chatgpt-user.json  ChatGPT-User  (user/agent-triggered)

We emit two products with different safety:

  openai                (SAFE)    GPTBot + OAI-SearchBot. Scheduled crawlers
      run by OpenAI itself; nothing third-party originates from them, and
      dropping them just makes your site invisible to ChatGPT.

  openai-user-fetchers  (OPT-IN)  ChatGPT-User. These addresses fetch a URL
      *because some user or agent asked ChatGPT to*, so arbitrary third parties
      choose the target -- the same "abuse can come through it" shape as an
      egress proxy. The IPs are OpenAI's, but the intent behind the request is
      not, so this stays out of all-safe.txt.

Note these ranges are Azure addresses assigned to OpenAI, not Azure service tags
-- we are not ingesting customer cloud space, only the specific prefixes OpenAI
publishes as its own. They do move, which is why the feed is re-read hourly-ish.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common as common  # noqa: E402

CRAWLER_NAME = "openai"
USER_NAME = "openai-user-fetchers"

GPTBOT_URL = "https://openai.com/gptbot.json"
SEARCHBOT_URL = "https://openai.com/searchbot.json"
CHATGPT_USER_URL = "https://openai.com/chatgpt-user.json"


def transform(gptbot, searchbot, chatgpt_user):
    """Pure: three ipranges payloads -> {name: list[ip_network]}."""
    crawlers = common.extract_prefix_entries(gptbot)
    crawlers += common.extract_prefix_entries(searchbot)
    return {
        CRAWLER_NAME: common.to_networks(crawlers),
        USER_NAME: common.to_networks(common.extract_prefix_entries(chatgpt_user)),
    }


def fetch():
    return (
        common.fetch_json(GPTBOT_URL),
        common.fetch_json(SEARCHBOT_URL),
        common.fetch_json(CHATGPT_USER_URL),
    )


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
