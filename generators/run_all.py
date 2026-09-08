#!/usr/bin/env python3
"""Run every provider generator, write each per-provider list, and build the
aggregate lists/all-safe.txt from the SAFE (non-CDN, non-egress-proxy) lists
only.

Failure policy: if a provider fails we still write every other provider's list
and the aggregate of what succeeded, but we exit non-zero so a scheduled run is
visibly red. A provider that fails does NOT overwrite its previously committed
list (we simply don't touch it), so a transient outage can't blank a good feed.
"""

import os
import sys
import traceback

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common as common  # noqa: E402

import anthropic
import apple
import atlassian
import aws
import bingbot
import bunny
import cloudflare
import datadog
import duckduckgo
import fastly
import github
import google
import google_crawlers
import meta
import microsoft365
import okta
import openai
import perplexity
import stripe
import telegram
import zoom
import zscaler

# Order is cosmetic (each writes its own file); aggregate is sorted anyway.
GENERATORS = [
    # provider services
    github,
    google,
    microsoft365,
    apple,
    meta,
    telegram,
    zoom,
    okta,
    stripe,
    datadog,
    atlassian,
    aws,
    # crawlers / AI fetchers
    google_crawlers,
    bingbot,
    duckduckgo,
    openai,
    anthropic,
    perplexity,
    # shared CDN / proxy edges
    cloudflare,
    fastly,
    bunny,
    zscaler,
]


def main():
    safe_networks = []
    failures = []

    for module in GENERATORS:
        mod_name = module.__name__
        try:
            products = module.build()
        except Exception as err:  # noqa: BLE001 -- one provider must not kill the rest
            failures.append(mod_name)
            sys.stderr.write(f"[error] generator '{mod_name}' failed: {err}\n")
            traceback.print_exc()
            continue

        for name, safe, nets in products:
            try:
                count = common.write_list(name, nets)
            except SystemExit as err:
                # empty-list guard tripped -> treat as a failure, keep old file
                failures.append(name)
                sys.stderr.write(f"[error] {err}\n")
                continue
            tag = "safe" if safe else "opt-in"
            print(f"{name:22s} {count:5d} CIDRs  [{tag}]")
            if safe:
                safe_networks.extend(nets)

    # Aggregate the safe lists. Guard against writing an empty aggregate.
    if safe_networks:
        agg = common.write_list("all-safe", safe_networks)
        print(f"{'all-safe':22s} {agg:5d} CIDRs  [aggregate]")
    else:
        failures.append("all-safe")
        sys.stderr.write("[error] no safe networks collected; not writing all-safe.txt\n")

    if failures:
        sys.stderr.write(f"\n[FAIL] {len(failures)} generator(s) failed: {', '.join(failures)}\n")
        sys.exit(1)

    print("\nAll generators succeeded.")


if __name__ == "__main__":
    main()
