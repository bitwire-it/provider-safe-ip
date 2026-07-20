#!/usr/bin/env python3
"""AWS ranges from https://ip-ranges.amazonaws.com/ip-ranges.json, filtered by
service. We emit two very different products:

  aws-cloudfront        (OPT-IN / shared)  service == "CLOUDFRONT"
      CloudFront is a shared CDN that fronts third-party (including abusive)
      customer sites, so this stays OUT of all-safe.txt.

  aws-r53-healthchecks  (SAFE)             service == "ROUTE53_HEALTHCHECKS"
      These are AWS's own Route 53 health-check probe sources -- AWS
      infrastructure, not customer workloads -- so this IS safe.

We never emit the generic "AMAZON"/"EC2" services: those are customer compute.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common as common  # noqa: E402

URL = "https://ip-ranges.amazonaws.com/ip-ranges.json"

CLOUDFRONT_NAME = "aws-cloudfront"
R53_NAME = "aws-r53-healthchecks"


def extract_service(payload, service):
    """Pull ip_prefix / ipv6_prefix strings for one AWS service value."""
    out = []
    for entry in payload.get("prefixes", []):
        if isinstance(entry, dict) and entry.get("service") == service:
            value = entry.get("ip_prefix")
            if isinstance(value, str):
                out.append(value)
    for entry in payload.get("ipv6_prefixes", []):
        if isinstance(entry, dict) and entry.get("service") == service:
            value = entry.get("ipv6_prefix")
            if isinstance(value, str):
                out.append(value)
    return out


def transform(payload):
    """Pure: ip-ranges payload -> {name: list[ip_network]}."""
    return {
        CLOUDFRONT_NAME: common.to_networks(extract_service(payload, "CLOUDFRONT")),
        R53_NAME: common.to_networks(extract_service(payload, "ROUTE53_HEALTHCHECKS")),
    }


def fetch():
    return common.fetch_json(URL)


def build():
    products = transform(fetch())
    return [
        (CLOUDFRONT_NAME, False, products[CLOUDFRONT_NAME]),  # shared CDN, opt-in
        (R53_NAME, True, products[R53_NAME]),                 # AWS's own probes, safe
    ]


def main():
    for name, _safe, nets in build():
        count = common.write_list(name, nets)
        print(f"{name}: {count} CIDRs")


if __name__ == "__main__":
    main()
