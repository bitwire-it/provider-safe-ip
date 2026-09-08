#!/usr/bin/env python3
"""Meta's own service ranges (facebook.com, instagram.com, whatsapp.com,
threads.net, messenger.com) from AS32934.

Meta publishes no HTTPS IP feed. The source Meta itself documents -- in the
crawler docs at https://developers.facebook.com/docs/sharing/webmasters/crawler/
-- is an IRR query:

    whois -h whois.radb.net -- '-i origin AS32934'

We run exactly that query (RFC 3912 over TCP/43, stdlib socket), with one
hardening step: **only RPKI-derived route objects are kept**.

Why that matters for a whitelist: anyone can register a plain `route:` object in
RADB for a prefix they do not hold, and an attacker who did so under
`origin: AS32934` would land their own range in this exclusion feed -- i.e.
whitelist themselves past a downstream blocklist. RADB also mirrors the RPKI as
route objects (IRRd's RPKI-to-IRR conversion, `source: RPKI # Trust Anchor:
<rir>`). Those come from ROAs cryptographically signed by the address holder
under an RIR trust anchor, so they cannot be forged by a third party. Keeping
only those trades a little completeness for a feed that cannot be poisoned.

Safety: AS32934 carries Meta's own production edge (the sites above, their APIs,
the Facebook crawler and webhook senders). Meta does not sell compute on it, so
there are no third-party workloads inside. Meta's corporate ASNs (AS54115,
AS63293) are deliberately NOT included: they carry office/employee egress, not
the services this feed exists to keep reachable.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common as common  # noqa: E402

NAME = "meta"
SAFE = True

WHOIS_HOST = "whois.radb.net"
ASN = "AS32934"
QUERY = f"-i origin {ASN}"

# Only IRR objects converted from the RPKI are trusted (see module docstring).
TRUSTED_SOURCE_PREFIX = "RPKI"

# A truncated whois read would silently shrink the feed instead of failing. The
# ROA set for AS32934 is in the high hundreds; anything far below that means the
# response was cut short or the format changed, so fail loudly instead.
MIN_EXPECTED_ROUTES = 100


def parse_route_objects(text):
    """Pure: RADB whois output -> [(prefix, source), ...] in file order.

    RPSL objects are blank-line separated `key: value` blocks; continuation
    lines start with whitespace and are ignored. Only route/route6 objects that
    carry a source are returned. The source of an RPKI-derived object looks like
    ``RPKI  # Trust Anchor: ripe``, so the trailing comment is stripped.
    """
    routes = []
    prefix = None
    source = None

    def flush():
        if prefix and source:
            routes.append((prefix, source))

    for raw in text.splitlines():
        if not raw.strip():
            flush()
            prefix = source = None
            continue
        if raw[:1].isspace():
            continue  # continuation of the previous attribute (remarks, ...)
        if ":" not in raw:
            continue
        key, value = raw.split(":", 1)
        key = key.strip().lower()
        value = value.split("#", 1)[0].strip()
        if key in ("route", "route6"):
            prefix = value
        elif key == "source":
            source = value
    flush()
    return routes


def transform(text, minimum=MIN_EXPECTED_ROUTES):
    """Pure: whois text -> list[ip_network], RPKI-sourced objects only."""
    strings = [
        prefix
        for prefix, source in parse_route_objects(text)
        if source.upper().startswith(TRUSTED_SOURCE_PREFIX)
    ]
    if len(strings) < minimum:
        raise RuntimeError(
            f"only {len(strings)} RPKI-validated routes for {ASN} "
            f"(expected >= {minimum}) -- refusing a truncated feed"
        )
    return common.to_networks(strings)


def fetch():
    return common.whois_query(QUERY, host=WHOIS_HOST)


def build():
    return [(NAME, SAFE, transform(fetch()))]


def main():
    for name, _safe, nets in build():
        count = common.write_list(name, nets)
        print(f"{name}: {count} CIDRs")


if __name__ == "__main__":
    main()
