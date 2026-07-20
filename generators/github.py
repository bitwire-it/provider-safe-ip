#!/usr/bin/env python3
"""GitHub's own service ranges from https://api.github.com/meta.

Include ONLY keys that are GitHub's own infrastructure (hooks/web/api/git/
pages/packages + the enterprise importer). We deliberately EXCLUDE actions,
dependabot and copilot: those run customer/third-party workloads on shared
Azure ranges, and excluding them would blind a blocklist to real abuse.

Fields can be null or missing (the `importer` key was removed at one point),
so we filter to `type == str` before parsing and never let a null crash the run.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _common as common  # noqa: E402

NAME = "github"
SAFE = True
URL = "https://api.github.com/meta"

# GitHub's own service ranges only. NOT actions/dependabot/copilot (shared Azure).
INCLUDE_KEYS = (
    "hooks",
    "web",
    "api",
    "git",
    "pages",
    "packages",
    "github_enterprise_importer",
    "importer",
)


def transform(meta):
    """Pure: dict payload -> list[ip_network]. Tolerant of null/missing keys and
    non-string entries (e.g. SSH key fingerprints living in other keys)."""
    strings = []
    for key in INCLUDE_KEYS:
        value = meta.get(key)
        if not isinstance(value, list):
            continue  # missing or null -> skip, never crash
        for entry in value:
            if isinstance(entry, str):
                strings.append(entry)
    return common.to_networks(strings)


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
