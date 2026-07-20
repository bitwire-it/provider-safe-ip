#!/usr/bin/env python3
"""Synthetic-payload unit tests for every generator transform + shared helpers.

Pure functions only -- no network. Run with:  python3 -m pytest tests/  or
                                               python3 tests/test_transforms.py
"""

import ipaddress
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "generators"))

import _common as common  # noqa: E402
import apple  # noqa: E402
import aws  # noqa: E402
import cloudflare  # noqa: E402
import fastly  # noqa: E402
import github  # noqa: E402
import google  # noqa: E402
import microsoft365  # noqa: E402
import zoom  # noqa: E402
import zscaler  # noqa: E402


def nets(strings):
    return {str(n) for n in common.to_networks(strings)}


# --------------------------------------------------------------------------
# _common helpers
# --------------------------------------------------------------------------

def test_to_networks_skips_junk():
    got = nets([
        "192.30.252.0/22",            # valid v4
        "2001:4860:4860::8888/128",   # valid v6
        "ssh-ed25519 AAAAC3Nza...",   # SSH key
        "github.com",                 # hostname
        "",                           # empty
        "   ",                        # blank
        None,                         # null
        12345,                        # non-str
        "999.999.999.999/8",          # invalid octets
    ])
    assert got == {"192.30.252.0/22", "2001:4860:4860::8888/128"}


def test_to_networks_tolerates_host_bits():
    # strict=False: host bits allowed, normalized to network address
    assert nets(["10.0.0.5/24"]) == {"10.0.0.0/24"}


def test_render_deterministic_and_dual_stack():
    payload = [
        "10.0.1.0/24", "10.0.0.0/24",         # unsorted v4, adjacent -> collapse
        "2001:db8:1::/48", "2001:db8::/48",   # unsorted v6
    ]
    out1 = common.render(common.to_networks(payload))
    out2 = common.render(common.to_networks(list(reversed(payload))))
    assert out1 == out2                       # order-independent
    assert out1.endswith("\n")
    lines = out1.strip().split("\n")
    # v4 collapses 10.0.0.0/24 + 10.0.1.0/24 -> 10.0.0.0/23, listed before v6
    assert lines[0] == "10.0.0.0/23"
    assert ":" in lines[-1]                   # v6 last


def test_collapse_dual_dedupes():
    out = common.collapse_dual(common.to_networks(["1.1.1.0/24", "1.1.1.0/24", "1.1.1.128/25"]))
    assert [str(n) for n in out] == ["1.1.1.0/24"]


def test_subtract_partial_carve():
    # 8.8.8.0/24 minus 8.8.8.128/25 == 8.8.8.0/25  (the canonical example)
    base = common.to_networks(["8.8.8.0/24"])
    remove = common.to_networks(["8.8.8.128/25"])
    out = [str(n) for n in common.subtract_dual(base, remove)]
    assert out == ["8.8.8.0/25"]


def test_subtract_full_removal():
    base = common.to_networks(["10.0.0.0/24"])
    remove = common.to_networks(["10.0.0.0/23"])  # base entirely inside remove
    assert common.subtract_dual(base, remove) == []


def test_subtract_disjoint_untouched():
    base = common.to_networks(["10.0.0.0/24"])
    remove = common.to_networks(["192.168.0.0/24"])
    out = [str(n) for n in common.subtract_dual(base, remove)]
    assert out == ["10.0.0.0/24"]


def test_subtract_dual_stack_independent():
    base = common.to_networks(["8.8.8.0/24", "2001:4860::/32"])
    remove = common.to_networks(["8.8.8.128/25", "2001:4860:8000::/33"])
    out = [str(n) for n in common.subtract_dual(base, remove)]
    assert out == ["8.8.8.0/25", "2001:4860::/33"]


# --------------------------------------------------------------------------
# github
# --------------------------------------------------------------------------

def test_github_includes_only_own_keys_and_excludes_shared():
    meta = {
        "hooks": ["192.30.252.0/22"],
        "web": ["185.199.108.0/22"],
        "api": ["140.82.112.0/20"],
        "git": ["140.82.112.0/20"],
        "pages": ["185.199.108.0/22"],
        "packages": ["2606:50c0::/32"],
        "actions": ["13.64.0.0/16"],       # shared Azure -> MUST be excluded
        "dependabot": ["4.0.0.0/8"],       # shared -> excluded
        "copilot": ["20.0.0.0/8"],         # shared -> excluded
        "ssh_key_fingerprints": {"SHA256": "..."},  # non-list -> skipped
    }
    got = {str(n) for n in github.transform(meta)}
    assert "13.64.0.0/16" not in got
    assert "4.0.0.0/8" not in got
    assert "20.0.0.0/8" not in got
    assert "192.30.252.0/22" in got
    assert "2606:50c0::/32" in got


def test_github_handles_null_and_missing_keys():
    # `importer` removed at one point; keys may be null
    meta = {"hooks": None, "web": ["185.199.108.0/22"]}
    got = {str(n) for n in github.transform(meta)}
    assert got == {"185.199.108.0/22"}


def test_github_containment_of_known_ips():
    meta = {"api": ["140.82.112.0/20"], "pages": ["185.199.108.0/22"]}
    cidrs = github.transform(meta)
    assert any(ipaddress.ip_address("140.82.112.4") in n for n in cidrs)
    assert any(ipaddress.ip_address("185.199.108.153") in n for n in cidrs)


# --------------------------------------------------------------------------
# google  (goog - cloud)
# --------------------------------------------------------------------------

def test_google_subtracts_cloud():
    goog = {"prefixes": [
        {"ipv4Prefix": "8.8.8.0/24"},
        {"ipv4Prefix": "142.250.0.0/16"},
        {"ipv6Prefix": "2001:4860:4860::/48"},
    ]}
    cloud = {"prefixes": [
        {"ipv4Prefix": "8.8.8.128/25"},    # carve out of 8.8.8.0/24
        {"ipv4Prefix": "34.128.0.0/10"},   # GCP range not present in goog -> no-op
    ]}
    got = {str(n) for n in google.transform(goog, cloud)}
    assert "8.8.8.0/25" in got             # remainder after carve
    assert "8.8.8.128/25" not in got       # removed
    assert "142.250.0.0/16" in got         # untouched
    assert "2001:4860:4860::/48" in got    # v6 untouched
    # goog dns + a well-known Google v6 stay inside the result
    assert any(ipaddress.ip_address("8.8.8.8") in n for n in google.transform(goog, cloud))


def test_google_extract_prefixes_defensive():
    payload = {"prefixes": [
        {"ipv4Prefix": "1.2.3.0/24"},
        {"ipv6Prefix": "2001:db8::/32"},
        {"garbage": "x"},                  # no prefix key
        "not-a-dict",
    ]}
    assert google.extract_prefixes(payload) == ["1.2.3.0/24", "2001:db8::/32"]


# --------------------------------------------------------------------------
# microsoft365
# --------------------------------------------------------------------------

def test_m365_collects_ips_arrays():
    endpoints = [
        {"id": 1, "ips": ["13.107.6.152/31", "2603:1006::/40"]},
        {"id": 2, "urls": ["outlook.office.com"]},          # no ips -> skipped
        {"id": 3, "ips": None},                              # null -> skipped
        {"id": 4, "ips": ["40.104.0.0/15"]},
    ]
    got = {str(n) for n in microsoft365.transform(endpoints)}
    assert got == {"13.107.6.152/31", "2603:1006::/40", "40.104.0.0/15"}


# --------------------------------------------------------------------------
# apple
# --------------------------------------------------------------------------

def test_apple_is_the_whole_eight():
    got = {str(n) for n in apple.transform(apple.APPLE_RANGES)}
    assert got == {"17.0.0.0/8"}
    assert any(ipaddress.ip_address("17.253.144.10") in n for n in apple.transform(apple.APPLE_RANGES))


# --------------------------------------------------------------------------
# zoom
# --------------------------------------------------------------------------

def test_zoom_parses_txt_with_comments():
    text = "# Zoom ranges\n3.7.35.0/25\n\n  15.220.80.0/24  \n2620:123:2000::/40\n"
    got = {str(n) for n in zoom.transform(text)}
    assert got == {"3.7.35.0/25", "15.220.80.0/24", "2620:123:2000::/40"}


# --------------------------------------------------------------------------
# aws (cloudfront opt-in + r53 healthchecks safe)
# --------------------------------------------------------------------------

def test_aws_service_filtering():
    payload = {
        "prefixes": [
            {"ip_prefix": "13.32.0.0/15", "service": "CLOUDFRONT"},
            {"ip_prefix": "52.46.0.0/18", "service": "ROUTE53_HEALTHCHECKS"},
            {"ip_prefix": "10.0.0.0/8", "service": "EC2"},          # customer -> excluded
            {"ip_prefix": "3.5.140.0/22", "service": "AMAZON"},     # generic -> excluded
        ],
        "ipv6_prefixes": [
            {"ipv6_prefix": "2600:9000::/28", "service": "CLOUDFRONT"},
        ],
    }
    products = aws.transform(payload)
    cf = {str(n) for n in products[aws.CLOUDFRONT_NAME]}
    r53 = {str(n) for n in products[aws.R53_NAME]}
    assert cf == {"13.32.0.0/15", "2600:9000::/28"}
    assert r53 == {"52.46.0.0/18"}
    # customer compute never leaks into either product
    assert "10.0.0.0/8" not in cf and "10.0.0.0/8" not in r53
    assert "3.5.140.0/22" not in cf and "3.5.140.0/22" not in r53


def test_aws_build_marks_safety_flags():
    # cloudfront must be opt-in (safe=False); r53 healthchecks must be safe=True.
    # We only check the static flags via a stub payload.
    payload = {"prefixes": [
        {"ip_prefix": "13.32.0.0/15", "service": "CLOUDFRONT"},
        {"ip_prefix": "52.46.0.0/18", "service": "ROUTE53_HEALTHCHECKS"},
    ], "ipv6_prefixes": []}
    saved = aws.fetch
    aws.fetch = lambda: payload
    try:
        products = {name: safe for name, safe, _ in aws.build()}
    finally:
        aws.fetch = saved
    assert products[aws.CLOUDFRONT_NAME] is False
    assert products[aws.R53_NAME] is True


# --------------------------------------------------------------------------
# cloudflare / fastly / zscaler (opt-in)
# --------------------------------------------------------------------------

def test_cloudflare_merges_v4_v6():
    v4 = "173.245.48.0/20\n103.21.244.0/22\n"
    v6 = "2400:cb00::/32\n2606:4700::/32\n"
    got = {str(n) for n in cloudflare.transform(v4, v6)}
    assert got == {"173.245.48.0/20", "103.21.244.0/22", "2400:cb00::/32", "2606:4700::/32"}
    assert cloudflare.SAFE is False


def test_fastly_reads_both_arrays():
    payload = {"addresses": ["23.235.32.0/20"], "ipv6_addresses": ["2a04:4e40::/32"]}
    got = {str(n) for n in fastly.transform(payload)}
    assert got == {"23.235.32.0/20", "2a04:4e40::/32"}
    assert fastly.SAFE is False


def test_zscaler_walks_nested_ranges_and_svpn():
    payload = {
        "zscaler.net": {
            "continent : EMEA": {
                "city : Amsterdam": [
                    {"range": "147.161.156.0/24", "latitude": "52.37", "longitude": "4.89"},
                    {"range": "2a03:eec0:3900::/40", "hostname": "ams.zscaler"},
                ]
            }
        },
        "svpnIPs": ["165.225.240.56", "2a03:eec0:1211::30", "not-an-ip"],
    }
    got = {str(n) for n in zscaler.transform(payload)}
    assert "147.161.156.0/24" in got
    assert "2a03:eec0:3900::/40" in got
    assert "165.225.240.56/32" in got
    assert "2a03:eec0:1211::30/128" in got
    # coordinates and hostnames must NOT be parsed as networks
    assert not any(s.startswith("52.") for s in got)
    assert zscaler.SAFE is False


# --------------------------------------------------------------------------
# runner
# --------------------------------------------------------------------------

if __name__ == "__main__":
    funcs = [v for k, v in sorted(globals().items()) if k.startswith("test_") and callable(v)]
    failed = 0
    for fn in funcs:
        try:
            fn()
            print(f"PASS {fn.__name__}")
        except AssertionError as err:
            failed += 1
            print(f"FAIL {fn.__name__}: {err}")
        except Exception as err:  # noqa: BLE001
            failed += 1
            print(f"ERROR {fn.__name__}: {err!r}")
    print(f"\n{len(funcs) - failed}/{len(funcs)} passed")
    sys.exit(1 if failed else 0)
