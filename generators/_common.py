"""Shared helpers for provider-safe-ip generators.

Python 3 standard library only (urllib, json, ipaddress). Every network-facing
function retries with backoff and fails loudly, because a silently empty
exclusion feed would let blocked IPs through downstream consumers.

The transform-side helpers here are pure functions (no I/O) so generators can be
unit-tested against synthetic payloads.
"""

import ipaddress
import json
import os
import sys
import time
import urllib.error
import urllib.request

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

GENERATORS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(GENERATORS_DIR)
LISTS_DIR = os.path.join(REPO_ROOT, "lists")

USER_AGENT = "provider-safe-ip/1.0 (+https://github.com/bitwire-it/provider-safe-ip)"


# ---------------------------------------------------------------------------
# Fetching (network I/O, loud on failure)
# ---------------------------------------------------------------------------

def fetch_bytes(url, retries=3, backoff=2.0, timeout=30, headers=None):
    """Fetch a URL, retrying up to ``retries`` times with exponential backoff.

    Raises RuntimeError if every attempt fails. Never returns partial/empty
    content silently.
    """
    req_headers = {"User-Agent": USER_AGENT}
    if headers:
        req_headers.update(headers)

    last_err = None
    for attempt in range(1, retries + 1):
        try:
            req = urllib.request.Request(url, headers=req_headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read()
            if not data:
                raise RuntimeError("empty response body")
            return data
        except (urllib.error.URLError, RuntimeError, OSError) as err:
            last_err = err
            if attempt < retries:
                sleep_for = backoff ** attempt
                sys.stderr.write(
                    f"[warn] fetch {url} failed (attempt {attempt}/{retries}): "
                    f"{err}; retrying in {sleep_for:.1f}s\n"
                )
                time.sleep(sleep_for)

    raise RuntimeError(f"failed to fetch {url} after {retries} attempts: {last_err}")


def fetch_text(url, **kwargs):
    return fetch_bytes(url, **kwargs).decode("utf-8")


def fetch_json(url, **kwargs):
    return json.loads(fetch_bytes(url, **kwargs).decode("utf-8"))


# ---------------------------------------------------------------------------
# Parsing (pure)
# ---------------------------------------------------------------------------

def to_networks(strings):
    """Parse an iterable of candidate strings into ip_network objects.

    Defensive: anything that is not a valid IPv4/IPv6 network (SSH keys,
    hostnames, ``None``, coordinates, empty strings, ...) is silently skipped
    via try/except ValueError -- never regex-based guessing. Host bits are
    tolerated (strict=False).
    """
    out = []
    for item in strings:
        if not isinstance(item, str):
            continue
        candidate = item.strip()
        if not candidate:
            continue
        try:
            out.append(ipaddress.ip_network(candidate, strict=False))
        except ValueError:
            # not an IP network -- skip quietly, this is expected for mixed feeds
            continue
    return out


def _split_families(networks):
    v4 = [n for n in networks if n.version == 4]
    v6 = [n for n in networks if n.version == 6]
    return v4, v6


def collapse_dual(networks):
    """Collapse + dedupe + sort per family, returning v4 networks then v6.

    ipaddress.collapse_addresses() only accepts a single family, so each family
    is collapsed independently. Output order is deterministic: ascending v4,
    then ascending v6, so identical input yields byte-identical output.
    """
    v4, v6 = _split_families(networks)
    collapsed = []
    if v4:
        collapsed.extend(sorted(ipaddress.collapse_addresses(v4)))
    if v6:
        collapsed.extend(sorted(ipaddress.collapse_addresses(v6)))
    return collapsed


def _subtract_one(net, remove_nets):
    """Return the list of networks covering ``net`` minus every net in
    ``remove_nets`` (same family). CIDR blocks are always either nested or
    disjoint -- never partially overlapping -- so containment logic is exact.
    """
    for rem in remove_nets:
        if rem.version != net.version:
            continue
        if net.subnet_of(rem):
            # net is entirely inside a removed range -> gone
            return []
        if rem.subnet_of(net):
            # rem is strictly inside net -> split net around it, recurse on pieces
            pieces = []
            for part in net.address_exclude(rem):
                pieces.extend(_subtract_one(part, remove_nets))
            return pieces
        # otherwise disjoint w.r.t. this rem -- keep checking others
    return [net]


def subtract_dual(base, remove):
    """Compute (union of base) minus (union of remove) using CIDR containment
    (address_exclude / subnet_of), never string comparison. Handles v4 and v6.

    Example: 8.8.8.0/24 minus 8.8.8.128/25 == 8.8.8.0/25.
    """
    base_v4, base_v6 = _split_families(base)
    rem_v4, rem_v6 = _split_families(remove)

    result = []
    for fam_base, fam_rem in ((base_v4, rem_v4), (base_v6, rem_v6)):
        if not fam_base:
            continue
        collapsed_base = list(ipaddress.collapse_addresses(fam_base))
        collapsed_rem = list(ipaddress.collapse_addresses(fam_rem)) if fam_rem else []
        for net in collapsed_base:
            result.extend(_subtract_one(net, collapsed_rem))
    return collapse_dual(result)


# ---------------------------------------------------------------------------
# Rendering / writing
# ---------------------------------------------------------------------------

def render(networks):
    """Render networks to deterministic text: collapsed, deduped, ascending per
    family (v4 then v6), one CIDR per line, trailing newline.
    """
    lines = [str(n) for n in collapse_dual(networks)]
    return "\n".join(lines) + "\n"


def write_list(name, networks):
    """Write ``lists/<name>.txt`` atomically. Refuses to write an empty list so
    a bad transform can never clobber a good committed file with nothing.

    Returns the number of CIDRs written.
    """
    text = render(networks)
    if not text.strip():
        raise SystemExit(f"refusing to write empty list for '{name}'")

    os.makedirs(LISTS_DIR, exist_ok=True)
    path = os.path.join(LISTS_DIR, name + ".txt")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    os.replace(tmp, path)
    return text.count("\n")
