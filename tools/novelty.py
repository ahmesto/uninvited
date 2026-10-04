"""How many of our listed attackers are on no other public list.

Reads four widely used free lists and compares them with the 7 day attacker list. Nothing is
stored and nothing is submitted anywhere; the lists are fetched into memory and dropped. Run it
by hand, with the owner's knowledge, because it reads third-party services:

    python tools/novelty.py https://dmz.ahmadmesto.com

The sources and their terms, as found on 2026-10-03:
  Feodo Tracker (abuse.ch) ip blocklist: CC0.
  blocklist.de all.txt: free to use, attribution asked for.
  Spamhaus DROP: free for non-commercial use.
  CINS Army list: free.
"""
from __future__ import annotations

import ipaddress
import sys
import urllib.request

SOURCES = {
    "Feodo Tracker": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "blocklist.de": "https://lists.blocklist.de/lists/all.txt",
    "Spamhaus DROP": "https://www.spamhaus.org/drop/drop.txt",
    "CINS Army": "https://cinsscore.com/list/ci-badguys.txt",
}
UA = {"User-Agent": "uninvited-novelty-check/1.0 (one read, nothing submitted)"}


def fetch(url: str) -> str:
    with urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=60) as r:
        return r.read().decode("utf-8", "replace")


def parse(text: str) -> tuple[set[str], list[ipaddress.IPv4Network]]:
    ips: set[str] = set()
    nets: list[ipaddress.IPv4Network] = []
    for line in text.splitlines():
        line = line.split(";")[0].split("#")[0].strip()
        if not line:
            continue
        token = line.split()[0]
        try:
            if "/" in token:
                nets.append(ipaddress.ip_network(token, strict=False))
            else:
                ips.add(str(ipaddress.ip_address(token)))
        except ValueError:
            continue
    return ips, nets


def main(site: str) -> None:
    ours = [l.strip() for l in fetch(f"{site}/feed/attackers-7d.txt").splitlines() if l.strip() and l[0] != "#"]
    persistent = [l.strip() for l in fetch(f"{site}/feed/tag-persistent-7d.txt").splitlines() if l.strip() and l[0] != "#"]
    print(f"ours: {len(ours)} on attackers-7d, {len(persistent)} on tag-persistent-7d")
    union: set[str] = set()
    for name, url in SOURCES.items():
        try:
            ips, nets = parse(fetch(url))
        except Exception as exc:
            print(f"{name:14s} could not be read: {exc}")
            continue
        hit = {ip for ip in ours if ip in ips or any(ipaddress.ip_address(ip) in n for n in nets)}
        union |= hit
        print(f"{name:14s} {len(ips):>7,} addresses {len(nets):>5,} ranges   overlap with ours: {len(hit):>4} ({100 * len(hit) / max(1, len(ours)):.1f}%)")
    novel = [ip for ip in ours if ip not in union]
    novel_p = [ip for ip in persistent if ip not in union]
    print(f"\nOn none of the four lists: {len(novel)} of {len(ours)} attackers ({100 * len(novel) / max(1, len(ours)):.1f}%), "
          f"{len(novel_p)} of {len(persistent)} persistent hosts ({100 * len(novel_p) / max(1, len(persistent)):.1f}%)")


if __name__ == "__main__":
    main(sys.argv[1].rstrip("/") if len(sys.argv) > 1 else "https://dmz.ahmadmesto.com")
