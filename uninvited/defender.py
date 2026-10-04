"""Blocklists in the formats defenders load directly: an nftables set file, a Zeek intel file and a
Suricata IP-reputation list. Each is a plain rendering of a list the feed already publishes.

Honesty note for the page and the docs: these were checked by hand against each tool's documented
format. They have not been loaded into a running nftables, Zeek or Suricata by this project. Say so
wherever they are offered until someone has.
"""
from __future__ import annotations

import ipaddress
from typing import Any

from .core import iso_utc
from .textsafe import csv_cell

# Suricata iprep: one category id per list, scores 0 to 127.
IPREP_CATEGORIES = {"attackers-7d": (1, "Uninvited attackers, 7 days"),
                    "tag-persistent-7d": (2, "Uninvited persistent attackers, 7 days")}


def _v4(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """IPv4 only: the set files below are typed, and the honeypot has no IPv6 listener yet."""
    out = []
    for r in rows:
        try:
            if ipaddress.ip_address(r["ip"]).version == 4:
                out.append(r)
        except ValueError:
            continue
    return out


def nft_name(stem: str) -> str:
    """The set a list loads into: attackers-7d is attackers_7d, tag-persistent-7d is persistent_7d.
    One set per list, so loading a second list never widens what the first one blocks."""
    return stem.removeprefix("tag-").replace("-", "_")


def nft_set(brand: str, site: str, stem: str, rows: list[dict[str, Any]], now: int) -> str:
    """A file for `nft -f`: declares the table and the list's own set, empties the set and fills it,
    so a cron job can reload it and an address that left the list leaves the set too. Blocking
    the set is a chain and a rule the operator adds once; they are in the comment, not applied."""
    ips = [r["ip"] for r in _v4(rows)]
    name = nft_name(stem)
    lines = [
        f"# {brand} blocklist as an nftables set ({site}), list {stem}, built {iso_utc(now)}",
        f"# {len(ips)} IPv4 addresses. Load with: nft -f this-file   (a reload replaces the set's contents)",
        "# Block with, once:",
        "#   nft add chain inet uninvited input '{ type filter hook input priority 0 ; policy accept ; }'",
        f"#   nft add rule inet uninvited input ip saddr @{name} drop",
        "table inet uninvited {",
        f"\tset {name} {{",
        "\t\ttype ipv4_addr",
        "\t\tflags interval",
        "\t}",
        "}",
        f"flush set inet uninvited {name}",
    ]
    if ips:
        lines.append(f"add element inet uninvited {name} {{ " + ", ".join(ips) + " }")
    return "\n".join(lines) + "\n"


def zeek_intel(brand: str, site: str, stem: str, rows: list[dict[str, Any]], now: int) -> str:
    """The Zeek intelligence framework format: a tab-separated file with a #fields header."""
    lines = ["#fields\tindicator\tindicator_type\tmeta.source\tmeta.desc\tmeta.url"]
    for r in rows:
        tags = ",".join(r.get("tags") or [])
        desc = (f"score {r.get('score')}" + (f" {tags}" if tags else "")).replace("\t", " ")
        lines.append("\t".join([r["ip"], "Intel::ADDR", f"{brand}", desc, f"https://{site}/#ip={r['ip']}"]))
    return "\n".join(lines) + "\n"


def iprep_categories() -> str:
    return "".join(f"{cid},{stem},{desc}\n" for stem, (cid, desc) in IPREP_CATEGORIES.items())


def iprep_list(stem: str, rows: list[dict[str, Any]]) -> str:
    """Suricata IP reputation: ip,category,reputation (0 to 127). The score is 0 to 100 here, so
    it maps straight through."""
    cid = IPREP_CATEGORIES[stem][0]
    out = []
    for r in _v4(rows):
        rep = max(0, min(127, int(r.get("score") or 0)))
        out.append(f"{csv_cell(r['ip'])},{cid},{rep}\n")
    return "".join(out)
