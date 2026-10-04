"""Telling research scanners apart from actual attacks.

Shodan, Censys and Shadowserver sweep the whole internet continuously. Counting
their probes as "attacks" inflates every number on the dashboard and is the
sort of thing a security reader notices immediately.

Reverse DNS is the primary signal here rather than a CIDR list, because these
operators name their hosts deliberately so they can be identified, and the
names outlive the addresses. CIDRs go stale; `census1.shodan.io` does not.

A reverse name is a claim, not a fact: whoever controls the reverse zone of an
address can write anything in it. So a name has to resolve forward to the same
address before it is fully believed, and a host that is believed on a name alone
loses that the moment it tries a password or an exploit. See Classifier.classify.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

log = logging.getLogger("uninvited.classify")

# rDNS suffix -> operator. Matched against the resolved hostname.
RDNS_OPERATORS: list[tuple[str, str]] = [
    ("shodan.io", "Shodan"),
    ("censys-scanner.com", "Censys"),
    ("censys.io", "Censys"),
    ("shadowserver.org", "Shadowserver"),
    ("binaryedge.ninja", "BinaryEdge"),
    ("rapid7.com", "Rapid7 Sonar"),
    ("stretchoid.com", "Stretchoid"),
    ("onyphe.net", "Onyphe"),
    ("leakix.net", "LeakIX"),
    ("internet-census.org", "Internet Census"),
    ("alphastrike.io", "Alpha Strike"),
    ("driftnet.io", "Driftnet"),
    ("criminalip.com", "Criminal IP"),
    ("expanseinc.com", "Palo Alto Xpanse"),
    ("netsystemsresearch.com", "NetSystems Research"),
    ("bitsight.com", "BitSight"),
    ("securitytrails.com", "SecurityTrails"),
    ("ipip.net", "IPIP.net"),
    ("scanworld.net", "ScanWorld"),
    ("cyber.casa", "Cyber Casa"),
    ("probe.onyphe.net", "Onyphe"),
    ("recyber.net", "Recyber"),
    ("rwth-aachen.de", "RWTH Aachen (research)"),
    ("tu-berlin.de", "TU Berlin (research)"),
    ("aeza.network", "Aeza (research)"),
    ("qualys.com", "Qualys"),
    # A self-declared research crawler (its user agent points at nokia.com/genomecrawler)
    # that was being listed as an attacker. Its hosts are named crawlerNNN.deepfield.net.
    ("deepfield.net", "Nokia Deepfield (research)"),
    ("intrinsec.com", "Intrinsec"),
]

# Hostname fragments that are not full suffixes.
RDNS_FRAGMENTS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\bcensys\b", re.I), "Censys"),
    (re.compile(r"\bshodan\b", re.I), "Shodan"),
    (re.compile(r"\bscanner\b", re.I), "Unattributed scanner"),
    # No trailing boundary: these hostnames run straight into a node number,
    # as in researchscan812.eecs.umich.edu.
    (re.compile(r"researchscan", re.I), "Academic research scan"),
    (re.compile(r"internet-?measurement", re.I), "Internet measurement"),
    (re.compile(r"\bnetscan|scan-?node|masscan", re.I), "Unattributed scanner"),
    (re.compile(r"security\.?(scan|research)", re.I), "Security research"),
]

# Fallback ranges for operators whose hosts have no useful rDNS. Kept short on
# purpose: this list rots, the rDNS table does not.
STATIC_NETS: list[tuple[Any, str]] = [
    (ipaddress.ip_network("71.6.128.0/17"), "Shodan"),
    (ipaddress.ip_network("198.20.69.0/24"), "Shodan"),
    (ipaddress.ip_network("198.20.70.0/24"), "Shodan"),
    (ipaddress.ip_network("198.20.99.0/24"), "Shodan"),
    (ipaddress.ip_network("66.240.192.0/18"), "Shodan"),
    (ipaddress.ip_network("162.142.125.0/24"), "Censys"),
    (ipaddress.ip_network("167.94.138.0/24"), "Censys"),
    (ipaddress.ip_network("167.94.145.0/24"), "Censys"),
    (ipaddress.ip_network("167.94.146.0/24"), "Censys"),
    (ipaddress.ip_network("167.248.133.0/24"), "Censys"),
]

TOR_LIST_URL = "https://check.torproject.org/torbulkexitlist"

KIND_RESEARCH = "research"
KIND_TOR = "tor"
KIND_ATTACK = "attack"


DNS_WORKERS = 8      # lookups running at once
DNS_QUEUE = 24       # lookups waiting; past this a new address is classified without one
SKIPPED = object()   # what a lookup returns when the queue was full and it was not made


def forward_confirms(host: str, ip: str) -> bool:
    """Does `host` resolve to `ip`? Together with the reverse lookup that named the
    host, this is forward-confirmed reverse DNS, the check Google documents for
    telling its crawler from someone claiming to be it. Blocking."""
    try:
        want = ipaddress.ip_address(ip)
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (OSError, ValueError):
        return False
    for info in infos:
        try:
            if ipaddress.ip_address(info[4][0].split("%")[0]) == want:
                return True
        except ValueError:
            continue
    return False


class Classifier:
    def __init__(self, enable_rdns: bool = True, enable_tor: bool = True,
                 cache_size: int = 20000):
        self.enable_rdns = enable_rdns
        self.enable_tor = enable_tor
        self.cache: dict[str, tuple[str, str | None, bool]] = {}
        self.cache_size = cache_size
        self.tor_exits: set[str] = set()
        self._tor_loaded = 0.0
        self._dns_pool = ThreadPoolExecutor(DNS_WORKERS, thread_name_prefix="dns")
        self._dns_pending = 0

    # ------------------------------------------------------------------ tor

    async def refresh_tor(self) -> int:
        """Pull the Tor exit list. Cheap, and exits behave very differently."""
        if not self.enable_tor:
            return 0
        try:
            import urllib.request
            loop = asyncio.get_running_loop()

            def _fetch() -> str:
                with urllib.request.urlopen(TOR_LIST_URL, timeout=20) as r:
                    return r.read().decode("utf-8", "replace")

            body = await loop.run_in_executor(None, _fetch)
            exits = set()
            for line in body.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                try:
                    ipaddress.ip_address(line)
                except ValueError:
                    continue
                exits.add(line)
            if exits:
                self.tor_exits = exits
                self._tor_loaded = time.time()
                log.info("loaded %d Tor exit nodes", len(exits))
            return len(exits)
        except Exception as exc:
            log.warning("Tor exit list unavailable: %s", exc)
            return 0

    # --------------------------------------------------------------- lookup

    @staticmethod
    def _static_match(ip: str) -> str | None:
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for net, name in STATIC_NETS:
            if addr.version == net.version and addr in net:
                return name
        return None

    @staticmethod
    def _name_match(host: str) -> tuple[str, bool] | None:
        """-> (operator, named) for a reverse name that looks like a scanner.
        named is True for a suffix of a domain the operator owns (shodan.io) and
        False for a generic word anywhere in the name ("scanner"), which anyone
        can put in a name of their own."""
        h = host.lower().rstrip(".")
        for suffix, name in RDNS_OPERATORS:
            if h == suffix or h.endswith("." + suffix):
                return name, True
        for pattern, name in RDNS_FRAGMENTS:
            if pattern.search(h):
                return name, False
        return None

    async def _dns(self, fn, *args):
        """Run one blocking lookup on the DNS pool, never the default executor, so
        a stalled lookup cannot hold up database writes. A name server that answers
        slowly is the attacker's to run, so the queue is capped too: past the cap
        the lookup is not made and SKIPPED comes back. An error or a timeout is
        None, the same as no answer."""
        if self._dns_pending >= DNS_QUEUE:
            return SKIPPED
        self._dns_pending += 1
        loop = asyncio.get_running_loop()
        try:
            return await asyncio.wait_for(loop.run_in_executor(self._dns_pool, fn, *args), 4.0)
        except (TimeoutError, Exception):
            return None
        finally:
            self._dns_pending -= 1

    async def _rdns(self, ip: str):
        if not self.enable_rdns:
            return None
        return await self._dns(self._resolve, ip)

    @staticmethod
    def _resolve(ip: str) -> str | None:
        try:
            return socket.gethostbyaddr(ip)[0]
        except (OSError, socket.herror):
            return None

    async def classify(self, ip: str) -> dict[str, Any]:
        """-> {kind, label, rdns, confirmed}. Cached, so repeat offenders cost nothing.

        Anyone who controls the reverse zone for their own address can make it say
        anything, so a name is never taken at its word:

          * an address in a known scanner range is a scanner (it needs no name);
          * a name under an operator's own domain is believed once it resolves
            forward to the same address (confirmed), and provisionally when it does
            not, because some real operators publish no forward records. A
            provisional scanner is demoted by demote() the moment it submits a
            credential or an exploit, which no research scanner does;
          * a generic word like "scanner" in a name counts only when confirmed.
        """
        hit = self.cache.get(ip)
        if hit is not None:
            kind, label, confirmed = hit
            return {"kind": kind, "label": label, "rdns": None, "confirmed": confirmed}

        label = self._static_match(ip)
        kind = KIND_RESEARCH if label else None
        confirmed = bool(label)
        host = None
        degraded = False     # a lookup was skipped, so this answer must not be remembered

        if label is None:
            host = await self._rdns(ip)
            if host is SKIPPED:
                host, degraded = None, True
            match = self._name_match(host) if host else None
            if match:
                name, named = match
                answer = await self._dns(forward_confirms, host, ip)
                if answer is SKIPPED:
                    degraded = True
                confirmed = answer is True
                if confirmed or named:
                    label, kind = name, KIND_RESEARCH

        if label is None and ip in self.tor_exits:
            label, kind, confirmed = "Tor exit node", KIND_TOR, True

        if kind is None:
            kind, confirmed = KIND_ATTACK, True

        if not degraded:
            self._remember(ip, kind, label, confirmed)
        return {"kind": kind, "label": label, "rdns": host, "confirmed": confirmed}

    def _remember(self, ip: str, kind: str, label: str | None, confirmed: bool) -> None:
        if len(self.cache) >= self.cache_size:
            # Cheap eviction: the working set is recent attackers, and a cold
            # cache costs one DNS query.
            self.cache.clear()
        self.cache[ip] = (kind, label, confirmed)

    def demote(self, ip: str) -> None:
        """A scanner we only provisionally believed has attacked. It is an attacker
        from now on, and stays one even if its name later confirms."""
        self._remember(ip, KIND_ATTACK, None, True)


# Mirai's hardcoded credential table leaked with its source in 2016 and still
# drives a large share of Telnet traffic. Flagging these separates commodity
# botnet noise from someone actually guessing at your accounts.
MIRAI_PAIRS: set[tuple[str, str]] = {
    ("root", "xc3511"), ("root", "vizxv"), ("root", "admin"), ("admin", "admin"),
    ("root", "888888"), ("root", "xmhdipc"), ("root", "default"), ("root", "juantech"),
    ("root", "123456"), ("root", "54321"), ("support", "support"), ("root", ""),
    ("admin", "password"), ("root", "root"), ("root", "12345"), ("user", "user"),
    ("admin", ""), ("root", "pass"), ("admin", "admin1234"), ("root", "1111"),
    ("admin", "smcadmin"), ("admin", "1111"), ("root", "666666"), ("root", "password"),
    ("root", "1234"), ("root", "klv123"), ("Administrator", "admin"), ("service", "service"),
    ("supervisor", "supervisor"), ("guest", "guest"), ("guest", "12345"),
    ("admin1", "password"), ("administrator", "1234"), ("666666", "666666"),
    ("888888", "888888"), ("ubnt", "ubnt"), ("root", "klv1234"), ("root", "Zte521"),
    ("root", "hi3518"), ("root", "jvbzd"), ("root", "anko"), ("root", "zlxx."),
    ("root", "7ujMko0vizxv"), ("root", "7ujMko0admin"), ("root", "system"),
    ("root", "ikwb"), ("root", "dreambox"), ("root", "user"), ("root", "realtek"),
    ("root", "00000000"), ("admin", "1111111"), ("admin", "1234"), ("admin", "12345"),
    ("admin", "54321"), ("admin", "123456"), ("admin", "7ujMko0admin"),
    ("admin", "pass"), ("admin", "meinsm"), ("tech", "tech"), ("mother", "fucker"),
}


def is_mirai_pair(user: str | None, password: str | None) -> bool:
    if user is None or password is None:
        return False
    return (user, password) in MIRAI_PAIRS
