"""Turning telemetry into findings.

Two jobs. `campaigns()` groups hosts that behave alike, because twelve
addresses replaying one credential list is a single actor, not twelve events.
`narrate()` writes the plain-English version, because a wall of counters shows
data and a sentence shows you can read it.

Deterministic and template-driven on purpose: no API key, no per-request cost,
no dependency that can go down and take the panel with it.
"""
from __future__ import annotations

import math
import re
import time
from typing import Any

from .classify import MIRAI_PAIRS

# Credentials that name the product they ship on. Knowing these is the
# difference between logging a string and reading the ecosystem.
CRED_LORE: dict[str, str] = {
    "xc3511": "XiongMai camera firmware default",
    "vizxv": "Dahua DVR default",
    "juantech": "Jovision camera default",
    "xmhdipc": "XiongMai IP camera default",
    "klv123": "HiSilicon DVR default",
    "klv1234": "HiSilicon DVR default",
    "zte521": "ZTE router backdoor",
    "hi3518": "HiSilicon SoC default",
    "7ujmko0admin": "Dahua hardcoded backdoor",
    "7ujmko0vizxv": "Dahua hardcoded backdoor",
    "ubnt": "Ubiquiti factory default",
    "raspberry": "Raspberry Pi default, never changed",
    "smcadmin": "SMC router default",
    "anko": "ANKO DVR default",
    "dreambox": "Dreambox satellite receiver default",
    "realtek": "Realtek SDK default",
    "meinsm": "Sanyo/Zhone default",
    "adtec": "ADTEC broadcast device default",
}

# Usernames that reveal what the attacker is hunting for.
TARGET_LORE: list[tuple[re.Pattern, str]] = [
    (re.compile(r"^eth[-_]?docker|^geth$|^validator$|^besu$", re.I), "Ethereum node operators"),
    (re.compile(r"^pfsense$|^opnsense$", re.I), "firewall appliances"),
    (re.compile(r"^ubnt$|^unifi$", re.I), "Ubiquiti gear"),
    (re.compile(r"^oracle$|^weblogic$", re.I), "Oracle middleware"),
    (re.compile(r"^postgres$|^mysql$|^mongodb$|^redis$", re.I), "database servers"),
    (re.compile(r"^jenkins$|^gitlab$|^git$|^runner$", re.I), "CI and source control"),
    (re.compile(r"^docker$|^kube|^k8s$", re.I), "container infrastructure"),
    (re.compile(r"^minecraft$|^steam$|^ark$", re.I), "game servers"),
    (re.compile(r"^solana$|^sol$|^bitcoin$|^btc$|^node$", re.I), "crypto infrastructure"),
    (re.compile(r"^pi$", re.I), "Raspberry Pi devices"),
    (re.compile(r"^nagios$|^zabbix$|^prometheus$", re.I), "monitoring systems"),
    (re.compile(r"^ftpuser$|^backup$", re.I), "file transfer accounts"),
]


def _is_mirai(cred: str) -> bool:
    user, _, password = cred.partition(":")
    return (user, password) in MIRAI_PAIRS


def _is_replay(cred: str) -> bool:
    """High-entropy passwords are not guesses, they are leaked and replayed."""
    _, _, password = cred.partition(":")
    if len(password) < 10:
        return False
    classes = sum([
        bool(re.search(r"[a-z]", password)),
        bool(re.search(r"[A-Z]", password)),
        bool(re.search(r"[0-9]", password)),
        bool(re.search(r"[^A-Za-z0-9]", password)),
    ])
    return classes >= 3


def _target_of(cred: str) -> str | None:
    user = cred.partition(":")[0]
    for pattern, what in TARGET_LORE:
        if pattern.search(user):
            return what
    return None


def _style(creds: set[str]) -> tuple[str, str]:
    """(slug, human phrase) describing how a group is guessing."""
    if not creds:
        return "recon", "connecting without offering credentials"
    mirai = sum(1 for c in creds if _is_mirai(c))
    replay = sum(1 for c in creds if _is_replay(c))
    total = len(creds)
    if mirai / total >= 0.4:
        return "mirai", "cycling Mirai's hardcoded credential table"
    if replay / total >= 0.4:
        return "replay", "replaying leaked credentials rather than guessing"
    targets = {t for t in (_target_of(c) for c in creds) if t}
    if targets:
        return "targeted", "hunting " + ", ".join(sorted(targets)[:2])
    return "dictionary", "working a common-password dictionary"


def _idf(by_ip: dict[str, set]) -> dict[str, float]:
    """How much a shared credential is worth as evidence.

    `admin:admin` appears in every wordlist ever written, so two hosts sharing
    it tells you nothing. `root:7ujMko0vizxv` is a Dahua backdoor string that
    only a specific tool carries. Weight by inverse frequency so rare pairs
    dominate and common ones contribute almost nothing.
    """
    total = max(1, len(by_ip))
    seen: dict[str, int] = {}
    for creds in by_ip.values():
        for c in creds:
            seen[c] = seen.get(c, 0) + 1
    return {c: math.log(total / n) + 0.05 for c, n in seen.items()}


def clusters(store, hours: int = 24, min_score: float = 2.2,
             limit: int = 8, max_size: int = 40) -> list[dict[str, Any]]:
    """Group hosts running the same credential list.

    What this measures, precisely: hosts whose credential sets overlap on pairs
    rare enough that coincidence is unlikely. That is shared *tooling*.

    What it does not measure: a shared operator. Mirai's table is public and
    sits in dozens of forks, so a thousand unrelated people running the same
    script produce identical credentials. Treating that as one actor would be
    wrong, which is why nothing here is labelled a campaign.
    """
    by_ip = store.actor_creds(hours)
    fingerprints = {}
    try:
        fingerprints = store.actor_hasshes(hours)
    except Exception:
        pass
    for ip in fingerprints:
        by_ip.setdefault(ip, set())
    if not by_ip:
        return []

    weight = _idf(by_ip)
    ips = list(by_ip)
    parent = {ip: ip for ip in ips}
    size = dict.fromkeys(ips, 1)

    def find(a):
        while parent[a] != a:
            parent[a] = parent[parent[a]]
            a = parent[a]
        return a

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra == rb:
            return
        # Union-find is transitive, so without a ceiling one common pair can
        # chain hundreds of unrelated hosts into a single blob.
        if size[ra] + size[rb] > max_size:
            return
        parent[rb] = ra
        size[ra] += size[rb]

    holders: dict[str, list[str]] = {}
    for ip, creds in by_ip.items():
        for c in creds:
            holders.setdefault(c, []).append(ip)

    # Score each pair of hosts by the combined rarity of what they share.
    score: dict[tuple[str, str], float] = {}
    for cred, hosts in holders.items():
        if len(hosts) < 2 or len(hosts) > 40:
            continue
        w = weight.get(cred, 0.0)
        if w <= 0.3:          # present in most hosts, worthless as evidence
            continue
        for i in range(len(hosts)):
            for j in range(i + 1, len(hosts)):
                key = (hosts[i], hosts[j]) if hosts[i] < hosts[j] else (hosts[j], hosts[i])
                score[key] = score.get(key, 0.0) + w

    # An identical SSH fingerprint means the same software build, which is a
    # much stronger signal than a shared wordlist. Those links go in first and
    # at full weight.
    by_fp: dict[str, list[str]] = {}
    for ip, fp in fingerprints.items():
        by_fp.setdefault(fp, []).append(ip)
    fp_linked: set[str] = set()
    for hosts in by_fp.values():
        if len(hosts) < 2 or len(hosts) > max_size:
            continue
        for i in range(1, len(hosts)):
            union(hosts[0], hosts[i])
        fp_linked.update(hosts)

    # Then credential overlap, strongest evidence first so tight groups form
    # before loose ones can chain them together.
    for (a, b), sc in sorted(score.items(), key=lambda kv: -kv[1]):
        if sc >= min_score:
            union(a, b)

    groups: dict[str, list[str]] = {}
    for ip in ips:
        groups.setdefault(find(ip), []).append(ip)

    meta = store.actor_meta(ips)
    out = []
    for members in groups.values():
        if len(members) < 2:
            continue
        creds: set[str] = set()
        for ip in members:
            creds |= by_ip[ip]
        # Shared subset only. The union includes everything each host tried
        # individually, which is not what bound them together.
        common = set.intersection(*(by_ip[ip] for ip in members)) or creds
        slug, phrase = _style(common)
        hits = sum(meta.get(ip, {}).get("hits", 0) for ip in members)
        countries = sorted({meta.get(ip, {}).get("country") for ip in members} - {None})
        protos: set[str] = set()
        for ip in members:
            protos |= {p for p in (meta.get(ip, {}).get("protos") or "").split(",") if p}
        # Show the rarest shared pairs: those are the ones doing the linking.
        top = sorted(common, key=lambda c: -weight.get(c, 0))[:6]
        confidence = round(sum(weight.get(c, 0) for c in common), 1)
        fps = {fingerprints[ip] for ip in members if ip in fingerprints}
        # One shared fingerprint across the whole group is the best evidence
        # available here, so say so rather than burying it in a score.
        same_build = len(fps) == 1 and len([ip for ip in members if ip in fingerprints]) > 1
        if same_build:
            confidence += 4.0
        out.append({
            "hosts": len(members),
            "ips": sorted(members)[:12],
            "hits": hits,
            "style": slug,
            "phrase": phrase,
            "countries": countries[:4],
            "protos": sorted(protos),
            "creds": top,
            "shared": len(common),
            "confidence": round(confidence, 1),
            "hassh": sorted(fps)[0][:12] if len(fps) == 1 else None,
            "same_build": same_build,
            "basis": ("identical SSH client build" if same_build
                      else "shared credential list"),
            "lore": sorted({CRED_LORE[c.partition(':')[2].lower()]
                            for c in common
                            if c.partition(':')[2].lower() in CRED_LORE})[:3],
            "loreMap": {c.partition(':')[2].lower(): CRED_LORE[c.partition(':')[2].lower()]
                        for c in top if c.partition(':')[2].lower() in CRED_LORE},
        })
    out.sort(key=lambda c: (-c["confidence"], -c["hosts"]))
    for i, c in enumerate(out[:limit], 1):
        c["id"] = f"SET-{i:02d}"
    return out[:limit]


# Kept so existing callers keep working.
campaigns = clusters


def _plural(n: int, one: str, many: str | None = None) -> str:
    return one if n == 1 else (many or one + "s")


def narrate(store, hours: int = 1) -> dict[str, Any]:
    """A few sentences on what just happened, ranked by how notable it is."""
    now = store.window(hours, 0)
    prev = store.window(hours, hours)
    lines: list[tuple[int, str]] = []

    if not now["hits"]:
        return {"generated": int(time.time()), "hours": hours,
                "lines": ["Nothing has reached the honeypot in the last "
                          f"{hours} {_plural(hours, 'hour')}. Quiet spells are normal; "
                          "scanners work in bursts."]}

    # Volume, and whether it moved.
    span = f"the last {hours} {_plural(hours, 'hour')}"
    opener = (f"{now['hits']:,} {_plural(now['hits'], 'attempt')} from "
              f"{now['hosts']:,} {_plural(now['hosts'], 'host')} in {span}")
    if prev["hits"] >= 8:
        change = (now["hits"] - prev["hits"]) / prev["hits"]
        if change >= 0.6:
            opener += f", up {round(change * 100)}% on the hour before"
        elif change <= -0.5:
            opener += f", down {round(abs(change) * 100)}% on the hour before"
    lines.append((100, opener + "."))

    # Is one host carrying the whole window?
    if now["actors"]:
        top = now["actors"][0]
        share = top["n"] / max(1, now["hits"])
        if share >= 0.4:
            who = top["isp"] or "an unnamed network"
            where = top["country"] or "an unknown location"
            lines.append((90,
                f"{round(share * 100)}% of it came from a single host on {who} "
                f"in {where}, which is one machine working through a list rather "
                f"than a distributed effort."))

    # How are they guessing?
    creds = {f"{u or ''}:{p or ''}" for u, p, _ in now["creds"]}
    if creds:
        slug, phrase = _style(creds)
        detail = {
            "mirai": "That table leaked with Mirai's source in 2016 and still "
                     "drives most Telnet traffic on the internet.",
            "replay": "Nobody guesses a sixteen-character mixed-case password; "
                      "these come from breach dumps being sprayed at random hosts.",
            "targeted": "That is a deliberate choice of target, not a generic sweep.",
        }.get(slug, "")
        lines.append((80, f"Credentials skewed toward {phrase}. {detail}".strip()))

    # Anything naming a specific product?
    lore = sorted({CRED_LORE[p.lower()] for _, p, _ in now["creds"]
                   if p and p.lower() in CRED_LORE})
    if lore:
        lines.append((70, "Among them: " + "; ".join(lore[:3]) +
                          ". Those identify the device class being hunted."))

    # Protocol mix.
    if len(now["protos"]) > 1:
        first, second = now["protos"][0], now["protos"][1]
        lines.append((60,
            f"{first[0]} drew the most traffic at {first[1]:,}, with {second[0]} "
            f"next at {second[1]:,}."))
    elif now["protos"]:
        only = now["protos"][0]
        lines.append((55, f"All of it arrived on {only[0]}."))

    # New faces.
    if now["new_hosts"] >= 3:
        lines.append((50,
            f"{now['new_hosts']} of those hosts had never been seen here before."))

    # Geography, only when it is concentrated enough to mean something.
    if now["countries"]:
        lead = now["countries"][0]
        if lead[1] / max(1, now["hits"]) >= 0.35 and len(now["countries"]) > 1:
            others = ", ".join(c for c, _ in now["countries"][1:3])
            lines.append((40, f"{lead[0]} led by volume, followed by {others}."))

    lines.sort(key=lambda x: -x[0])
    return {"generated": int(time.time()), "hours": hours,
            "lines": [text for _, text in lines[:2]]}
