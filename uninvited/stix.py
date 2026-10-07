"""STIX 2.1 objects for the published feeds.

The downloadable bundle files (feeds.py) and the TAXII server (taxii.py) both build
their objects here, so one host is described exactly the same way wherever it is
fetched. Identifiers and timestamps come from the data, never the clock, so an
unchanged list serializes to identical bytes.

Each indicator comes with an `indicates` relationship to the ATT&CK attack-pattern of
every technique it showed (matched by its ATT&CK id in external_references), and a
malware URL with a family hint relates to a malware object at low confidence, because a
file name is a hint and not an identification.
"""
from __future__ import annotations

import ipaddress
import time
import uuid
from typing import Any

from . import intel

IDENTITY_TS = "2026-08-14T00:00:00.000Z"   # first day of data; never changes


def stix_ts(ts: float | int) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts)) + ".000Z"


class Maker:
    def __init__(self, site: str, brand: str, ns: uuid.UUID):
        self.site, self.brand, self.ns = site, brand, ns
        self.identity_id = "identity--" + str(uuid.uuid5(ns, "identity"))

    def identity(self) -> dict[str, Any]:
        return {
            "type": "identity", "spec_version": "2.1", "id": self.identity_id,
            "created": IDENTITY_TS, "modified": IDENTITY_TS,
            "name": f"{self.brand} ({self.site})", "identity_class": "system",
        }

    def _id(self, kind: str, key: str) -> str:
        return f"{kind}--" + str(uuid.uuid5(self.ns, f"{kind}-{key}"))

    def attack_pattern(self, tid: str) -> dict[str, Any]:
        source = "mitre-ics-attack" if tid in intel.ICS_TECHNIQUES else "mitre-attack"
        return {
            "type": "attack-pattern", "spec_version": "2.1", "id": self._id("attack-pattern", tid),
            "created_by_ref": self.identity_id, "created": IDENTITY_TS, "modified": IDENTITY_TS,
            "name": intel.TECHNIQUES.get(tid, tid).split(": ")[-1],
            "external_references": [{"source_name": source, "external_id": tid, "url": intel.technique_url(tid)}],
        }

    def malware(self, family: str) -> dict[str, Any]:
        return {
            "type": "malware", "spec_version": "2.1", "id": self._id("malware", family.lower()),
            "created_by_ref": self.identity_id, "created": IDENTITY_TS, "modified": IDENTITY_TS,
            "name": family, "is_family": True,
        }

    def relationship(self, source: dict[str, Any], target_id: str, **extra: Any) -> dict[str, Any]:
        return {
            "type": "relationship", "spec_version": "2.1",
            "id": self._id("relationship", source["id"] + "-" + target_id),
            "created_by_ref": self.identity_id, "created": source["created"], "modified": source["created"],
            "relationship_type": "indicates", "source_ref": source["id"], "target_ref": target_id, **extra,
        }

    def ip_objects(self, r: dict[str, Any]) -> list[dict[str, Any]]:
        """One attacker: its indicator and what it indicates."""
        ind = self.indicator(r)
        return [ind] + [self.relationship(ind, self._id("attack-pattern", t)) for t in r["techniques"]]

    def url_objects(self, r: dict[str, Any]) -> list[dict[str, Any]]:
        """One malware URL: its indicator, Ingress Tool Transfer, and the family it hints at."""
        ind = self.url_indicator(r)
        out = [ind, self.relationship(ind, self._id("attack-pattern", "T1105"))]
        if r["family"]:
            out.append(self.relationship(
                ind, self._id("malware", r["family"].lower()), confidence=30,
                description="The file name suggests this family. A hint, not an identification."))
        return out

    def shared(self, rows: list[dict[str, Any]], urls: bool = False) -> list[dict[str, Any]]:
        """The attack-pattern and malware objects the rows point at, each once."""
        if urls:
            fams = sorted({r["family"] for r in rows if r["family"]})
            return ([self.attack_pattern("T1105")] if rows else []) + [self.malware(f) for f in fams]
        return [self.attack_pattern(t) for t in sorted({t for r in rows for t in r["techniques"]})]

    def indicator_id(self, ip: str) -> str:
        return "indicator--" + str(uuid.uuid5(self.ns, "indicator-" + ip))

    def indicator(self, r: dict[str, Any]) -> dict[str, Any]:
        addr = ipaddress.ip_address(r["ip"])
        kind = "ipv6-addr" if addr.version == 6 else "ipv4-addr"
        refs = [{"source_name": ("mitre-ics-attack" if t in intel.ICS_TECHNIQUES
                                 else "mitre-attack"), "external_id": t,
                 "url": intel.technique_url(t)} for t in r["techniques"]]
        refs += [{"source_name": "cve", "external_id": c, "url": intel.cve_url(c)}
                 for c in r["cves"]]
        note = (f"Attacked a honeypot {r['engaged']} times over "
                f"{', '.join(r['protocols'])}. Network type: {r['host_type']}, "
                f"collateral risk {r['collateral']}.")
        if r["exploits"]:
            note += " Exploits: " + ", ".join(r["exploits"]) + "."
        return {
            "type": "indicator", "spec_version": "2.1",
            "id": self.indicator_id(r["ip"]),
            "created_by_ref": self.identity_id,
            "created": stix_ts(r["first_ts"]),
            "modified": stix_ts(max(r["last_ts"], r["first_ts"])),
            "name": r["ip"],
            "description": note,
            "indicator_types": ["malicious-activity"],
            "labels": r["tags"],
            "pattern": f"[{kind}:value = '{r['ip']}']",
            "pattern_type": "stix",
            "valid_from": stix_ts(r["first_ts"]),
            "valid_until": stix_ts(r["expires_ts"]),
            "confidence": r["score"],
            "external_references": refs,
        }

    def url_indicator(self, r: dict[str, Any]) -> dict[str, Any]:
        """A download address (urlfeed.py) as a STIX url indicator."""
        value = r["url"].replace("\\", "\\\\").replace("'", "\\'")
        note = (f"Download address in a command sent to a honeypot {r['hits']} times by "
                f"{r['sources']} host{'s' if r['sources'] != 1 else ''}"
                + (", hosted by the host that sent it" if r["self_hosted"] else "") + ".")
        if r["exploits"]:
            note += " Delivered with: " + ", ".join(r["exploits"]) + "."
        if r["family"]:
            note += f" The file name suggests {r['family']}, which is a hint and not an identification."
        note += " Listed from what was asked for. The address was not fetched."
        return {
            "type": "indicator", "spec_version": "2.1",
            "id": "indicator--" + str(uuid.uuid5(self.ns, "url-" + r["url"])),
            "created_by_ref": self.identity_id,
            "created": stix_ts(r["first_ts"]),
            "modified": stix_ts(max(r["last_ts"], r["first_ts"])),
            "name": r["url"],
            "description": note,
            "indicator_types": ["malicious-activity"],
            "labels": ["malware-delivery"] + ([r["family"].lower()] if r["family"] else []),
            "pattern": f"[url:value = '{value}']",
            "pattern_type": "stix",
            "valid_from": stix_ts(r["first_ts"]),
            "valid_until": stix_ts(r["expires_ts"]),
            "confidence": r["confidence"],
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1105",
                                     "url": intel.technique_url("T1105")}],
        }

    def url_bundle(self, hours: int, rows: list[dict[str, Any]]) -> dict[str, Any]:
        newest = max((r["last_ts"] for r in rows), default=0)
        return {
            "type": "bundle",
            "id": "bundle--" + str(uuid.uuid5(self.ns, f"urlbundle-{hours}-{newest}-{len(rows)}")),
            "objects": [self.identity()] + self.shared(rows, urls=True) + [o for r in rows for o in self.url_objects(r)],
        }

    def bundle(self, hours: int, rows: list[dict[str, Any]]) -> dict[str, Any]:
        newest = max((r["last_ts"] for r in rows), default=0)
        return {
            "type": "bundle",
            "id": "bundle--" + str(uuid.uuid5(self.ns, f"bundle-{hours}-{newest}-{len(rows)}")),
            "objects": [self.identity()] + self.shared(rows) + [o for r in rows for o in self.ip_objects(r)],
        }
