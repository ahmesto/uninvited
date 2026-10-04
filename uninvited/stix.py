"""STIX 2.1 objects for the published feeds.

The downloadable bundle files (feeds.py) and the TAXII server (taxii.py) both build
their indicators here, so one host is described exactly the same way wherever it is
fetched. Identifiers and timestamps come from the data, never the clock, so an
unchanged list serializes to identical bytes.
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
            "objects": [self.identity()] + [self.url_indicator(r) for r in rows],
        }

    def bundle(self, hours: int, rows: list[dict[str, Any]]) -> dict[str, Any]:
        newest = max((r["last_ts"] for r in rows), default=0)
        return {
            "type": "bundle",
            "id": "bundle--" + str(uuid.uuid5(self.ns, f"bundle-{hours}-{newest}-{len(rows)}")),
            "objects": [self.identity()] + [self.indicator(r) for r in rows],
        }
