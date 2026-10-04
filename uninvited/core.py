"""Configuration, protocol registry and the Knock record."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Panel colours, keyed by protocol tag. ALL is the neutral/aggregate colour.
PROTO_COLORS = {
    "ALL": "#9ca3af",
    "SSH": "#22c55e",
    "TNET": "#06b6d4",
    "FTP": "#3b82f6",
    "RDP": "#fde047",
    "SMB": "#94a3b8",
    "SIP": "#f59e0b",
    "HTTP": "#a855f7",
    "SMTP": "#ec4899",
    # Industrial protocols share one family colour in different shades.
    "MODBUS": "#a3e635",
    "S7": "#bef264",
    "ENIP": "#84cc16",
    "DNP3": "#d9f99d",
    "CAM": "#fb923c",
    "ROUTER": "#2dd4bf",
    "MCP": "#fda4af",
}

# (captures usernames, captures passwords) -> drives which panels are shown
# when a protocol filter is active.
PROTO_CAPS = {
    "SSH": (True, True),
    "TNET": (True, True),
    "FTP": (True, True),
    "SMTP": (True, True),
    "HTTP": (True, True),
    "RDP": (True, False),
    "SIP": (True, False),
    "SMB": (False, False),
    "MODBUS": (False, False),
    "S7": (False, False),
    "ENIP": (False, False),
    "DNP3": (False, False),
    "CAM": (True, True),
    "ROUTER": (True, True),
    "MCP": (False, False),
}

PROTO_LABELS = {
    "SSH": "Secure Shell",
    "TNET": "Telnet",
    "FTP": "File Transfer",
    "RDP": "Remote Desktop",
    "SMB": "Windows File Sharing",
    "SIP": "VoIP Signalling",
    "HTTP": "Web",
    "SMTP": "Mail",
    "MODBUS": "Modbus (industrial)",
    "S7": "Siemens S7 (industrial)",
    "ENIP": "EtherNet/IP (industrial)",
    "DNP3": "DNP3 (industrial)",
    "CAM": "IP Camera",
    "ROUTER": "Router",
    "MCP": "AI Tool Server",
}


MAX_FIELD = 512            # characters kept of a username or a password


@dataclass
class Knock:
    """One hostile connection attempt."""

    proto: str
    ip: str
    port: int
    ts: int = field(default_factory=lambda: int(time.time()))
    username: str | None = None
    password: str | None = None
    # Protocol-specific extras rendered as label/value lines in the feed.
    lines: list[tuple[str, str]] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)

    # Filled in by the geo enricher.
    iso: str = "XX"
    country: str = "Unknown"
    region: str = ""
    city: str = ""
    lat: float | None = None
    lng: float | None = None
    asn: int | None = None
    isp: str = "Unknown"

    # Filled in by the classifier.
    kind: str = "attack"        # attack | research | tor
    label: str | None = None    # "Shodan", "Tor exit node", ...
    rdns: str | None = None
    demoted: bool = False      # a scanner we believed on an unconfirmed name, now an attacker
    mirai: bool = False
    hassh: str | None = None   # SSH client fingerprint, survives IP rotation
    ja3: str | None = None     # TLS client fingerprint, from a hello sent to a plain web port

    # Raw request bytes and the signature they dedupe on. Kept in the payloads
    # table for the owner and never part of public().
    raw: bytes | None = None
    raw_sig: bytes | None = None
    # Download URLs found in the request (droppers.Dropper). Recorded in their own table.
    droppers: list = field(default_factory=list)

    def __post_init__(self) -> None:
        # One cap for every decoy, whatever its protocol allows: a "username" longer than this is
        # a payload, not a credential, and the start of it is all the boards need.
        if self.username is not None:
            self.username = self.username[:MAX_FIELD]
        if self.password is not None:
            self.password = self.password[:MAX_FIELD]

    def public(self) -> dict[str, Any]:
        """The shape the browser consumes."""
        return {
            "ts": self.ts,
            "proto": self.proto,
            "ip": self.ip,
            "port": self.port,
            "user": self.username,
            "pass": self.password,
            "lines": [list(pair) for pair in self.lines],
            "iso": self.iso,
            "country": self.country,
            "region": self.region,
            "city": self.city,
            "lat": self.lat,
            "lng": self.lng,
            "asn": self.asn,
            "isp": self.isp,
            "kind": self.kind,
            "label": self.label,
            "rdns": self.rdns,
            "mirai": self.mirai,
            "hassh": self.hassh,
            "ja3": self.ja3,
            "cred": self.cred(),
        }

    def cred(self) -> str | None:
        """user:pass as one unit. The pair says more than either half."""
        if self.username is None and self.password is None:
            return None
        return f"{self.username or ''}:{self.password or ''}"


DEFAULTS: dict[str, Any] = {
    "listen_ip": "0.0.0.0",
    "database": "./data/uninvited.db",
    "retention_days": 90,
    "max_connections": 400,
    "dashboard": {"host": "127.0.0.1", "port": 8080},
    "site": {
        "title": "Uninvited",
        "tagline": "a server left open on purpose",
        "about": "",
    },
    "geoip": {"city_db": "", "asn_db": ""},
    "ssh_host_key": "./data/ssh_host_rsa_key",
    "feed_size": 100,
    "board_size": 30,
    "services": [],
}


class Config:
    def __init__(self, raw: dict[str, Any]):
        merged = dict(DEFAULTS)
        for key, value in (raw or {}).items():
            if isinstance(value, dict) and isinstance(merged.get(key), dict):
                merged[key] = {**merged[key], **value}
            else:
                merged[key] = value
        self._raw = merged

    def __getitem__(self, key: str) -> Any:
        return self._raw[key]

    def get(self, key: str, default: Any = None) -> Any:
        return self._raw.get(key, default)

    @property
    def services(self) -> list[dict[str, Any]]:
        out = []
        for svc in self._raw.get("services") or []:
            svc = dict(svc)
            svc["proto"] = str(svc.get("proto", "")).upper()
            if svc["proto"] not in PROTO_CAPS:
                raise ValueError(f"unknown protocol in config: {svc['proto']}")
            if svc.get("enabled", True):
                out.append(svc)
        return out

    @property
    def protocols(self) -> list[str]:
        seen: list[str] = []
        for svc in self.services:
            if svc["proto"] not in seen:
                seen.append(svc["proto"])
        return seen

    def protocol_meta(self) -> list[dict[str, Any]]:
        meta = []
        for proto in self.protocols:
            user, password = PROTO_CAPS[proto]
            meta.append(
                {
                    "name": proto,
                    "label": PROTO_LABELS.get(proto, proto),
                    "color": PROTO_COLORS.get(proto, PROTO_COLORS["ALL"]),
                    "user": user,
                    "pass": password,
                }
            )
        return meta


def load_config(path: str | Path) -> Config:
    with open(path, encoding="utf-8") as handle:
        return Config(yaml.safe_load(handle) or {})


def iso_utc(ts: float | int | None) -> str | None:
    """A timestamp as the feeds print it: 2026-10-03T12:41:47Z, or None for no time."""
    if not ts:
        return None
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))
