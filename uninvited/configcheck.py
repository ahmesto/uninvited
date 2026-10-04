"""Check a config file before the service is started with it.

    python -m uninvited --check -c /etc/uninvited/config.yaml

Exit status 0 means the file will load and every decoy can bind. Errors are things
that would stop the service or silently turn a feature off (a stray space that breaks
the YAML, a key that is misspelt and so ignored, two decoys on one port). Warnings are
legal but probably not what you meant (the dashboard bound to a public address, the
documentation address still in `hide`).

It reads the file and the local filesystem only. It opens no sockets, so it is safe to
run while the service is running.
"""
from __future__ import annotations

import difflib
import ipaddress
import os
from pathlib import Path
from typing import Any

import yaml

from . import enip, modbus, personas, s7
from .core import PROTO_CAPS
from .identity import Identity

TOP_KEYS = {
    "listen_ip", "database", "ssh_host_key", "retention_days", "max_connections",
    "feed_size", "board_size", "dashboard", "feed", "geoip", "site", "services", "classify",
}
NESTED_KEYS = {
    "dashboard": {"host", "port", "hide"},
    "feed": {"exclude", "state"},
    "geoip": {"city_db", "asn_db"},
    "site": {"title", "tagline", "about", "url", "security_contact", "csp", "owner", "owner_title", "owner_url"},
    "classify": {"rdns", "tor"},
}
SERVICE_KEYS = {"proto", "port", "enabled", "banner", "udp", "identity", "service", "model",
                "address", "server", "name"}
SERVICE_KINDS = {"CAM": {"web", "rtsp"}, "ROUTER": {"web", "tr069"}}


def _shipped_identity(proto: str, svc: dict) -> list[str]:
    """The settings of an enabled decoy that still hold the made-up identity this code ships with.
    Those values are public, so they work as a search term for every sensor that keeps them."""
    ident = svc.get("identity") if isinstance(svc.get("identity"), dict) else {}
    shipped = {
        "MODBUS": {"identity.vendor": (ident.get("vendor"), modbus.Identity.vendor),
                   "identity.product": (ident.get("product"), modbus.Identity.product)},
        "S7": {"identity.serial": (ident.get("serial"), s7.Identity.serial),
               "identity.plant": (ident.get("plant"), s7.Identity.plant)},
        "ENIP": {"identity.serial": (ident.get("serial"), enip.Identity.serial)},
        "CAM": {"model": (svc.get("model"), personas.CAM_MODEL)},
        "ROUTER": {"model": (svc.get("model"), personas.ROUTER_MODEL)},
    }.get(proto, {})
    if proto == "ROUTER" and svc.get("service") == "tr069":
        return []                                   # that port shows no model
    return [key for key, (value, default) in shipped.items() if value is None or value == default]


def _hint(word: str, choices: set[str]) -> str:
    close = difflib.get_close_matches(word, sorted(choices), n=1, cutoff=0.6)
    return f" (did you mean '{close[0]}'?)" if close else ""


def _is_port(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 65535


def _is_address(value: Any) -> bool:
    try:
        ipaddress.ip_address(str(value))
        return True
    except ValueError:
        return False


def check_file(path: str | os.PathLike) -> tuple[list[str], list[str], dict | None]:
    """-> (errors, warnings, the parsed mapping or None if it could not be read)."""
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        return [f"cannot read {path}: {exc.strerror or exc}"], [], None
    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        mark = getattr(exc, "problem_mark", None)
        where = f" at line {mark.line + 1}, column {mark.column + 1}" if mark else ""
        problem = getattr(exc, "problem", None) or str(exc)
        lines = text.splitlines()
        shown = ""
        if mark and mark.line < len(lines):
            shown = f"\n    {lines[mark.line]!r}"
        return [f"the YAML does not parse{where}: {problem}{shown}"], [], None
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        return ["the file must be a mapping of settings, not a list or a single value"], [], None
    errors, warnings = check(raw)
    return errors, warnings, raw


def check(raw: dict) -> tuple[list[str], list[str]]:
    errors: list[str] = []
    warn: list[str] = []

    for key in raw:
        if key not in TOP_KEYS:
            errors.append(f"unknown setting '{key}'{_hint(str(key), TOP_KEYS)}. "
                          "It would be ignored.")
    for section, allowed in NESTED_KEYS.items():
        block = raw.get(section)
        if block is None:
            continue
        if not isinstance(block, dict):
            errors.append(f"'{section}' must be a block of settings")
            continue
        for key in block:
            if key not in allowed:
                errors.append(f"unknown setting '{section}.{key}'{_hint(str(key), allowed)}. "
                              "It would be ignored.")

    if "listen_ip" in raw and not _is_address(raw["listen_ip"]):
        errors.append(f"listen_ip '{raw['listen_ip']}' is not an IP address")
    for key in ("retention_days", "max_connections", "feed_size", "board_size"):
        value = raw.get(key)
        if value is not None and (not isinstance(value, int) or isinstance(value, bool) or value < 0):
            errors.append(f"{key} must be a whole number, not {value!r}")

    dash = raw.get("dashboard") if isinstance(raw.get("dashboard"), dict) else {}
    host = dash.get("host", "127.0.0.1")
    if not _is_address(host):
        errors.append(f"dashboard.host '{host}' is not an IP address")
    elif not ipaddress.ip_address(str(host)).is_loopback:
        warn.append(f"dashboard.host is {host}, not loopback. Every captured credential on the "
                    "dashboard is then visible to whatever can reach that address.")
    dash_port = dash.get("port", 8080)
    if not _is_port(dash_port):
        errors.append(f"dashboard.port must be 1 to 65535, not {dash_port!r}")
    hide = dash.get("hide") or []
    if not isinstance(hide, list):
        errors.append("dashboard.hide must be a list of addresses")
    else:
        for entry in hide:
            if not _is_address(entry):
                errors.append(f"dashboard.hide entry {entry!r} is not an IP address")
            elif str(entry).startswith(("203.0.113.", "198.51.100.", "192.0.2.")):
                warn.append(f"dashboard.hide holds {entry}, a documentation address. Put your own "
                            "public address there or it is not hidden.")

    feed = raw.get("feed") if isinstance(raw.get("feed"), dict) else {}
    exclude = feed.get("exclude") or []
    if not isinstance(exclude, list):
        errors.append("feed.exclude must be a list of addresses or networks")
    else:
        for entry in exclude:
            try:
                ipaddress.ip_network(str(entry).strip(), strict=False)
            except ValueError:
                errors.append(f"feed.exclude entry {entry!r} is not an address or network")

    site = raw.get("site") if isinstance(raw.get("site"), dict) else {}
    if site.get("csp") not in (None, "report", "enforce"):
        errors.append(f"site.csp must be 'report' or 'enforce', not {site.get('csp')!r}")
    contact = site.get("security_contact")
    if contact is not None and not str(contact).startswith(("https://", "mailto:")):
        errors.append("site.security_contact must start with https:// or mailto:")
    if site.get("url") in (None, "example.org"):
        warn.append("site.url is not set, so the page, the feeds, robots.txt and the sitemap say example.org")
    errors += Identity.from_site(site).problems()

    services = raw.get("services")
    if services is None:
        warn.append("no services are configured, so nothing will listen")
        services = []
    if not isinstance(services, list):
        errors.append("services must be a list")
        services = []
    taken: dict[tuple[str, int], str] = {}
    enabled = 0
    # A sensor that only listens on this machine cannot be found from outside, whatever it says it is.
    public = str(raw.get("listen_ip", "0.0.0.0")) not in ("127.0.0.1", "::1", "localhost")
    for n, svc in enumerate(services, 1):
        label = f"service {n}"
        if not isinstance(svc, dict):
            errors.append(f"{label} must be a block with proto and port")
            continue
        proto = str(svc.get("proto", "")).upper()
        label = f"service {n} ({proto or '?'})"
        if proto not in PROTO_CAPS:
            errors.append(f"{label}: unknown proto '{svc.get('proto')}'"
                          f"{_hint(proto, set(PROTO_CAPS))}. Known: {', '.join(sorted(PROTO_CAPS))}")
            continue
        for key in svc:
            if key not in SERVICE_KEYS:
                errors.append(f"{label}: unknown setting '{key}'{_hint(str(key), SERVICE_KEYS)}")
        port = svc.get("port")
        if not _is_port(port):
            errors.append(f"{label}: port must be 1 to 65535, not {port!r}")
            continue
        flag = svc.get("enabled", True)
        if not isinstance(flag, bool):
            errors.append(f"{label}: enabled must be true or false, not {flag!r}")
            continue
        kind = svc.get("service")
        if proto in SERVICE_KINDS and kind is not None and kind not in SERVICE_KINDS[proto]:
            errors.append(f"{label}: service must be one of {', '.join(sorted(SERVICE_KINDS[proto]))}")
        if not flag:
            continue
        enabled += 1
        if port < 1024:
            warn.append(f"{label}: port {port} is a privileged port, which the unprivileged service "
                        "user cannot bind. Listen on a high port and forward to it at the gateway.")
        kept = _shipped_identity(proto, svc) if public else []
        if kept:
            warn.append(f"{label}: {' and '.join(kept)} still {'hold' if len(kept) > 1 else 'holds'} the made-up identity "
                        "this code ships with. It is public, so anyone can search for it and find this sensor: "
                        "set your own.")
        transports = ["tcp"] + (["udp"] if proto == "SIP" and svc.get("udp", True) else [])
        for transport in transports:
            if (transport, port) in taken:
                errors.append(f"{label}: port {port}/{transport} is already used by {taken[(transport, port)]}")
            taken[(transport, port)] = label
    if _is_port(dash_port) and ("tcp", dash_port) in taken:
        errors.append(f"dashboard.port {dash_port} is also used by {taken[('tcp', dash_port)]}")
    if services and not enabled:
        warn.append("every service is disabled, so nothing will listen")

    for key in ("city_db", "asn_db"):
        db = (raw.get("geoip") or {}).get(key) if isinstance(raw.get("geoip"), dict) else None
        if db and not os.path.exists(db):
            warn.append(f"geoip.{key} {db} does not exist here, so locations will show as unknown")
    for key in ("database", "ssh_host_key"):
        target = raw.get(key)
        if target:
            folder = os.path.dirname(os.path.abspath(str(target)))
            if os.path.isdir(folder) and not os.access(folder, os.W_OK):
                warn.append(f"{key}: this user cannot write to {folder} "
                            "(fine if you are checking as someone other than the service user)")
    return errors, warn


def report(path: str | os.PathLike) -> int:
    """Print the findings and return the exit status."""
    errors, warnings, raw = check_file(path)
    for message in errors:
        print(f"ERROR   {message}")
    for message in warnings:
        print(f"warning {message}")
    if errors:
        print(f"{path}: {len(errors)} error(s). The service would not start cleanly with this file.")
        return 1
    count = sum(1 for s in (raw or {}).get("services") or []
                if isinstance(s, dict) and s.get("enabled", True))
    print(f"{path}: OK, {count} service(s) enabled" + (f", {len(warnings)} warning(s)" if warnings else ""))
    return 0
