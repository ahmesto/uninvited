"""IP enrichment against local MaxMind GeoLite2 databases.

Lookups are local files, so there is no API budget to blow through and no
outbound request per knock. If the databases are missing the honeypot still
runs, it just reports everything as unknown.
"""
from __future__ import annotations

import ipaddress
import logging
import os

log = logging.getLogger("uninvited.geo")

try:  # geoip2 is optional so the daemon can boot without the databases
    import geoip2.database  # type: ignore
    import geoip2.errors  # type: ignore
except ImportError:  # pragma: no cover
    geoip2 = None  # type: ignore


class Geo:
    def __init__(self, city_db: str = "", asn_db: str = ""):
        self.city = None
        self.asn = None
        if geoip2 is None:
            log.warning("geoip2 not installed, all knocks will show as Unknown")
            return
        if city_db and os.path.exists(city_db):
            self.city = geoip2.database.Reader(city_db)
        else:
            log.warning("city database not found at %r", city_db)
        if asn_db and os.path.exists(asn_db):
            self.asn = geoip2.database.Reader(asn_db)
        else:
            log.warning("ASN database not found at %r", asn_db)

    def close(self) -> None:
        for reader in (self.city, self.asn):
            if reader is not None:
                reader.close()

    def lookup(self, ip: str) -> dict:
        out = {
            "iso": "XX",
            "country": "Unknown",
            "region": "",
            "city": "",
            "lat": None,
            "lng": None,
            "asn": None,
            "isp": "Unknown",
        }
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return out

        if addr.is_private or addr.is_loopback or addr.is_link_local:
            out.update(iso="LAN", country="Private Network", isp="Local")
            return out

        if self.city is not None:
            try:
                res = self.city.city(ip)
                out["iso"] = (res.country.iso_code or "XX").upper()
                out["country"] = res.country.name or "Unknown"
                if res.subdivisions:
                    out["region"] = res.subdivisions.most_specific.name or ""
                out["city"] = res.city.name or ""
                if res.location.latitude is not None:
                    out["lat"] = float(res.location.latitude)
                    out["lng"] = float(res.location.longitude)
            except Exception:
                pass

        if self.asn is not None:
            try:
                res = self.asn.asn(ip)
                out["asn"] = res.autonomous_system_number
                out["isp"] = res.autonomous_system_organization or "Unknown"
            except Exception:
                pass

        return out
