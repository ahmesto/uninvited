"""The small files every site is expected to have, and the page a person sees on a
wrong address. All self-contained: nothing here loads anything from elsewhere.
"""
from __future__ import annotations

import datetime as dt
from html import escape

# The mark from the page header and the social card: a red door with a sliver of
# dark down one side.
FAVICON_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">'
    '<rect width="32" height="32" rx="6" fill="#0b0b0c"/>'
    '<rect x="6" y="5" width="20" height="22" fill="#dc2626"/>'
    '<rect x="17" y="5" width="3" height="22" fill="#0b0b0c"/></svg>'
)


def robots_txt(site: str) -> str:
    # The API is rate limited and not for crawlers. The feeds are public and fine.
    return ("User-agent: *\n"
            "Allow: /\n"
            "Disallow: /api/\n"
            f"Sitemap: https://{site}/sitemap.xml\n")


def sitemap_xml(site: str) -> str:
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
            f"  <url><loc>https://{site}/</loc></url>\n"
            f"  <url><loc>https://{site}/week</loc></url>\n"
            f"  <url><loc>https://{site}/feed/index.json</loc></url>\n"
            "</urlset>\n")


def security_txt(site: str, contact: str | None, now: dt.datetime | None = None) -> str | None:
    """RFC 9116. Only served when a contact is configured: the owner decides what
    address to publish, and an empty or invented one would be worse than none."""
    contact = (contact or "").strip()
    if not contact:
        return None
    now = now or dt.datetime.now(dt.UTC)
    expires = (now + dt.timedelta(days=365)).strftime("%Y-%m-%dT%H:%M:%SZ")
    return (f"Contact: {contact}\n"
            f"Expires: {expires}\n"
            "Preferred-Languages: en\n"
            f"Canonical: https://{site}/.well-known/security.txt\n")


def not_found_html(site: str, brand: str) -> str:
    site, brand = escape(site), escape(brand)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>Nothing here &middot; {brand}</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<style>
body{{margin:0;background:#0b0b0c;color:#f2f2f0;font:15px/1.6 Arial,Helvetica,sans-serif}}
main{{max-width:560px;margin:0 auto;padding:12vh 22px}}
.k{{font-size:11px;letter-spacing:1.6px;text-transform:uppercase;color:#ef4444;font-weight:700}}
h1{{font-size:30px;line-height:1.2;margin:10px 0 14px}}
p{{color:#c4c4c8;margin:0 0 22px}}
nav{{display:flex;flex-wrap:wrap;gap:8px}}
a{{color:#f2f2f0;text-decoration:none;border:1px solid rgba(255,255,255,.2);padding:9px 14px;font-size:12px;
  letter-spacing:.8px;text-transform:uppercase}}
a:hover{{background:#f2f2f0;color:#0b0b0c}}
small{{display:block;margin-top:34px;color:#86868c;font-size:12px}}
</style></head><body><main>
<div class="k">404 &middot; {brand}</div>
<h1>Nothing at this address.</h1>
<p>This server is left open on purpose, but this particular door goes nowhere.
Here is where the real ones are.</p>
<nav>
<a href="/#live">Live</a><a href="/#intel">Threat intel</a><a href="/#use">Use it</a><a href="/#build">About</a>
<a href="/feed/index.json">Feed index</a>
</nav>
<small>{site}</small>
</main></body></html>
"""
