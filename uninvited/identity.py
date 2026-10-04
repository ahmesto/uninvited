"""Who runs this instance: its public address, the name it publishes under, and the owner credit.

Everything that names the site reads it from here: the feed files and their headers, the STIX,
TAXII and MISP identifiers, the social cards, robots.txt and the sitemap, the frame policy, and
the dashboard page. It comes from the config's `site:` section:

    site:
      url: feeds.example.net            # the public address, with or without https://
      title: Uninvited                  # the name on the page and in the feeds
      owner: Jane Doe                   # optional: the footer credit and the header link
      owner_title: Security Engineer
      owner_url: https://example.net

A fresh install says example.org and credits nobody, so a copy of this code never publishes
under somebody else's name. The STIX and MISP identifiers are derived from `url`, so they stay
the same for as long as the address does.
"""
from __future__ import annotations

import html
import re
import uuid
from dataclasses import dataclass
from urllib.parse import urlsplit

_HOST = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:\d{1,5})?$")
_NAME = re.compile(r"^[\w .,'()-]{1,60}$")      # plain words, safe in HTML and in feed headers
_BRAND = re.compile(r"^[\w .-]{1,40}$")         # also written into the page's script, so no quotes


def host_of(url: str | None) -> str:
    """'https://Feeds.Example.net/' and 'feeds.example.net' are both feeds.example.net."""
    url = (url or "").strip()
    if not url:
        return ""
    return (urlsplit(url).netloc if "://" in url else url.split("/")[0]).lower()


@dataclass(frozen=True)
class Identity:
    site: str = "example.org"
    brand: str = "Uninvited"
    owner: str = ""
    owner_title: str = ""
    owner_url: str = ""

    @classmethod
    def from_site(cls, s: dict) -> Identity:
        """From the config's site section, as written. problems() says what is wrong with it."""
        text = lambda key: str(s.get(key) or "").strip()  # noqa: E731
        return cls(site=host_of(text("url")) or cls.site, brand=text("title") or cls.brand,
                   owner=text("owner"), owner_title=text("owner_title"), owner_url=text("owner_url"))

    @classmethod
    def from_cfg(cls, cfg) -> Identity:
        ident = cls.from_site(cfg["site"] or {})
        problems = ident.problems()
        if problems:
            raise ValueError("; ".join(problems))
        return ident

    def problems(self) -> list[str]:
        out = []
        if not _HOST.match(self.site):
            out.append(f"site.url {self.site!r} is not a host name")
        if not _BRAND.match(self.brand):
            out.append("site.title may only hold letters, digits, spaces, dots and hyphens")
        for key in ("owner", "owner_title"):
            if getattr(self, key) and not _NAME.match(getattr(self, key)):
                out.append(f"site.{key} may only hold letters, digits, spaces and . , ' ( ) -")
        if self.owner_url and not (self.owner_url.startswith("https://") and _HOST.match(host_of(self.owner_url))):
            out.append("site.owner_url must be an https:// address")
        return out

    @property
    def ns(self) -> uuid.UUID:
        """The namespace every published identifier is derived from."""
        return uuid.uuid5(uuid.NAMESPACE_DNS, self.site)

    @property
    def frame_ancestors(self) -> str:
        """Who may show this site in a frame: itself, and the owner's own site if there is one."""
        out = ["'self'"]
        if self.owner_url:
            host = host_of(self.owner_url)
            out.append(f"https://{host}")
            if not host.startswith("www."):
                out.append(f"https://www.{host}")
        return "frame-ancestors " + " ".join(out)

    def owner_link(self, attrs: str = "") -> str:
        """'example.net ->' pointing at the owner's site, or nothing."""
        if not self.owner_url:
            return ""
        e = html.escape
        return f'<a{" " + attrs if attrs else ""} href="{e(self.owner_url)}">{e(host_of(self.owner_url))} &rarr;</a>'

    def credit(self) -> str:
        """'Designed and run by <owner>, <title>', or nothing."""
        if not self.owner:
            return ""
        e = html.escape
        name = f'<a href="{e(self.owner_url)}">{e(self.owner)}</a>' if self.owner_url else e(self.owner)
        return f"Designed and run by {name}" + (f", {e(self.owner_title)}" if self.owner_title else "")

    def render(self, page: str) -> str:
        """Fill the dashboard page's placeholders."""
        return (page.replace("{{site}}", self.site).replace("{{brand}}", html.escape(self.brand))
                .replace("{{BRAND}}", html.escape(self.brand.upper()))
                .replace("{{owner_link}}", self.owner_link('class="cv"')).replace("{{credit}}", self.credit()))
