# The published feeds

Everything is read-only, needs no key and is rebuilt every five minutes from a read-only database connection, so polling it
costs the honeypot nothing. Replace `example.org` with the instance you use.

The data is licensed **CC BY 4.0**: use it for anything and credit the source. How the lists decide is in
[METHODOLOGY.md](METHODOLOGY.md).

## Lists

| Files | What | Rule |
|---|---|---|
| `attackers-24h`, `attackers-7d`, `attackers-30d` | Attacking hosts | TCP-verified, 3+ engaged events, classified as an attacker |
| `attackers-high-7d` | The high-confidence cut | score 60 or higher |
| `tag-persistent-7d`, `tag-ssh-bruteforce-7d`, `tag-telnet-bruteforce-7d`, `tag-rdp-scan-7d`, `tag-web-exploit-7d` | One behaviour each | the 7 day list filtered by tag |
| `research-7d`, `tor-7d` | Research scanners and Tor exits | kept off the attacker lists |
| `malware-urls-24h`, `malware-urls-7d`, `malware-urls-30d` | Malware download URLs | delivered by 2+ hosts or self-hosted. Never fetched. |

Each attacker, research, Tor and URL list exists as `.txt` (one entry per line, `#` comments), `.json` (the full record),
`.csv` (the same columns) and, for the attacker and URL lists, `.stix.json`. Tag lists and `attackers-high-7d` are `.txt`
only. All live under `/feed/`. `/feed/index.json` is the catalog: every list with its count and files, the measured
accuracy, the tag meanings, and the TAXII collections. `/feed/status.json` has counts, how far back the change history
reaches, and a changelog of the data format.

```
curl -s https://example.org/feed/attackers-24h.txt | grep -v '^#'
curl -s https://example.org/feed/attackers-7d.json | jq -r '.indicators[] | select(.score >= 60) | .ip'
```

## An attacker record (`.json`)

```json
{
  "ip": "203.0.113.45",
  "first_seen": "2026-09-14T08:12:31Z",
  "last_seen": "2026-10-02T07:50:02Z",
  "events": 412,
  "protocols": ["SSH", "TNET"],
  "country": "NL", "asn": 64500, "network": "Example Hosting BV",
  "attack_techniques": ["T1110.001"],
  "cves": [], "exploits": [],
  "hassh": "ae8bd7dd09970555aa4ea8ab1b0b1e1c",
  "label": null,
  "classification": "malicious",
  "tags": ["ssh-bruteforce", "telnet-bruteforce", "multi-service", "persistent"],
  "host_type": "hosting",
  "collateral_risk": "low",
  "score": 80,
  "expires": "2026-10-13T07:50:02Z"
}
```

`score` is 0 to 100. `expires` is when the host leaves the list unless it attacks again. Every list is ordered by score
halved for every 3 days without an attack, so the most active hosts come first. `host_type` and `collateral_risk` are a
guess from the network number and name, and are labelled as one.

## A malware URL record

```json
{
  "url": "http://203.0.113.9:43777/Mozi.a", "host": "203.0.113.9", "port": 43777, "scheme": "http",
  "file": "Mozi.a", "family_hint": "Mozi",
  "first_seen": "2026-10-02T09:01:11Z", "last_seen": "2026-10-02T11:40:52Z",
  "sightings": 12, "sources": 3, "self_hosted": false,
  "delivered_by": ["Malware Dropper Command"], "confidence": 80, "expires": "2026-10-16T11:40:52Z"
}
```

`sources` is how many different hosts delivered the URL. `family_hint` comes from the file name only. These addresses were
asked for in exploit requests and **have not been fetched or checked**. Do not browse to them. A URL from a single host that
is not its own is never in these files; the site shows it defanged and grey until a second host asks for it.

## STIX 2.1 and TAXII 2.1

The `.stix.json` files are STIX 2.1 bundles: an identity, one `indicator` per entry, and the objects it points at. Each
indicator has the tags as `labels`, ATT&CK and CVE `external_references`, `confidence` from the score, `valid_from` from
the first sighting and `valid_until` from its expiry, and an `indicates` relationship to an `attack-pattern` for every
technique it showed. A malware URL also relates to a `malware` object for its family hint, at confidence 30, because a
file name is not an identification. Attackers use `[ipv4-addr:value = '...']` or `ipv6-addr`; URLs use
`[url:value = '...']`. Identifiers are derived from the data, so an unchanged list is byte-identical from one rebuild to the
next. They parse with the strict `stix2` library.

The same objects are served by a read-only **TAXII 2.1** server so a threat-intelligence platform can subscribe:

```python
from taxii2client.v21 import Server
root = Server("https://example.org/taxii2/").api_roots[0]
for collection in root.collections:
    print(collection.id, collection.title)
```

Six collections (the three attacker windows, the high-confidence cut, the persistent hosts, malware URLs 7d). The objects
endpoint takes `added_after`, `limit`, `next` and `match[id|type|version|spec_version]`. A host that attacks again is served
again with a later `valid_until`, so `added_after` returns exactly what is new or changed. 120 requests a minute per client.
Tested with the reference Python client; not yet with vendor platforms.

## MISP

`/feed/misp/manifest.json` is a MISP feed: one event, the 7 day attacker list, updated in place. Each address carries
`first_seen` and `last_seen`, its behaviours as `uninvited:tag`, its score as `uninvited:score` and its ATT&CK techniques as
`mitre-attack-pattern` galaxy tags; CVEs tried are `vulnerability` attributes. An address that left the list in the last
two weeks is sent with `deleted` set, so MISP removes it. Imported into a stock MISP 2.5.48 on 2026-10-03 with no errors.

## How long an entry stays

The window decides what counts as evidence: 3 attack events in 24 hours, 7 days or 30 days. The expiry decides how long
the host stays: 3 days after its last attack for a consumer line, 7 for hosting, 5 when unknown, half as long again for a
score of 60 or more. A host leaves every list, format and collection at `expires` (`valid_until` in STIX), so the files
never hold an entry they say is stale. A malware URL leaves 14 days after it was last asked for.

The malware URL files hold the raw URL, because a proxy or DNS filter needs it; only the site shows them defanged.

## The notable feed

`/feed/notable.atom` holds the last day's firsts: an exploit, a control command or a malware download nobody sent in the
week before. Each entry names the sending address in its summary and carries its indicators as
`<ioc:indicator type="ipv4-addr">` elements (`url` once the download address is on the malware URL list), so a
threat-intelligence platform that reads feeds can extract them. Readers ignore those elements.

## Keeping a copy current

Every list has a **changes feed**: `GET /feed/changes/{list}?since=<ISO 8601 time or epoch seconds>` returns what was added
and removed since then, as a net effect (an address that joined and left in between is not mentioned), plus `as_of_epoch`
to use as the next `since`. History reaches back 14 days. A `since` older than that returns `reset: true` and means "fetch
the whole list again", never a partial answer that would corrupt your copy. `tools/uninvited_sync.py` is a small script
that does this. Send `If-None-Match` when you poll the files: an unchanged list answers 304 with no body.

## Stability

`schema_version` (currently `1.0`) is bumped when a field is renamed or removed. Adding a field does not bump it. Every
change is listed in the `changelog` of `/feed/status.json`.

## Rules of the road

- Poll no more often than every five minutes: that is how often the lists rebuild.
- Set your own `User-Agent`. Some CDNs refuse the default one of common HTTP libraries.
- Wrong entry? Addresses get reassigned. Use the report form on the site, or open an issue with the address.
