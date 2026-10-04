# Uninvited

*A server left open on purpose.*

Uninvited is a honeypot with a live public dashboard and a threat feed built from what hits it. It pretends to be a careless
server: SSH, Telnet, RDP and web, plus IP cameras, routers, industrial controllers and AI tool servers. Everything that
knocks is recorded, scored and published as lists you can load into a firewall or a threat intelligence platform. Nothing
a visitor sends is ever executed, and no login ever succeeds.

See it running: **https://dmz.ahmadmesto.com**

## What makes it different

Most honeypots stop at the log. This one publishes the result, and tries to make the result trustworthy. An address only goes
on a list after a completed TCP session, so a forged source can never put a victim there. A bare port scan never counts. The
big internet scanners, Shodan and Censys among them, get their own list, and a name in reverse DNS has to resolve back to the
address before it is believed. The page measures itself: of the hosts it listed a day ago, how many came back.

The lists come as text, JSON, CSV, STIX 2.1, a MISP feed and a read-only TAXII 2.1 server. There is also a list nobody else
gives you from a honeypot: the malware download URLs that botnets ask the decoys to fetch. Nothing is ever fetched. They are
listed from what was asked for.

The decoys go past the usual SSH and Telnet. Modbus, S7, EtherNet/IP and DNP3 for industrial scanners. A camera and a router
that accept the exploit and ask for the payload. An AI tool server with a bait tool, because scanners have started looking for
those too.

## Try it in two minutes

You need Python 3.12. Nothing is reachable from outside your machine.

```
pip install -r requirements.txt
python -m uninvited --config config.quickstart.yaml
```

In a second terminal, knock on every decoy:

```
python tools/try_it.py
```

Open http://127.0.0.1:8090/ and watch it arrive.

## Put it on the internet

That part needs care. Run it on a machine you could lose, on a network segment that cannot reach anything else, with its
outbound traffic denied. [docs/RUNNING.md](docs/RUNNING.md) walks through it and
[docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md) explains what protects you and what does not.

## How it works

```
 internet ──► decoys (listeners.py, ssh_pot.py, s7.py, enip.py, ...)  bounded, nothing executed
                 │
                 ▼
            classify + enrich ──► SQLite (WAL) ──► dashboard (FastAPI, WebSocket, one HTML file)
            reverse DNS, GeoIP, Tor      │
                                         ▼
                              feed builder (every 5 min, read-only)
                              txt json csv STIX MISP TAXII, malware URLs
```

The rules that decide everything are tables and arithmetic in `uninvited/intel.py`. No model sits in the path, so you can read
why an address got a tag or a score. [docs/METHODOLOGY.md](docs/METHODOLOGY.md) explains each rule and where it is weak,
[docs/DECOYS.md](docs/DECOYS.md) lists what every decoy does and promises, and [docs/FEEDS.md](docs/FEEDS.md) documents the
formats.

## Principles

Nothing a client sends is trusted, executed or fetched. Every rule can be read in a few lines. Every claim the site makes is
computed from the data and can be rechecked. The tests include a fuzz harness and independent protocol clients, and a
number you cannot reproduce does not go in the copy.

## Contributing, security, license

[CONTRIBUTING.md](CONTRIBUTING.md) has the ground rules and how to add a signature or a decoy. A vulnerability in the
honeypot itself is handled privately, see [SECURITY.md](SECURITY.md). The code is Apache 2.0. The published data is CC BY 4.0:
use it for anything and credit the source. The bundled font, map data and flags keep their own licenses, listed in
[THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md). A fork that publishes its own feed should use its own name, so nobody mistakes
its data for the reference instance.

Built by [Ahmad Mesto](https://ahmadmesto.com), a security engineer.
