# Security model

A honeypot is internet-facing software whose whole job is to parse hostile input. This page is the threat model: what is
trusted, what is not, what stops a bad day from becoming a worse one, and what is still your problem. If you find a hole,
[SECURITY.md](../SECURITY.md) says how to report it.

**Assume the honeypot machine can be compromised.** Everything below is about making that unlikely and making it cheap if
it happens. Run it somewhere you could wipe without regret.

## What is trusted

Nothing from the network. Every byte a client sends, every header, every username, the contents of a reverse DNS answer,
the name of the network a registry returns for an address: all of it is attacker-controlled. The only trusted inputs are the
configuration file, the GeoIP databases and the code.

## Layers

**1. The code is built to survive garbage.** Every decoy is a state machine over bounded reads with timeouts (see
[DECOYS.md](DECOYS.md)). The parsers are pure functions that never raise on client input. A seeded fuzz harness
(`tests/test_fuzz.py`) throws mutated and random bytes at every decoy over real sockets and at every parser, asserting no
handler error, bounded stored fields, no leaked tasks and a decoy that still answers afterwards. It has found no bug so far,
and it does notice a decoy that is deliberately broken.

**2. The process has almost no power.** The systemd unit (`deploy/uninvited.service`) runs it as its own unprivileged user
with an empty capability set, `NoNewPrivileges`, a read-only file system except its data directory, no access to home
directories, devices, kernel tunables or other users' processes, only IPv4, IPv6 and Unix sockets, a system-call filter, a
768 MB memory cap and a task cap. `systemd-analyze security uninvited.service` scores it 1.7 (OK) on the reference
deployment. The decoys listen on high ports (`>1024`); the gateway forwards the well-known ports to them, so the process
never needs a privileged port.

**3. The network does the real containment.** The honeypot sits on its own VLAN or subnet with a default-deny rule to
everything else on your network. That rule, at the gateway, is the control that matters: a bug in any layer above is
survivable if the machine cannot reach anything. Recommended:

- **Inbound:** only the ports you forward, to the honeypot only.
- **Egress:** deny by default. The honeypot legitimately needs three things: **DNS** (reverse and forward lookups of
  attacker addresses, which is how scanners are told from attackers, through your resolver), a periodic fetch of the
  **Tor exit list** (`classify.tor: false` turns it off), and the dashboard's **"check your own ports"** button, which opens
  TCP connections to *the visitor's own address only* (ten common ports, one check per address every two minutes, private
  addresses refused, no way to name a target). If you do not want any outbound scanning, remove that endpoint. Alert on any
  other denied outbound traffic from that VLAN: it means something is wrong.
- **No route to your management network.** Administer it from outside the VLAN with a key, never a password.

**4. The dashboard is read-only and rate limited.** It binds to loopback by default. Put a tunnel or reverse proxy in front.
The public API cannot write except the wrong-entry report form, which is capped (5 per visitor per hour, 500 characters,
5,000 stored). Address lookups are 40 a minute, bulk checks 10 an hour. The heavy dashboard queries share one cached answer
per few seconds, run off the event loop on a small thread pool and are refused with a 503 when too many are waiting, so a
flood of requests cannot starve the decoys. Request bodies are read with a hard cap, one address gets at most 8 WebSocket
seats, a WebSocket message over 2 KB is refused, and the dashboard reads the database through separate read-only
connections so a slow query never holds the writer. Security headers and an enforced Content-Security-Policy are sent on
every response.

**5. The data is handled as evidence, not as content.** Raw requests are stored as bytes and only ever displayed through an
escaper. The page builds its HTML from escaped fields and was probed with injection strings in every attacker-controlled
field (usernames, passwords, paths, user agents, labels, reverse names, networks): nothing executed. The published feed
files contain only values the feed built.

## What is still your problem

- **Dependencies.** The decoys use paramiko (SSH), FastAPI and uvicorn. Keep them updated. A parsing flaw in one of them is
  reachable from the internet. CI should run a dependency audit.
- **The host.** Patch the operating system. A kernel or sshd flaw is outside this project's reach.
- **Captured passwords are shown in full on the dashboard.** That is a deliberate transparency choice for the reference
  deployment: they are passwords strangers typed against a server that is not theirs. A bot credential-stuffing with a
  breach list can type a *real person's* password, though. If that matters to you, do not expose the dashboard, or fork the
  one line that renders them.
- **You are publishing addresses.** A listed address might be a compromised device whose owner has no idea. The lists carry
  host type, expiry and a collateral-risk guess for that reason, and the project offers a way to report a wrong entry. Read
  your provider's acceptable-use terms before you expose a decoy, and think about whether running one from a residential
  connection is allowed where you live. This is not legal advice.
- **Raw requests may contain a victim's data.** An attacker's request can embed a URL, a token or an address that is not
  theirs. Raw bytes are for the owner and are never served publicly.

## Known limitations

- DNP3 is experimental and has not been run against an independent master.
- The MISP feed was imported into a stock MISP 2.5.48 (2026-10-03). The TAXII server is tested with the reference
  Python client, not with a vendor platform.
- One sensor sees a small slice of the internet. See [METHODOLOGY.md](METHODOLOGY.md).
