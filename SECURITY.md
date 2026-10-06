# Security policy

This project is internet-facing software whose job is to parse hostile input, so a vulnerability in it matters. Thank you
for looking.

## Reporting a vulnerability

Please report privately, not in a public issue:

- **GitHub private vulnerability reporting** on this repository (Security tab, "Report a vulnerability"), or
- the contact in the `security.txt` of the reference instance, served at `/.well-known/security.txt`.

Include what you found, how to reproduce it (a request, a byte string, a config) and what you think the impact is. A
proof of concept that runs against a local instance (`python -m uninvited --demo`) is ideal.

I will acknowledge within a few days, tell you what I plan to do, and credit you in the fix unless you prefer otherwise.
This is a personal project, so there is no bug bounty and no formal SLA, but a report that shows a way to make a decoy
execute something, grant a session, disclose data it should not, crash or stall the honeypot from the network, or inject
into the dashboard or the feeds gets attention first.

## What is in scope

- Any decoy (`uninvited/listeners.py`, `ssh_pot.py`, `s7.py`, `enip.py`, `dnp3.py`, `modbus.py`, `personas.py`): parsing
  flaws, unbounded memory or time, a way to get a session or execution.
- The dashboard and API (`uninvited/app.py`, `static/index.html`): injection, access to data that is not public, a way to
  starve the decoys.
- The feeds (`uninvited/feeds.py`, `taxii.py`, `urlfeed.py`, `droppers.py`): a way to put an address or URL on a list that
  should not be there, to keep one off that should be, or to inject into a consumer of the files.
- The deployment scripts and the systemd unit in `deploy/`.

## What is out of scope

- Findings that need a compromised host, a malicious configuration file or write access to the database.
- Vulnerabilities in third-party dependencies with no way to reach them through this project (report those upstream).
- Please **do not run scans, load tests or exploit attempts against the public reference instance**. It is a real machine on
  a real connection. Run your own copy; it takes two minutes.

## How the project defends itself

See [docs/SECURITY-MODEL.md](docs/SECURITY-MODEL.md): bounded decoys, a seeded fuzz harness, an unprivileged and heavily
restricted service, read-only dashboard queries, and the network containment that is your job when you deploy it.

## Supported versions

Only the latest commit on the default branch.
