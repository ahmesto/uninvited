# Running it for real

The two-minute demo (`uninvited --demo`, which runs `config.quickstart.yaml`) is safe by construction: everything on loopback, no outbound traffic. This
page is about putting decoys where the internet can reach them. Read [SECURITY-MODEL.md](SECURITY-MODEL.md) first. The
short version: use a machine you can lose, on a network segment that cannot reach anything you care about.

## What you need

- A small Linux machine or VM (2 vCPU and 2 GB of memory is plenty; a few hundred MB of disk per month at typical traffic
  with the default 90 day retention).
- Python 3.12.
- A network where you can forward ports to it and block everything else it might try to reach.
- Optional: the free MaxMind GeoLite2 City and ASN databases for locations and network names. Without them the honeypot
  runs and everything shows as unknown.
- Optional: a Cloudflare tunnel or a reverse proxy to publish the dashboard.

## 1. Install

```
sudo useradd --system --home /opt/uninvited --shell /usr/sbin/nologin uninvited
sudo mkdir -p /opt/uninvited /etc/uninvited /var/lib/uninvited
sudo cp -r uninvited static /opt/uninvited/
sudo install -m 755 deploy/reports.py deploy/payloads.py /opt/uninvited/     # the owner's reading tools
sudo cp config.example.yaml /etc/uninvited/config.yaml        # then edit it
cd /opt/uninvited && sudo python3 -m venv .venv
sudo .venv/bin/pip install -r /path/to/requirements.txt
sudo chown -R uninvited:uninvited /opt/uninvited /var/lib/uninvited
sudo chgrp uninvited /etc/uninvited/config.yaml && sudo chmod 640 /etc/uninvited/config.yaml
```

## 2. Configure

Start from `config.example.yaml`; every key is explained in it. The ones that matter:

| Key | What it does |
|---|---|
| `dashboard.host` | Keep it `127.0.0.1` and put a tunnel or proxy in front. A wider bind publishes every captured credential. |
| `dashboard.hide` | Addresses never shown on the dashboard. **Put your own public address here.** Scanners type the address they are attacking into the RDP cookie, which would publish yours. |
| `feed.exclude` | Addresses never published on any list. Put your own public address here too, as an exact `/32`. |
| `site.url` | The public name of your instance. It goes in feed headers, links, robots.txt, the sitemap and the TAXII server. |
| `site.security_contact` | Where to report a problem with your instance (`https://...` or `mailto:...`). Served as `/.well-known/security.txt`. Left out, that file is not served. |
| `site.csp` | `report` while you check the browser console is clean, then `enforce`. |
| `services` | One block per decoy. `enabled: false` turns one off. Industrial, camera, router and AI decoys ship off. |
| `classify.rdns`, `classify.tor` | Turn off the reverse DNS lookups and the Tor exit list download if you want no outbound traffic from the process. Without reverse DNS, research scanners are only recognised by address range. |
| `max_connections`, `retention_days` | The concurrent connection ceiling and how long raw events are kept. |
| `demo` | Only in the demo configs: knock on every decoy once at start, so the dashboard has something to show. Leave it out. |

**Check a configuration before you start the service with it.** A stray space once took a deployment down:

```
python -m uninvited --check -c /etc/uninvited/config.yaml
```

On a server, `sudo bash deploy/edit-config.sh` edits a copy, checks it, installs it with a backup, restarts the service and
puts the old file back if the dashboard does not come up.

## 3. Run it

```
sudo cp deploy/uninvited.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now uninvited
journalctl -u uninvited -f
```

The unit runs it as its own user with no capabilities and a read-only file system. The decoys listen on high ports. Get the
well-known ports to them at your gateway (forward WAN 22 to the decoy's 2222, and so on), or with an nftables redirect
on the machine if you would rather translate there. If you forward port 22, your real SSH daemon must be somewhere else.

## With Docker, instead of steps 1 and 3

`docker build -t uninvited .` builds the image from a clone. It runs as an unprivileged user and keeps everything it
records in `/data`. Out of the box it runs the demo. A real sensor mounts its own config over the built-in one and
publishes each decoy on the port scanners look for:

```
docker run -d --name uninvited --restart unless-stopped \
  --read-only --tmpfs /tmp --cap-drop ALL --security-opt no-new-privileges:true \
  -v "$PWD/config.yaml:/etc/uninvited/config.yaml:ro" -v uninvited-data:/data \
  -p 127.0.0.1:8090:8090 -p 22:2222 -p 23:2323 \
  uninvited
```

In that config keep `listen_ip` and `dashboard.host` at `0.0.0.0`: they are addresses inside the container, and the `-p`
flags decide what the outside can reach. The dashboard's stays on loopback, as above. Put `database` and `ssh_host_key`
under `/data`, mount the GeoLite2 databases if you use them, and leave `demo` out. Check the file before you start:

```
docker run --rm -v "$PWD/config.yaml:/etc/uninvited/config.yaml:ro" uninvited uninvited --check -c /etc/uninvited/config.yaml
```

Two things to know. Docker on Linux normally hands the decoys the visitor's real address. Docker Desktop on Windows and
macOS does not: every visitor shows up as Docker's own gateway address, which makes the lists worthless. So run a real
sensor on Linux, and confirm it with one connection from another machine: the dashboard should show the address you
came from. And step 4 still applies: the container limits what the process can touch, not what the machine can reach.

## 4. Contain it

This is the control that matters. At your gateway:

1. Put the honeypot on its own VLAN or subnet.
2. Deny that segment to every other segment, and to your management network.
3. Deny its outbound traffic by default. Allow DNS to your resolver, and the Tor exit list fetch if you kept it.
4. Alert on any other denied outbound connection from it. That means something is wrong.
5. Exclude its forwards from any intrusion prevention or deep inspection on the gateway, or the gateway scrubs the traffic
   you are trying to collect.

The reference deployment does this on a TP-Link Omada gateway with a dedicated VLAN. The idea is the same on any gateway.

## 5. Publish the dashboard (optional)

A Cloudflare tunnel to `http://127.0.0.1:8090` works well and keeps the dashboard off any open port. A reverse proxy such as
nginx works too: proxy to `127.0.0.1:8090`, and pass the WebSocket upgrade for `/ws`. If you use a CDN, cache `/feed/*`, `/` and the favicon, never `/api/`, and never enable "ignore query
string" for the feed rule: `/feed/changes/{list}?since=` depends on it.

The dashboard needs each visitor's real address: the per-visitor limits and the "check your own ports" button depend on
it. It believes the proxy on the same machine, so that proxy has to state the address itself and must not pass a
visitor's own claim through. A Cloudflare tunnel does this by itself. With nginx, put this in the `location` that proxies
to the dashboard:

```
proxy_set_header X-Forwarded-For $remote_addr;
```

Leave it out and a visitor can name any address as their own with a request header: the limits stop working, and the
port check knocks on the address they named. The header handling is tested; the nginx line is standard configuration
and has not been run on an nginx by this project. If your proxy sits behind a CDN itself, have it work out the
visitor's address first (nginx: the `real_ip` module).

## 6. Keep it healthy

- Update the operating system and the Python dependencies. A flaw in paramiko, FastAPI or uvicorn is reachable from the
  internet.
- `python3 /opt/uninvited/payloads.py --new 7` shows the raw web requests captured in the last week, owner only: that is where
  new exploits show up first.
- `python3 /opt/uninvited/reports.py` shows the wrong-entry reports visitors sent.
- The database is a single SQLite file in WAL mode. Back it up with `sqlite3 uninvited.db ".backup copy.db"`, never by copying
  the file while the service runs.
- Raw events older than `retention_days` are pruned every six hours. Counters and the per-address summary are kept.

## Before you expose it

Read your provider's acceptable-use terms: some do not allow a server that invites attacks. Think about whether running one
from a residential connection is fine where you live, and about the fact that you are publishing addresses of machines that
may be compromised devices. The project publishes a way to report a wrong entry for that reason. This is not legal advice.
