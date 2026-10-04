#!/usr/bin/env python3
# Keep a local copy of one Uninvited list current by asking only what changed.
import json
import os
import urllib.parse
import urllib.request

BASE = "https://dmz.ahmadmesto.com/feed"
LIST = "tag-persistent-7d"
STATE = f"/var/tmp/uninvited-{LIST}.json"


def get(path):
    req = urllib.request.Request(BASE + path, headers={"User-Agent": "uninvited-sync/1.0"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return r.read().decode()


def full_copy():
    since = json.loads(get("/status.json"))["generated"]   # note the time first
    lines = get(f"/{LIST}.txt").splitlines()
    return {"since": since, "ips": sorted(x for x in lines if x and x[0] != "#")}


state = None
if os.path.exists(STATE):
    with open(STATE) as f:
        state = json.load(f)
if state:
    d = json.loads(get(f"/changes/{LIST}?since={urllib.parse.quote(state['since'])}"))
    if d["reset"]:
        state = None                      # our copy is too old, start again
    else:
        ips = (set(state["ips"]) | {a["ip"] for a in d["added"]}) - set(d["removed"])
        state = {"since": d["as_of"], "ips": sorted(ips)}
        print(f"changed: {len(d['added'])} added, {len(d['removed'])} removed, {len(ips)} addresses now")
if state is None:
    state = full_copy()
    print(f"full copy: {len(state['ips'])} addresses")
with open(STATE, "w") as f:
    json.dump(state, f)
