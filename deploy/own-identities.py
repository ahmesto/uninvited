#!/usr/bin/env python3
"""Give every decoy an identity of its own, in one go.

    sudo /opt/uninvited/.venv/bin/python own-identities.py            change, check, restart
    sudo /opt/uninvited/.venv/bin/python own-identities.py --dry-run  only say what would change

The made-up device names this code ships with are public, so a sensor that keeps them can be
found by searching an internet scanner for them. This replaces each one the config check warns
about with a random value of the same shape, made on this machine and written nowhere else.
Values you already set yourself are left alone, and so are the file's comments and layout.

It edits a copy, runs the config check on it, keeps a backup, installs it, restarts the
service and waits for the dashboard. If the service does not come back, the backup goes back.
"""
from __future__ import annotations

import argparse
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import urllib.request

FIRST = ["North", "West", "Brook", "Stone", "Clear", "Iron", "Red", "High", "Oak", "Mill", "Grey", "Lake", "Elm", "Bright"]
SECOND = ["field", "gate", "water", "ridge", "ford", "mont", "vale", "wick", "haven", "crest", "bury", "march"]
TRADE = ["Controls", "Automation", "Systems", "Instruments", "Engineering", "Process"]
PLACE = ["Pump House", "Filter Hall", "Boiler Room", "Tank Farm", "Lift Station", "Mixing Line", "Intake Works", "Valve Pit"]
LETTERS = "ABCDEFGHJKLMNPRSTUVWXYZ"


def pick(words: list[str]) -> str:
    return secrets.choice(words)


def digits(n: int) -> str:
    return "".join(str(secrets.randbelow(10)) for _ in range(n))


def letters(n: int) -> str:
    return "".join(secrets.choice(LETTERS) for _ in range(n))


def fresh() -> dict[tuple[str, str], str]:
    """One random value per setting the check can warn about. The camera's two ports share a model."""
    name = pick(FIRST) + pick(SECOND)
    return {
        ("MODBUS", "identity.vendor"): f"{name} {pick(TRADE)}",
        ("MODBUS", "identity.product"): f"{name[:1]}{letters(1)}-{digits(3)} {pick(['RTU', 'Controller', 'PLC'])}",
        ("S7", "identity.serial"): f"S C-{letters(1)}{digits(1)}{letters(1)}{digits(9)}",
        ("S7", "identity.plant"): f"{pick(PLACE)} {secrets.randbelow(8) + 2}",
        ("ENIP", "identity.serial"): str(secrets.randbelow(0xFFFF0000 - 0x10000) + 0x10000),
        ("CAM", "model"): f"{letters(3)}-{digits(4)}",
        ("ROUTER", "model"): f"{letters(2)}-{digits(4)}{letters(1)}",
    }


def items(lines: list[str]) -> list[tuple[int, int, str]]:
    """(first line, line after the last, indent of the item's keys) for each entry under services:."""
    start = next((n for n, line in enumerate(lines) if re.match(r"^services:\s*(#.*)?$", line)), None)
    if start is None:
        raise SystemExit("no services: section in the config")
    out: list[tuple[int, int, str]] = []
    dash = None
    n = start + 1
    while n < len(lines):
        line = lines[n]
        if line.strip() and not line.lstrip().startswith("#"):
            m = re.match(r"^(\s*)-\s", line)
            if dash is None and m:
                dash = m.group(1)
            if m and m.group(1) == dash:
                if out:
                    out[-1] = (out[-1][0], n, out[-1][2])
                out.append((n, len(lines), dash + "  "))
            elif len(line) - len(line.lstrip()) <= len(dash or ""):
                break                                        # the services list ended
        n += 1
    if out:
        end = n
        while end > out[-1][0] + 1 and not lines[end - 1].strip():
            end -= 1                                         # trailing blank lines stay outside the item
        out[-1] = (out[-1][0], end, out[-1][2])
    return out


def set_value(lines: list[str], item: tuple[int, int, str], key: str, value: str) -> None:
    """Set `model` or `identity.<name>` inside one item, replacing the line or adding it."""
    first, end, indent = item
    if "." not in key:
        for n in range(first, end):
            if re.match(rf"^{indent}{re.escape(key)}:", lines[n]) or re.match(rf"^\s*-\s+{re.escape(key)}:", lines[n]):
                lines[n] = re.sub(rf"({re.escape(key)}:).*", lambda m: f"{m.group(1)} {value}", lines[n], count=1)
                return
        lines.insert(first + 1, f"{indent}{key}: {value}")
        return
    sub = key.split(".", 1)[1]
    head = next((n for n in range(first, end) if re.match(rf"^{indent}identity:", lines[n])), None)
    if head is None:
        lines[first + 1:first + 1] = [f"{indent}identity:", f"{indent}  {sub}: {value}"]
        return
    if not re.match(rf"^{indent}identity:\s*(#.*)?$", lines[head]):
        raise SystemExit(f"line {head + 1}: identity is written on one line; set {sub} there by hand")
    n = head + 1
    while n < end and (not lines[n].strip() or len(lines[n]) - len(lines[n].lstrip()) > len(indent)):
        if re.match(rf"^\s+{re.escape(sub)}:", lines[n]):
            lines[n] = re.sub(rf"({re.escape(sub)}:).*", lambda m: f"{m.group(1)} {value}", lines[n], count=1)
            return
        n += 1
    lines.insert(head + 1, f"{indent}  {sub}: {value}")


def rewrite(text: str, check, shipped) -> tuple[str, list[str]]:
    """-> (new text, what was changed). `check` and `shipped` come from uninvited.configcheck."""
    import yaml
    raw = yaml.safe_load(text) or {}
    services = raw.get("services") or []
    lines = text.split("\n")
    found = items(lines)
    if len(found) != len(services):
        raise SystemExit(f"could not match the file's layout to its {len(services)} services; nothing was changed")
    values = fresh()
    changed = []
    for n in range(len(services) - 1, -1, -1):               # last first, so line numbers above stay valid
        svc = services[n]
        proto = str(svc.get("proto", "")).upper()
        if svc.get("enabled", True) is False:
            continue
        keys = shipped(proto, svc)
        for key in keys:
            set_value(lines, items(lines)[n], key, values[(proto, key)])
        changed[:0] = [f"service {n + 1} ({proto}) {key}" for key in keys]
    new = "\n".join(lines)
    errors, warnings = check(yaml.safe_load(new) or {})
    left = [w for w in warnings if "ships with" in w]
    if errors or left:
        raise SystemExit("the edited copy did not pass the check, so nothing was changed:\n  " + "\n  ".join(errors + left))
    return new, changed


def healthy(port: int) -> bool:
    for _ in range(40):
        time.sleep(1)
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/split", timeout=3) as r:
                if r.status == 200:
                    return True
        except OSError:
            continue
    return False


def main() -> int:
    ap = argparse.ArgumentParser(description="Replace the shipped decoy identities with random ones of your own")
    ap.add_argument("--config", default="/etc/uninvited/config.yaml")
    ap.add_argument("--home", default="/opt/uninvited", help="where the uninvited package is installed")
    ap.add_argument("--service", default="uninvited")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    sys.path.insert(0, args.home)
    import yaml
    from uninvited.configcheck import _shipped_identity, check

    with open(args.config, encoding="utf-8") as fh:
        text = fh.read()
    new, changed = rewrite(text, check, _shipped_identity)
    if not changed:
        print("Every reachable decoy already has an identity of its own. Nothing to do.")
        return 0
    print("Giving these their own identity (the values are in the config, not shown here):")
    for line in changed:
        print("  " + line)
    if args.dry_run:
        print("Dry run: nothing was changed.")
        return 0
    if os.geteuid() != 0:
        raise SystemExit("run with sudo")

    backup = f"{args.config}.bak.{time.strftime('%Y%m%d-%H%M%S')}"
    shutil.copy2(args.config, backup)
    with open(args.config, "w", encoding="utf-8") as fh:      # in place: owner and mode stay as they are
        fh.write(new)
    print(f"Installed. Backup of the old file: {backup}")
    port = int(((yaml.safe_load(new) or {}).get("dashboard") or {}).get("port", 8080))
    subprocess.run(["systemctl", "restart", args.service], check=False)
    if healthy(port):
        print("OK. The service is back and the dashboard answers.")
        return 0
    print("The service did not come back. Putting the old config back.")
    shutil.copy2(backup, args.config)
    subprocess.run(["systemctl", "restart", args.service], check=False)
    print("Restored and restarted on the old config." if healthy(port) else
          f"Still not healthy. Look at: journalctl -u {args.service} -n 40 --no-pager")
    return 1


if __name__ == "__main__":
    sys.exit(main())
