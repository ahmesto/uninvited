"""deploy/own-identities.py: the shipped decoy identities are replaced, and nothing else is."""
import importlib.util
import unittest
from pathlib import Path

import yaml

from uninvited.configcheck import _shipped_identity, check

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("own_identities", ROOT / "deploy" / "own-identities.py")
own = importlib.util.module_from_spec(spec)
spec.loader.exec_module(own)

CONFIG = """# the live config
listen_ip: 0.0.0.0
dashboard:
  port: 8090   # behind the tunnel
site:
  csp: enforce
services:
  - proto: SSH
    port: 2222
    banner: SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10
  - proto: MODBUS
    port: 5020             # the gateway forwards 502 to it
    identity:              # what the decoy says it is
      vendor: Lakeside Controls
      product: LC-2200 Controller
      revision: V2.1.4

  # More decoys.
  - proto: S7                # Siemens S7comm
    port: 5102
    identity:
      module_type: CPU 315-2 PN/DP
      plant: Pump Station 4
  - proto: ENIP
    port: 44818
  - proto: CAM
    port: 8083
    service: web
    model: IPC-2100
  - proto: CAM
    port: 8554
    service: rtsp
  - proto: ROUTER
    port: 8084
    service: web
    model: MyOwn-9
  - proto: ROUTER
    port: 7547
    service: tr069
  - proto: MODBUS
    port: 5021
    enabled: false

feed:
  exclude: []
"""


def shipped_warnings(text):
    errors, warnings = check(yaml.safe_load(text))
    assert errors == [], errors
    return [w for w in warnings if "ships with" in w]


class OwnIdentityTests(unittest.TestCase):
    def test_every_shipped_value_is_replaced_and_the_check_goes_quiet(self):
        self.assertEqual(len(shipped_warnings(CONFIG)), 5)
        new, changed = own.rewrite(CONFIG, check, _shipped_identity)
        self.assertEqual(shipped_warnings(new), [])
        self.assertEqual(changed, [
            "service 2 (MODBUS) identity.vendor", "service 2 (MODBUS) identity.product",
            "service 3 (S7) identity.serial", "service 3 (S7) identity.plant",
            "service 4 (ENIP) identity.serial", "service 5 (CAM) model", "service 6 (CAM) model"])
        for gone in ("Lakeside Controls", "LC-2200", "Pump Station 4", "IPC-2100"):
            self.assertNotIn(gone, new)

    def test_nothing_else_in_the_file_moves(self):
        new, _ = own.rewrite(CONFIG, check, _shipped_identity)
        before, after = yaml.safe_load(CONFIG), yaml.safe_load(new)
        for key in ("listen_ip", "dashboard", "site", "feed"):
            self.assertEqual(before[key], after[key])
        b, a = before["services"], after["services"]
        self.assertEqual([(s["proto"], s["port"], s.get("service"), s.get("enabled")) for s in b],
                         [(s["proto"], s["port"], s.get("service"), s.get("enabled")) for s in a])
        self.assertEqual(a[1]["identity"]["revision"], "V2.1.4")           # not a search term, so untouched
        self.assertEqual(a[2]["identity"]["module_type"], "CPU 315-2 PN/DP")
        self.assertEqual(a[6]["model"], "MyOwn-9")                         # the owner's own value stays
        self.assertNotIn("identity", a[8])                                 # a disabled decoy is left alone
        self.assertNotIn("model", a[7])                                    # the TR-069 port shows no model
        for comment in ("# the live config", "# behind the tunnel", "# the gateway forwards 502 to it",
                        "# what the decoy says it is", "  # More decoys.", "# Siemens S7comm"):
            self.assertIn(comment, new)
        self.assertEqual(a[4]["model"], a[5]["model"])                     # one camera, two ports, one model

    def test_the_new_values_have_the_shape_of_real_ones(self):
        new, _ = own.rewrite(CONFIG, check, _shipped_identity)
        s = yaml.safe_load(new)["services"]
        self.assertRegex(s[2]["identity"]["serial"], r"^S C-[A-Z]\d[A-Z]\d{9}$")
        self.assertIsInstance(s[3]["identity"]["serial"], int)
        self.assertRegex(s[4]["model"], r"^[A-Z]{3}-\d{4}$")
        self.assertRegex(s[1]["identity"]["vendor"], r"^[A-Z][a-z]+ [A-Z][a-z]+$")
        other, _ = own.rewrite(CONFIG, check, _shipped_identity)
        self.assertNotEqual(new, other)                                    # random, so two sensors differ

    def test_a_second_run_changes_nothing(self):
        new, _ = own.rewrite(CONFIG, check, _shipped_identity)
        again, changed = own.rewrite(new, check, _shipped_identity)
        self.assertEqual((again, changed), (new, []))


if __name__ == "__main__":
    unittest.main()
