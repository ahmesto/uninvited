"""The config checker: the mistakes that took the site down once, and the ones like them."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

from uninvited import configcheck

ROOT = Path(__file__).resolve().parent.parent


def write(text: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".yaml")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


GOOD = """
listen_ip: 0.0.0.0
dashboard:
  host: 127.0.0.1
  port: 8090
  hide:
    - 198.51.100.77
site:
  url: dmz.example.net
  csp: enforce
services:
  - proto: SSH
    port: 2222
  - proto: SIP
    port: 5060
    udp: true
  - proto: CAM
    port: 8083
    service: web
"""


class FileTests(unittest.TestCase):
    def test_a_good_file_has_no_errors(self):
        errors, _warnings, raw = configcheck.check_file(write(GOOD))
        self.assertEqual(errors, [])
        self.assertEqual(raw["dashboard"]["port"], 8090)

    def test_the_shipped_example_has_no_errors(self):
        errors, _, _ = configcheck.check_file(ROOT / "config.example.yaml")
        self.assertEqual(errors, [])

    def test_a_stray_space_that_breaks_the_yaml_is_reported_with_its_line(self):
        # The mistake that took the site down: one leading space on a top-level key.
        bad = GOOD.replace("\ndashboard:", "\n dashboard:")
        errors, _, raw = configcheck.check_file(write(bad))
        self.assertIsNone(raw)
        self.assertEqual(len(errors), 1)
        self.assertIn("does not parse", errors[0])
        self.assertIn("line", errors[0])
        self.assertIn("dashboard", errors[0])         # the offending line is shown

    def test_a_missing_file_is_an_error_not_a_traceback(self):
        errors, _, raw = configcheck.check_file("/no/such/config.yaml")
        self.assertIsNone(raw)
        self.assertIn("cannot read", errors[0])

    def test_a_file_that_is_not_a_mapping_is_refused(self):
        for text in ("- a\n- b\n", "just text\n"):
            errors, _, raw = configcheck.check_file(write(text))
            self.assertIsNone(raw)
            self.assertIn("mapping", errors[0])

    def test_an_empty_file_is_legal_but_warned_about(self):
        errors, warnings, _raw = configcheck.check_file(write(""))
        self.assertEqual(errors, [])
        self.assertTrue(any("nothing will listen" in w for w in warnings))


class SettingTests(unittest.TestCase):
    def errors(self, text):
        return configcheck.check(yaml.safe_load(text))[0]

    def warnings(self, text):
        return configcheck.check(yaml.safe_load(text))[1]

    def test_a_misspelt_setting_is_named_with_a_suggestion(self):
        errs = self.errors(GOOD.replace("dashboard:", "dashbord:"))
        self.assertTrue(any("'dashbord'" in e and "did you mean 'dashboard'" in e for e in errs), errs)
        errs = self.errors(GOOD.replace("hide:", "hid:"))
        self.assertTrue(any("dashboard.hid" in e and "'hide'" in e for e in errs), errs)
        errs = self.errors(GOOD.replace("csp:", "cps:"))
        self.assertTrue(any("site.cps" in e for e in errs), errs)

    def test_a_misspelt_protocol_is_named_with_a_suggestion(self):
        errs = self.errors(GOOD.replace("proto: SSH", "proto: SHH"))
        self.assertTrue(any("unknown proto 'SHH'" in e for e in errs), errs)

    def test_two_decoys_on_one_port_are_an_error(self):
        errs = self.errors(GOOD + "  - proto: FTP\n    port: 2222\n")
        self.assertTrue(any("2222/tcp is already used" in e for e in errs), errs)

    def test_a_disabled_service_does_not_take_the_port(self):
        errs = self.errors(GOOD + "  - proto: FTP\n    port: 2222\n    enabled: false\n")
        self.assertEqual(errs, [])

    def test_sip_uses_tcp_and_udp_on_one_port_without_clashing_with_itself(self):
        self.assertEqual(self.errors(GOOD), [])
        errs = self.errors(GOOD + "  - proto: HTTP\n    port: 5060\n")
        self.assertTrue(any("5060/tcp" in e for e in errs), errs)

    def test_the_dashboard_cannot_share_a_port_with_a_decoy(self):
        errs = self.errors(GOOD + "  - proto: HTTP\n    port: 8090\n")
        self.assertTrue(any("dashboard.port 8090" in e for e in errs), errs)

    def test_ports_and_flags_must_be_the_right_kind_of_value(self):
        for bad in ("port: 0", "port: 70000", "port: '22'", "port: true", "port: 22.5"):
            errs = self.errors(GOOD + f"  - proto: FTP\n    {bad}\n")
            self.assertTrue(any("port must be" in e for e in errs), (bad, errs))
        errs = self.errors(GOOD + "  - proto: FTP\n    port: 2121\n    enabled: 'no'\n")
        self.assertTrue(any("enabled must be true or false" in e for e in errs), errs)

    def test_addresses_and_networks_are_parsed(self):
        self.assertTrue(self.errors(GOOD.replace("127.0.0.1", "localhost")))
        self.assertTrue(self.errors(GOOD.replace("198.51.100.77", "not-an-address")))
        errs = self.errors(GOOD + "feed:\n  exclude:\n    - 198.51.100.0/24\n    - banana\n")
        self.assertEqual(len([e for e in errs if "feed.exclude" in e]), 1)

    def test_a_camera_or_router_needs_a_service_it_has(self):
        errs = self.errors(GOOD.replace("service: web", "service: ftp"))
        self.assertTrue(any("service must be one of" in e for e in errs), errs)

    def test_the_security_contact_must_be_a_link_or_a_mail_address(self):
        errs = self.errors(GOOD + "")
        self.assertEqual(errs, [])
        errs = self.errors(GOOD.replace("csp: enforce", "csp: enforce\n  security_contact: me@example.org"))
        self.assertTrue(any("security_contact" in e for e in errs), errs)
        self.assertEqual(self.errors(GOOD.replace(
            "csp: enforce", "csp: enforce\n  security_contact: mailto:me@example.org")), [])

    def test_warnings_for_what_is_legal_but_probably_not_meant(self):
        w = self.warnings(GOOD.replace("127.0.0.1", "0.0.0.0"))
        self.assertTrue(any("not loopback" in x for x in w), w)
        w = self.warnings(GOOD.replace("198.51.100.77", "203.0.113.10"))
        self.assertTrue(any("documentation address" in x for x in w), w)
        w = self.warnings(GOOD.replace("port: 2222", "port: 22"))
        self.assertTrue(any("privileged port" in x for x in w), w)
        w = self.warnings(GOOD.replace("enabled", "enabled").replace("proto: SSH\n    port: 2222",
                                                                      "proto: SSH\n    port: 2222\n    enabled: false"))
        self.assertFalse(any("every service is disabled" in x for x in w))


class CommandTests(unittest.TestCase):
    def run_check(self, path):
        return subprocess.run([sys.executable, "-m", "uninvited", "--check", "-c", str(path)],
                              cwd=ROOT, capture_output=True, text=True, timeout=60)

    def test_exit_status_is_zero_for_a_good_file_and_one_for_a_bad_one(self):
        ok = self.run_check(write(GOOD))
        self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
        self.assertIn("OK, 3 service(s) enabled", ok.stdout)
        bad = self.run_check(write(GOOD.replace("\ndashboard:", "\n dashboard:")))
        self.assertEqual(bad.returncode, 1)
        self.assertIn("ERROR", bad.stdout)
        self.assertIn("would not start cleanly", bad.stdout)


class ShippedIdentityTests(unittest.TestCase):
    """The made-up device names in this code are public the day it is. A sensor that keeps them
    can be found by searching for them, so the check says so for every decoy that is reachable."""

    def warnings(self, services, listen="0.0.0.0"):
        errors, warn = configcheck.check({"listen_ip": listen, "services": services})
        self.assertEqual(errors, [])
        return [w for w in warn if "ships with" in w]

    def test_a_reachable_decoy_with_the_shipped_identity_is_warned_about(self):
        w = self.warnings([{"proto": "MODBUS", "port": 5020},
                           {"proto": "CAM", "port": 8083, "service": "web", "model": "IPC-2100"},
                           {"proto": "ROUTER", "port": 8084, "service": "web"},
                           {"proto": "S7", "port": 5102, "identity": {"serial": "S C-X4U421302009", "plant": "Works 2"}}])
        self.assertEqual(len(w), 4)
        self.assertIn("identity.vendor and identity.product still hold", w[0])
        self.assertIn("model still holds", w[1])
        self.assertIn("identity.serial still holds", w[3])
        self.assertNotIn("identity.plant", w[3])

    def test_your_own_identity_a_disabled_decoy_and_a_local_sensor_are_quiet(self):
        own = [{"proto": "MODBUS", "port": 5020, "identity": {"vendor": "Northfield", "product": "NF-40"}},
               {"proto": "CAM", "port": 8083, "service": "web", "model": "DS-7"},
               {"proto": "ROUTER", "port": 7547, "service": "tr069"},
               {"proto": "ROUTER", "port": 8084, "service": "web", "enabled": False},
               {"proto": "SSH", "port": 2222}]
        self.assertEqual(self.warnings(own), [])
        self.assertEqual(self.warnings([{"proto": "MODBUS", "port": 5020}], listen="127.0.0.1"), [])


if __name__ == "__main__":
    unittest.main()
