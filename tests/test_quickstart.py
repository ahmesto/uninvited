"""The two-minute demo: the config is valid and loopback-only, and the knocking tool agrees with
it and will not be pointed at anyone else's machine."""
import importlib.util
import ipaddress
import sys
import unittest
from pathlib import Path

import yaml

from uninvited import configcheck

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("try_it", ROOT / "tools" / "try_it.py")
try_it = importlib.util.module_from_spec(spec)
spec.loader.exec_module(try_it)


class QuickstartConfigTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = yaml.safe_load((ROOT / "config.quickstart.yaml").read_text(encoding="utf-8"))

    def test_it_has_no_errors(self):
        errors, _warnings, _ = configcheck.check_file(ROOT / "config.quickstart.yaml")
        self.assertEqual(errors, [])

    def test_nothing_is_reachable_from_outside(self):
        self.assertTrue(ipaddress.ip_address(self.raw["listen_ip"]).is_loopback)
        self.assertTrue(ipaddress.ip_address(self.raw["dashboard"]["host"]).is_loopback)
        self.assertFalse(self.raw["classify"]["rdns"])          # no outbound DNS
        self.assertFalse(self.raw["classify"]["tor"])           # no download of the Tor list
        self.assertFalse(self.raw["services"][7].get("udp", True))   # SIP is TCP only here

    def test_it_knocks_on_itself_and_the_example_for_a_real_sensor_does_not(self):
        self.assertIs(self.raw["demo"], True)
        example = yaml.safe_load((ROOT / "config.example.yaml").read_text(encoding="utf-8"))
        self.assertNotIn("demo", example)
        errors, _ = configcheck.check({**self.raw, "demo": "yes"})
        self.assertIn("demo must be true or false", errors)

    def test_every_decoy_is_on_a_high_port(self):
        for svc in self.raw["services"]:
            self.assertGreaterEqual(svc["port"], 1024, svc)

    def test_every_protocol_is_there(self):
        from uninvited.core import PROTO_CAPS
        self.assertEqual({s["proto"] for s in self.raw["services"]}, set(PROTO_CAPS))

    def test_the_knocking_tool_uses_the_configured_ports(self):
        ports = {(s["proto"], s.get("service", "")): s["port"] for s in self.raw["services"]}
        want = {"ssh": ports[("SSH", "")], "telnet": ports[("TNET", "")], "ftp": ports[("FTP", "")],
                "http": ports[("HTTP", "")], "smtp": ports[("SMTP", "")], "rdp": ports[("RDP", "")],
                "smb": ports[("SMB", "")], "sip": ports[("SIP", "")], "modbus": ports[("MODBUS", "")],
                "s7": ports[("S7", "")], "enip": ports[("ENIP", "")], "dnp3": ports[("DNP3", "")],
                "cam": ports[("CAM", "web")], "rtsp": ports[("CAM", "rtsp")], "router": ports[("ROUTER", "web")],
                "tr069": ports[("ROUTER", "tr069")], "mcp": ports[("MCP", "")]}
        self.assertEqual(try_it.PORTS, want)


class DockerFilesTests(unittest.TestCase):
    """The image is built and run by hand (it needs Docker); these keep its files consistent with
    each other and with the demo."""

    @classmethod
    def setUpClass(cls):
        cls.config = yaml.safe_load((ROOT / "config.docker.yaml").read_text(encoding="utf-8"))
        cls.compose = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
        cls.dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
        cls.ignore = (ROOT / ".dockerignore").read_text(encoding="utf-8").split()

    def test_the_config_has_no_errors(self):
        errors, _, _ = configcheck.check_file(ROOT / "config.docker.yaml")
        self.assertEqual(errors, [])

    def test_the_builder_gets_everything_the_package_is_built_from_and_nothing_else(self):
        import tomllib
        project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        carried = project["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
        self.assertIn("*", self.ignore)                       # everything is left out, then let back in by name
        for needed in [*carried, "uninvited", "pyproject.toml", "requirements.txt", project["project"]["readme"],
                       "config.docker.yaml"]:
            self.assertIn("!" + needed, self.ignore, needed)
        for kept_out in ("config.yaml", ".git", "tests", "deploy", "docs"):
            self.assertNotIn("!" + kept_out, self.ignore)

    def test_the_image_runs_the_installed_command_as_an_unprivileged_user(self):
        self.assertIn('CMD ["uninvited", "--config", "/etc/uninvited/config.yaml"]', self.dockerfile)
        self.assertIn("config.docker.yaml /etc/uninvited/config.yaml", self.dockerfile)
        self.assertLess(self.dockerfile.index("USER uninvited"), self.dockerfile.index("CMD ["))
        self.assertEqual(self.config["database"].rsplit("/", 1)[0], "/data")
        self.assertIn("VOLUME /data", self.dockerfile)

    def test_it_is_the_demo_with_decoys_docker_can_publish(self):
        self.assertIs(self.config["demo"], True)
        self.assertEqual(self.config["listen_ip"], "0.0.0.0")

    def test_the_ports_published_are_the_ports_the_decoys_use(self):
        published = [p.split(":") for p in self.compose["services"]["uninvited"]["ports"]]
        self.assertTrue(all(host == "127.0.0.1" for host, _, _ in published), "a port is published beyond loopback")
        self.assertTrue(all(a == b for _, a, b in published))
        wanted = {s["port"] for s in self.config["services"]} | {self.config["dashboard"]["port"]}
        self.assertEqual({int(a) for _, a, _ in published}, wanted)

    def test_the_container_is_locked_down(self):
        svc = self.compose["services"]["uninvited"]
        self.assertTrue(svc["read_only"])
        self.assertEqual(svc["cap_drop"], ["ALL"])
        self.assertIn("no-new-privileges:true", svc["security_opt"])
        self.assertNotEqual(svc["user"].split(":")[0], "0")

    def test_the_demo_config_makes_no_outbound_requests(self):
        self.assertFalse(self.config["classify"]["rdns"])
        self.assertFalse(self.config["classify"]["tor"])

    def test_the_decoy_ports_match_the_local_quickstart(self):
        local = yaml.safe_load((ROOT / "config.quickstart.yaml").read_text(encoding="utf-8"))
        self.assertEqual([(s["proto"], s["port"]) for s in self.config["services"]],
                         [(s["proto"], s["port"]) for s in local["services"]])


class KnockingToolTests(unittest.TestCase):
    def run_main(self, *args):
        old = sys.argv
        sys.argv = ["try_it.py", *args]
        try:
            return try_it.main()
        finally:
            sys.argv = old

    def test_it_refuses_a_public_address(self):
        self.assertEqual(self.run_main("--host", "8.8.8.8"), 2)
        self.assertEqual(self.run_main("--host", "93.184.216.34"), 2)

    def test_it_refuses_a_name_that_does_not_resolve(self):
        self.assertEqual(self.run_main("--host", "no-such-host.invalid"), 2)

    def test_every_probe_has_a_port_and_a_name(self):
        names = [n for n, _ in try_it.PROBES]
        self.assertEqual(len(names), len(set(names)))
        self.assertGreaterEqual(len(names), 17)

    def test_it_stays_importable_on_older_pythons(self):
        # No backslash inside an f-string expression: that is a syntax error before Python 3.12.
        import ast
        tree = ast.parse((ROOT / "tools" / "try_it.py").read_text(encoding="utf-8"), feature_version=(3, 9))
        self.assertIsNotNone(tree)


if __name__ == "__main__":
    unittest.main()
