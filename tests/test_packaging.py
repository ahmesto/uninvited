"""pip install: what pyproject.toml promises, and that a copy laid out the way the wheel lays it
out runs the demo from an empty folder, with nothing of the repository beside it."""
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import tomllib
import unittest
import urllib.request
from pathlib import Path

import yaml

from uninvited import core

ROOT = Path(__file__).resolve().parent.parent
PROJECT = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
CARRIED = PROJECT["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
DEMO = yaml.safe_load((ROOT / "config.quickstart.yaml").read_text(encoding="utf-8"))


def port_free(port: int) -> bool:
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", port)) != 0


class PyprojectTests(unittest.TestCase):
    def test_the_dependencies_are_the_pinned_ones(self):
        pinned = [line.strip() for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
                  if line.strip() and not line.startswith("#")]
        self.assertEqual(PROJECT["project"]["dependencies"], pinned)

    def test_the_command_points_at_main(self):
        self.assertEqual(PROJECT["project"]["scripts"], {"uninvited": "uninvited.__main__:main"})
        from uninvited.__main__ import main
        self.assertTrue(callable(main))

    def test_everything_the_wheel_carries_exists_and_lands_where_the_code_looks(self):
        for source, target in CARRIED.items():
            self.assertTrue((ROOT / source).exists(), source)
            self.assertTrue(target.startswith("uninvited/"), target)
        # The code asks for these four by name: uninvited/app.py and uninvited/__main__.py.
        self.assertEqual(set(CARRIED.values()), {"uninvited/static", "uninvited/quickstart.yaml",
                                                 "uninvited/example.yaml", "uninvited/try_it.py"})
        sdist = PROJECT["tool"]["hatch"]["build"]["targets"]["sdist"]["include"]
        for source in CARRIED:
            self.assertIn("/" + source, sdist)       # a wheel built from the sdist needs them too

    def test_a_file_inside_the_package_wins_over_the_one_beside_it(self):
        with tempfile.TemporaryDirectory() as tmp:
            here = Path(tmp) / "site" / "uninvited"
            here.mkdir(parents=True)
            (here.parent / "static").mkdir()
            self.assertEqual(core.shipped("static", "static", here), here.parent / "static")
            (here / "static").mkdir()
            self.assertEqual(core.shipped("static", "static", here), here / "static")
        self.assertEqual(core.shipped("static", "static"), ROOT / "static")     # a checkout


@unittest.skipUnless(port_free(DEMO["dashboard"]["port"]), "something is already listening on the demo's dashboard port")
class InstalledCopyTests(unittest.TestCase):
    """A stand-in for site-packages: the package, with the carried files copied to the places
    pyproject.toml names. The demo is started from an empty folder with only that on the path."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        site, cls.cwd = Path(cls.tmp.name) / "site", Path(cls.tmp.name) / "empty"
        cls.cwd.mkdir()
        shutil.copytree(ROOT / "uninvited", site / "uninvited", ignore=shutil.ignore_patterns("__pycache__"))
        for source, target in CARRIED.items():
            if (ROOT / source).is_dir():
                shutil.copytree(ROOT / source, site / target)
            else:
                shutil.copy(ROOT / source, site / target)
        cls.env = {**os.environ, "PYTHONPATH": str(site)}
        cls.base = f"http://127.0.0.1:{DEMO['dashboard']['port']}"
        # Closed in tearDownClass: the demo writes to it for as long as it runs.
        cls.log = open(cls.cwd / "demo.log", "w", encoding="utf-8")  # noqa: SIM115
        cls.proc = subprocess.Popen([sys.executable, "-m", "uninvited", "--demo"], cwd=cls.cwd, env=cls.env,
                                    stdout=cls.log, stderr=subprocess.STDOUT)
        deadline = time.time() + 60
        while time.time() < deadline and cls.proc.poll() is None:
            try:
                urllib.request.urlopen(cls.base + "/api/split", timeout=2).close()
                return
            except OSError:
                time.sleep(0.5)
        cls.tearDownClass()
        raise AssertionError("the demo did not start:\n" + (cls.cwd / "demo.log").read_text(encoding="utf-8")[-2000:])

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try:
            cls.proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            cls.proc.kill()
            cls.proc.wait(timeout=15)
        cls.log.close()
        cls.tmp.cleanup()

    def get(self, path):
        with urllib.request.urlopen(self.base + path, timeout=10) as r:
            return r.status, r.read()

    def run_cli(self, *args):
        return subprocess.run([sys.executable, "-m", "uninvited", *args], cwd=self.cwd, env=self.env,
                              capture_output=True, text=True, timeout=120)

    def test_the_page_and_its_bundled_files_are_served(self):
        status, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn(b"<title>", body)
        for path in ("/static/vendor/jetbrains-mono.css", "/static/vendor/flags/nl.png",
                     "/static/vendor/licenses/JetBrainsMono-OFL.txt"):
            self.assertEqual(self.get(path)[0], 200, path)

    def test_the_demo_knocks_on_its_own_decoys_and_can_be_knocked_again(self):
        deadline = time.time() + 60
        total = 0
        while time.time() < deadline and total < len(DEMO["services"]):
            total = json.loads(self.get("/api/stats")[1])["total"]
            time.sleep(0.5)
        self.assertGreaterEqual(total, len(DEMO["services"]))            # every decoy heard from
        again = self.run_cli("--knock")
        self.assertEqual(again.returncode, 0, again.stdout + again.stderr)
        self.assertIn(f"{len(DEMO['services'])} of {len(DEMO['services'])} decoys answered", again.stdout)

    def test_what_it_records_stays_in_one_named_folder(self):
        self.assertEqual({p.name for p in self.cwd.iterdir()}, {"demo.log", "uninvited-demo"})

    def test_the_example_config_comes_with_it_and_passes_the_check(self):
        out = self.run_cli("--example-config")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout, (ROOT / "config.example.yaml").read_text(encoding="utf-8"))
        self.assertEqual(self.run_cli("--demo", "--check").returncode, 0)

    def test_no_config_says_what_to_do_instead_of_a_traceback(self):
        out = self.run_cli("--config", "nothing-here.yaml")
        self.assertEqual(out.returncode, 1)
        self.assertIn("uninvited --demo", out.stderr)
        self.assertNotIn("Traceback", out.stderr)


if __name__ == "__main__":
    unittest.main()
