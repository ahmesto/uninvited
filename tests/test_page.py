"""The page must show exactly the scripts that were run, and its sections must hold together."""
import html
import re
import unittest
from pathlib import Path

from uninvited.identity import Identity

ROOT = Path(__file__).resolve().parent.parent
# The page as the reference deployment serves it: the placeholders filled in from its config.
PAGE = Identity(site="dmz.ahmadmesto.com", owner="Ahmad Mesto", owner_title="Security Engineer",
                owner_url="https://ahmadmesto.com").render((ROOT / "static" / "index.html").read_text(encoding="utf-8"))


def code_after(anchor: str) -> str:
    start = PAGE.index(anchor)
    m = re.search(r'<pre class="code d copyable">(.*?)</pre>', PAGE[start:], re.S)
    return html.unescape(m.group(1))


def view(name: str) -> str:
    start = PAGE.index(f'<main id="v-{name}"')
    return PAGE[start:PAGE.index("</main>", start)]


def panel(view_name: str, sub: str) -> str:
    """The markup of one section: from its opening tag to the next section or the end of the view."""
    body = view(view_name)
    m = re.search(rf'<div class="sub(?: on)?" data-sub="{sub}">', body)
    assert m, f"no section {sub} in {view_name}"
    nxt = re.search(r'\n\s+<div class="sub(?: on)?" data-sub="', body[m.end():])
    return body[m.start(): m.end() + nxt.start()] if nxt else body[m.start():]


# Which strip, in which tab, and the first section of each (the one shown by default).
TABS = {"intel": "overview", "use": "start", "build": "how"}


class RecipeTests(unittest.TestCase):
    def test_sync_recipe_on_the_page_is_the_tested_script(self):
        shown = code_after('id="use-sync"')
        tested = (ROOT / "tools" / "uninvited_sync.py").read_text(encoding="utf-8")
        self.assertEqual(shown.strip(), tested.replace("\r\n", "\n").strip())

    def test_no_top_level_name_is_declared_twice_in_the_page_script(self):
        """A second `const NAME` at the top level is a SyntaxError that stops the whole
        script, so the page loads with empty panels and no navigation. This happened once."""
        scripts = re.findall(r"<script>(.*?)</script>", PAGE, re.S)
        self.assertTrue(scripts)
        seen: dict[str, int] = {}
        for script in scripts:
            for m in re.finditer(r"^(?:const|let|var|function|class)\s+([A-Za-z_$][\w$]*)", script, re.M):
                seen[m.group(1)] = seen.get(m.group(1), 0) + 1
        dupes = sorted(n for n, c in seen.items() if c > 1)
        self.assertEqual(dupes, [], f"declared more than once: {dupes}")

    def test_the_anchor_and_links_exist(self):
        self.assertEqual(PAGE.count('id="use-sync"'), 1)
        self.assertIn('href="#use-sync"', PAGE)
        self.assertIn("/feed/status.json", PAGE)
        self.assertIn("/feed/changes/", PAGE)


class DeployTests(unittest.TestCase):
    def test_the_deploy_installs_every_module_of_the_package(self):
        """It only copies the files it lists. A module left off the list is never updated on the
        server, and a fresh install would not even import. Five were missing until 2026-10-03."""
        path = ROOT / "deploy" / "deploy-site.sh"
        if not path.exists():
            self.skipTest("the deploy script is not part of the public export")
        script = path.read_text(encoding="utf-8")
        listed = set(re.search(r'^PYFILES="([^"]+)"$', script, re.M).group(1).split())
        package = {p.name for p in (ROOT / "uninvited").glob("*.py")}
        self.assertEqual(listed, package)


class SectionTests(unittest.TestCase):
    def test_every_strip_link_has_a_panel_and_the_router_knows_the_same_names(self):
        """A mismatch would show an empty or unreachable section."""
        router = PAGE[PAGE.index("const SECTIONS = {"):]
        router = router[:router.index("};")]
        for name in TABS:
            body = view(name)
            tabs = re.findall(r'<a href="#[^"]*" data-sub="(\w+)"', body)
            panels = re.findall(r'<div class="sub(?: on)?" data-sub="(\w+)"', body)
            known = re.findall(r'"(\w+)"', re.search(rf"{name}: \[(.*?)\]", router).group(1))
            self.assertEqual(tabs, panels, f"{name}: strip and panels differ")
            self.assertEqual(tabs, known, f"{name}: strip and router differ")
            self.assertEqual(body.count('class="sub on"'), 1, f"{name}: needs exactly one default section")
            self.assertIn(f'class="sub on" data-sub="{TABS[name]}"', body)
            self.assertIn(f'<a href="#{"use" if name == "use" else name}" data-sub="{TABS[name]}" class="on"', body)

    def test_threat_intel_sections_hold_what_they_should(self):
        """Five sections since 2026-10-05: the Check tools folded into Hosts and Behavior, Download
        moved to the Use it tab, and the Timeline took its place."""
        want = {
            "overview": ["acc-a1", 'id="top-ov"', 'id="urls-ov"', 'id="svc-bar"', 'id="ov-get"',
                         'id="ibrief"', 'class="pg-h"', 'class="pg-lead"'],
            "hosts": ['id="check"', 'id="lookup-form"', 'id="bulk-go"', 'id="bulk-out"',
                      'id="top"', 'id="nets"', 'id="geo"', 'id="spread"', 'id="wsel"'],
            "timeline": ['id="tlsel"', 'id="tl-axis"', 'id="tl-pins"', 'id="tl-rows"', 'id="tl-lines"', 'id="tl-note"',
                         "score 80 or more", "last 24 hours"],
            "behavior": ['id="techs"', 'id="tagbars"', 'id="cves"', 'id="icamp"', 'id="emerging"', 'id="hm-attack"',
                         'id="pw-grid"', 'id="pw-form"', 'id="pw-rank"', "What they do", "How they do it"],
            "urls": ['id="urls"'],
        }
        for name, needles in want.items():
            body = panel("intel", name)
            for n in needles:
                self.assertIn(n, body, f"{n} should be in the {name} section")
        # the audit (2026-10-03) removed the duplicates: the indicator row and the New here? strip on
        # the overview, the second host table style, and the headline is on the overview only
        intel = view("intel")
        for gone in ('class="kpis"', 'class="usebar"', 'id="k-24"', 'class="trow', 'class="fmts'):
            self.assertNotIn(gone, intel, gone)
        self.assertEqual(intel.count('class="pg-h"'), 1)
        self.assertIn('class="pg-h"', panel("intel", "overview"))
        # the lookup and the log checker sit above the host list; the password check under the password shapes
        hosts, behavior = panel("intel", "hosts"), panel("intel", "behavior")
        self.assertLess(hosts.index('id="bulk"'), hosts.index('id="hostlist"'))
        self.assertLess(behavior.index('id="pwshape"'), behavior.index('id="pwcheck"'))
        # the overview points at the tools and the formats where they live now
        self.assertIn('href="#intel-hosts" data-glyph="&rarr;">Check it</a>', panel("intel", "overview"))
        self.assertIn('href="#use-download"', panel("intel", "overview"))

    def test_the_timeline_reads_what_the_hosts_list_reads_and_opens_the_same_drawer(self):
        """No new endpoint and nothing newly published: the bars come from the list file the Hosts
        section already reads, the pins from the notables the Live screen already shows, and a bar
        is a .clk[data-ip] row, so the shared click handler opens the evidence drawer with each
        event's own time."""
        self.assertIn("function hostList(win)", PAGE)
        self.assertIn("function drawTimeline()", PAGE)
        tl = PAGE[PAGE.index("function drawTimeline()"):]
        tl = tl[:tl.index('$$("#tlsel .tg").forEach(b => { b.onclick')]
        self.assertIn("hostList(win)", tl)
        self.assertIn('class="tl-row clk" role="button" tabindex="0" data-ip=', tl)
        self.assertIn('"/api/notables?hours=24"', PAGE)
        self.assertNotIn("/feed/notable.atom", tl)                      # same origin, so the API, not the atom
        self.assertNotIn("/api/timeline", tl)                            # that one is the Live screen's hourly bars
        self.assertEqual(PAGE.count('fetch("/feed/attackers-" + win + ".json")'), 1)   # one loader, one cache
        self.assertIn('if(view === "intel" && sub === "timeline") drawTimeline();', PAGE)
        # grey by default, red only for the strongest: the legend says what the code does
        self.assertIn('>= 80 || (h.tags || []).includes("malware-delivery")', PAGE)
        # rows are the arrivals in the window, persisters only fill the rest (review of 2026-10-05: by score
        # alone every bar was a persister pinned to the left edge, and the axis did no work)
        self.assertIn("const arrived = all.filter(h => h.fs >= start), carried = all.filter(h => h.fs < start);", tl)
        self.assertIn("arrived in the window", tl)

    def test_use_it_sections_hold_what_they_should(self):
        want = {
            "start": ["Which list should I use?", 'id="use-download"', 'id="sample"', 'id="sample-box"', 'id="curated"',
                      'class="fmts"', 'class="snips"', "/feed/notable.atom", "/feed/attackers-7d.nft", "/feed/misp/manifest.json"],
            "firewall": ['id="use-firewall"', "pfSense and OPNsense", "nftables"],
            "logs": ['id="use-logs"', "The log checker", "jq"],
            "platform": ['id="use-platform"', "MISP", "STIX 2.1", "Splunk"],
            "api": ['id="use-api"', 'id="use-sync"', "A polling script that behaves", "The small print"],
        }
        for name, needles in want.items():
            body = panel("use", name)
            for n in needles:
                self.assertIn(n, body, f"{n} should be in the {name} section")
        # which list first, then the tiles, then the folded sample record
        start = panel("use", "start")
        self.assertLess(start.index("Which list should I use?"), start.index('id="use-download"'))
        self.assertLess(start.index('class="fmts"'), start.index('id="sample-box"'))
        self.assertEqual(PAGE.count('class="fmts"'), 1)                 # the tiles live here and nowhere else
        self.assertIn('href="#use-download">Get the feed</a>', view("use"))

    def test_use_it_has_one_navigation_and_no_repeat_of_about(self):
        use = view("use")
        self.assertNotIn('class="jobs', use)             # the strip is the nav; the four cards doubled it
        self.assertNotIn('class="st-steps"', use)        # "How it works" is the About tab's job
        self.assertIn('id="usetabs"', use)
        self.assertIn('<button class="lnk" type="button" id="st-look">', use)   # opens the drawer for that event

    def test_about_sections_hold_what_they_should(self):
        how, feed = panel("build", "how"), panel("build", "feed")
        for n in ("Path in", "The decoys", "Why those decoys", "Nothing sent here runs", "Containment", "Modbus", "Stack"):
            self.assertIn(n, how)
        self.assertIn('class="armed-rest"', how)         # "one service is listening" reads right too
        for n in ("What gets on the feed", "The score", "Tags", "Never listed", "A wrong entry"):
            self.assertIn(n, feed)
        self.assertNotIn("What gets on the feed", how)
        self.assertNotIn("Path in", feed)

    def test_the_tab_is_called_about_and_the_copy_never_says_build_tab(self):
        self.assertIn('data-view="build" title="What this is, how it is built, and how the feed decides">About<', PAGE)
        self.assertNotIn("Build</a> tab", PAGE)
        self.assertNotIn("Eight\n", view("build"))                 # the stale count is gone
        self.assertIn('class="armed-word"', view("build"))          # filled from the live number

    def test_old_links_still_resolve(self):
        """Links written before the split must land somewhere real."""
        aliases = PAGE[PAGE.index("const SUB_ALIASES"):]
        aliases = aliases[:aliases.index("};")]
        for alias in ("bulk", "lookup", "check", "accuracy", '"use-firewall"', '"use-logs"', '"use-platform"', '"use-api"',
                      '"use-download"'):
            self.assertIn(alias, aliases)
        self.assertIn('href="#intel-bulk"', PAGE)            # the Use it tab links to it
        self.assertIn('id="bulk"', PAGE)
        self.assertIn('id="check"', PAGE)                     # #intel-check scrolls to the tools in Hosts
        # a section that moved tabs: #intel-download opens Use it at the formats
        self.assertIn('const LINK_ALIASES = {"intel-download": "use-download"};', PAGE)
        self.assertIn("name = LINK_ALIASES[name] || name;", PAGE)
        self.assertIn('id="use-download"', PAGE)
        for old in ("feed", "method", "about"):
            self.assertIn(f'{old}: ', PAGE[PAGE.index("const VIEW_ALIASES"):][:200])

    def test_links_point_at_sections_that_exist(self):
        """Every in-page #intel-x, #use-x and #build-x link must resolve to a section or an element."""
        ids = set(re.findall(r'\bid="([^"]+)"', PAGE))
        subs = {n: set(re.findall(r'data-sub="(\w+)"', view(n))) for n in TABS}
        aliases = {"intel": {"bulk", "lookup", "accuracy", "check"}, "use": {"download"}, "build": set()}
        for href in set(re.findall(r'href="#((?:intel|use|build)-[\w-]+)"', PAGE)):
            tab, rest = href.split("-", 1)
            ok = (rest in subs[tab] or rest in aliases[tab] or href in ids or rest in ids)
            self.assertTrue(ok, f"#{href} points at nothing")

    def test_the_credit_line_is_the_owners_choice(self):
        """The footer carries one credit, the owner's, with the name and title from the config
        (here "Security Engineer", never "IT/OT")."""
        self.assertIn("Security Engineer</span>", PAGE)
        self.assertNotIn("IT/OT", PAGE)
        self.assertEqual(PAGE.count("Designed and run by"), 1)

    def test_page_colours_and_sounds_match_the_servers_registry(self):
        """A protocol the server can run but the page does not know would show in the wrong
        colour, with no sound, and its tag would not link to a protocol."""
        from uninvited.core import PROTO_CAPS, PROTO_COLORS
        fallback = re.search(r"const PROTO_FALLBACK = \{(.*?)\};", PAGE, re.S).group(1)
        tones = re.search(r"const TONES = \{(.*?)\};", PAGE, re.S).group(1)
        page_colours = dict(re.findall(r'(\w+): "(#[0-9a-fA-F]{6})"', fallback))
        for proto in PROTO_CAPS:
            self.assertIn(proto, page_colours, f"{proto} has no colour on the page")
            self.assertEqual(page_colours[proto].lower(), PROTO_COLORS[proto].lower(), proto)
            self.assertRegex(tones, rf"\b{proto}: [0-9.]+", f"{proto} has no sound")

    def test_text_that_describes_a_service_is_gated_on_that_service(self):
        from uninvited.core import PROTO_CAPS
        needs = re.findall(r'data-needs="([^"]+)"', PAGE)
        self.assertTrue(needs)
        for group in needs:
            for proto in group.split():
                self.assertIn(proto, PROTO_CAPS, f"data-needs names unknown protocol {proto}")
        # every new decoy is described, and starts hidden, so nothing is claimed before it runs
        for proto in ("S7", "ENIP", "DNP3", "CAM", "ROUTER", "MCP"):
            self.assertRegex(PAGE, rf'<li data-needs="{proto}" hidden>', proto)

    def test_the_diagram_lists_services_from_the_live_config(self):
        self.assertIn('id="dg-1"', PAGE)
        self.assertIn("function drawDiagram()", PAGE)

    def test_every_new_tag_has_a_colour_mapping(self):
        from uninvited import intel
        mapping = re.search(r"const TAG_PROTO = \{(.*?)\};", PAGE, re.S).group(1)
        for tag in intel.TAG_DESCRIPTIONS:
            if tag.startswith(("camera-", "router-", "ai-endpoint", "proxy-", "ics-")):
                self.assertIn(f'"{tag}"', mapping, tag)

    def test_the_live_screen_has_worth_a_look_and_one_tabbed_side_panel(self):
        for needle in ('id="look-cards"', 'id="look-bulk"', 'id="p-side"', 'id="side-tabs"', "/api/notables?hours=1"):
            self.assertIn(needle, PAGE, needle)
        # the three old side panels are tabs now, and the summary's range switch is gone
        for gone in ('id="p-camp"', 'id="p-off"', 'class="rg on"'):
            self.assertNotIn(gone, PAGE, gone)
        for kept in ('id="campaign"', 'id="onfeed"', 'id="b-cred"', 'id="p-creds"'):
            self.assertEqual(PAGE.count(kept), 1, kept)

    def test_the_pages_generic_probe_names_are_the_servers(self):
        """A generic probe name is a web row on the page, not an exploit. The page keeps its own copy
        of the list, so it must match uninvited/intel.py exactly."""
        from uninvited.intel import GENERIC_EXPLOITS
        m = re.search(r"const GENERIC_EXPLOITS = new Set\(\[(.*?)\]\);", PAGE, re.S)
        self.assertTrue(m)
        on_page = set(re.findall(r'"([^"]+)"', m.group(1)))
        self.assertEqual(on_page, set(GENERIC_EXPLOITS) - {""})

    def test_every_cve_the_server_names_has_a_plain_name_on_the_page(self):
        """The overview read "CVE-2021-36260 (CVE-2021-36260)" while the page's table lagged behind
        uninvited/intel.py: three CVEs the server could report had no name here."""
        from uninvited.intel import EXPLOIT_CVE
        m = re.search(r"const CVE_NAMES = \{(.*?)\};", PAGE, re.S)
        self.assertTrue(m)
        on_page = set(re.findall(r'"(CVE-\d{4}-\d+)":', m.group(1)))
        self.assertEqual(on_page, set(EXPLOIT_CVE.values()))

    def test_no_em_dashes_in_the_new_copy(self):
        # Ahmad's rule for anything he publishes.
        for name in TABS:
            self.assertNotIn("—", view(name), f"em dash in the {name} view")


if __name__ == "__main__":
    unittest.main()
