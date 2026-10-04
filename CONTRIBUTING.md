# Contributing

Thanks for wanting to help. This is a small project with strong opinions, so a few minutes with this page saves everyone a
round trip.

## The ground rules

1. **Nothing a client sends is ever executed, trusted or fetched.** A decoy records and refuses. See
   [docs/DECOYS.md](docs/DECOYS.md) for the promises; the tests check them, and a change that weakens one will not be merged.
2. **Rules are tables and arithmetic, not models.** Classification, tags and scores live in `uninvited/intel.py` and the
   signature table in `uninvited/listeners.py`. A reader should be able to see why an address got a tag. No machine learning in
   the decision path.
3. **Classify from real traffic.** A new signature needs the real request that motivated it (redact anything private), a
   test that feeds exactly that request through the classifier, and a test that a few look-alike innocent requests are left
   alone. "A scanner might send this" is not enough; "a scanner sent this" is.
4. **Say only what you ran.** If you add a recipe, a format or a claim, run it. If you could not, say so in the text.
5. **Numbers in copy come from data, not memory.** Anything the site or the docs state as a measured number must be
   recomputable from the database or the feed.
6. **No personal data in the repository.** Use documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`,
   `2001:db8::/32`) and `example.org` names in code, tests, docs and examples. Never commit a real address of yours, a key, or
   a captured credential that looks real.

## Setting up

```
python -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
python -m unittest discover tests                    # about a minute and a half
python -m uninvited --config config.quickstart.yaml     # a local instance on loopback
python tools/try_it.py                               # knock on every decoy
```

`FUZZ_CASES=300 python -m unittest tests.test_fuzz` runs the fuzz harness harder. `python -m uninvited --check -c <file>`
validates a configuration without starting anything.

## Adding a signature

1. Capture the request. The raw bytes of every web request are kept for the owner (`python3 /opt/uninvited/payloads.py`).
2. Add one tuple to `HTTP_SIGNATURES` in `uninvited/listeners.py`: a regex, a name, and what it was for. Order matters, specific
   before general. The regex runs against the path, the header values and the start of the body, as sent and with
   percent-encoding removed.
3. If it names exactly one CVE, add it to `EXPLOIT_CVE` in `uninvited/intel.py`. If it is only looking (a probe, a
   fingerprint), add the name to `GENERIC_EXPLOITS` so it adds nothing to a score.
4. Add the test described in rule 3.

## Adding a decoy

A decoy is a pure function from one parsed request to one canned reply (see `uninvited/s7.py`, `enip.py`, `personas.py`) plus
a listener that bounds everything (see `S7Listener`). Checklist:

- Reads have a timeout, a frame count is capped, a looping scanner logs a limited number of reads.
- Credentials are never accepted, writes are acknowledged and forgotten.
- Replies are small and fixed. No UDP unless you also rate limit it and never reply with more than you received.
- It ships `enabled: false` in `config.example.yaml`.
- Tests: the frame rules, the listener over a socket, a real independent client if one exists, a seed for
  `tests/test_fuzz.py`.
- A protocol colour and label in `uninvited/core.py`, and the description text on the page shows only while the service runs.

## Changing what the feeds publish

The published files are an interface other people build on. A field that is renamed or removed bumps `SCHEMA_VERSION`;
adding a field does not, but either way add a line to `CHANGELOG` in `uninvited/feeds.py`. `tests/test_published.py` compares
the STIX, CSV and MISP output byte for byte with reference files; regenerate them only on purpose.

## Pull requests

Keep them small and say why. Match the surrounding code: its comment density, its naming, its idiom. Run the whole test
suite first. Commit messages in the imperative, one line, then a paragraph on the reason if it is not obvious.

By contributing you agree your contribution is licensed under the project's license.
