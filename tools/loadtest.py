"""A bounded load test, for the owner of an instance to run against that instance and no other.

    python tools/loadtest.py https://example.org --viewers 50 --seconds 60

Each "viewer" loops over what a real visitor fetches: the page, the catalog, the feed, a kind
filter, one address page, one lookup. It reports requests, errors, and p50/p95 latency per path,
nothing else. Standard library only. Stop it with Ctrl-C; it stops on its own at --seconds.
"""
from __future__ import annotations

import argparse
import random
import statistics
import threading
import time
import urllib.error
import urllib.request

PATHS = [
    ("/", 3), ("/feed/index.json", 2), ("/api/feed?proto=ALL&limit=300", 2), ("/api/feed?kind=device&limit=300", 1),
    ("/api/notables?hours=1", 1), ("/api/timeline?hours=24&buckets=144", 1), ("/api/services?hours=24", 1),
    ("/feed/attackers-24h.json", 1), ("/ip/{ip}", 1), ("/api/lookup?ip={ip}", 1),
    ("/static/vendor/land-50m.json", 1),
]
UA = {"User-Agent": "uninvited-loadtest/1.0 (owner, bounded)"}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("site")
    ap.add_argument("--viewers", type=int, default=50)
    ap.add_argument("--seconds", type=int, default=60)
    a = ap.parse_args()
    site = a.site.rstrip("/")
    # One listed address for the address page and the lookup, taken from the site's own feed.
    with urllib.request.urlopen(urllib.request.Request(site + "/feed/attackers-24h.txt", headers=UA), timeout=30) as r:
        ip = next(x for x in r.read().decode().splitlines() if x and x[0] != "#")
    weighted = [p.format(ip=ip) for p, w in PATHS for _ in range(w)]
    stats: dict[str, list[float]] = {p.format(ip=ip): [] for p, _ in PATHS}
    errors: dict[str, int] = {}
    lock = threading.Lock()
    stop = time.time() + a.seconds

    def viewer() -> None:
        while time.time() < stop:
            path = random.choice(weighted)
            t = time.time()
            try:
                with urllib.request.urlopen(urllib.request.Request(site + path, headers=UA), timeout=30) as r:
                    r.read()
                    code = r.status
            except urllib.error.HTTPError as e:
                code = e.code
            except Exception:
                code = 0
            dt = time.time() - t
            with lock:
                stats[path].append(dt)
                if code != 200:
                    errors[f"{path} -> {code}"] = errors.get(f"{path} -> {code}", 0) + 1
            time.sleep(random.uniform(0.2, 1.0))

    threads = [threading.Thread(target=viewer, daemon=True) for _ in range(a.viewers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    total = sum(len(v) for v in stats.values())
    print(f"{a.viewers} viewers for {a.seconds}s: {total} requests, {total / a.seconds:.1f}/s, {sum(errors.values())} not-200")
    for path, times in stats.items():
        if not times:
            continue
        times.sort()
        p50 = statistics.median(times)
        p95 = times[min(len(times) - 1, int(len(times) * 0.95))]
        print(f"  {path:42s} {len(times):5d}  p50 {p50 * 1000:6.0f} ms  p95 {p95 * 1000:6.0f} ms  max {times[-1] * 1000:6.0f} ms")
    for k, n in sorted(errors.items()):
        print(f"  {n:5d}  {k}")


if __name__ == "__main__":
    main()
