"""uninvited entrypoint: python -m uninvited --config config.yaml"""
from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import os
import signal
import sys

import uvicorn

from . import intel
from .app import Hub, build_app
from .classify import Classifier, is_mirai_pair
from .core import Knock, load_config
from .feeds import REFRESH_SECONDS, FeedCache
from .identity import Identity
from .geo import Geo
from .listeners import LISTENERS, SipUdpProtocol
from .ssh_pot import SshPot
from .store import Store

log = logging.getLogger("uninvited")


async def run(config_path: str) -> None:
    cfg = load_config(config_path)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)-14s %(message)s",
    )

    store = Store(cfg["database"])
    geo = Geo(cfg["geoip"].get("city_db", ""), cfg["geoip"].get("asn_db", ""))
    cls_cfg = cfg.get("classify") or {}
    classifier = Classifier(
        enable_rdns=cls_cfg.get("rdns", True),
        enable_tor=cls_cfg.get("tor", True),
    )
    hub = Hub(cfg, store)
    loop = asyncio.get_running_loop()

    async def emit(knock: Knock) -> None:
        """Enrich, classify, persist, broadcast. One funnel for every listener."""
        for key, value in geo.lookup(knock.ip).items():
            setattr(knock, key, value)
        verdict = await classifier.classify(knock.ip)
        if (verdict["kind"] == "research" and not verdict["confirmed"]
                and intel.is_attack_event(knock.password, knock.detail)):
            # Believed on the strength of a name it could not confirm, and it has
            # just tried a password or an exploit. A research scanner does not.
            classifier.demote(knock.ip)
            knock.demoted = True
            verdict = {"kind": "attack", "label": None, "rdns": verdict["rdns"]}
        knock.kind = verdict["kind"]
        knock.label = verdict["label"]
        knock.rdns = verdict["rdns"]
        knock.mirai = is_mirai_pair(knock.username, knock.password)
        stats = await loop.run_in_executor(None, store.record, knock)
        log.info(
            "%-4s %-15s %-2s %-8s %s",
            knock.proto, knock.ip, knock.iso, knock.kind,
            knock.label or (knock.username or "")[:24],
        )
        await hub.publish(knock, stats)

    limiter = asyncio.Semaphore(cfg["max_connections"])
    listeners = []
    ssh_pots = []
    udp_transports = []

    for svc in cfg.services:
        proto, port = svc["proto"], int(svc["port"])
        if proto == "SSH":
            pot = SshPot(
                cfg["listen_ip"], port, cfg["ssh_host_key"],
                svc.get("banner", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10"),
                emit, loop, cfg["max_connections"],
            )
            pot.start()
            ssh_pots.append(pot)
            continue

        cls = LISTENERS[proto]
        listener = cls(svc, emit, limiter)
        try:
            await listener.start(cfg["listen_ip"])
        except OSError as exc:
            # One port that is taken must not take the other decoys, or the dashboard,
            # down with it. Say so loudly and carry on.
            log.error("cannot listen for %s on %s:%d (%s). That service is OFF until the "
                      "port is free and the service is restarted.", proto, cfg["listen_ip"], port, exc)
            continue
        listeners.append(listener)

        if proto == "SIP" and svc.get("udp", True):
            try:
                transport, _ = await loop.create_datagram_endpoint(
                    lambda port=port: SipUdpProtocol(emit, port),
                    local_addr=(cfg["listen_ip"], port),
                )
            except OSError as exc:
                log.error("cannot listen for SIP on %s:%d/udp (%s). UDP is OFF.",
                          cfg["listen_ip"], port, exc)
                continue
            udp_transports.append(transport)
            log.info("SIP  listening on %s:%d/udp", cfg["listen_ip"], port)

    async def pruner() -> None:
        while True:
            await asyncio.sleep(6 * 3600)
            removed = await loop.run_in_executor(
                None, store.prune, cfg["retention_days"]
            )
            if removed:
                log.info("pruned %d knocks past the retention window", removed)

    async def tor_refresher() -> None:
        await classifier.refresh_tor()
        while True:
            await asyncio.sleep(6 * 3600)
            await classifier.refresh_tor()

    feed_cfg = cfg.get("feed") or {}
    # Who joined and left each list, kept next to the database across restarts.
    state_path = feed_cfg.get("state") or os.path.join(
        os.path.dirname(os.path.abspath(cfg["database"])), "feed_state.json")
    feeds = FeedCache(cfg["database"], feed_cfg.get("exclude", []), state_path, Identity.from_cfg(cfg))

    async def feed_refresher() -> None:
        # Read-only connection, so a slow rebuild never blocks the honeypot.
        while True:
            try:
                await loop.run_in_executor(None, feeds.refresh)
            except Exception:
                log.exception("feed rebuild failed")
            await asyncio.sleep(REFRESH_SECONDS)

    prune_task = asyncio.create_task(pruner())
    tor_task = asyncio.create_task(tor_refresher())
    feed_task = asyncio.create_task(feed_refresher())

    app = build_app(cfg, store, hub, feeds)
    server = uvicorn.Server(
        uvicorn.Config(
            app,
            host=cfg["dashboard"]["host"],
            port=int(cfg["dashboard"]["port"]),
            log_level="warning",
            access_log=False,
            # The page never sends the server a WebSocket message, so a large one is
            # an attack: uvicorn's default would buffer up to 16 MB per connection.
            ws_max_size=2048,
            limit_concurrency=400,
            timeout_keep_alive=10,
        )
    )

    stopping = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stopping.set)

    log.info(
        "dashboard on http://%s:%s",
        cfg["dashboard"]["host"], cfg["dashboard"]["port"],
    )
    serve_task = asyncio.create_task(server.serve())
    await stopping.wait()

    log.info("shutting down")
    server.should_exit = True
    prune_task.cancel()
    tor_task.cancel()
    feed_task.cancel()
    for task in (prune_task, tor_task, feed_task):
        with contextlib.suppress(asyncio.CancelledError):
            await task
    with contextlib.suppress(asyncio.TimeoutError):
        await asyncio.wait_for(asyncio.shield(serve_task), 8)
    for transport in udp_transports:
        transport.close()
    await asyncio.gather(*(listener.stop() for listener in listeners), return_exceptions=True)
    for pot in ssh_pots:
        pot.stop()
    geo.close()
    store.close()


def main() -> None:
    parser = argparse.ArgumentParser(prog="uninvited")
    parser.add_argument("-c", "--config", default="config.yaml")
    parser.add_argument("--check", action="store_true",
                        help="check the config file and exit (0 = fine, 1 = errors); "
                             "run it before restarting the service with a changed file")
    args = parser.parse_args()
    if args.check:
        from .configcheck import report
        sys.exit(report(args.config))
    try:
        asyncio.run(run(args.config))
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
