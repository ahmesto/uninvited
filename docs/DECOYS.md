# The decoys

Fifteen services, all **low interaction**: each speaks enough of a protocol to be taken for the real thing, records what a
client does, and nothing more. This page says what each one pretends to be, what it records, and the promises every one of
them keeps.

## The promises

These are checked by the test suite (`tests/`), not just stated.

1. **No login ever succeeds.** A credential is recorded and refused, every time. Nothing a client does gets a session.
2. **Nothing a client sends is executed, interpreted or kept as state.** A Modbus write, an S7 stop, a camera command
   injection and a shell command in a web request are logged and answered with a canned reply. Nothing runs.
3. **Nothing is fetched.** When a request carries a download command, the URL is *read out of the text*. It is never
   opened, resolved or downloaded.
4. **Replies are small and fixed.** No decoy can be made to send a large or amplified answer.
5. **Everything is bounded.** Every read has a timeout. A line is capped at 2,048 bytes, a connection lives at most about
   30 seconds, a connection serves a fixed number of requests (32 frames for the industrial decoys, 40 header lines for
   HTTP), a looping scanner logs a limited number of identical reads, and the raw bytes kept per request are capped at
   4 KB. Total concurrent connections are capped (`max_connections`, 400 by default) and so are WebSocket viewers.
6. **No UDP except SIP, and SIP is limited.** An answer to a forged source address would turn the honeypot into a reflector,
   so EtherNet/IP and BACnet over UDP are deliberately not collected. The one UDP service (SIP) is rate limited per source
   and for the whole port, never answers with more bytes than it received, and nothing from it is published.
7. **Attacker-controlled text is never trusted when it is shown or written out.** The page escapes every field, raw
   requests are only ever displayed through an escaper that leaves no markup, control character or newline, CSV cells that
   start with `=`, `+`, `-` or `@` are defused, and feed files contain only values the feed built itself.

## Services

| Service | Port in the example config | Pretends to be | Records | Notes |
|---|---|---|---|---|
| `SSH` | 2222 | OpenSSH on Ubuntu (paramiko) | username, password, public-key fingerprint, client banner, **HASSH** client fingerprint | Every authentication fails. HASSH survives address rotation, so it groups hosts running the same tool. |
| `TNET` | 2323 | A Linux login prompt | up to 3 username/password pairs per connection | The classic IoT-botnet door. Mirai's default pairs are flagged. |
| `FTP` | 2121 | vsFTPd | USER/PASS pairs | Refuses everything. |
| `SMTP` | 2525 | Postfix | AUTH PLAIN/LOGIN credentials, open-relay probes | Relays nothing. |
| `HTTP` | 8081 | nginx on Ubuntu | method, path, headers, body start, matched signature, the raw request (owner only) | 404 for everything. Matches about 30 exploit and probe signatures, decoding the request first. Reads out malware download URLs. |
| `RDP` | 33890 | A Windows RDP listener | the connection request and its username cookie | Never negotiates. |
| `SMB` | 4445 | A Windows file server | the negotiate dialect | Replies nothing. |
| `SIP` | 5060 | A PBX (TCP and UDP) | method, caller, destination, toll-fraud destination country | Always refuses. |
| `MODBUS` | 5020 | A small controller (Modbus TCP) | every function code, address range, writes and identity reads, labelled `read`, `identity` or `write` | Disabled in the example config. |
| `S7` | 5102 | A Siemens S7-300 style PLC | setup, identification (SZL) reads, reads, writes, stop/start, block transfer, labelled | Tested with an independent S7 client. |
| `ENIP` | 44818 | A Rockwell-style controller (EtherNet/IP over TCP) | identity, services, sessions, CIP reads and writes | Tested with an independent client. TCP only. |
| `DNP3` | 20000 | A utility outstation | link frames and application functions | **Experimental**: no independent client has been run against it. |
| `CAM` | 8083 web, 8554 RTSP | An IP camera's web server and video port | logins, vendor exploit paths, which camera brand an RTSP scanner is hunting | A camera that "accepted" an injected command, so the download that follows gets sent and captured. |
| `ROUTER` | 8084 web, 7547 TR-069 | A home router's admin page and its remote-management port | logins, router exploit paths, TR-069 SOAP calls | Same idea as the camera. |
| `MCP` | 8085 | An AI tool server (Model Context Protocol) and a model API | discovery, tool calls, model requests | Lists a bait `run_command` tool; calling it is answered "permission denied" and labelled. |

Every service ships **off** in the example configuration except the classic ones, and every industrial, camera, router and AI
decoy needs its own port forward at the gateway before anything reaches it.

## Identities

What a decoy says it is (vendor, model, firmware, plant name) is set in the configuration, never in code. The defaults are
realistic so scanners treat the decoys as the real thing. Read them before you expose them: naming a real vendor on the
public internet is your call. Never put a real address of yours in an identity (`advertise_ip` stays `0.0.0.0`).

## Adding a decoy

See [CONTRIBUTING.md](../CONTRIBUTING.md). The short version: pure functions that turn one parsed request into one canned
reply, a listener that bounds everything, tests that include a real client where one exists, and a fuzz seed.

## Give every decoy your own identity

The made-up device names in this repository (the Modbus vendor and product, the S7 serial number and plant name, the
EtherNet/IP serial number, the camera and router models) are public. A sensor that keeps them can be found by searching
an internet scanner for them, and so can every other copy. Set your own under `identity:` or `model:` before you expose a
decoy. `python -m uninvited --check -c <file>` warns about each reachable decoy that still announces a shipped value,
and `deploy/own-identities.py` replaces every one of them with a random value of the same shape in one go (it checks
the result, restarts the service and puts the old file back if the service does not come up).
