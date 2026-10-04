"""Static enrichment rules for the published feed.

Everything here is a lookup table or a few lines of arithmetic, on purpose. A
consumer should be able to read this file and know exactly why an address got a
tag or a score, and a contributor should be able to fix a rule with a one-line
change. There is no model in this path.

Only tag what the evidence supports. A CVE appears here only where a request
signature matches one vulnerability unambiguously. Signatures that cover a whole
family of devices (IoT router paths, WordPress probes) get an ATT&CK technique
but no CVE.
"""
from __future__ import annotations

# HTTP exploit name (as named in listeners.HTTP_SIGNATURES) -> CVE.
EXPLOIT_CVE: dict[str, str] = {
    "Log4Shell (CVE-2021-44228)": "CVE-2021-44228",
    "Laravel Ignition RCE (CVE-2021-3129)": "CVE-2021-3129",
    "Shellshock (CVE-2014-6271)": "CVE-2014-6271",
    "PHPUnit eval-stdin RCE": "CVE-2017-9841",
    "Hikvision RCE (CVE-2021-36260)": "CVE-2021-36260",
    "Hikvision Auth Bypass (CVE-2017-7921)": "CVE-2017-7921",
    "Huawei HG532 RCE (CVE-2017-17215)": "CVE-2017-17215",
}

# Names the HTTP listener gives to requests that were looking, not attacking.
# They count as activity but not as an exploit attempt, so they add nothing to the
# exploit part of the score and do not earn the web-exploit tag.
GENERIC_EXPLOITS = frozenset({
    "", "Unclassified Probe", "Root Fingerprint", "Open Proxy Probe",
    "HTTP/2 Prior-Knowledge Probe", "MGLNDD Scanner Banner", "Malformed Request",
    "MCP/LLM Endpoint Discovery", "IP Camera Probe", "RTSP Stream Probe",
    "TLS Handshake on Plain HTTP", "SOCKS Proxy Probe",
})

# Services whose events carry an exploit name, and the industrial protocols.
HTTP_PROTOS = frozenset({"HTTP", "CAM", "ROUTER", "MCP"})
ICS_PROTOS = frozenset({"MODBUS", "S7", "ENIP", "DNP3"})


def is_attack_event(password: str | None, detail: dict) -> bool:
    """Did this one event do something a research scanner does not: try a
    password, send a named exploit, or write to a controller? Used to withdraw
    the benefit of the doubt from a host whose scanner name could not be
    confirmed (classify.py). A username alone does not count: an RDP probe
    carries one as a cookie."""
    if password is not None:
        return True
    exploit = detail.get("exploit")
    if exploit and exploit not in GENERIC_EXPLOITS:
        return True
    return detail.get("ics") in ("write", "control", "program")

CAMERA_EXPLOITS = frozenset({"Hikvision RCE (CVE-2021-36260)", "Hikvision Auth Bypass (CVE-2017-7921)"})
ROUTER_EXPLOITS = frozenset({"Huawei HG532 RCE (CVE-2017-17215)", "TR-064 Router Exploit",
                             "GPON Router Exploit", "Linksys Router Exploit", "IoT Router Exploit"})
# Named by the AI-endpoint decoy when a client does more than look.
AI_ABUSE = frozenset({"MCP Tool Call Attempt", "LLM Endpoint Abuse"})

TECHNIQUES: dict[str, str] = {
    "T1110": "Brute Force",
    "T1190": "Exploit Public-Facing Application",
    "T1021.001": "Remote Services: Remote Desktop Protocol",
    "T1595": "Active Scanning",
    "T1595.002": "Active Scanning: Vulnerability Scanning",
    "T1105": "Ingress Tool Transfer",
    # ATT&CK for ICS. The ids are not all in the T0xxx range: Command Message
    # was renumbered under Unauthorized Message, so keep an explicit set.
    "T1692.001": "Unauthorized Message: Command Message",
    "T0888": "Remote System Information Discovery",
    "T0801": "Monitor Process State",
    "T0858": "Change Operating Mode",
    "T0843": "Program Download",
}

# The same techniques under the names MISP's mitre-attack-pattern galaxy uses (galaxy version 41,
# github.com/MISP/misp-galaxy, clusters/mitre-attack-pattern.json). A tag MISP does not know is
# kept as a plain tag and never reaches the ATT&CK views, so these are copied, never guessed.
MISP_ATTACK = {
    "T1110": "Brute Force - T1110",
    "T1190": "Exploit Public-Facing Application - T1190",
    "T1021.001": "Remote Desktop Protocol - T1021.001",
    "T1595": "Active Scanning - T1595",
    "T1595.002": "Vulnerability Scanning - T1595.002",
    "T1105": "Ingress Tool Transfer - T1105",
    "T1692.001": "Command Message - T1692.001",
    "T0888": "Remote System Information Discovery - T0888",
    "T0801": "Monitor Process State - T0801",
    "T0858": "Change Operating Mode - T0858",
    "T0843": "Program Download - T0843",
}
ICS_TECHNIQUES = frozenset({"T1692.001", "T0888", "T0801", "T0858", "T0843"})

# Protocols where the honeypot sees credential guessing.
CREDENTIAL_PROTOS = frozenset({"SSH", "TNET", "FTP", "SMTP"})


# ---------------------------------------------------------------------------
# Behaviour tags. Plain words for what a host did, so a consumer can pull one
# list ("only the SSH brute-forcers") instead of taking everything.

TAG_DESCRIPTIONS: dict[str, str] = {
    "ssh-bruteforce": "guessed SSH logins",
    "telnet-bruteforce": "guessed Telnet logins, the classic IoT botnet move",
    "ftp-bruteforce": "guessed FTP logins",
    "smtp-abuse": "tried SMTP authentication or open relay",
    "rdp-scan": "probed Remote Desktop with a username cookie",
    "smb-scan": "probed Windows file sharing",
    "sip-scan": "probed VoIP signalling",
    "ics-recon": "read from or identified an industrial controller",
    "ics-write": "tried to write to an industrial controller",
    "ics-control": "tried to stop, start or reprogram an industrial controller",
    "camera-scan": "probed IP cameras",
    "camera-bruteforce": "tried logins on an IP camera",
    "camera-exploit": "sent an exploit meant for an IP camera",
    "router-scan": "probed a router's web or management port",
    "router-bruteforce": "tried logins on a router",
    "router-exploit": "sent an exploit meant for a router",
    "proxy-scan": "looked for an open web proxy to use",
    "malware-delivery": "sent a command that downloads malware onto the target",
    "ai-endpoint-scan": "looked for AI tool servers or model endpoints",
    "ai-endpoint-abuse": "tried to call an AI tool or use a model that is not theirs",
    "web-scan": "sent web requests that matched no known exploit",
    "web-exploit": "sent a request matching a named exploit",
    "cve-exploit": "sent a request matching exactly one CVE",
    "multi-service": "attacked three or more services",
    "persistent": "on record for a week or longer",
}

# Tags with their own downloadable list. The rest are still on every record.
TAG_LISTS = ("persistent", "ssh-bruteforce", "telnet-bruteforce", "rdp-scan", "web-exploit")

HIGH_SCORE = 60          # the "high confidence" list


def behaviour_tags(engaged_by_proto: dict[str, int], exploits: dict[str, int],
                   cves: list[str], span_seconds: float,
                   ics: dict[str, int] | None = None,
                   creds: dict[str, int] | None = None) -> list[str]:
    tags: set[str] = set()
    by = {p for p, n in engaged_by_proto.items() if n > 0}
    if "SSH" in by:
        tags.add("ssh-bruteforce")
    if "TNET" in by:
        tags.add("telnet-bruteforce")
    if "FTP" in by:
        tags.add("ftp-bruteforce")
    if "SMTP" in by:
        tags.add("smtp-abuse")
    if "RDP" in by:
        tags.add("rdp-scan")
    if "SMB" in by:
        tags.add("smb-scan")
    if "SIP" in by:
        tags.add("sip-scan")
    if by & ICS_PROTOS:
        # ics maps what the client did ("write", "control", "program", "identity",
        # "read") to counts. With no detail, an engaged industrial event is recon.
        kinds = {k for k, n in (ics or {}).items() if n > 0}
        if "write" in kinds:
            tags.add("ics-write")
        if kinds & {"control", "program"}:
            tags.add("ics-control")
        if kinds - {"write", "control", "program"} or not kinds:
            tags.add("ics-recon")

    names = set(exploits)
    web_named = [n for n in named_exploits(exploits) if n not in AI_ABUSE]
    if by & HTTP_PROTOS:
        if web_named:
            tags.add("web-exploit")
        elif "HTTP" in by:
            tags.add("web-scan")
    c = creds or {}
    if "CAM" in by or names & {"IP Camera Probe"}:
        tags.add("camera-scan")
    if "CAM" in by and c.get("CAM"):
        tags.add("camera-bruteforce")
    if names & CAMERA_EXPLOITS:
        tags.add("camera-exploit")
    if "ROUTER" in by:
        tags.add("router-scan")
        if c.get("ROUTER"):
            tags.add("router-bruteforce")
    if names & ROUTER_EXPLOITS:
        tags.add("router-exploit")
    if names & {"Open Proxy Probe", "SOCKS Proxy Probe"}:
        tags.add("proxy-scan")
    if "Malware Dropper Command" in names:
        tags.add("malware-delivery")
    if "MCP/LLM Endpoint Discovery" in names or ("MCP" in by and not names & AI_ABUSE):
        tags.add("ai-endpoint-scan")
    if names & AI_ABUSE:
        tags.add("ai-endpoint-abuse")
    if cves:
        tags.add("cve-exploit")
    if len(by) >= 3:
        tags.add("multi-service")
    if span_seconds >= 7 * 86400:
        tags.add("persistent")
    return sorted(tags)


CLASSIFICATION = {"attack": "malicious", "research": "scanner", "tor": "tor-exit"}


# ---------------------------------------------------------------------------
# Who you might hit. A guess from the network's name, and it is labelled as one.
# An address inside a hosting provider is usually one customer's server, so
# blocking it is low risk. An address inside a consumer ISP can be shared or
# reassigned next week, so it gets a shorter expiry and a warning.

HOSTING_WORDS = (
    "hosting", "cloud", "server", "vps", "datacenter", "data center", "colo",
    "digitalocean", "amazon", "aws", "google", "microsoft", "azure", "ovh",
    "hetzner", "linode", "akamai", "vultr", "contabo", "alibaba", "aliyun",
    "tencent", "choopa", "leaseweb", "scaleway", "oracle", "rackspace",
    "kimsufi", "psychz", "quadranet", "m247", "cdn", "hostinger", "namecheap",
    "volcano engine", "bytedance", "baidu", "unmanaged", "massivegrid", "techoff",
    "selectel", "timeweb", "gcore", "data campus", "colocation", "pfcloud",
)
ISP_WORDS = (
    "telecom", "telekom", "telecommunications", "broadband", "cable", "mobile",
    "wireless", "communications", "comcast", "verizon", "at&t", "charter",
    "frontier", "vodafone", "orange", "unicom", "rostelecom", "telefonica",
    "telstra", "korea telecom", "sk broadband", "lg uplus", "pldt", "airtel",
    "jio", "reliance", "ptcl", "vnpt", "viettel", "fpt", "true corp",
    "internet service", "internet services", "residential", "chinanet",
    "china telecom", "cmnet", "kpn", "swisscom", "deutsche telekom",
)
RESIDENTIAL_RDNS = (
    "dynamic", "dyn-", "dhcp", "pool", "dsl", "adsl", "cable", "cust", "customer",
    "ppp", "broadband", "residential",
)


def host_type(network: str | None, rdns: str | None = None) -> str:
    """'hosting', 'isp' or 'unknown', from words in the network and reverse-DNS
    names. Reverse DNS that looks like a customer line wins over the network."""
    r = (rdns or "").lower()
    if r and any(w in r for w in RESIDENTIAL_RDNS):
        return "isp"
    n = (network or "").lower()
    if any(w in n for w in HOSTING_WORDS):
        return "hosting"
    if any(w in n for w in ISP_WORDS):
        return "isp"
    return "unknown"


COLLATERAL = {"hosting": "low", "isp": "medium", "unknown": "unknown"}


def ttl_days(kind_of_host: str, score: int | None) -> int:
    """How long a consumer who caches the list should keep an entry after the
    last time it was seen. Consumer lines get less time, strong evidence more."""
    base = {"hosting": 7, "isp": 3}.get(kind_of_host, 5)
    if score is not None and score >= HIGH_SCORE:
        base = (base * 3 + 1) // 2
    return base


# ---------------------------------------------------------------------------
# Never listed, however they behave. Addresses that would do more harm blocked
# than the noise they make. Private and shared address space is excluded
# elsewhere; anything you add under feed.exclude in the config is on top of this.

NEVER_ADDRESSES = (
    "1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
    "208.67.222.222", "208.67.220.220",
)
# Big platforms. A download URL on one of these is never listed: it is as likely an attempt to
# get a legitimate file blocked as a real dropper, and listing it only costs that platform's users.
NEVER_DOMAINS = (
    "google.com", "googleapis.com", "gstatic.com", "googleusercontent.com", "github.com",
    "githubusercontent.com", "microsoft.com", "windowsupdate.com", "live.com", "apple.com",
    "icloud.com", "amazon.com", "cloudflare.com", "cloudfront.net", "akamaihd.net", "akamai.net",
    "fastly.net", "ubuntu.com", "debian.org", "mozilla.org", "python.org", "pypi.org", "npmjs.org",
    "docker.com", "wikipedia.org", "w3.org",
)
NEVER_RDNS_SUFFIXES = (
    ".googlebot.com", ".search.msn.com", ".applebot.apple.com",
)


def technique_url(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


def cve_url(cve: str) -> str:
    return "https://nvd.nist.gov/vuln/detail/" + cve


def named_exploits(exploits: dict[str, int]) -> list[str]:
    return sorted(e for e in exploits if e not in GENERIC_EXPLOITS)


ICS_TECHNIQUE_FOR = {"write": "T1692.001", "identity": "T0888", "read": "T0801",
                     "control": "T0858", "program": "T0843"}


def tags(engaged_by_proto: dict[str, int], exploits: dict[str, int],
         ics: dict[str, int] | None = None,
         creds: dict[str, int] | None = None) -> tuple[list[str], list[str]]:
    """-> (ATT&CK technique ids, CVE ids) for one address.

    An address with no engaged events only connected and left, which is
    reconnaissance: T1595.
    """
    named = named_exploits(exploits)
    techniques: set[str] = set()
    for proto, count in engaged_by_proto.items():
        if count <= 0:
            continue
        if proto in CREDENTIAL_PROTOS:
            techniques.add("T1110")
        elif proto == "RDP":
            techniques.add("T1021.001")
        elif proto == "SMB":
            techniques.add("T1595")
        elif proto in HTTP_PROTOS:
            if named:
                techniques.add("T1190")
                if "Malware Dropper Command" in named:
                    techniques.add("T1105")
            else:
                techniques.add("T1595.002" if proto == "HTTP" else "T1595")
            if (creds or {}).get(proto):
                techniques.add("T1110")
        elif proto in ICS_PROTOS:
            kinds = [k for k, n in (ics or {}).items() if n > 0 and k in ICS_TECHNIQUE_FOR]
            techniques.update(ICS_TECHNIQUE_FOR[k] for k in kinds)
            if not kinds:
                techniques.add("T0801")
    if not techniques:
        techniques.add("T1595")
    cves = sorted({EXPLOIT_CVE[e] for e in named if e in EXPLOIT_CVE})
    return sorted(techniques), cves


def score(engaged: int, protocols: int, span_seconds: float, exploit_names: int) -> int:
    """Confidence that an address is worth blocking, 0 to 100.

    Four independent signals, each capped, so the number can be explained in one
    sentence. Volume, breadth and exploits are counted over the trailing 30
    days. Persistence is the address's whole history with this honeypot.

      volume       10 / 20 / 30 / 40   at 3 / 10 / 50 / 200 engaged events
      breadth      10 / 20             at 2 / 3 or more protocols engaged
      persistence   5 / 10 / 20        seen over 1 / 3 / 7 or more days
      exploits     20                  at least one named exploit attempt
    """
    total = 0
    for threshold, points in ((200, 40), (50, 30), (10, 20), (3, 10)):
        if engaged >= threshold:
            total += points
            break
    if protocols >= 3:
        total += 20
    elif protocols == 2:
        total += 10
    days = span_seconds / 86400
    for threshold, points in ((7, 20), (3, 10), (1, 5)):
        if days >= threshold:
            total += points
            break
    if exploit_names:
        total += 20
    return min(100, total)
