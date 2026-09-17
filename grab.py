#!/usr/bin/env python3
"""grab — collect the IP addresses that belong to a target, without a third-party API.

Four ways in, detected from the argument:

    grab.py example.com              a domain or subdomain
    grab.py cert.pem                 a certificate file (PEM or DER)
    grab.py 6153a96f...2200          a certificate SHA-256 fingerprint
    grab.py --live host              a host, whose certificate is fetched over TLS first

Every source is passive, keyless and public: DNS over HTTPS, Certificate Transparency
(crt.sh and Cert Spotter), subfinder's keyless sources, subdomain.center, Team Cymru's
DNS-based ASN service, and RIR RDAP. No API key is read or required, and nothing is
scanned — the only packet sent to a target is the single TLS handshake behind --live.

Enumeration only. Run it against assets you have confirmed are in scope, and read the
program's rules before you do.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import concurrent.futures
import hashlib
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

UA = "grab/2.0 (authorized-asset recon; passive sources only)"
# Only resolvers that answer the JSON API are listed: Quad9 speaks the RFC 8484 wire
# format and rejects these queries, and OpenDNS answers nothing here.
DOH_RESOLVERS = (
    ("google", "https://dns.google/resolve"),
    ("cloudflare", "https://cloudflare-dns.com/dns-query"),
    ("adguard", "https://dns.adguard-dns.com/resolve"),
)
CERTSPOTTER_URL = "https://api.certspotter.com/v1/issuances"
CACHE_DIR = Path(os.environ.get("GRAB_CACHE") or (Path.home() / ".cache" / "grab"))
CERT_CACHE_TTL = 30 * 24 * 3600
WORKERS = 16
HTTP_TIMEOUT = 25
HEX64 = re.compile(r"\A(?:[0-9a-fA-F]{2}:){31}[0-9a-fA-F]{2}\Z|\A[0-9a-fA-F]{64}\Z")
ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
HOSTNAME = re.compile(r"\A(?:\*\.)?(?:[a-zA-Z0-9_](?:[a-zA-Z0-9_-]{0,61}[a-zA-Z0-9_])?\.)+[a-zA-Z]{2,}\Z")
MULTI_PART_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "co.nz", "net.nz", "org.nz",
    "com.au", "net.au", "org.au", "co.jp", "com.br", "com.mx", "com.ar", "com.co",
    "co.in", "co.za", "com.tr", "com.tw", "com.hk", "com.sg", "co.kr", "co.il",
    "com.cn", "com.pl", "com.ua",
}
# Matched against the CNAME target rather than compared literally: edge hostnames vary
# per customer, so Vercel answers as vercel-dns-013.com, not vercel-dns.com.
CDN_PROVIDERS = (
    ("Cloudflare", r"\.cloudflare\.(?:net|com)\Z"),
    ("Vercel", r"vercel-dns(?:-\d+)?\.com\Z|\.vercel\.app\Z"),
    ("Akamai", r"\.akamaiedge\.net\Z|\.akamai\.net\Z|\.akamaitechnologies\.com\Z|edgesuite\.net\Z|edgekey\.net\Z"),
    ("Fastly", r"\.fastly\.net\Z|fastlylb\.net\Z"),
    ("CloudFront", r"\.cloudfront\.net\Z"),
    ("Azure", r"\.azureedge\.net\Z|\.trafficmanager\.net\Z|\.azurefd\.net\Z"),
    ("Netlify", r"\.netlify\.app\Z|\.netlify\.com\Z"),
    ("Sucuri", r"\.sucuri\.net\Z"),
    ("StackPath", r"stackpathdns\.com\Z|hwcdn\.net\Z"),
    ("CDN77", r"\.cdn77\.org\Z"),
    ("Limelight", r"\.llnwd\.net\Z"),
    ("Imperva", r"\.incapdns\.net\Z|\.impervadns\.net\Z"),
    ("CacheFly", r"\.cachefly\.net\Z"),
    ("Automattic", r"\.wordpress\.com\Z|\.wpengine\.com\Z"),
    ("Heroku", r"\.herokudns\.com\Z|\.herokuapp\.com\Z"),
    ("Shopify", r"\.myshopify\.com\Z|\.shopify\.com\Z"),
    ("GitHub Pages", r"\.github\.io\Z"),
    ("Render", r"\.onrender\.com\Z|\.render\.com\Z"),
    ("Fly", r"\.fly\.dev\Z"),
    ("Netlify DNS", r"\.nsone\.net\Z"),
)

# Some providers answer with a flattened A record and no CNAME at all, so the address's
# registry holder is the only remaining signal. Only networks that exist to serve other
# people's content belong here: Amazon, Microsoft and Google all host a target's own
# servers directly, and calling those an edge would be wrong.
CDN_ORGS = (
    ("Cloudflare", r"cloudflare"),
    ("Akamai", r"akamai"),
    ("Fastly", r"fastly"),
    ("Imperva", r"imperva|incapsula"),
    ("Sucuri", r"sucuri"),
    ("StackPath", r"stackpath"),
    ("Edgio", r"edgio|limelight"),
    ("CDN77", r"cdn77"),
    ("Bunny", r"bunnyway|bunny cdn"),
)
RDAP_BY_REGISTRY = {
    "arin": "https://rdap.arin.net/registry",
    "ripencc": "https://rdap.db.ripe.net",
    "apnic": "https://rdap.apnic.net",
    "lacnic": "https://rdap.lacnic.net",
    "afrinic": "https://rdap.afrinic.net/rdap",
}


class SourceError(Exception):
    """A source failed in a way worth reporting rather than swallowing."""


class RateLimited(SourceError):
    def __init__(self, message: str):
        super().__init__(message)


# --------------------------------------------------------------------------- http

def http_get_json(url: str, *, retries: int = 3, headers: dict | None = None) -> tuple[object, dict]:
    """GET a JSON document. Retries transient 5xx; surfaces 429 as RateLimited."""
    request_headers = {"User-Agent": UA, "Accept": "application/json"}
    if headers:
        request_headers.update(headers)
    meta: dict = {"url": url, "attempts": 0}
    last: Exception | None = None
    for attempt in range(1, retries + 1):
        meta["attempts"] = attempt
        try:
            request = urllib.request.Request(url, headers=request_headers)
            with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT) as response:
                raw = response.read().decode("utf-8", "replace")
                meta["status"] = response.status
                meta["rate_limit_limit"] = response.headers.get("x-ratelimit-limit")
                meta["rate_limit_remaining"] = response.headers.get("x-ratelimit-remaining")
                meta["rate_limit_reset"] = response.headers.get("x-ratelimit-reset")
                return json.loads(raw), meta
        except urllib.error.HTTPError as error:
            meta["status"] = error.code
            if error.code == 429:
                reset = error.headers.get("x-ratelimit-reset") if error.headers else None
                raise RateLimited(
                    f"{url} refused the request: rate limit exhausted"
                    + (f", resets at {reset}" if reset else "")
                ) from error
            if error.code in (500, 502, 503, 504) and attempt < retries:
                last = error
                time.sleep(2 ** attempt)
                continue
            raise SourceError(f"{url} returned HTTP {error.code}") from error
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as error:
            last = error
            if attempt < retries:
                time.sleep(2 ** attempt)
                continue
    raise SourceError(f"{url} failed after {retries} attempts: {last}")


# ------------------------------------------------------------------ dns over https

def doh_answers(payload: object, record_type: int) -> list[str]:
    """Pull the data fields of one record type out of a DoH JSON answer."""
    if not isinstance(payload, dict):
        return []
    answers = payload.get("Answer") or []
    return [a["data"] for a in answers if isinstance(a, dict) and a.get("type") == record_type]


def doh_lookup(name: str) -> dict:
    """Resolve a name through the keyless DoH resolvers. Returns A, AAAA and CNAME data.

    NXDOMAIN short-circuits: a name that does not exist costs one request rather than
    one per record type per resolver, which matters on a list full of dead wildcard names.
    """
    result: dict = {"name": name, "A": [], "AAAA": [], "CNAME": [], "resolver": None}
    for label, base in DOH_RESOLVERS:
        try:
            payload, _ = http_get_json(
                f"{base}?name={urllib.parse.quote(name)}&type=1",
                headers={"Accept": "application/dns-json"},
                retries=2,
            )
            if isinstance(payload, dict) and payload.get("Status") == 3:
                return result
            result["A"].extend(doh_answers(payload, 1))
            for record_type, key in ((28, "AAAA"), (5, "CNAME")):
                more, _ = http_get_json(
                    f"{base}?name={urllib.parse.quote(name)}&type={record_type}",
                    headers={"Accept": "application/dns-json"},
                    retries=2,
                )
                result[key].extend(doh_answers(more, record_type))
            if result["A"] or result["AAAA"] or result["CNAME"]:
                result["resolver"] = label
                break
        except SourceError:
            continue
    return result


def doh_txt(name: str) -> list[str]:
    for _, base in DOH_RESOLVERS:
        try:
            payload, _ = http_get_json(
                f"{base}?name={urllib.parse.quote(name)}&type=TXT",
                headers={"Accept": "application/dns-json"},
                retries=2,
            )
            answers = doh_answers(payload, 16)
            if answers:
                return [a.strip('"') for a in answers]
        except SourceError:
            continue
    return []


def cname_chain(name: str) -> list[str]:
    seen, frontier, hops = {name}, [name], []
    while frontier and len(hops) < 8:
        current = frontier.pop()
        for target in doh_lookup(current)["CNAME"]:
            target = target.rstrip(".").lower()
            hops.append(target)
            if target not in seen:
                seen.add(target)
                frontier.append(target)
    return hops


def cdn_fronts(hops: list[str]) -> tuple[str, str] | None:
    """Return the CDN provider and the edge hostname, if the CNAME chain lands on one."""
    for hop in hops:
        normalized = hop.rstrip(".")
        for provider, pattern in CDN_PROVIDERS:
            if re.search(pattern, normalized):
                return provider, hop
    return None


def cdn_org(org: str | None) -> str | None:
    """Return the CDN provider when an allocation's holder is a CDN, else None."""
    if not org:
        return None
    for provider, pattern in CDN_ORGS:
        if re.search(pattern, org, re.IGNORECASE):
            return provider
    return None


# --------------------------------------------------------------------------- names

def guess_apex(host: str) -> str:
    """Best-effort registrable domain: enough to ask certificate transparency for the tree."""
    host = host.strip().lower().lstrip("*.").rstrip(".")
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in MULTI_PART_TLDS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def in_domain(name: str, domain: str) -> bool:
    return name == domain or name.endswith("." + domain)


def names_from_crt_entries(entries: object, domain: str) -> set[str]:
    """Extract in-domain names from a crt.sh JSON payload.

    crt.sh answers a name query with every certificate that mentions it, so a shared
    certificate can pull in unrelated hosts; only names under `domain` are kept.
    """
    names: set[str] = set()
    if not isinstance(entries, list):
        return names
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        for field in ("name_value", "common_name"):
            for raw in str(entry.get(field) or "").split("\n"):
                candidate = raw.strip().lower().lstrip("*.").rstrip(".")
                if candidate and in_domain(candidate, domain):
                    names.add(candidate)
    return names


def names_from_certspotter(payload: object, domain: str | None) -> set[str]:
    names: set[str] = set()
    if not isinstance(payload, list):
        return names
    for issuance in payload:
        if not isinstance(issuance, dict):
            continue
        for raw in issuance.get("dns_names") or []:
            candidate = str(raw).strip().lower().lstrip("*.").rstrip(".")
            if candidate and (domain is None or in_domain(candidate, domain)):
                names.add(candidate)
    return names


def source_crtsh(domain: str) -> tuple[set[str], dict]:
    names: set[str] = set()
    meta: dict = {"name": "crt.sh", "kind": "names", "ok": False}
    for query in (f"%.{domain}", domain):
        url = f"https://crt.sh/?q={urllib.parse.quote(query)}&output=json"
        try:
            payload, response_meta = http_get_json(url, retries=4)
            names |= names_from_crt_entries(payload, domain)
            meta.update(ok=True, status=response_meta.get("status"))
        except SourceError as error:
            meta.setdefault("errors", []).append(str(error))
    meta["count"] = len(names)
    return names, meta


def source_subdomain_center(domain: str) -> tuple[set[str], dict]:
    url = f"https://api.subdomain.center/?domain={urllib.parse.quote(domain)}"
    meta: dict = {"name": "subdomain.center", "kind": "names", "url": url}
    try:
        payload, _ = http_get_json(url)
        names = {str(n).strip().lower() for n in payload if str(n).strip()} if isinstance(payload, list) else set()
        names = {n for n in names if in_domain(n, domain)}
        meta.update(ok=True, count=len(names))
        return names, meta
    except SourceError as error:
        meta.update(ok=False, error=str(error), count=0)
        return set(), meta


def source_subfinder(domain: str) -> tuple[set[str], dict]:
    binary = shutil.which("subfinder")
    meta: dict = {"name": "subfinder", "kind": "names", "request": f"subfinder -d {domain} -all -silent"}
    if not binary:
        meta.update(ok=False, error="subfinder not on PATH", count=0)
        return set(), meta
    try:
        completed = subprocess.run(
            [binary, "-d", domain, "-all", "-silent", "-nc"],
            capture_output=True, text=True, timeout=300, check=False,
        )
        names = {strip_ansi(line).strip().lower() for line in completed.stdout.splitlines()
                 if strip_ansi(line).strip()}
        names = {n for n in names if in_domain(n, domain)}
        meta.update(ok=True, count=len(names),
                    note="keyless sources only: most subfinder sources now require API keys")
        return names, meta
    except (subprocess.SubprocessError, OSError) as error:
        meta.update(ok=False, error=str(error), count=0)
        return set(), meta


def certspotter_get(params: dict, *, cache_key: str, use_cache: bool = True) -> tuple[object, dict]:
    """Call Cert Spotter, caching by key.

    Measured free-tier limits differ per query shape: a subdomain-inclusive domain
    lookup allows 10 requests an hour, a plain domain lookup 100, and the certificate
    fingerprint lookups advertise no limit at all. Results are cached regardless, so a
    repeated run costs nothing.
    """
    cache_file = CACHE_DIR / "certspotter" / f"{cache_key}.json"
    meta: dict = {"kind": "certificate transparency"}
    if use_cache and cache_file.is_file():
        age = time.time() - cache_file.stat().st_mtime
        if age < CERT_CACHE_TTL:
            meta.update(ok=True, cached=True, age_seconds=int(age))
            return json.loads(cache_file.read_text()), meta
    query = urllib.parse.urlencode({**params, "expand": "dns_names"})
    payload, response_meta = http_get_json(f"{CERTSPOTTER_URL}?{query}", retries=2)
    meta.update(
        ok=True, cached=False, url=f"{CERTSPOTTER_URL}?{query}",
        rate_limit_remaining=response_meta.get("rate_limit_remaining"),
        rate_limit_limit=response_meta.get("rate_limit_limit"),
        rate_limit_reset=response_meta.get("rate_limit_reset"),
    )
    cache_file.parent.mkdir(parents=True, exist_ok=True)
    cache_file.write_text(json.dumps(payload))
    return payload, meta


def source_certspotter_domain(domain: str, *, use_cache: bool = True) -> tuple[set[str], dict]:
    payload, meta = certspotter_get(
        {"domain": domain, "include_subdomains": "true"},
        cache_key=f"domain-{domain}", use_cache=use_cache,
    )
    names = names_from_certspotter(payload, domain)
    meta.update(name="cert spotter (domain)", ok=True, count=len(names),
                note="subdomain-inclusive lookups allow 10 requests per hour")
    return names, meta


# ---------------------------------------------------------------------- resolution

def strip_ansi(text: str) -> str:
    """dnsx and subfinder colour their output even when it is piped, so strip escapes."""
    return ANSI.sub("", text)


def parse_dnsx_output(text: str) -> dict[str, set[str]]:
    """Parse `dnsx -a -resp` lines of the form `name [A] [1.2.3.4]`."""
    found: dict[str, set[str]] = {}
    for line in strip_ansi(text).splitlines():
        match = re.match(r"\A(\S+)\s+\[[A]+\]\s+\[([0-9a-fA-F:.]+)\]\s*\Z", line.strip())
        if match:
            found.setdefault(match.group(1).lower(), set()).add(match.group(2))
    return found


def resolve_with_dnsx(names: list[str]) -> tuple[dict[str, set[str]], dict]:
    binary = shutil.which("dnsx")
    meta: dict = {"name": "dnsx", "kind": "resolution", "request": "dnsx -silent -a -resp"}
    if not binary or not names:
        meta.update(ok=False, error="dnsx not on PATH" if not binary else "no names", count=0)
        return {}, meta
    try:
        completed = subprocess.run(
            [binary, "-silent", "-a", "-resp", "-nc"],
            input="\n".join(names) + "\n", capture_output=True, text=True, timeout=600, check=False,
        )
        found = parse_dnsx_output(completed.stdout)
        meta.update(ok=True, count=len(found))
        return found, meta
    except (subprocess.SubprocessError, OSError) as error:
        meta.update(ok=False, error=str(error), count=0)
        return {}, meta


def resolve_with_doh(names: list[str]) -> tuple[dict[str, set[str]], dict]:
    """The second, independent resolver: a different implementation from dnsx on purpose."""
    found: dict[str, set[str]] = {}
    meta: dict = {"name": "dns over https", "kind": "resolution",
                  "resolvers": [r[0] for r in DOH_RESOLVERS]}
    if not names:
        meta.update(ok=False, error="no names", count=0)
        return found, meta

    def one(name: str) -> tuple[str, set[str]]:
        answers = doh_lookup(name)
        return name, {a for a in answers["A"] + answers["AAAA"]}

    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as pool:
        for name, addresses in pool.map(one, names):
            if addresses:
                found[name] = addresses
    meta.update(ok=True, count=len(found))
    return found, meta


# -------------------------------------------------------------------- certificates

def pem_to_der(data: bytes) -> bytes:
    if b"-----BEGIN" not in data:
        return data
    parts = []
    for block in data.split(b"-----BEGIN")[1:]:
        header, _, rest = block.partition(b"-----")
        body, _, _ = rest.partition(b"-----END")
        if b"CERTIFICATE" in header:
            parts.append(body)
    if not parts:
        raise SourceError("no PEM certificate block found in the file")
    try:
        return base64.b64decode(b"".join(parts))
    except (binascii.Error, ValueError) as error:
        raise SourceError(f"the PEM certificate block is not valid base64: {error}") from error


def cert_facts(der: bytes) -> dict:
    """Everything a certificate can tell us, including the hashes used for pivoting."""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
    except ImportError:
        try:
            return openssl_facts(der)
        except SourceError:
            raise
    certificate = x509.load_der_x509_certificate(der)
    # pubkey_sha256 is the SHA-256 of the DER-encoded SubjectPublicKeyInfo. It is named
    # for the certificate transparency query parameter it feeds, and it identifies the
    # key rather than the certificate, so a reissued certificate still pivots.
    facts: dict = {
        "sha256": certificate.fingerprint(hashes.SHA256()).hex(),
        "tbs_sha256": hashlib.sha256(certificate.tbs_certificate_bytes).hexdigest(),
        "pubkey_sha256": hashlib.sha256(
            certificate.public_key().public_bytes(
                serialization.Encoding.DER,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        ).hexdigest(),
        "serial": format(certificate.serial_number, "x"),
        "issuer": certificate.issuer.rfc4514_string(),
        "subject": certificate.subject.rfc4514_string(),
        "not_before": certificate.not_valid_before_utc.isoformat(),
        "not_after": certificate.not_valid_after_utc.isoformat(),
        "size_bytes": len(der),
        "common_names": [
            attribute.value for attribute in certificate.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        ],
    }
    try:
        extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        facts["sans"] = sorted(extension.value.get_values_for_type(x509.DNSName))
        facts["ip_sans"] = sorted(str(value) for value in extension.value.get_values_for_type(x509.IPAddress))
    except x509.ExtensionNotFound:
        facts["sans"] = []
    return facts


def openssl_facts(der: bytes) -> dict:
    """Fallback when the cryptography module is absent: shell out to openssl."""
    openssl = shutil.which("openssl")
    if not openssl:
        raise SourceError("neither the cryptography module nor openssl is available to parse a certificate")
    completed = subprocess.run(
        [openssl, "x509", "-inform", "DER", "-noout", "-text", "-fingerprint", "-sha256"],
        input=der, capture_output=True, check=False,
    )
    text = completed.stdout.decode("utf-8", "replace")
    facts: dict = {"parser": "openssl", "sans": [], "common_names": []}
    for line in text.splitlines():
        if "DNS:" in line and "Subject Alternative Name" not in line:
            facts["sans"].extend(part.strip() for part in line.replace("DNS:", "").split(",") if part.strip())
        elif line.strip().startswith("CN") and "=" in line:
            facts["common_names"].append(line.split("=", 1)[1].strip())
    for match in re.finditer(r"(?i)sha256 Fingerprint=([0-9A-Fa-f:]+)", text):
        facts["sha256"] = match.group(1).replace(":", "").lower()
    facts["sans"] = sorted({s for s in facts["sans"] if s})
    return facts


def fetch_live_cert(host: str, port: int = 443) -> tuple[bytes, bool]:
    """One TLS handshake, to read the certificate a host presents.

    Returns the certificate and whether its chain verified against the system trust store.
    Verification is attempted first so that an untrusted chain — a private CA, an expired
    certificate, a name mismatch — is recorded rather than hidden, but the certificate is
    read either way: this reads what is served, it does not rely on it.
    """
    last_error: Exception | None = None
    for trusted in (True, False):
        context = ssl.create_default_context()
        if not trusted:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=HTTP_TIMEOUT) as connection:
                with context.wrap_socket(connection, server_hostname=host) as tls:
                    der = tls.getpeercert(binary_form=True)
            if der:
                return der, trusted
            last_error = SourceError(f"{host}:{port} presented no certificate")
        except ssl.SSLCertVerificationError as error:
            last_error = error
            continue
    raise SourceError(f"could not read a certificate from {host}:{port}: {last_error}")


# ------------------------------------------------------------------------ asn/rdap

def cymru_asn(ip: str) -> dict | None:
    """IP to origin AS and allocation prefix, via Team Cymru's DNS service.

    IPv6 uses a separate zone whose key is the address's 32 hex nibbles in reverse.
    """
    if ":" in ip:
        try:
            nibbles = socket.inet_pton(socket.AF_INET6, ip).hex()
        except OSError:
            return None
        query = ".".join(reversed(nibbles)) + ".origin6.asn.cymru.com"
    else:
        query = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com"
    for answer in doh_txt(query):
        fields = [field.strip() for field in answer.split("|")]
        if len(fields) >= 4:
            return {"asn": fields[0], "prefix": fields[1], "country": fields[2], "registry": fields[3].lower()}
    return None


def rdap_org(asn: str, registry: str) -> str | None:
    base = RDAP_BY_REGISTRY.get(registry)
    if not base:
        return None
    try:
        payload, _ = http_get_json(f"{base}/autnum/{asn}", retries=1)
    except SourceError:
        return None
    if not isinstance(payload, dict):
        return None
    for entity in payload.get("entities") or []:
        vcard = entity.get("vcardArray") or [None, []]
        for field in vcard[1] or []:
            if isinstance(field, list) and len(field) >= 4 and field[0] == "fn":
                return str(field[3])
    return payload.get("name")


# ------------------------------------------------------------------------------ run

def address_url(address: str, scheme: str) -> str:
    """Format an address as a URL. An IPv6 literal needs brackets or the URL is malformed."""
    host = f"[{address}]" if ":" in address else address
    return f"{scheme}://{host}/"


def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def sort_ips(addresses) -> list[str]:
    def key(address: str):
        if ":" in address:
            return (1, (), address)
        return (0, tuple(int(part) for part in address.split(".")), address)

    return sorted(addresses, key=key)


class Run:
    def __init__(self, target: str, mode: str, out_dir: Path):
        self.target = target
        self.mode = mode
        self.out_dir = out_dir
        self.started = datetime.now(timezone.utc).isoformat()
        self.sources: list[dict] = []
        self.notes: list[str] = []

    def log(self, message: str) -> None:
        print(f"[grab] {message}", file=sys.stderr, flush=True)

    def record(self, meta: dict) -> None:
        self.sources.append(meta)
        status = "ok" if meta.get("ok") else "failed"
        detail = f", {meta['count']} result(s)" if meta.get("count") is not None else ""
        error = f" ({meta['error']})" if meta.get("error") else ""
        self.log(f"{meta.get('name', 'source')}: {status}{detail}{error}")

    def note(self, message: str) -> None:
        self.notes.append(message)
        self.log(message)

    def write(self, name: str, lines) -> Path:
        path = self.out_dir / name
        path.write_text("".join(f"{line}\n" for line in lines))
        return path


def collect_names(domain: str, run: Run, *, ct_domain: bool) -> dict[str, list[str]]:
    """Domain mode: gather candidate names from every keyless source."""
    provenance: dict[str, list[str]] = {}

    def absorb(names: set[str], label: str) -> None:
        for name in names:
            provenance.setdefault(name, []).append(label)

    for label, fn in (("subfinder", source_subfinder), ("crt.sh", source_crtsh),
                      ("subdomain.center", source_subdomain_center)):
        names, meta = fn(domain)
        run.record(meta)
        absorb(names, label)

    if ct_domain:
        try:
            names, meta = source_certspotter_domain(domain)
            run.record(meta)
            absorb(names, "cert spotter")
        except RateLimited as error:
            run.record({"name": "cert spotter (domain)", "ok": False, "error": str(error), "count": 0})

    if not provenance:
        run.note("no keyless source returned a name for this domain")
    return provenance


def names_for_cert(facts: dict, run: Run, *, ct_pivot: bool) -> dict[str, list[str]]:
    """Certificate mode: the certificate's own names, plus the CT pivot by fingerprint.

    The pivot is what replaces a search engine: certificate transparency records every
    issuance, so other hosts presenting the same certificate come back as extra names.
    """
    provenance: dict[str, list[str]] = {}
    for name in list(facts.get("sans") or []) + list(facts.get("common_names") or []):
        candidate = str(name).strip().lower().lstrip("*.").rstrip(".")
        if candidate and HOSTNAME.match(candidate):
            provenance.setdefault(candidate, []).append("certificate (SAN/CN)")
    if not ct_pivot:
        run.note("certificate transparency pivot skipped")
        return provenance

    for fact_key, parameter in (("sha256", "cert_sha256"), ("pubkey_sha256", "pubkey_sha256")):
        digest = facts.get(fact_key)
        if not digest:
            continue
        try:
            payload, meta = certspotter_get({parameter: digest}, cache_key=f"{parameter}-{digest}")
        except RateLimited as error:
            run.record({"name": f"cert spotter ({parameter})", "ok": False, "error": str(error), "count": 0})
            run.note(f"certificate transparency pivot unavailable: {error}")
            return provenance
        except SourceError as error:
            run.record({"name": f"cert spotter ({parameter})", "ok": False, "error": str(error), "count": 0})
            continue
        pivot_names = names_from_certspotter(payload, None)
        meta.update(name=f"cert spotter ({parameter})", count=len(pivot_names))
        run.record(meta)
        for name in pivot_names:
            provenance.setdefault(name, []).append("certificate transparency pivot")
        if pivot_names:
            break
    return provenance


def build_report(provenance: dict[str, list[str]], dnsx_found, doh_found) -> dict[str, dict]:
    addresses: dict[str, dict] = {}
    for name in sorted(provenance):
        for source, found in (("dnsx", dnsx_found), ("dns over https", doh_found)):
            for address in found.get(name, ()):
                entry = addresses.setdefault(address, {"names": [], "seen_by": []})
                if name not in entry["names"]:
                    entry["names"].append(name)
                if source not in entry["seen_by"]:
                    entry["seen_by"].append(source)
    return addresses


def package_version() -> str:
    """The installed version, so `grab --version` reports what pipx actually installed."""
    try:
        from importlib.metadata import PackageNotFoundError, version
    except ImportError:  # pragma: no cover - importlib.metadata is present on 3.8+
        return "unknown"
    try:
        return version("grab")
    except PackageNotFoundError:
        return "uninstalled (running from a source checkout)"


def status_main(argv: list[str] | None = None, prog: str = "grab status") -> int:
    """Check which collected URLs respond, and keep the successful ones.

    This is the original status.py, moved here so the whole tool is one command. requests is
    imported inside the function: the enumeration modes must not need it.
    """
    import requests

    parser = argparse.ArgumentParser(
        prog=prog,
        description="Check which collected URLs respond, and keep the successful ones.",
        epilog="Enumeration only: one GET per URL, and every URL should be a host you have confirmed is in scope.",
    )
    parser.add_argument("file", nargs="?", default="urls.txt",
                        help="file of URLs to check, one per line (default: urls.txt)")
    parser.add_argument("--out", default="results.txt",
                        help="where to write the responding URLs (default: results.txt)")
    parser.add_argument("--insecure", action="store_true",
                        help="do not verify TLS certificates: needed for https://<ip>/ URLs, "
                             "which cannot match a certificate name")
    parser.add_argument("--timeout", type=float, default=10.0,
                        help="seconds per request (default: 10)")
    args = parser.parse_args(argv)

    try:
        with open(args.file, 'r') as file:
            targets = [line for line in file.read().splitlines() if line.strip()]
    except FileNotFoundError:
        print(f"\033[91mFile not found: {args.file}\033[0m")
        return 1

    green, yellow, red, reset = '\033[92m', '\033[93m', '\033[91m', '\033[0m'
    responding = 0
    try:
        with open(args.out, 'w') as output_file:
            for target in targets:
                try:
                    response = requests.get(target, timeout=args.timeout,
                                            verify=not args.insecure, allow_redirects=True)
                    if response.status_code == 200:
                        responding += 1
                        result = f"{green}{target} is responding with a 200 OK status.{reset}\n"
                        output_file.write(target + "\n")
                    elif response.status_code >= 400:
                        result = f"{red}{target} is responding with a {response.status_code} status.{reset}\n"
                    elif response.status_code >= 300:
                        responding += 1
                        result = f"{yellow}{target} is responding with a {response.status_code} status (warning).{reset}\n"
                        output_file.write(target + "\n")
                    else:
                        result = f"{yellow}{target} is responding with a {response.status_code} status.{reset}\n"
                    print(result, end='')  # Print to terminal as well
                except requests.RequestException as e:
                    print(f"{red}Error accessing {target}: {e}{reset}\n", end='')
    except OSError as e:
        print(f"{red}An error occurred: {e}{reset}")
        return 1

    print(f"\n{responding} of {len(targets)} responded; wrote {args.out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args_in = list(sys.argv[1:] if argv is None else argv)

    if args_in and args_in[0] in ("--version", "-V"):
        print(f"grab {package_version()}")
        return 0
    if args_in and args_in[0] == "status":
        return status_main(args_in[1:])

    parser = argparse.ArgumentParser(
        prog="grab",
        description="Collect the IP addresses belonging to an in-scope target, using only keyless public sources.",
        epilog="Subcommand: `grab status [file]` checks which collected URLs respond.\n"
               "Enumeration only: run it against assets you have confirmed are in scope.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("target", help="domain, subdomain, certificate file, or certificate SHA-256 fingerprint")
    parser.add_argument("--live", action="store_true",
                        help="treat the target as a host and fetch its certificate over TLS first")
    parser.add_argument("--port", type=int, default=443, help="TLS port for --live (default: 443)")
    parser.add_argument("--ct-domain", action="store_true",
                        help="add the keyless Cert Spotter domain lookup (shares a 10 requests/hour budget)")
    parser.add_argument("--no-ct-pivot", action="store_true",
                        help="certificate modes: skip the transparency pivot, use the cert's own names only")
    parser.add_argument("--out", help="output directory (default: ./grab-<target>-<utc timestamp>)")
    parser.add_argument("--version", "-V", action="version", version=f"grab {package_version()}",
                        help="print the installed version and exit")
    if not args_in:
        parser.print_help()
        return 2
    args = parser.parse_args(args_in)

    raw_target = args.target.strip()
    path = Path(raw_target).expanduser()

    if args.live:
        mode, target = "live host", raw_target.lower().rstrip(".")
    elif path.is_file():
        mode, target = "certificate file", str(path)
    elif HEX64.match(raw_target):
        mode, target = "fingerprint", raw_target.replace(":", "").lower()
    elif HOSTNAME.match(raw_target):
        mode, target = "domain", raw_target.lower().rstrip(".")
    else:
        parser.error(f"cannot tell what {raw_target!r} is: not a file, a 64-hex fingerprint, or a hostname")

    out_dir = Path(args.out) if args.out else Path(
        f"grab-{re.sub(r'[^A-Za-z0-9._-]', '_', raw_target)[:60]}-{timestamp()}")
    out_dir.mkdir(parents=True, exist_ok=True)
    run = Run(target, mode, out_dir)
    run.log(f"mode: {mode}, target: {target}")
    run.log(f"output: {out_dir.resolve()}")
    run.log("scope check: confirm this target is listed in the program's scope before acting on results")

    facts: dict = {}
    if mode == "domain":
        apex = guess_apex(target)
        if apex != target:
            run.note(f"{target} looks like a subdomain of {apex}; enumerating {apex}")
        provenance = collect_names(apex, run, ct_domain=args.ct_domain)
    else:
        if mode == "live host":
            run.log(f"fetching the certificate served by {target}:{args.port} (one TLS handshake)")
            try:
                der, trusted = fetch_live_cert(target, args.port)
            except (OSError, ssl.SSLError, SourceError) as error:
                run.log(f"could not fetch a certificate: {error}")
                return 1
            facts = cert_facts(der)
            (out_dir / "cert.pem").write_text(ssl.DER_cert_to_PEM_cert(der))
            run.record({"name": "live TLS certificate", "kind": "certificate", "ok": True,
                        "request": f"TLS handshake to {target}:{args.port}", "count": 1,
                        "chain_trusted_by_system_store": trusted})
            if not trusted:
                run.note("the served chain does not verify against the system trust store"
                         " (private CA, expired or name mismatch)")
        elif mode == "certificate file":
            facts = cert_facts(pem_to_der(path.read_bytes()))
            run.record({"name": "certificate file", "kind": "certificate", "ok": True,
                        "request": str(path), "count": 1})
        else:
            facts = {"sha256": target}
            run.record({"name": "fingerprint", "kind": "certificate", "ok": True, "count": 1})
        if facts.get("sha256"):
            run.log(f"certificate sha256: {facts['sha256']}")
        provenance = names_for_cert(facts, run, ct_pivot=not args.no_ct_pivot)

    names = sorted(provenance)
    dnsx_found, dnsx_meta = resolve_with_dnsx(names)
    doh_found, doh_meta = resolve_with_doh(names)
    run.record(dnsx_meta)
    run.record(doh_meta)
    addresses = build_report(provenance, dnsx_found, doh_found)

    # An address shared with a CDN edge is not the target's own; say so rather than
    # letting it be written up as an origin.
    for name in names:
        front = cdn_fronts(cname_chain(name))
        if front:
            provider, edge = front
            run.note(f"{name} is fronted by {provider} ({edge}): its addresses are edge addresses, not the origin")
            for entry in addresses.values():
                if name in entry["names"]:
                    entry["cdn_front"] = f"{provider} ({edge})"

    prefixes: dict[str, dict] = {}
    for address in sort_ips(addresses):
        asn = cymru_asn(address)
        if not asn:
            continue
        entry = prefixes.setdefault(asn["prefix"], {"asn": asn["asn"], "country": asn["country"],
                                                    "registry": asn["registry"]})
        addresses[address].update(asn=asn["asn"], prefix=asn["prefix"])
        entry.setdefault("addresses", []).append(address)
    for entry in prefixes.values():
        org = rdap_org(entry["asn"], entry["registry"])
        if org:
            entry["org"] = org
        provider = cdn_org(org)
        if not provider:
            continue
        signal = f"{provider} (AS{entry['asn']}{', ' + org if org else ''})"
        for address in entry["addresses"]:
            existing = addresses[address].get("cdn_front")
            addresses[address]["cdn_front"] = f"{existing}; {signal}" if existing else signal
        run.note(f"AS{entry['asn']} is {provider}: its addresses are edge addresses, not the origin")

    resolved = [name for name in names if dnsx_found.get(name) or doh_found.get(name)]
    ordered = sort_ips(addresses)
    run.write("names.txt", names)
    run.write("resolved.txt", resolved)
    run.write("ips.txt", ordered)
    run.write("ips-annotated.tsv", [
        "\t".join([
            address,
            ",".join(addresses[address]["names"]),
            ",".join(addresses[address]["seen_by"]),
            addresses[address].get("cdn_front", ""),
            addresses[address].get("asn", ""),
            addresses[address].get("prefix", ""),
        ])
        for address in ordered
    ])
    run.write("prefixes.txt", [
        f"{prefix}\tAS{entry['asn']}\t{entry.get('org', '')}\t{entry['country']}\t{len(entry['addresses'])} address(es)"
        for prefix, entry in sorted(prefixes.items())
    ])
    # A hostname carries SNI, so name-based URLs are the honest liveness list; the raw
    # address list is kept alongside because that is the shape upstream grab produced.
    run.write("urls.txt", [f"https://{name}/" for name in resolved])
    run.write("urls-ip.txt", [address_url(address, scheme)
                              for address in ordered for scheme in ("https", "http")])

    report = {
        "tool": "grab",
        "target": target,
        "mode": mode,
        "started_utc": run.started,
        "finished_utc": datetime.now(timezone.utc).isoformat(),
        "sources": run.sources,
        "notes": run.notes,
        "certificate": facts or None,
        "names": provenance,
        "addresses": addresses,
        "prefixes": prefixes,
        "confirmation": {
            "rule": "an address seen by one resolver is reported as a candidate; two resolvers agree it is real",
            "confirmed_by_both": sum(1 for a in ordered if len(addresses[a]["seen_by"]) > 1),
            "single_source": sum(1 for a in ordered if len(addresses[a]["seen_by"]) == 1),
        },
        "caveats": [
            "enumeration only: no probing beyond DNS, certificate transparency and one optional TLS handshake",
            "only ports 443 and 80 are assumed in urls-ip.txt; no port scan was run",
            "round-robin DNS means an independent second pass can return a different address set",
            "CDN edge addresses are marked as such and are not the target's origin",
            "passive sources are incomplete: an empty result is not proof that nothing exists",
        ],
    }
    (out_dir / "sources.json").write_text(json.dumps(report, indent=2))

    edges = sum(1 for address in ordered if addresses[address].get("cdn_front"))
    print()
    print(f"target        {target} ({mode})")
    print(f"names         {len(names)} ({len(resolved)} resolved)")
    print(f"addresses     {len(ordered)}  ({report['confirmation']['confirmed_by_both']} seen by both resolvers)")
    print(f"prefixes      {len(prefixes)}")
    if edges:
        print(f"edge addrs    {edges} of {len(ordered)} belong to a CDN — not the target's origin")
    print(f"output        {out_dir.resolve()}")
    if not ordered:
        print("\nNo addresses found. That is a gap in coverage, not evidence that none exist.")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        sys.exit(130)
    except SourceError as error:
        print(f"grab: {error}", file=sys.stderr)
        sys.exit(2)
