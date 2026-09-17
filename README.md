# grab

Collect the IP addresses that belong to a target, using **no third-party API and no API key**.

Feed it a domain, a subdomain, a certificate, or a certificate fingerprint, and it works out
which addresses that target uses — then writes them out with the provenance of every claim,
so you can tell an address that two independent resolvers agreed on from one that a single
source mentioned once.

```shell
grab example.com                  # domain or subdomain
grab cert.pem                     # a certificate file (PEM or DER)
grab 6153a96f...2200              # a certificate SHA-256 fingerprint
grab --live example.com           # fetch the host's certificate first
grab example.com --ct-domain      # add the Cert Spotter domain lookup
grab status                       # check which collected names respond
grab --version
```

Installed as a command, so it runs by name from any directory:

```shell
pipx install --editable ~/grab     # links `grab` into ~/.local/bin
grab --help
```

The editable install points at this checkout, so editing `grab.py` takes effect on the next run
with no reinstall. `python3 grab.py <target>` and `python3 status.py` keep working too, for a
checkout that was never installed. Uninstall with `pipx uninstall grab`.

This replaces the original `grab.py`, which ran a Censys search query and stopped working the
moment credentials were missing (it exits with `No API ID or API secret configured`). That
script is preserved unchanged as `grab_censys.py`.

## Why there is no API key

The original design asked a search engine "which hosts on the internet look like X". The
rebuilt one answers a narrower and more defensible question: **which addresses does this
target actually use**. That question can be answered from public data alone.

| Mode | Input | Path |
| --- | --- | --- |
| domain | `example.com` or `www.example.com` | subfinder's keyless sources, crt.sh, subdomain.center → resolve |
| certificate | PEM or DER file | parse the certificate locally → SANs, then the certificate transparency pivot |
| fingerprint | 64 hex characters | certificate transparency pivot by `cert_sha256`, then by `pubkey_sha256` |
| `--live` | a host | one TLS handshake → the served certificate → as above |

### The certificate pivot, in one paragraph

A certificate file alone tells you the names its SANs list. Certificate transparency tells you
something better: every certificate ever issued is logged, so a lookup by certificate hash
(`cert_sha256`) or by public-key hash (`pubkey_sha256`) returns every *other* name that
appeared on that same certificate. Certificates are frequently shared across a target's
services, so this surfaces hosts that never appeared in the certificate's own SAN list. This
lookup is what the rebuild uses in place of a search engine, and it needs no key. Names found
this way are labelled `certificate transparency pivot` in `sources.json` rather than being
silently merged with the certificate's own names, because a shared certificate can legitimately
cover unrelated third parties.

## Sources, and what each one really gives you

Every source is public and keyless. Measured on 2026-09-17:

| Source | Used for | Limits and notes |
| --- | --- | --- |
| Google, Cloudflare, AdGuard DoH | resolution (A, AAAA, CNAME, TXT) | none |
| crt.sh | names from certificate transparency | occasionally returns 502; retried with backoff |
| Cert Spotter | the certificate pivot | fingerprint lookups advertise no limit; a **subdomain-inclusive domain lookup allows 10/hour**, a plain domain lookup 100/hour |
| subfinder | names, keyless sources only | most of its ~50 sources now require API keys, so expect a thin result |
| subdomain.center | names | none |
| Team Cymru (DNS TXT) | IP → ASN and allocation prefix | none |
| RIR RDAP | ASN → holder name | one request per ASN |

Deliberately **not** used, because each needs a key: Censys, Shodan, VirusTotal, SecurityTrails,
AlienVault OTX, and `asnmap` (which now requires a ProjectDiscovery key). `bgpview.io` and
ThreatMiner are dead. Quad9's DoH speaks the RFC 8484 wire format rather than the JSON API, so
it is not used as a resolver here.

Cert Spotter results are cached under `~/.cache/grab/` for 30 days, so re-running against the
same certificate costs nothing. Set `GRAB_CACHE` to move that directory.

## Output

Each run writes a timestamped directory:

| File | Contents |
| --- | --- |
| `ips.txt` | every address found, IPv4 numerically sorted before IPv6 |
| `ips-annotated.tsv` | address, names, which resolvers saw it, CDN edge flag, ASN, prefix |
| `names.txt` | every candidate name |
| `resolved.txt` | the names that resolved |
| `hosts.txt` | name and its addresses |
| `prefixes.txt` | allocation prefix, ASN, holder, country, address count |
| `urls.txt` | `https://<name>/` for each resolved name — the honest liveness list, since a name carries SNI |
| `urls-ip.txt` | `https://<ip>/` and `http://<ip>/` for each address, the shape the original tool produced |
| `sources.json` | full provenance: every source queried, its URL, count, errors, rate-limit state, confirmation counts, and the caveats below |
| `cert.pem` | the certificate, in the certificate and `--live` modes |

## What it will not claim

- **Enumeration only.** DNS, certificate transparency, RDAP, and — for `--live` — exactly one
  TLS handshake. No port scanning, no probing, no payloads. `urls-ip.txt` assumes ports 443 and
  80 and says so.
- **Two resolvers, not one.** `dnsx` and DNS over HTTPS resolve independently; an address seen
  by both is reported as confirmed, one seen by a single resolver is reported as a candidate.
  This matters because round-robin DNS legitimately returns different addresses on a second
  pass — so a set that differs between runs is not automatically a bug.
- **CDN edges are marked, not mistaken for origins.** A name fronted by Cloudflare, Vercel,
  Akamai, Fastly and the rest is flagged, by CNAME where there is one and by the ASN holder
  where the A record is flattened and there is not. Generic cloud hosting is deliberately *not*
  treated as an edge: a target's own servers on AWS, Azure or GCP are its own, so for those the
  ASN and holder are recorded and no edge claim is made.
- **An empty result is a coverage gap, not proof of absence.** Passive sources are incomplete
  by construction. `sources.json` records which sources failed, so a thin result can be
  attributed to a failing source rather than read as a finding.

## Requirements

Python 3.9+ with the `cryptography` module (used to parse certificates; `openssl` is the
fallback), `requests` for `status.py`, and optionally `subfinder` and `dnsx` on `PATH`. Without
the two binaries the tool still works — it falls back to its own queries and DoH resolution,
and records that they were missing.

```shell
# dnsx has no Go toolchain requirement here: take the prebuilt release
curl -sL https://github.com/projectdiscovery/dnsx/releases/latest/download/dnsx_1.3.1_linux_amd64.zip -o dnsx.zip
unzip -o dnsx.zip && install -m 0755 dnsx ~/.local/bin/dnsx

python3 -m unittest discover -s tests -v     # offline; no network access needed
```

## Scope

This is reconnaissance tooling for authorized testing. It enumerates, it does not exploit.
Run it against assets you have confirmed are in scope for a program, and read that program's
rules first: some programs forbid automated tooling outright, and passive enumeration of a
host that merely looks related is still out-of-scope testing.

## Credits

The original tool is [nouaim/grab](https://github.com/nouaim/grab), which collects targets from
Censys. This rebuild keeps its purpose — gathering candidate hosts for a security test — and
drops its dependency on a commercial search API.
