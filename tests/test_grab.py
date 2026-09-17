"""Offline tests for grab. No network access: every payload is a fixture.

Run with:  python3 -m unittest discover -s tests -v
"""

import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import grab  # noqa: E402


# --------------------------------------------------------------------------- fixtures

CRT_ENTRIES = [
    {
        "common_name": "www.example.com",
        "name_value": "www.example.com\nexample.com\n*.example.com",
    },
    {
        "common_name": "unrelated.test",
        # A shared certificate: this host is not the queried domain and must be dropped.
        "name_value": "unrelated.test\napi.other-company.net",
    },
    {"common_name": None, "name_value": None},
    "not-a-dict",
]

CERTSPOTTER_ISSUANCES = [
    {"dns_names": ["example.com", "*.example.com", "cdn.example.net"]},
    {"dns_names": ["shared.example.org"]},
]


def self_signed_pem() -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    import datetime as dt

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "grabtest.example")])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(0x1234)
        .not_valid_before(dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc))
        .not_valid_after(dt.datetime(2026, 12, 31, tzinfo=dt.timezone.utc))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("grabtest.example"), x509.DNSName("*.wild.grabtest.example")]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return certificate.public_bytes(serialization.Encoding.PEM)


# ------------------------------------------------------------------------------- tests

class ApexTest(unittest.TestCase):
    def test_apex(self):
        cases = {
            "example.com": "example.com",
            "www.example.com": "example.com",
            "deep.sub.example.com": "example.com",
            "*.example.com": "example.com",
            "example.co.uk": "example.co.uk",
            "api.example.co.uk": "example.co.uk",
            "EXAMPLE.COM.": "example.com",
        }
        for host, expected in cases.items():
            with self.subTest(host=host):
                self.assertEqual(grab.guess_apex(host), expected)


class NamesTest(unittest.TestCase):
    def test_crt_entries_are_filtered_to_the_domain(self):
        names = grab.names_from_crt_entries(CRT_ENTRIES, "example.com")
        self.assertEqual(names, {"example.com", "www.example.com"})
        # The shared-certificate hosts must not leak in, and wildcards are stripped.
        self.assertNotIn("unrelated.test", names)
        self.assertNotIn("api.other-company.net", names)
        self.assertNotIn("*.example.com", names)

    def test_crt_payload_that_is_not_a_list(self):
        self.assertEqual(grab.names_from_crt_entries({"error": "bad"}, "example.com"), set())
        self.assertEqual(grab.names_from_crt_entries([], "example.com"), set())

    def test_certspotter_names_filtered_and_unfiltered(self):
        # The fixture has no www.example.com: the wildcard reduces to example.com here.
        self.assertEqual(
            grab.names_from_certspotter(CERTSPOTTER_ISSUANCES, "example.com"),
            {"example.com"},
        )
        # With no domain the pivot keeps everything, which is the point of the pivot,
        # including names belonging to unrelated parties worth flagging rather than hiding.
        self.assertEqual(
            grab.names_from_certspotter(CERTSPOTTER_ISSUANCES, None),
            {"example.com", "cdn.example.net", "shared.example.org"},
        )

    def test_in_domain_is_not_suffix_naive(self):
        self.assertTrue(grab.in_domain("a.example.com", "example.com"))
        self.assertTrue(grab.in_domain("example.com", "example.com"))
        # notexample.com merely ends with an in-domain-looking string and must be rejected
        self.assertFalse(grab.in_domain("notexample.com", "example.com"))


class DnsxParsingTest(unittest.TestCase):
    def test_plain_output(self):
        text = "example.com [A] [1.2.3.4] \nwww.example.com [A] [5.6.7.8] \n"
        self.assertEqual(grab.parse_dnsx_output(text),
                         {"example.com": {"1.2.3.4"}, "www.example.com": {"5.6.7.8"}})

    def test_colour_codes_are_stripped(self):
        # This is exactly what dnsx emits when its stdout is a pipe, which is how grab runs it.
        text = "example.com [\x1b[35mA\x1b[0m] [\x1b[32m1.2.3.4\x1b[0m] \n"
        self.assertEqual(grab.parse_dnsx_output(text), {"example.com": {"1.2.3.4"}})

    def test_multiple_records_and_junk_lines(self):
        text = "a.example.com [A] [1.1.1.1] \na.example.com [A] [2.2.2.2] \nrandom noise\n"
        self.assertEqual(grab.parse_dnsx_output(text), {"a.example.com": {"1.1.1.1", "2.2.2.2"}})

    def test_empty(self):
        self.assertEqual(grab.parse_dnsx_output(""), {})


class DohParsingTest(unittest.TestCase):
    def test_answer_types_are_separated(self):
        payload = {
            "Answer": [
                {"name": "example.com", "type": 1, "data": "1.2.3.4"},
                {"name": "example.com", "type": 28, "data": "2001:db8::1"},
                {"name": "example.com", "type": 5, "data": "edge.example.net."},
            ]
        }
        self.assertEqual(grab.doh_answers(payload, 1), ["1.2.3.4"])
        self.assertEqual(grab.doh_answers(payload, 28), ["2001:db8::1"])
        self.assertEqual(grab.doh_answers(payload, 5), ["edge.example.net."])

    def test_missing_answer_key(self):
        self.assertEqual(grab.doh_answers({}, 1), [])
        self.assertEqual(grab.doh_answers({"Answer": None}, 1), [])
        self.assertEqual(grab.doh_answers("not-a-dict", 1), [])


class CdnTest(unittest.TestCase):
    def test_cname_detection(self):
        self.assertEqual(grab.cdn_fronts(["a.cloudflare.net"]), ("Cloudflare", "a.cloudflare.net"))
        self.assertEqual(grab.cdn_fronts(["1.2.3.4"]), None)
        self.assertEqual(grab.cdn_fronts([]), None)

    def test_versioned_edge_hostname(self):
        # Observed in the wild: Vercel answers as vercel-dns-013.com, not vercel-dns.com.
        self.assertEqual(grab.cdn_fronts(["40f531535c18fa28.vercel-dns-013.com."]),
                         ("Vercel", "40f531535c18fa28.vercel-dns-013.com."))

    def test_cdn_org_detection(self):
        self.assertEqual(grab.cdn_org("Cloudflare, Inc."), "Cloudflare")
        self.assertEqual(grab.cdn_org("Akamai Technologies, Inc."), "Akamai")

    def test_generic_cloud_is_not_an_edge(self):
        # A target's own server on AWS is its own server; claiming "edge" would be wrong.
        self.assertIsNone(grab.cdn_org("Amazon.com, Inc."))
        self.assertIsNone(grab.cdn_org("Microsoft Corporation"))
        self.assertIsNone(grab.cdn_org("Google LLC"))
        self.assertIsNone(grab.cdn_org(None))


class CertificateTest(unittest.TestCase):
    def setUp(self):
        self.pem = self_signed_pem()

    def test_pem_round_trip_and_facts(self):
        der = grab.pem_to_der(self.pem)
        facts = grab.cert_facts(der)
        self.assertEqual(facts["sans"], ["*.wild.grabtest.example", "grabtest.example"])
        self.assertEqual(facts["common_names"], ["grabtest.example"])
        self.assertEqual(facts["sha256"], __import__("hashlib").sha256(der).hexdigest())
        for key in ("tbs_sha256", "pubkey_sha256", "serial", "not_after"):
            self.assertTrue(facts.get(key), f"{key} missing")

    def test_der_passthrough(self):
        der = grab.pem_to_der(self.pem)
        self.assertEqual(grab.pem_to_der(der), der)

    def test_concatenated_pem_blocks_take_the_certificates(self):
        der = grab.pem_to_der(self.pem + self.pem)
        self.assertEqual(der[:1], b"\x30")  # a DER SEQUENCE

    def test_garbage_input_is_an_error_not_a_silent_empty(self):
        with self.assertRaises(grab.SourceError):
            grab.pem_to_der(b"-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n")


class HttpBehaviourTest(unittest.TestCase):
    def setUp(self):
        self._real = grab.urllib.request.urlopen
        self._sleep = grab.time.sleep
        grab.time.sleep = lambda _seconds: None  # keep the backoff from slowing the suite

    def tearDown(self):
        grab.urllib.request.urlopen = self._real
        grab.time.sleep = self._sleep

    def test_rate_limit_surfaces_as_a_distinct_error(self):
        def raise_429(*_args, **_kwargs):
            raise urllib.error.HTTPError("http://x", 429, "Too Many Requests",
                                         {"x-ratelimit-reset": "2026-09-17T11:00:00Z"}, None)

        grab.urllib.request.urlopen = raise_429
        with self.assertRaises(grab.RateLimited) as caught:
            grab.http_get_json("http://x")
        self.assertIn("rate limit", str(caught.exception))

    def test_transient_5xx_is_retried_then_succeeds(self):
        calls = {"n": 0}

        class FakeResponse:
            status = 200
            headers = {}

            def read(self):
                return b'{"ok": true}'

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

        def flaky(*_args, **_kwargs):
            calls["n"] += 1
            if calls["n"] == 1:
                raise urllib.error.HTTPError("http://x", 502, "Bad Gateway", {}, None)
            return FakeResponse()

        grab.urllib.request.urlopen = flaky
        payload, meta = grab.http_get_json("http://x", retries=3)
        self.assertEqual(payload, {"ok": True})
        self.assertEqual(meta["attempts"], 2)

    def test_client_error_fails_immediately(self):
        calls = {"n": 0}

        def raise_400(*_args, **_kwargs):
            calls["n"] += 1
            raise urllib.error.HTTPError("http://x", 400, "Bad Request", {}, None)

        grab.urllib.request.urlopen = raise_400
        with self.assertRaises(grab.SourceError):
            grab.http_get_json("http://x", retries=3)
        self.assertEqual(calls["n"], 1)


class CertSpotterCacheTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self._real_cache = grab.CACHE_DIR
        grab.CACHE_DIR = Path(self.temp.name)
        self.calls = {"n": 0}
        self._real_get = grab.http_get_json

    def tearDown(self):
        grab.CACHE_DIR = self._real_cache
        grab.http_get_json = self._real_get
        self.temp.cleanup()

    def _fake_fetch(self, payload):
        def fetch(url, **_kwargs):
            self.calls["n"] += 1
            return payload, {"status": 200, "rate_limit_remaining": "7", "rate_limit_limit": "10"}

        grab.http_get_json = fetch

    def test_second_call_is_served_from_cache(self):
        self._fake_fetch(CERTSPOTTER_ISSUANCES)
        first, first_meta = grab.certspotter_get({"cert_sha256": "ab" * 32}, cache_key="cert-ab")
        second, second_meta = grab.certspotter_get({"cert_sha256": "ab" * 32}, cache_key="cert-ab")
        self.assertEqual(self.calls["n"], 1)
        self.assertFalse(first_meta["cached"])
        self.assertTrue(second_meta["cached"])
        self.assertEqual(first, second)
        self.assertEqual(first_meta["rate_limit_remaining"], "7")

    def test_use_cache_false_always_refetches(self):
        self._fake_fetch(CERTSPOTTER_ISSUANCES)
        grab.certspotter_get({"cert_sha256": "cd" * 32}, cache_key="cert-cd", use_cache=False)
        grab.certspotter_get({"cert_sha256": "cd" * 32}, cache_key="cert-cd", use_cache=False)
        self.assertEqual(self.calls["n"], 2)

    def test_cache_is_written_under_the_configured_directory(self):
        self._fake_fetch([])
        grab.certspotter_get({"cert_sha256": "ef" * 32}, cache_key="cert-ef")
        cached = Path(self.temp.name) / "certspotter" / "cert-ef.json"
        self.assertTrue(cached.is_file())
        self.assertEqual(json.loads(cached.read_text()), [])


class ReportTest(unittest.TestCase):
    def test_agreement_is_recorded_per_address(self):
        provenance = {"a.example.com": ["crt.sh"], "b.example.com": ["subfinder"]}
        dnsx_found = {"a.example.com": {"1.1.1.1", "2.2.2.2"}}
        doh_found = {"a.example.com": {"1.1.1.1"}, "b.example.com": {"3.3.3.3"}}
        report = grab.build_report(provenance, dnsx_found, doh_found)
        self.assertEqual(sorted(report["1.1.1.1"]["seen_by"]), ["dns over https", "dnsx"])
        self.assertEqual(report["2.2.2.2"]["seen_by"], ["dnsx"])
        self.assertEqual(report["3.3.3.3"]["names"], ["b.example.com"])

    def test_ipv4_sorts_numerically_before_ipv6(self):
        addresses = ["2001:db8::1", "10.0.0.2", "9.9.9.9", "10.0.0.10"]
        self.assertEqual(grab.sort_ips(addresses), ["9.9.9.9", "10.0.0.2", "10.0.0.10", "2001:db8::1"])

    def test_address_urls_bracket_ipv6_literals(self):
        # Without brackets "https://2606:4700::1/" parses as a host and a port, not an address.
        self.assertEqual(grab.address_url("1.2.3.4", "https"), "https://1.2.3.4/")
        self.assertEqual(grab.address_url("2606:4700:10::1", "https"), "https://[2606:4700:10::1]/")


class PivotFailureTest(unittest.TestCase):
    """A rate-limited or broken pivot must never silently produce a short list."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self._real_cache, self._real_get, self._real_sleep = grab.CACHE_DIR, grab.http_get_json, grab.time.sleep
        grab.CACHE_DIR = Path(self.temp.name)
        grab.time.sleep = lambda _seconds: None
        self.facts = grab.cert_facts(grab.pem_to_der(self_signed_pem()))

    def tearDown(self):
        grab.CACHE_DIR, grab.http_get_json, grab.time.sleep = self._real_cache, self._real_get, self._real_sleep
        self.temp.cleanup()

    def _run_pivot(self):
        run = grab.Run("x", "certificate file", Path(self.temp.name))
        with contextlib.redirect_stderr(io.StringIO()):
            provenance = grab.names_for_cert(self.facts, run, ct_pivot=True)
        return provenance, run

    def test_rate_limited_pivot_keeps_the_certificate_names_and_says_so(self):
        def raise_429(*_args, **_kwargs):
            raise grab.RateLimited("rate limit exhausted, resets at 11:00")

        grab.http_get_json = raise_429
        provenance, run = self._run_pivot()
        self.assertIn("grabtest.example", provenance)          # the cert's own names survive
        self.assertTrue(any("rate limit" in note for note in run.notes))
        self.assertTrue([s for s in run.sources if not s.get("ok")])  # recorded as failed

    def test_a_failing_first_pivot_falls_through_to_the_second(self):
        tried = []

        def fail_first(url, **_kwargs):
            tried.append(url)
            raise grab.SourceError("upstream is down")

        grab.http_get_json = fail_first
        _, run = self._run_pivot()
        self.assertTrue(any("cert_sha256" in url for url in tried), tried)
        self.assertTrue(any("pubkey_sha256" in url for url in tried), tried)

    def test_pivot_skipped_when_asked(self):
        def should_not_be_called(*_args, **_kwargs):
            raise AssertionError("the pivot was called despite --no-ct-pivot")

        grab.http_get_json = should_not_be_called
        run = grab.Run("x", "certificate file", Path(self.temp.name))
        with contextlib.redirect_stderr(io.StringIO()):
            provenance = grab.names_for_cert(self.facts, run, ct_pivot=False)
        self.assertIn("grabtest.example", provenance)
        self.assertEqual([s for s in run.sources], [])


class CliDispatchTest(unittest.TestCase):
    """The command-line surface: `grab`, `grab status`, `--version`, and a bare invocation."""

    def test_status_is_dispatched_not_treated_as_a_target(self):
        # A missing file inside `status` proves the dispatch happened: were it parsed as a
        # target, a word like "status" would fail the hostname/file/fingerprint check instead.
        with contextlib.redirect_stdout(io.StringIO()):
            code = grab.main(["status", "/nonexistent/urls.txt"])
        self.assertEqual(code, 1)

    def test_version_prints_and_exits_cleanly(self):
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            code = grab.main(["--version"])
        self.assertEqual(code, 0)
        self.assertTrue(captured.getvalue().startswith("grab "), captured.getvalue())

    def test_bare_invocation_prints_help_and_returns_2(self):
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            code = grab.main([])
        self.assertEqual(code, 2)
        self.assertIn("usage: grab", captured.getvalue())

    def test_unknown_argument_is_not_a_target(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            grab.main(["not a file", "not a hostname", "not a fingerprint"])


class StatusScriptTest(unittest.TestCase):
    """status.py against a local server: one path answers 200, another 404."""

    @classmethod
    def setUpClass(cls):
        serve_dir = tempfile.TemporaryDirectory()
        Path(serve_dir.name, "index.html").write_text("ok")

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/":
                    body = b"ok"
                    self.send_response(200)
                else:
                    body = b"missing"
                    self.send_response(404)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_args):
                pass

        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.server.server_port}"
        cls.serve_dir = serve_dir

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.serve_dir.cleanup()

    def test_only_responding_urls_are_kept(self):
        workdir = tempfile.TemporaryDirectory()
        urls = Path(workdir.name, "urls.txt")
        urls.write_text(f"{self.base}/\n{self.base}/missing\n")
        result = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parent.parent / "status.py"),
             str(urls), "--out", str(Path(workdir.name, "results.txt"))],
            capture_output=True, text=True, timeout=60, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        kept = Path(workdir.name, "results.txt").read_text().split()
        self.assertEqual(kept, [f"{self.base}/"])
        workdir.cleanup()

    def test_missing_input_file_is_reported_not_crashed(self):
        result = subprocess.run(
            [sys.executable, str(Path(__file__).resolve().parent.parent / "status.py"),
             "/nonexistent/urls.txt"],
            capture_output=True, text=True, timeout=60, check=False,
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("File not found", result.stdout)


class SourceGuardTest(unittest.TestCase):
    """The promise is no keys. Keep it honest by inspecting the source itself."""

    def test_no_api_credential_surface_at_all(self):
        lowered = Path(grab.__file__).read_text().lower()
        for needle in ("censys", "api_key", "apikey", "client_secret", "access_token", "getenv"):
            with self.subTest(needle=needle):
                self.assertNotIn(needle, lowered)

    def test_the_only_environment_variable_read_is_the_cache_directory(self):
        source = Path(grab.__file__).read_text()
        reads = __import__("re").findall(r"environ\.get\(\"([A-Z_]+)\"", source)
        self.assertEqual(set(reads), {"GRAB_CACHE"})

    def test_certspotter_limits_are_documented_from_measurement(self):
        # A wrong limit here would silently truncate a run, so the comment carries the numbers.
        source = Path(grab.__file__).read_text()
        self.assertIn("10 requests an hour", source)
        self.assertIn("100", source)


if __name__ == "__main__":
    unittest.main()
