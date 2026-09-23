"""Scanner unit tests (offline, fixture-based). Run:
    python -m unittest discover -s tests -p 'test_scan.py' -v
"""
from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scanner"))
import scan  # noqa: E402


class TestDiscovery(unittest.TestCase):
    def test_private_and_reserved_ips_discarded(self):
        self.assertFalse(scan.is_public("10.0.0.1"))
        self.assertFalse(scan.is_public("192.168.1.1"))
        self.assertFalse(scan.is_public("127.0.0.1"))
        self.assertFalse(scan.is_public("169.254.1.1"))
        self.assertFalse(scan.is_public("224.0.0.1"))
        self.assertFalse(scan.is_public("::1"))
        self.assertFalse(scan.is_public("fe80::1"))
        self.assertTrue(scan.is_public("93.184.216.34"))
        self.assertTrue(scan.is_public("2606:2800:220:1:248:1893:25c8:1946"))

    def test_domain_dedupe_and_provenance(self):
        # Two domains resolving to the same IP: one candidate, two sources.
        sources = {"domains": [
            {"domain": "a.example", "enabled": True, "ports": [443]},
            {"domain": "b.example", "enabled": True, "ports": [443]},
        ]}
        def fake(host, *a, **k):
            # Pretend every domain resolves to the same public IP. No real DNS:
            # CI resolvers return different failures for invalid TLDs, which made
            # this test flake on the shape of the failure rather than the logic.
            return [(2, None, 6, "", ("93.184.216.34", 0))]
        real = scan.socket.getaddrinfo
        scan.socket.getaddrinfo = fake
        try:
            queue = scan.discover_from_domains(sources)
        finally:
            scan.socket.getaddrinfo = real
        self.assertEqual(len(queue), 1)
        self.assertEqual(queue[0]["address"], "93.184.216.34")
        self.assertEqual(sorted(queue[0]["sources"]), ["domain:a.example", "domain:b.example"])

    def test_disabled_domain_skipped(self):
        sources = {"domains": [
            {"domain": "off.example", "enabled": False, "ports": [443]},
        ]}
        self.assertEqual(scan.discover_from_domains(sources), [])

    def test_catalog_ingest_preserves_country_claims(self, ):
        tmp = scan.COUNTRIES
        scan.COUNTRIES = Path(self.enterContext(_TmpDir())) / "countries"
        scan.COUNTRIES.mkdir(parents=True)
        (scan.COUNTRIES / "DE.json").write_text(json.dumps({
            "endpoints": [{"address": "93.184.216.34", "port": 8443,
                           "country_claims": ["DE"]}],
        }))
        try:
            queue = scan.discover_from_catalog(100)
        finally:
            scan.COUNTRIES = tmp
        self.assertEqual(len(queue), 1)
        self.assertEqual(queue[0]["port"], 8443)  # exact source port kept
        self.assertEqual(queue[0]["sources"], ["catalog:DE"])


class _TmpDir:
    """Minimal context manager for a temp directory."""
    def __init__(self):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
    def __enter__(self):
        return Path(self._tmp.name)
    def __exit__(self, *a):
        self._tmp.cleanup()


class TestPolicyAndScoring(unittest.TestCase):
    def test_provider_exclusion_uses_observed_metadata(self):
        policy = {"deny": [{"match": "Oracle"}], "warn": []}
        # Hostname contains nothing; observed provider decides.
        rec = {"observed_provider": "Oracle Cloud Infrastructure"}
        self.assertIsNotNone(scan.provider_exclusion(rec, policy))
        rec = {"observed_provider": "Hetzner Online GmbH"}
        self.assertIsNone(scan.provider_exclusion(rec, policy))

    def test_verified_scores_above_unverified(self):
        good = {"tcp_ok": True, "tls_ok": True, "app_ok": True,
                "verified": True, "last_rtt_ms": 100, "failure_count": 0}
        bad = {"tcp_ok": True, "tls_ok": True, "app_ok": False,
               "verified": False, "failure_count": 3}
        self.assertGreater(scan.score(good), scan.score(bad))
        self.assertLessEqual(scan.score(good), 100)


class TestStateAndVerified(unittest.TestCase):
    def test_merge_counts_and_provenance(self):
        state = {"candidates": {}}
        state = scan.merge_state(state, [{
            "address": "203.0.113.7", "port": 443, "app_ok": True,
            "sources": ["domain:di.nscl.ir"], "source_countries": [],
            "country": "DE", "total_ms": 140,
        }], "2026-09-21T03:00:00Z")
        rec = state["candidates"]["203.0.113.7:443"]
        self.assertEqual(rec["success_count"], 1)
        self.assertEqual(rec["observed_country"], "DE")
        self.assertIn("last_success", rec)

    def test_verified_requires_recent_success_and_country(self):
        # Old success beyond TTL -> stale, not published.
        state = {"candidates": {
            "203.0.113.7:443": {
                "first_seen": "2026-01-01T00:00:00Z",
                "last_seen": "2026-01-01T00:00:00Z",
                "last_success": "2026-01-01T00:00:00Z",
                "success_count": 5, "observed_country": "DE",
                "sources": ["x"], "source_countries": [],
            },
        }}
        pools, stale = scan.build_verified(state, "2026-09-21T03:00:00Z")
        self.assertEqual(pools, {})
        self.assertIn("203.0.113.7:443", stale["stale"])

    def test_verified_pool_capped_per_country(self):
        import time as _t
        now = _t.strftime("%Y-%m-%dT%H:%M:%SZ", _t.gmtime())
        state = {"candidates": {}}
        for i in range(scan.PER_COUNTRY_PUBLISH_CAP + 10):
            state["candidates"][f"203.0.113.{i}:443"] = {
                "first_seen": now, "last_seen": now, "last_success": now,
                "success_count": 1, "observed_country": "DE",
                "sources": ["x"], "source_countries": [],
                "last_rtt_ms": 100 + i,
            }
        pools, _ = scan.build_verified(state, now)
        self.assertEqual(len(pools["DE"]), scan.PER_COUNTRY_PUBLISH_CAP)


class TestFeedValidation(unittest.TestCase):
    def _feed(self, **over):
        feed = {
            "schema_version": 1,
            "upstream_revision": "a" * 64,
            "content_revision": "b" * 64,
            "generated_at": "2026-09-23T00:00:00Z",
            "counts": {"verified": 1, "countries": 1},
            "countries": {"DE": [["93.184.216.34", 443]]},
        }
        feed.update(over)
        return feed

    def test_valid_feed_passes(self):
        scan.validate_feed(self._feed())

    def test_bad_schema_rejected(self):
        with self.assertRaises(ValueError):
            scan.validate_feed(self._feed(schema_version=2))

    def test_bad_country_code_rejected(self):
        with self.assertRaises(ValueError):
            scan.validate_feed(self._feed(countries={"de": [["93.184.216.34", 443]]}))
        with self.assertRaises(ValueError):
            scan.validate_feed(self._feed(countries={"D1": [["93.184.216.34", 443]]}))

    def test_malformed_endpoint_rejected(self):
        with self.assertRaises(ValueError):
            scan.validate_feed(self._feed(countries={"DE": [["10.0.0.1", 443]]}))
        with self.assertRaises(ValueError):
            scan.validate_feed(self._feed(countries={"DE": [["93.184.216.34", 99999]]}))
        with self.assertRaises(ValueError):
            scan.validate_feed(self._feed(countries={"DE": [["93.184.216.34", "443"]]}))

    def test_duplicate_endpoint_rejected(self):
        with self.assertRaises(ValueError):
            scan.validate_feed(self._feed(countries={
                "DE": [["93.184.216.34", 443]],
                "FR": [["93.184.216.34", 443]]}))

    def test_ipv6_literal_accepted(self):
        feed = self._feed(countries={"DE": [["2606:2800:220:1:248:1893:25c8:1946", 443]]})
        scan.validate_feed(feed)

    def test_count_mismatch_rejected(self):
        with self.assertRaises(ValueError):
            scan.validate_feed(self._feed(counts={"verified": 2, "countries": 1}))

    def test_anomaly_guard_keeps_previous_feed(self, ):
        # Simulate: previous healthy feed present; new pools near-zero.
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "verified"
            out.mkdir()
            prev = {"schema_version": 1, "counts": {"verified": 500}}
            (out / "feed.json").write_text(json.dumps(prev), encoding="utf-8")
            try:
                pools = {"DE": []}  # total = 0 → collapse
                state = {"candidates": {}}
                report = {"scanner_revision": "t", "pool_sizes": {}}
                with self.assertRaises(SystemExit):
                    scan.publish(pools, state, report, {}, out_dir=out)
                # previous feed retained
                self.assertEqual(
                    json.loads((out / "feed.json").read_text())["counts"]["verified"], 500)
            finally:
                pass

    def test_anomaly_guard_allows_growth(self):
        import tempfile
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "verified"
            out.mkdir()
            (out / "feed.json").write_text(json.dumps({"counts": {"verified": 10}}), encoding="utf-8")
            scan.OUT = out
            try:
                pools = {"DE": [{"address": "93.184.216.34", "port": 443,
                                 "observed_country": "DE", "source_countries": [],
                                 "sources": [], "score": 1, "last_rtt_ms": 10,
                                 "last_success": "2026-09-23T00:00:00Z",
                                 "success_count": 1, "failure_count": 0,
                                 "status": "verified", "success_ratio": 1.0,
                                 "quality_rank": 1}]}
                report = {"scanner_revision": "t"}
                scan.publish(pools, {"candidates": {}}, report, {}, out_dir=out)
                self.assertEqual(
                    json.loads((out / "feed.json").read_text())["counts"]["verified"], 1)
            finally:
                pass


if __name__ == "__main__":
    unittest.main()
