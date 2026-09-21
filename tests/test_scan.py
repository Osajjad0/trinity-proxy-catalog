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
        real = scan.socket.getaddrinfo
        def fake(host, *a, **k):
            infos = real(host, *a, **k)
            # Pretend every domain resolves to the same public IP.
            return [(infos[0][0], None, 6, "", ("93.184.216.34", 0))] if infos else []
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


if __name__ == "__main__":
    unittest.main()
