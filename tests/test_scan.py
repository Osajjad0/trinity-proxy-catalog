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


class TestCountryBatches(unittest.TestCase):
    def test_stalest_and_passthrough_verified_first(self):
        # The 12h geo gate needs fresh evidence for pool members; a pure cursor
        # rotation can leave the country's passthrough candidate unverified for
        # ~13h. The window must verify the stalest evidence first and put
        # passthrough candidates ahead of equal-staleness others.
        def cand(addr, cap=None, last=None):
            return {"address": addr, "port": 443, "source_countries": ["ZZ"]}
        state = {"candidates": {
            "a:443": {"last_success": "2020-01-01T00:00:00Z",
                      "capability": "cf-relay"},
            "b:443": {"last_success": "2026-09-28T18:00:00Z",
                      "capability": "cf-relay"},
            "c:443": {"last_success": "2026-09-28T18:00:00Z",
                      "capability": "passthrough"},
            "d:443": {"capability": "cf-relay"},  # never probed
        }}
        cands = [cand("b"), cand("c"), cand("a"), cand("d")]
        picked, meta = scan.country_batches(cands, state, "2026-09-28T18:30:00Z")
        order = [f'{c["address"]}:{c["port"]}' for c in picked]
        # passthrough first; then unknown/stalest-first among cf-relay
        # (never-probed = oldest), freshest last.
        self.assertEqual(order[0], "c:443")
        self.assertEqual(order[1], "d:443")
        self.assertEqual(order[2], "a:443")
        self.assertEqual(order[3], "b:443")

    def test_passthrough_selected_across_pool_not_only_cursor_window(self):
        # Regression: the old code picked a cursor slice FIRST and only then
        # sorted it, so a passthrough candidate sitting outside the slice was
        # never selected (measured: 99/144 passthrough excluded from the
        # published feed by age alone). With a per-country budget of 16 and a
        # pool larger than that, an expired passthrough at position 40 must
        # still be picked ahead of fresher cf-relay candidates in any slice.
        def cand(addr):
            return {"address": addr, "port": 443, "source_countries": ["ZZ"]}
        state = {"candidates": {
            # 40 cf-relay boxes, recently attempted (would win any slice race)
            **{f"f{i}:443": {"last_seen": "2026-09-28T17:30:00Z",
                             "last_success": "2026-09-28T17:30:00Z",
                             "capability": "cf-relay"}
               for i in range(40)},
            # the country's only passthrough: expired evidence, never attempted
            "p:443": {"last_success": "2026-09-26T18:30:00Z",
                      "capability": "passthrough"},
        }}
        cands = [cand(f"f{i}") for i in range(40)] + [cand("p")]
        picked, meta = scan.country_batches(cands, state, "2026-09-28T18:30:00Z")
        order = [f'{c["address"]}:{c["port"]}' for c in picked]
        self.assertEqual(len(picked), scan.DAILY_BUDGET_PER_COUNTRY)
        self.assertEqual(order[0], "p:443",
                         "expired passthrough outside any cursor slice must be selected")

    def test_failed_candidate_rotates_not_hammers(self):
        # A candidate that failed its last attempt must go to the back of the
        # rotation (attempt-age clock), or a dead box pins the window every
        # run and the feed membership freezes. Two cf-relay boxes: one failed
        # an hour ago, one succeeded 30h ago and was last attempted 20h ago.
        def cand(addr):
            return {"address": addr, "port": 443, "source_countries": ["ZZ"]}
        state = {"candidates": {
            "dead:443": {"last_seen": "2026-09-28T17:30:00Z",
                         "last_success": "2026-09-20T18:30:00Z",
                         "capability": "cf-relay"},
            "live:443": {"last_seen": "2026-09-27T22:30:00Z",
                         "last_success": "2026-09-27T12:30:00Z",
                         "capability": "cf-relay"},
        }}
        picked, _ = scan.country_batches([cand("dead"), cand("live")],
                                         state, "2026-09-28T18:30:00Z")
        order = [f'{c["address"]}:{c["port"]}' for c in picked]
        self.assertEqual(order[0], "live:443",
                         "recently-failed box must yield to the stale live one")


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
        # Latency must actually reach the record. `total_ms` was declared in
        # the probe's result shape and read by the scorer, but probe_stage
        # never assigned it -- so every candidate carried last_rtt_ms=None and
        # the scorer's speed term (+0..+20) could never fire. This assertion
        # is what that bug would have tripped.
        self.assertEqual(rec["last_rtt_ms"], 140)

    def test_probe_reports_total_rtt(self):
        """probe_stage must fill total_ms, not only its components.

        Guards the regression directly against the real function: the merge
        test above proves the plumbing, this proves the producer. Without
        total_ms, latency silently ranks nothing.
        """
        import socket as _s

        class FakeSock:
            def __init__(self):
                self.sent = b""
            def sendall(self, b):
                self.sent += b
            def close(self):
                pass

        body = (b"HTTP/1.1 200 OK\r\nContent-Length: 46\r\n\r\n"
                b"loc=US\r\ncolo=IAD\r\nip=203.0.113.9\r\n")

        def fake_recv(sock):
            return len(body), body.decode()

        orig_conn = _s.create_connection
        orig_recv = scan._recv_response
        orig_ctx = scan.ssl.create_default_context
        try:
            _s.create_connection = lambda *a, **k: FakeSock()
            scan._recv_response = fake_recv
            class Ctx:
                def wrap_socket(self, raw, server_hostname=None):
                    return raw
            scan.ssl.create_default_context = lambda *a, **k: Ctx()
            res = scan.probe_stage("203.0.113.7", 443, "speed.cloudflare.com", "speed.cloudflare.com")
        finally:
            _s.create_connection = orig_conn
            scan._recv_response = orig_recv
            scan.ssl.create_default_context = orig_ctx
        self.assertTrue(res["app_ok"], res.get("error"))
        self.assertIsNotNone(res["total_ms"],
                             "probe_stage must report a total round trip")
        self.assertIsInstance(res["total_ms"], int)

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
                "egress_country": "DE",
                "egress_verdicts": {"cloudflare-trace": "DE", "ipwho": "DE"},
                "country_confidence": "high",
                "country_conflict": False,
                "verification_sources": ["cloudflare-trace", "ipwho"],
                "verification_timestamp": now,
                "sources": ["x"], "source_countries": [],
                "last_rtt_ms": 100 + i,
            }
        pools, _ = scan.build_verified(state, now)
        self.assertEqual(len(pools["DE"]), scan.PER_COUNTRY_PUBLISH_CAP)

    def test_http_forward_probe(self):
        """http_forwarding probe: example.com relay with marker = True, else False."""
        import socket as _s, threading
        # Real relay (example.com page carrying its marker) = True.
        for payload, expect in ((b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>Example Domain</html>", True),
                                (b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n", False),
                                # Appliance false-positive class: 200 for ANY Host but no marker.
                                (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html>Client Portal v9</html>", False)):
            srv=_s.socket(); srv.setsockopt(_s.SOL_SOCKET,_s.SO_REUSEADDR,1)
            srv.bind(("127.0.0.1",0)); srv.listen(1); port=srv.getsockname()[1]
            def run(srv=srv,payload=payload):
                c,_=srv.accept(); c.recv(4096); c.sendall(payload); c.close()
            th=threading.Thread(target=run); th.start()
            got=scan.probe_http_forward("127.0.0.1",port)
            th.join(); srv.close()
            self.assertEqual(got,expect)
        self.assertFalse(scan.probe_http_forward("127.0.0.1",1))  # nothing listens

    def test_ipapi_target_parsed_and_consensus_extended(self):
        """4-source consensus: ip-api (plain HTTP) verdict counts toward agreement."""
        ip, cc = scan._parse_egress(
            "ipapi",
            'HTTP/1.1 200 OK\r\n\r\n{"query":"1.2.3.4","countryCode":"TR","as":"AS9121","isp":"TT"}')
        self.assertEqual((ip, cc), ("1.2.3.4", "TR"))
        ip, cc = scan._parse_egress(
            "ipapi",
            'HTTP/1.1 200 OK\r\n\r\n{"query":"1.2.3.4","countryCode":"IT"}')
        self.assertEqual((ip, cc), ("1.2.3.4", "IT"))
        # malformed -> unreadable, never a wrong verdict
        ip, cc = scan._parse_egress("ipapi", 'HTTP/1.1 200 OK\r\n\r\nnot json')
        self.assertEqual((ip, cc), (None, None))

    def test_stale_egress_evidence_excluded_from_country_pool(self):
        # Bug #1: a candidate whose last success is inside the 48 h candidate
        # TTL but older than GEO_TTL_H must NOT enter a country pool — its
        # exit country may have rotated since the probe. It is reported
        # stale-for-pooling, not deleted.
        import time as _t
        now = _t.time()
        fmt = lambda ts: _t.strftime("%Y-%m-%dT%H:%M:%SZ", _t.gmtime(ts))
        recent = fmt(now - 3600)          # 1 h old -> pools
        mid = fmt(now - (scan.GEO_TTL_H + 2) * 3600)   # > GEO_TTL_H, < 48 h
        state = {"candidates": {
            "203.0.113.1:443": {
                "first_seen": recent, "last_seen": recent,
                "last_success": recent, "success_count": 1,
                "observed_country": "DE", "sources": ["x"],
                "source_countries": [],
                "egress_country": "DE",
                "egress_verdicts": {"cloudflare-trace": "DE", "ipwho": "DE"},
                "country_confidence": "high",
                "country_conflict": False,
                "verification_sources": ["cloudflare-trace", "ipwho"],
                "verification_timestamp": recent,
            },
            "203.0.113.2:443": {
                "first_seen": mid, "last_seen": mid,
                "last_success": mid, "success_count": 1,
                "observed_country": "TR", "sources": ["x"],
                "source_countries": [],
                "egress_country": "TR",
                "egress_verdicts": {"cloudflare-trace": "TR", "ipwho": "TR"},
                "country_confidence": "high",
                "country_conflict": False,
                "verification_sources": ["cloudflare-trace", "ipwho"],
                "verification_timestamp": mid,
            },
        }}
        pools, stale = scan.build_verified(state, fmt(now))
        self.assertIn("DE", pools)
        self.assertNotIn("TR", pools)
        self.assertNotIn("203.0.113.1:443", stale["stale"])
        self.assertIn("203.0.113.2:443", stale["stale"])

    def test_country_conflict_bars_strict_pool(self):
        # Bug #1 v2: cloudflare says TR but ipwho/ipinfo say IT -> conflict ->
        # the candidate must NOT enter any country pool, even though the CF
        # trace alone said TR and the record is fresh. Correctness > count.
        import time as _t
        now = _t.strftime("%Y-%m-%dT%H:%M:%SZ", _t.gmtime())
        state = {"candidates": {
            "203.0.113.9:443": {
                "first_seen": now, "last_seen": now, "last_success": now,
                "success_count": 1,
                "observed_country": "TR",          # CF-trace verdict
                "egress_country": "TR",
                "egress_verdicts": {"cloudflare-trace": "TR", "ipwho": "IT"},
                "country_confidence": "conflict",
                "country_conflict": True,
                "verification_sources": ["cloudflare-trace"],
                "verification_timestamp": now,
                "sources": ["x"], "source_countries": [],
            },
        }}
        pools, stale = scan.build_verified(state, now)
        self.assertEqual(pools, {}, "conflicting egress must not serve a country")
        self.assertIn("203.0.113.9:443", stale["stale"])

    def test_consensus_agreement_publishes_confidence(self):
        # Two independent targets agreeing => high confidence => pool member,
        # with the consensus fields carried into the feed entry.
        import time as _t
        now = _t.strftime("%Y-%m-%dT%H:%M:%SZ", _t.gmtime())
        state = {"candidates": {
            "203.0.113.10:443": {
                "first_seen": now, "last_seen": now, "last_success": now,
                "success_count": 1,
                "observed_country": "TR",
                "egress_country": "TR",
                "egress_ip": "203.0.113.10",
                "egress_verdicts": {"cloudflare-trace": "TR", "ipwho": "TR"},
                "country_confidence": "high",
                "country_conflict": False,
                "verification_sources": ["cloudflare-trace", "ipwho"],
                "verification_timestamp": now,
                "sources": ["x"], "source_countries": [],
            },
        }}
        pools, stale = scan.build_verified(state, now)
        self.assertIn("TR", pools)
        entry = pools["TR"][0]
        self.assertEqual(entry["country_confidence"], "high")
        self.assertEqual(entry["egress_ip"], "203.0.113.10")
        self.assertEqual(entry["verification_sources"], ["cloudflare-trace", "ipwho"])
        self.assertNotIn("203.0.113.10:443", stale["stale"])

    def test_single_source_low_confidence_bars_pool(self):
        # One readable verdict alone is "low": real traffic could take another
        # upstream. Never serve a strict country on single-source evidence.
        import time as _t
        now = _t.strftime("%Y-%m-%dT%H:%M:%SZ", _t.gmtime())
        state = {"candidates": {
            "203.0.113.11:443": {
                "first_seen": now, "last_seen": now, "last_success": now,
                "success_count": 1, "observed_country": "TR",
                "egress_country": "TR",
                "egress_verdicts": {"cloudflare-trace": "TR"},
                "country_confidence": "low",
                "country_conflict": False,
                "verification_sources": ["cloudflare-trace"],
                "verification_timestamp": now,
                "sources": ["x"], "source_countries": [],
            },
        }}
        pools, stale = scan.build_verified(state, now)
        self.assertNotIn("TR", pools)
        self.assertIn("203.0.113.11:443", stale["stale"])

    def test_stale_reputation_decays_to_unknown(self):
        import time as _t
        now = _t.strftime("%Y-%m-%dT%H:%M:%SZ", _t.gmtime())
        old_ts = "2026-08-01T00:00:00Z"  # far older than VERIFIED_TTL_H
        state = {"candidates": {
            "203.0.113.1:443": {
                "first_seen": now, "last_seen": now, "last_success": now,
                "success_count": 1, "observed_country": "DE",
                "egress_country": "DE",
                "egress_verdicts": {"cloudflare-trace": "DE", "ipwho": "DE"},
                "country_confidence": "high",
                "country_conflict": False,
                "verification_sources": ["cloudflare-trace", "ipwho"],
                "verification_timestamp": now,
                "sources": ["x"], "source_countries": [],
                "ip_quality": {"risk": "high", "ip_type": "datacenter",
                               "confidence": "high", "source": "ip-api"},
                "ip_quality_at": old_ts,
            },
            "203.0.113.2:443": {
                "first_seen": now, "last_seen": now, "last_success": now,
                "success_count": 1, "observed_country": "DE",
                "egress_country": "DE",
                "egress_verdicts": {"cloudflare-trace": "DE", "ipwho": "DE"},
                "country_confidence": "high",
                "country_conflict": False,
                "verification_sources": ["cloudflare-trace", "ipwho"],
                "verification_timestamp": now,
                "sources": ["x"], "source_countries": [],
                "ip_quality": {"risk": "low", "ip_type": "residential",
                               "confidence": "high", "source": "ip-api"},
                "ip_quality_at": now,
            },
        }}
        pools, _ = scan.build_verified(state, now)
        by_addr = {e["address"]: e for e in pools["DE"]}
        # Stale verdict decays to unmeasured (never published as current).
        self.assertEqual(by_addr["203.0.113.1"]["risk"], "unknown")
        # Fresh verdict keeps its value.
        self.assertEqual(by_addr["203.0.113.2"]["risk"], "low")
        # And the feed map (same comprehension publish() uses) only carries
        # the fresh verdict.
        feed_q = {
            f'{e["address"]}:{e["port"]}': e["risk"]
            for entries in pools.values() for e in entries
            if e.get("risk", "unknown") != "unknown"
            or e.get("ip_type", "unknown") != "unknown"
        }
        self.assertNotIn("203.0.113.1:443", feed_q)
        self.assertIn("203.0.113.2:443", feed_q)


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
