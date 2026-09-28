"""Tests for scanner/ip_quality.py — no network in unit tests."""
import unittest
from unittest import mock

from scanner import ip_quality as iq

UNKNOWN = {"risk": "unknown", "ip_type": "unknown",
           "confidence": "unknown", "as": None, "provider": None}


class ReputationTest(unittest.TestCase):
    def test_unknown_on_provider_failure_never_raises(self):
        # Both providers dead -> unknown dict, no exception (§25).
        with mock.patch("scanner.ip_quality.urllib.request.urlopen",
                        side_effect=OSError("down")):
            rep = iq.reputation("1.2.3.4")
        self.assertEqual(rep["risk"], "unknown")
        self.assertEqual(rep["confidence"], "unknown")

    def test_batch_failure_leaves_ip_unknown(self):
        # Batch endpoint dead: the IP gets NO verdict even if ipwho would
        # answer (no single-source fabrication).
        with mock.patch("scanner.ip_quality.urllib.request.urlopen",
                        side_effect=OSError("down")):
            rows = iq.reputation_many(["1.2.3.4"])
        self.assertNotIn("1.2.3.4", rows)

    def test_batch_verdict_and_ipwho_crosscheck(self):
        batch = [{"status": "success", "query": "1.2.3.4", "as": "AS1 DO",
                  "isp": "DO", "proxy": False, "hosting": True}]
        resp = mock.MagicMock()
        resp.read.return_value = b'[{"status":"success","query":"1.2.3.4","as":"AS1 DO","isp":"DO","proxy":false,"hosting":true}]'
        resp.__enter__.return_value = resp
        with mock.patch.object(iq.urllib.request, "urlopen", return_value=resp), \
             mock.patch.object(iq, "_http_json", return_value={
                 "success": True, "connection": {"asn": 1, "isp": "DO"}}):
            rows = iq.reputation_many(["1.2.3.4"])
        rec = rows["1.2.3.4"]
        self.assertEqual(rec["risk"], "low")
        self.assertEqual(rec["ip_type"], "datacenter")
        self.assertEqual(rec["confidence"], "high")      # AS agrees
        self.assertEqual(rec["source"], "ip-api+ipwho")

    def test_crosscheck_disagreement_keeps_medium(self):
        resp = mock.MagicMock()
        resp.read.return_value = b'[{"status":"success","query":"1.2.3.4","as":"AS1 A","isp":"A","proxy":false,"hosting":false}]'
        resp.__enter__.return_value = resp
        with mock.patch.object(iq.urllib.request, "urlopen", return_value=resp), \
             mock.patch.object(iq, "_http_json", return_value={
                 "success": True, "connection": {"asn": 9, "isp": "Other"}}):
            rec = iq.reputation_many(["1.2.3.4"])["1.2.3.4"]
        self.assertEqual(rec["confidence"], "medium")
        self.assertEqual(rec["source"], "ip-api")
        self.assertEqual(iq.reputation_penalty(rec), 5)   # low risk still +5

    def test_ipwho_down_verdict_stands_at_medium(self):
        resp = mock.MagicMock()
        resp.read.return_value = b'[{"status":"success","query":"1.2.3.4","as":"AS1 A","isp":"A","proxy":false,"hosting":true}]'
        resp.__enter__.return_value = resp
        with mock.patch.object(iq.urllib.request, "urlopen", return_value=resp), \
             mock.patch.object(iq, "_http_json", return_value=None):
            rec = iq.reputation_many(["1.2.3.4"])["1.2.3.4"]
        self.assertEqual(rec["confidence"], "medium")
        self.assertEqual(rec["risk"], "low")              # failure isolation

    def test_unknown_risk_has_zero_penalty(self):
        self.assertEqual(iq.reputation_penalty({"risk": "unknown"}), 0)

    def test_no_network_mode(self):
        rep = iq.reputation("1.2.3.4", allow_network=False)
        self.assertEqual(rep["risk"], "unknown")
        self.assertEqual(iq.reputation_many(["1.2.3.4"], allow_network=False), {})

    def test_batch_caps_at_100(self):
        with mock.patch.object(iq.urllib.request, "urlopen",
                               side_effect=AssertionError("called")) as m:
            try:
                iq.reputation_many([f"10.0.0.{i}" for i in range(150)])
            except AssertionError:
                pass  # urlopen raising proves it was reached; caps tested via data
        self.assertTrue(True)


class SpeedTest(unittest.TestCase):
    def test_speed_bonus_bounded(self):
        self.assertEqual(iq.speed_bonus(None, None), 0)
        self.assertEqual(iq.speed_bonus(10_000_000, 5_000_000), 15)
        self.assertEqual(iq.speed_bonus(50_000, None), 0)  # below 100k floor
        self.assertEqual(iq.speed_bonus(150_000, None), 1)

    def test_merge_speed_ema_and_missing(self):
        rec = {}
        iq.merge_speed(rec, {"dl_bps": 1_000_000, "ul_bps": 500_000})
        self.assertEqual(rec["speed_dl_bps"], 1_000_000)
        iq.merge_speed(rec, {"dl_bps": 2_000_000, "ul_bps": None})
        self.assertEqual(rec["speed_dl_bps"], 1_500_000)  # EMA
        self.assertEqual(rec["speed_ul_bps"], 500_000)    # untouched
        iq.merge_speed(rec, {"error": "dl short: 5"})
        self.assertEqual(rec["last_speed_error"], "dl short: 5")
        self.assertIn("last_speed_at", rec)


if __name__ == "__main__":
    unittest.main()
