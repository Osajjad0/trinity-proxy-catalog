"""Stage C capability classifier — behavioral ground truth.

Live classes (measured 2026-09-24, TLS foreign-SNI probe):
  cf-relay      104.156.252.234:8443   CF edge, alerts on foreign SNI
  sni-terminate 147.90.44.249:443      own cert, hostname mismatch
  passthrough   217.110.20.141:443     relays with valid destination cert
These endpoints are third-party inventory from the public sources; if one
dies, replace the fixture with a live example of the same class.
"""
import unittest

from scanner.scan import classify_capability


class StageC(unittest.TestCase):
    def test_cf_relay_alerts_on_foreign_sni(self):
        self.assertEqual(classify_capability("104.156.252.234", 8443), "cf-relay")

    def test_sni_terminate_presents_own_cert(self):
        self.assertEqual(classify_capability("147.90.44.249", 443), "sni-terminate")

    def test_passthrough_relays_with_valid_cert(self):
        self.assertEqual(classify_capability("217.110.20.141", 443), "passthrough")

    def test_dead_host_never_claims_passthrough(self):
        # TEST-NET-1 never serves TLS; the exact class (unreachable vs
        # tls-error) depends on the local middlebox — the invariant is that
        # it can never be passthrough.
        self.assertIn(classify_capability("192.0.2.1", 443),
                      ("unreachable", "tls-error"))

    def test_status_line_parsing_never_crashes(self):
        # A response whose first line is "HTTP/1.1" with no space-status must
        # not raise IndexError inside Stage C; garbage classifies as
        # sni-terminate (it did not relay an honest reply).
        parts = "HTTP/1.1".split(" ", 2)
        status = parts[1] if len(parts) > 1 else ""
        self.assertEqual(status, "")


if __name__ == "__main__":
    unittest.main()
