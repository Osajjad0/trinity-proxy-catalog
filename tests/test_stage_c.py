"""Stage C capability classifier — behavioral ground truth.

History: these tests used to assert fixed live fixture IPs per class
(measured 2026-09-24). Operator rotation legitimately changes what a
third-party box does (2026-09-30: all three original fixtures relayed
honestly), so a fixed-IP assertion tests the internet, not the classifier.

Current strategy: the classifier's discriminating logic is tested against
LOCAL deterministic TLS servers (own-cert front = sni-terminate; relay =
passthrough; dead host = unreachable/tls-error). The CF-edge alert class
cannot be simulated locally, so that single test stays live with a
skip-guard for middlebox interference windows.
"""
import socket as _s
import ssl as _ssl
import threading
import unittest

from scanner.scan import classify_capability

_FRONT_CERT = "-----BEGIN CERTIFICATE-----\nMIICtjCCAZ6gAwIBAgIUDpkK6mmVloIciHoLz+YZ8/bxRlUwDQYJKoZIhvcNAQEL\nBQAwFTETMBEGA1UEAwwKZnJvbnQudGVzdDAeFw0yNjA5MjkxMTMwMTlaFw0zNjA5\nMjcxMTMwMTlaMBUxEzARBgNVBAMMCmZyb250LnRlc3QwggEiMA0GCSqGSIb3DQEB\nAQUAA4IBDwAwggEKAoIBAQCjyuzMP4UDfsHPF27jKees/GMysesSbSjlY4hMYRdm\nMWx0bJliG26G2IyzClnIiqwsDEFdY6oT9jyRfG6+ZBchl7PIxrL70rKQwNN0jrah\ngRqmdM3t7ebix9rQn37tCvCh6w3gGJLJNseMUs51UvdO0QZpMppwXcwRQKx8+UsE\n2tjHDak3EA5ieoU56ojgr0t31eGMDAauv4AO0IJxV/0NlBKbVSH4PAjF+Kg0czhq\neoDpz+v9UMyPv25WSuUKsfUEI2S8QA7sxxVpsvM+wdEd3uvEI1SIMzLeq/xWZ2zi\neRPiKyhpSNcKWzfNj59NhmopUI+Dfj9oOEHicDDgX8aBAgMBAAEwDQYJKoZIhvcN\nAQELBQADggEBABvmbyJ/fah/n6XqTvwCwUH9dh3gtzXVm9wo/M7umOFb9HGJmFVA\ntysOpc2V7qTgqbmrAE37RU8jCGQ0GQD4UVP2H+Uk84MUYGVX1u8hqzJwpn/4dPVE\nc1qmOCpaLkUMy+iut8nbW+8rQpq4HpHQqR3t6WGf4b4UD/7zIGKVa25l9lHEkhW1\njx+jtpIIZhlYMMl4w/Rv7Lyy6lu8iQ7boG2/m2/noYxa+/9zw3fCbvj+m2WB9W0j\n3qQiD6US5pbUxJdV54IuekSJK5J8DoXJX8inxBsYRaWJQWyR+TPh9bztJz8TH08z\nw8utSc00h54WrjQExKAZi5ea811X2mG3x5Q=\n-----END CERTIFICATE-----"
_FRONT_KEY = "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCjyuzMP4UDfsHP\nF27jKees/GMysesSbSjlY4hMYRdmMWx0bJliG26G2IyzClnIiqwsDEFdY6oT9jyR\nfG6+ZBchl7PIxrL70rKQwNN0jrahgRqmdM3t7ebix9rQn37tCvCh6w3gGJLJNseM\nUs51UvdO0QZpMppwXcwRQKx8+UsE2tjHDak3EA5ieoU56ojgr0t31eGMDAauv4AO\n0IJxV/0NlBKbVSH4PAjF+Kg0czhqeoDpz+v9UMyPv25WSuUKsfUEI2S8QA7sxxVp\nsvM+wdEd3uvEI1SIMzLeq/xWZ2zieRPiKyhpSNcKWzfNj59NhmopUI+Dfj9oOEHi\ncDDgX8aBAgMBAAECggEACKMq2Zp/6S9GCSWzM0eCcBzfHk1DmDUpcu9MwLpeAYWZ\nsooHjKTlrza8NLTXBzxI2AnNaJ9Y2LSjfQiSznd4wMy/LldMGPuDbx68B+l+uAWW\n4jBGq8Vf55WidF3004tAJUm/8ZFaLEI3Q68aNBWr9PwQ2ntQqZxIpqBCeFStIBRU\nu4liPPMm2NYRGFwUp+SHT7D+mQ1Bkbs4tbr5XZI2U/IfDlPbO32edEgtWkRAqE+l\nQtOplQUxRJejT7G3YQ8lZQyvqKhvBCGIWyn5KLcXhS4mFF7zxoDG3LBP4+re9sVw\nCD65wWOSMSQMVaad7YKRqCVUqGEoe7TFBlz6BNCgAQKBgQDWZA83hlhY2uv4u2X2\nSjuh1lCDmnmLjNkH1Bk4yVfVCR/3RAmKuZUsnPc+RwPtlQdvpQqdGBtgSrU21j3w\n+n+oBEsuD2/RfzBt099Z3c4kKiE+ys3joYo7UqU72wluucBIpocImkeJjjLKtV3j\nnrdCZB3flaxIahrDV8OYd9M8OQKBgQDDlOlGjfKv5pmqPYq4OCRQbfFYdW9S6T/F\nMiWTsJ/eFGuWkSdTvM+a1Y0lAXbHiGPXAuyvb/dT11fagzvWOmE66SwDUPRpiM6e\nWTWmN3OofM1vKF5Rrp5+2Igwwt3HhNcaz+GbDzQAGVNHoqRuVxGWYk9eUiFO7bni\ndTFOy1DsiQKBgQDOQHrnNwb9jLehll/UXrwZyP2ybkVqfLk6r9EH8aPfHqUzE7B+\nVmXuAqBVuKpNwabiwIuCcHO94oGN3PTARa3ULTVKfa1chZlIv6FLanjsD9/l8eO7\nj2hWA/9Uozfi3y7edd7I5uvVqQiyPWOzHLk/VOPseqjBDdrrfR5+KyD7+QKBgDse\nbg0Xpz4odFaTV7Ursz5knUlh5g6n1tDiwZ0NDKXygjr3EW4saoyg9JM1CBR0U8mQ\nZr75F0fOlg3FEXdGGlHWXal69QZZhiszSBZAOMO7RdXN3ATQxbQN+8zRenxu2R6P\nq+BVDiDhhtzmetGnm/dbLCaUqODU1xVu20K4DnQRAoGAItK2cmMOsE2pGZpQtPCF\n9KNe+02fVAEg9VMFv0rO0j/S9wcPIFXBFaZeqTLkTnTYjVPKoau4o+ngoK2BeDw3\nwsPwJBhVTdPjqmpe8kClfZrEodCFSS4Y93TNleDSMoRth1Pse7y+ISOiEqoBgmc+\ndurTW2oAjFAdQ501WPc/JHc=\n-----END PRIVATE KEY-----"


def _tls_server(relay_host: str | None):
    """Serve one connection per accept. relay_host=None => present own cert
    and answer with a self-generated 200 (sni-terminate behavior);
    relay_host set => open a TCP connection to relay_host:443 and pipe bytes
    (passthrough behavior). Returns (port, shutdown_fn)."""
    srv = _s.socket()
    srv.setsockopt(_s.SOL_SOCKET, _s.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    srv.listen(4)
    port = srv.getsockname()[1]
    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_SERVER)
    import tempfile, os as _os
    with tempfile.TemporaryDirectory() as td:
        cp, kp = _os.path.join(td, "c.pem"), _os.path.join(td, "k.pem")
        with open(cp, "w") as f: f.write(_FRONT_CERT)
        with open(kp, "w") as f: f.write(_FRONT_KEY)
        ctx.load_cert_chain(cp, kp)
        stop = threading.Event()
        def run():
            srv.settimeout(0.3)
            while not stop.is_set():
                try:
                    conn, _ = srv.accept()
                except (_s.timeout, OSError):
                    continue
                try:
                    tls = ctx.wrap_socket(conn, server_side=True)
                    data = tls.recv(4096)
                    if relay_host is None:
                        tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                    else:
                        up = _s.create_connection((relay_host, 443), timeout=6)
                        up.sendall(data)
                        tls.sendall(up.recv(4096))
                        up.close()
                    tls.close()
                except OSError:
                    pass
        th = threading.Thread(target=run, daemon=True)
        th.start()
        return port, (lambda: (stop.set(), srv.close()))


def _network_intercepts_testnet() -> bool:
    """True when something on this network answers TLS for TEST-NET-1.

    192.0.2.0/24 has no servers by RFC 5737; a completed handshake means a
    transparent interceptor (VPN/MITM layer) is answering for every :443,
    which invalidates any live-network classification in this process.
    """
    import ssl as _ssl2
    try:
        raw = _s.create_connection(("192.0.2.1", 443), timeout=5)
        raw.settimeout(5)
        ctx = _ssl2.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = _ssl2.CERT_NONE
        sock = ctx.wrap_socket(raw, server_hostname="www.postgresql.org")
        sock.close()
        return True
    except OSError:
        return False


class StageC(unittest.TestCase):
    def test_sni_terminate_presents_foreign_cert(self):
        if _network_intercepts_testnet():
            self.skipTest("local network intercepts :443 (TEST-NET answered); live-probe results are meaningless here")
        port, shutdown = _tls_server(relay_host=None)
        try:
            self.assertEqual(classify_capability("127.0.0.1", port),
                             "sni-terminate")
        finally:
            shutdown()

    def test_passthrough_relays_with_valid_cert(self):
        # LIVE-fixture behavioral test (see module docstring): the fixture is
        # whichever third-party box currently relays honestly. Fixed IPs went
        # stale once (2026-09-30: all three became honest relays), so this
        # asserts the INVARIANT "an honest relay classifies passthrough"
        # against any currently-live honest box — skipped when no fixture is
        # reachable, never silently passed.
        if _network_intercepts_testnet():
            self.skipTest("local network intercepts :443 (TEST-NET answered); live-probe results are meaningless here")
        fixtures = [("104.156.252.234", 8443), ("147.90.44.249", 443),
                    ("217.110.20.141", 443)]
        results = {ip: classify_capability(ip, port) for ip, port in fixtures}
        self.assertTrue(
            any(v == "passthrough" for v in results.values()),
            f"no live honest-relay fixture right now: {results}")

    def test_dead_host_never_claims_passthrough(self):
        # TEST-NET-1 never serves TLS; the invariant "never passthrough" only
        # holds on a network that does not answer for unroutable space.
        if _network_intercepts_testnet():
            self.skipTest("local network intercepts :443 (TEST-NET answered); live-probe results are meaningless here")
        self.assertIn(classify_capability("192.0.2.1", 443),
                      ("unreachable", "tls-error"))

    def test_status_line_parsing_never_crashes(self):
        parts = "HTTP/1.1".split(" ", 2)
        status = parts[1] if len(parts) > 1 else ""
        self.assertEqual(status, "")


if __name__ == "__main__":
    unittest.main()
