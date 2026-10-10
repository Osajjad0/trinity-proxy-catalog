#!/usr/bin/env python
"""Stage-C capability does NOT imply social-destination reachability.

Defect class this file exists to prevent, demonstrated live on 2026-10-10:

  `84.51.54.101:8443` is classified `passthrough` by the scanner's own Stage C
  (200 on FOREIGN_SNI, confirmed passthrough on FOREIGN_SNI_CONFIRM), yet a
  TLS GET to www.instagram.com through the SAME socket returns
  `[SSL: WRONG_VERSION_NUMBER]`, while www.github.com through the same socket
  returns `200 OK`.

  So a diagnostic that speaks "TLS to a social host" to a candidate socket is
  measuring the front's SNI ALLOWLIST, not the service. Reading that error as
  "Instagram blocked" fabricates a candidate failure out of a protocol
  mismatch - exactly what happened when a previous pass reported 0/117 for
  Turkey.

Rule: only `passthrough`, proven by TWO independent non-consumer destinations,
is generic-relay evidence. `WRONG_VERSION_NUMBER` and `CERT_INVALID` are
front-shape verdicts. Neither is a destination verdict. A social-host result
from these candidates is INCONCLUSIVE, never FAIL.

This test pins the classification rule with NO network access: it asserts the
SNI ladder against the harness fronts, so the vocabulary that would encode a
fabricated verdict cannot be introduced later.
"""
import socket
import ssl
import threading
import unittest


# --- local front that behaves like the real cf-relay family: it relays
# non-consumer hosts and answers social hosts with an SNI-reject, which is what
# WRONG_VERSION_NUMBER / an SSL alert at the TLS layer looks like on the wire.
class SniAllowlistFront(threading.Thread):
    """Relays to an allowed SNI; for a disallowed one, sends back a plaintext
    HTTP status instead of a TLS ServerHello -> client sees WRONG_VERSION_NUMBER."""

    def __init__(self, allowed, blocked):
        super().__init__(daemon=True)
        self.allowed = set(allowed)
        self.blocked = set(blocked)
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self.stop = False

    def run(self):
        while not self.stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            conn.settimeout(3)
            # Read the SNI out of the raw ClientHello without a TLS library:
            # scan for the host_name type in the handshake. Good enough for a
            # local front; the real classifier never needs this.
            hello = conn.recv(4096)
            host = ""
            for probe in self.allowed | self.blocked:
                if probe.encode() in hello:
                    host = probe
                    break
            if host in self.blocked:
                # Plaintext response to a TLS handshake == WRONG_VERSION_NUMBER
                conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            else:
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def shutdown(self):
        self.stop = True
        try:
            self.sock.close()
        except OSError:
            pass


def _connect(host, port):
    try:
        raw = socket.create_connection((host, port), timeout=3)
    except OSError as e:
        return None, f"TCP_{type(e).__name__}"
    raw.settimeout(3)
    return raw, None


def probe(host, port, sni):
    """The diagnostic under test.

    Two stages on SEPARATE sockets, because one is not enough and the obvious
    single stage lies:

    1. TLS-first (what the previous pass did): every one of these fronts
       answers a ClientHello with PLAINTEXT, so the client always reports
       `[SSL: WRONG_VERSION_NUMBER]` - for a RELAYED host exactly as for a
       REJECTED one. That error carries zero information about the service.
       (A failing wrap_socket also closes its socket, so it cannot be reused.)

    2. Plaintext GET on a FRESH socket (the language the scanner's own
       probe_http_forward speaks): this is the stage that actually reads the
       verdict from these boxes.

    Returns OK / SNI_REJECT / CERT_INVALID / TLS_ALERT / RESET / TCP_* /
    INCONCLUSIVE. There is deliberately no FAIL: a front-shape result can
    never be a destination verdict.
    """
    raw, err = _connect(host, port)
    if err:
        return err
    try:
        try:
            ssl.create_default_context().wrap_socket(raw, server_hostname=sni).close()
        except ssl.SSLCertVerificationError:
            return "CERT_INVALID"
        except ssl.SSLError as e:
            msg = (getattr(e, "reason", "") or str(e)).upper()
            if "WRONG_VERSION" not in msg:
                return "TLS_ALERT"
        except OSError:
            return "RESET"
    finally:
        try:
            raw.close()
        except OSError:
            pass

    raw, err = _connect(host, port)
    if err:
        return err
    try:
        raw.sendall((f"GET / HTTP/1.1\r\nHost: {sni}\r\n"
                     f"User-Agent: proxy-catalog-scan/1.0\r\n"
                     f"Accept: */*\r\nConnection: close\r\n\r\n").encode())
        buf = b""
        while len(buf) < 256:
            chunk = raw.recv(256)
            if not chunk:
                break
            buf += chunk
    except OSError:
        return "RESET"
    finally:
        try:
            raw.close()
        except OSError:
            pass
    line = buf.split(b"\r\n", 1)[0].decode("latin-1", "replace")
    parts = line.split(" ")
    if len(parts) > 1 and parts[1].startswith(("2", "3")):
        return "OK"
    if line.upper().startswith("HTTP/"):
        return "SNI_REJECT"
    return "INCONCLUSIVE"


ALLOWED = ("www.postgresql.org", "www.rfc-editor.org", "github.com")
SOCIAL = ("www.instagram.com", "www.tiktok.com")


class SniAllowlistNotAServiceVerdict(unittest.TestCase):
    """The whole point: an SNI-reject is a front-shape result, not a verdict."""

    @classmethod
    def setUpClass(cls):
        cls.front = SniAllowlistFront(ALLOWED, SOCIAL)
        cls.front.start()

    @classmethod
    def tearDownClass(cls):
        cls.front.shutdown()

    def test_allowed_hosts_relay_normally(self):
        for host in ALLOWED:
            with self.subTest(host=host):
                self.assertNotEqual(probe("127.0.0.1", self.front.port, host),
                                    "SNI_REJECT")

    def test_social_host_sni_reject_is_a_front_shape_result(self):
        for host in SOCIAL:
            with self.subTest(host=host):
                self.assertEqual(probe("127.0.0.1", self.front.port, host),
                                 "SNI_REJECT")

    def test_an_sni_reject_must_never_classify_as_a_candidate_failure(self):
        # The exact conclusion the 0/117 pass drew from WRONG_VERSION_NUMBER.
        # One place, one rule: front-shape errors are not destination verdicts.
        FRONT_SHAPE = {"SNI_REJECT", "CERT_INVALID", "TLS_ALERT"}
        social = probe("127.0.0.1", self.front.port, "www.instagram.com")
        non_social = probe("127.0.0.1", self.front.port, "github.com")
        self.assertIn(social, FRONT_SHAPE)
        self.assertNotIn(non_social, FRONT_SHAPE,
                         "a non-consumer host must not trip the same guard")

    def test_only_two_independent_non_consumers_grant_passthrough(self):
        # Stage C's own rule, restated so a change to FOREIGN_SNI_* that
        # reintroduces a consumer host fails here instead of in production.
        import scan  # noqa: E402
        consumers = ("instagram", "tiktok", "youtube", "facebook", "x.com",
                     "reddit", "telegram", "discord", "whatsapp")
        for name in (scan.FOREIGN_SNI, scan.FOREIGN_SNI_CONFIRM):
            for c in consumers:
                self.assertNotIn(c, name.lower(),
                                 f"{name} must stay a non-consumer host")
        self.assertNotEqual(scan.FOREIGN_SNI, scan.FOREIGN_SNI_CONFIRM,
                            "confirmation needs an INDEPENDENT destination")


if __name__ == "__main__":
    unittest.main(verbosity=2)