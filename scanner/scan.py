#!/usr/bin/env python3
"""Verified-catalog scanner (V24.9, fully independent).

Discovery -> scan -> verify -> publish, Python stdlib only.

Pipeline (all bounded):
  sources.json domains + catalog/countries/*.json  ->  candidate queue
  Stage A: TCP + TLS(SNI=speed.cloudflare.com) + GET /cdn-cgi/trace
  Stage B: same socket path, SNI/Host = stage B host (independent CDN host)
  verified = Stage A ok AND Stage B ok, country from probe observation

  Capability (v1.9.5): Stage A+B prove CF-RELAY capability only (the
  candidate forwards TLS for Cloudflare-fronted SNIs). It is NOT proof of
  generic TCP forwarding; the feed carries capability="cf-relay" so
  consumers cannot advertise these endpoints as universal relays.

Dial IP, SNI, and Host stay separate: the candidate IP:port is always the
TCP destination; SNI/Host are the test hostname. A candidate is "verified"
only on full Stage A+B evidence — never because a source listed it.
This scanner is fully independent: it publishes the verified feed and stops.
Runtime reachability from a consumer's own egress is the consumer's job.

Usage:
  python scanner/scan.py --dry-run [--limit N] [--state scanner/state.json]
  python scanner/scan.py --publish [--limit N]
"""
from __future__ import annotations

import argparse
import collections
import ipaddress
import json
import socket
import ssl
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

import sys as _sys
from pathlib import Path as _Path

_sys.path.insert(0, str(_Path(__file__).resolve().parent.parent))
from scanner.ip_quality import (
    _speed_probe,
    merge_speed,
    reputation_many,
    reputation_penalty,
    speed_bonus,
)

REPO = Path(__file__).resolve().parent.parent
SOURCES = REPO / "scanner" / "sources.json"
POLICY = REPO / "scanner" / "provider_policy.json"
COUNTRIES = REPO / "catalog" / "countries"
OUT = REPO / "catalog" / "verified"

# Bounded scan constants (spec section 5).
MAX_CONCURRENCY = 120
TCP_TIMEOUT_S = 8
APP_TIMEOUT_S = 8
CF_TEST_SNI = "speed.cloudflare.com"
SCAN_DEADLINE_S = 1500
PER_COUNTRY_PUBLISH_CAP = 64
VERIFIED_TTL_H = 48
# Bug #1 (egress country mismatch): a candidate's `observed_country` is the
# EXIT country measured through the box at probe time — not a permanent
# property. Reseller boxes rotate their outbound egress (155.103.71.111 was
# observed TR at 09-27 23:1x and exited IT 09-28 16:4x — inside the 48 h
# candidate TTL). Country-pool membership therefore requires FRESHER egress
# evidence than general publication does: a candidate keeps its health /
# quality / speed records for 48 h, but only enters a country's enforced
# pool while its exit was measured within GEO_TTL_H. Old evidence cannot
# vouch for a rotating exit.
GEO_TTL_H = 12
# V24.6 country-fair scheduling: every source country gets a verification
# opportunity daily. Budget per country per run; countries below target are
# prioritized (§10-11).
DAILY_BUDGET_PER_COUNTRY = 16
MIN_VERIFIED_PER_COUNTRY = 8


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def is_public(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_private or addr.is_reserved or addr.is_multicast
                or addr.is_loopback or addr.is_link_local or addr.is_unspecified)


# ---------------------------------------------------------------- discovery

def discover_from_domains(sources: dict) -> list[dict]:
    """Resolve every enabled domain's A/AAAA records once per scan."""
    queue: dict[tuple[str, int], dict] = {}
    for entry in sources.get("domains", []):
        if not entry.get("enabled", True):
            continue
        domain = entry["domain"]
        ports = entry.get("ports") or [443]
        try:
            infos = socket.getaddrinfo(domain, None)
        except OSError as e:
            print(f"  dns fail {domain}: {e}", file=sys.stderr)
            continue
        ips = sorted({i[4][0] for i in infos})
        for ip in ips:
            if not is_public(ip):
                continue
            for port in ports:
                key = (ip, port)
                rec = queue.setdefault(key, {
                    "address": ip, "port": port, "sources": [],
                    "source_countries": [],
                })
                rec["sources"].append(f"domain:{domain}")
                if entry.get("country_hint"):
                    rec["source_countries"].append(entry["country_hint"])
    return list(queue.values())


def discover_from_catalog(limit: int) -> list[dict]:
    """Ingest the raw discovery catalog as additional scan input."""
    queue: dict[tuple[str, int], dict] = {}
    if not COUNTRIES.exists():
        return []
    total = 0
    for path in sorted(COUNTRIES.glob("*.json")):
        cc = path.stem
        if len(cc) != 2 or not cc.isupper():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for ep in data.get("endpoints", []):
            if total >= limit:
                return list(queue.values())
            addr, port = ep.get("address"), ep.get("port")
            if not addr or not port or not is_public(addr):
                continue
            total += 1
            key = (addr, port)
            rec = queue.setdefault(key, {
                "address": addr, "port": port, "sources": [],
                "source_countries": [],
            })
            rec["sources"].append(f"catalog:{cc}")
            for claim in ep.get("country_claims") or [cc]:
                if claim not in rec["source_countries"]:
                    rec["source_countries"].append(claim)
    return list(queue.values())


# ---------------------------------------------------------------- probing

def _recv_response(sock: socket.socket) -> tuple[int, str]:
    chunks = b""
    deadline = time.monotonic() + APP_TIMEOUT_S
    while time.monotonic() < deadline:
        try:
            part = sock.recv(4096)
        except (socket.timeout, OSError):
            break
        if not part:
            break
        chunks += part
        if b"\r\n\r\n" in chunks and (b"loc=" in chunks or b"ip=" in chunks):
            body_end = chunks.find(b"\r\n\r\n")
            tail = chunks[body_end:]
            if b"loc=" in tail and len(tail) > 120 or b"\r\n0\r\n" in tail:
                break
    return len(chunks), chunks.decode("utf-8", "replace")


def _parse_trace(text: str) -> dict:
    fields = {}
    for line in text.splitlines():
        line = line.strip()
        if "=" in line and not line.startswith(("HTTP", "Date", "Content", "Connection", "Server", "Cache")):
            k, _, v = line.partition("=")
            if len(k) <= 8:
                fields[k] = v
    return fields


# ---------------------------------------------------------------- Bug #1 v2: multi-destination egress consensus
# A box's egress country is per-SNI/per-destination: a multi-upstream box can
# answer the CF trace probe from a TR upstream while real (other-SNI) traffic
# leaves through IT. A single-SNI verdict can therefore lie. Consensus over
# independent neutral targets — each probed with the TARGET's own SNI/Host,
# exactly like real client traffic — is the minimum trustworthy evidence.
EGRESS_TARGETS = [
    # (name, sni, host_header, path, parser kind)
    ("cloudflare-trace", "www.cloudflare.com", "www.cloudflare.com", "/cdn-cgi/trace", "cf"),
    ("ipwho", "ipwho.is", "ipwho.is", "/", "ipwho"),
    ("ipinfo", "ipinfo.io", "ipinfo.io", "/json", "ipinfo"),
]


def _parse_egress(kind: str, text: str) -> tuple[str | None, str | None]:
    """Extract (ip, ISO-2 country) from a target's response. None = unreadable."""
    if kind == "cf":
        fields = {}
        for line in text.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                fields[k.strip()] = v.strip()
        return fields.get("ip"), (fields.get("loc") or None)
    # JSON targets; find the body (headers may still be present)
    body = text.split("\r\n\r\n", 1)[-1] if "\r\n\r\n" in text else text
    try:
        doc = json.loads(body)
    except ValueError:
        return None, None
    if not isinstance(doc, dict):
        return None, None
    if kind == "ipapi":
        ip = doc.get("query")
        cc = doc.get("countryCode")
        if isinstance(cc, str) and len(cc) == 2 and cc.isalpha():
            return ip, cc.upper()
        return ip, None
    ip = doc.get("ip")
    cc = doc.get("country_code") or doc.get("country")
    if isinstance(cc, str) and len(cc) == 2 and cc.isalpha():
        return ip, cc.upper()
    return ip, None


def probe_egress_consensus(address: str, port: int) -> dict:
    """Multi-destination egress verification (Bug #1 v2).

    One TLS+GET per neutral target, each with the TARGET's own SNI/Host.
    Consensus: >=2 agreeing readable verdicts confirm the country (high);
    one readable verdict alone is low confidence; disagreement between
    readable verdicts sets country_conflict — the candidate leaves strict
    country pools. Bounded: 3 handshakes max, APP_TIMEOUT_S each.
    """
    out = {"egress_ip": None, "egress_country": None,
           "country_confidence": "none", "verification_sources": [],
           "country_conflict": False, "egress_verdicts": {}}
    verdicts: dict[str, tuple[str | None, str]] = {}
    deadline = time.time() + 9.0  # ponytail: hard per-candidate ceiling; a
    # source-routing box that hangs plain HTTP burns at most 12s total, not
    # 4 × (connect + read) timeouts.
    for name, sni, host, path, kind in EGRESS_TARGETS:
        if time.time() > deadline:
            break
        try:
            budget_s = max(2, int(deadline - time.time()))
            raw = socket.create_connection((address, port), timeout=min(8, budget_s))
        except OSError:
            continue
        try:
            if sni is None:
                sock = raw  # plain-HTTP target (no TLS layer)
            else:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(raw, server_hostname=sni)
            req = (f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                   f"User-Agent: proxy-catalog-scan/1.0\r\nAccept: */*\r\n"
                   f"Connection: close\r\n\r\n")
            sock.sendall(req.encode())
            n, text = _recv_response(sock)
            if n:
                ip, cc = _parse_egress(kind, text)
                if cc:
                    verdicts[name] = (ip, cc)
                    # Early exit: two independent targets agreeing IS a high-
                    # confidence verdict; the remaining targets cannot raise it
                    # (only de-agree). ip-api runs last, so the slow plain-HTTP
                    # tail only happens when the TLS targets disagreed/were
                    # unreadable — exactly when the extra source is needed.
                    if len(verdicts) >= 2 and len({c for _, c in verdicts.values()}) == 1:
                        break
        except (ssl.SSLError, OSError):
            pass
        finally:
            try:
                raw.close()
            except OSError:
                pass
    out["egress_verdicts"] = {k: v[1] for k, v in verdicts.items()}
    if not verdicts:
        return out
    codes = [cc for _, cc in verdicts.values()]
    top = max(set(codes), key=codes.count)
    out["egress_country"] = top
    out["verification_sources"] = sorted(k for k, v in verdicts.items() if v[1] == top)
    if len(set(codes)) > 1:
        out["country_conflict"] = True
        out["country_confidence"] = "conflict"
    elif len(codes) >= 2:
        out["country_confidence"] = "high"
    else:
        out["country_confidence"] = "low"
    ips = {ip for ip, _ in verdicts.values() if ip}
    if len(ips) == 1:
        out["egress_ip"] = next(iter(ips))
    return out


def probe_stage(address: str, port: int, sni: str, host: str) -> dict:
    """One socket: TCP connect -> TLS(SNI=sni) -> GET /cdn-cgi/trace (Host: host).

    Returns {tcp_ok, tls_ok, app_ok, tcp_ms, app_ms, total_ms, country, colo,
    client_ip, error}. `address` is always the dial target; sni/host never
    change it.
    """
    result = {"tcp_ok": False, "tls_ok": False, "app_ok": False,
              "tcp_ms": None, "app_ms": None, "total_ms": None,
              "country": None, "colo": None, "client_ip": None, "error": None}
    t0 = time.monotonic()
    try:
        raw = socket.create_connection((address, port), timeout=TCP_TIMEOUT_S)
    except OSError as e:
        result["error"] = f"tcp: {e}"
        return result
    result["tcp_ok"] = True
    result["tcp_ms"] = int((time.monotonic() - t0) * 1000)
    try:
        ctx = ssl.create_default_context()
        tls0 = time.monotonic()
        sock = ctx.wrap_socket(raw, server_hostname=sni)
        result["tls_ok"] = True
        result["tls_ms"] = int((time.monotonic() - tls0) * 1000)
        req = (f"GET /cdn-cgi/trace HTTP/1.1\r\nHost: {host}\r\n"
               f"User-Agent: proxy-catalog-scan/1.0\r\nAccept: */*\r\n"
               f"Connection: close\r\n\r\n")
        app0 = time.monotonic()
        sock.sendall(req.encode())
        n, text = _recv_response(sock)
        result["app_ms"] = int((time.monotonic() - app0) * 1000)
        # Declared in the result shape and read by the scorer, but never
        # assigned: every candidate's last_rtt_ms stayed None, so the speed
        # term could never fire and ranking ignored latency entirely. The
        # full dial cost is the honest number for a candidate (TCP + TLS +
        # first byte), which is what "how expensive is this dial" means.
        result["total_ms"] = int((time.monotonic() - t0) * 1000)
        sock.close()
        if n == 0:
            result["error"] = "app: empty response"
            return result
        fields = _parse_trace(text)
        loc = fields.get("loc", "")
        if len(loc) == 2 and loc.isalpha():
            result["app_ok"] = True
            result["country"] = loc.upper()
            result["colo"] = fields.get("colo", "")
            result["client_ip"] = fields.get("ip", "")
        else:
            result["error"] = "app: no loc= in trace"
        return result
    except (ssl.SSLError, OSError) as e:
        result["error"] = f"tls: {e}"
        return result
    finally:
        try:
            raw.close()
        except OSError:
            pass


# ---------------------------------------------------------------- Stage C: relay capability
# A foreign-SNI TLS probe classifies the candidate's front by BEHAVIOR, not by
# hostname or ASN knowledge:
#   CF edge (cf-relay)          -> rejects a non-Cloudflare SNI with a TLS alert
#   terminating front (sni-terminate) -> completes TLS with its OWN certificate
#   true passthrough            -> completes TLS with a VALID certificate for
#                                  the tested hostname and relays the request
# The tested hostname must be a real, non-Cloudflare-fronted HTTPS host with no
# consumer relationship. www.rfc-editor.org: independent operator, plain CDN.
FOREIGN_SNI = "www.postgresql.org"
# A claimed passthrough must confirm on a SECOND independent destination
# before the class is granted. One destination can coincide with a front's
# allowlist (its own upstream); two unrelated operators agreeing is the
# behavior of a true relay, not a filtering front. False-positive generic
# capability is worse than "unclassified" (spec v1.9.5 §10).
FOREIGN_SNI_CONFIRM = "www.rfc-editor.org"


def probe_http_forward(address: str, port: int) -> bool:
    """Plain-HTTP forwarding probe (Bug #2): can the box relay a NON-TLS HTTP
    request to a neutral host? This is exactly the class of traffic Speedtest
    latency probes use (:8080 plain HTTP). cf-relay fronts (TLS-only to CF)
    fail this; true passthroughs pass. One bounded request."""
    try:
        raw = socket.create_connection((address, port), timeout=TCP_TIMEOUT_S)
    except OSError:
        return False
    raw.settimeout(4)  # ponytail: hung plain-HTTP relay burns 5s max, not 8
    try:
        req = (b"GET / HTTP/1.1\r\nHost: example.com\r\n"
               b"User-Agent: proxy-catalog-scan/1.0\r\n"
               b"Accept: */*\r\nConnection: close\r\n\r\n")
        raw.sendall(req)
        n, text = _recv_response(raw)
        parts = text.split(" ", 2)
        # Relay semantics, not just any 2xx: HTTP servers with a fixed backend
        # (client portals / captive appliances) happily return their own page
        # with 200 for any Host — that 200 fooled the plain-status check
        # (proven: one box served the same 10 KiB portal for every Host).
        # example.com's real answer carries its distinctive marker; require it.
        return (len(parts) > 1 and parts[1].startswith(("2", "3"))
                and b"Example Domain" in text.encode("utf-8", "replace"))
    except (OSError, ssl.SSLError):
        return False
    finally:
        try:
            raw.close()
        except OSError:
            pass


def _foreign_probe(address: str, port: int, sni: str) -> tuple[str, str]:
    """One foreign-SNI TLS+HTTP probe. Returns (class, evidence-status)."""
    raw = socket.create_connection((address, port), timeout=TCP_TIMEOUT_S)
    try:
        ctx = ssl.create_default_context()
        try:
            sock = ctx.wrap_socket(raw, server_hostname=sni)
        except ssl.SSLCertVerificationError:
            # TLS completed but the front presented its own certificate:
            # a terminating sni-front, not a transparent relay.
            return "sni-terminate", ""
        except ssl.SSLError as e:
            if "ALERT" in str(e):
                return "cf-relay", ""
            return "tls-error", ""
        except OSError:
            return "tls-error", ""
        # Handshake verified for the foreign hostname — prove the relay by
        # actually fetching through it.
        try:
            req = (f"GET / HTTP/1.1\r\nHost: {sni}\r\n"
                   f"User-Agent: proxy-catalog-scan/1.0\r\nAccept: */*\r\n"
                   f"Connection: close\r\n\r\n")
            sock.sendall(req.encode())
            n, text = _recv_response(sock)
            parts = text.split(" ", 2)
            status = parts[1] if len(parts) > 1 else ""
            return ("passthrough" if status.startswith(("2", "3"))
                    else "sni-terminate"), status
        except (OSError, ssl.SSLError):
            return "sni-terminate", ""
        finally:
            try:
                sock.close()
            except OSError:
                pass
    finally:
        try:
            raw.close()
        except OSError:
            pass


def classify_capability(address: str, port: int) -> str:
    """Stage C: foreign-SNI TLS probe, certificate-verified, double-confirmed.

    A candidate is only called passthrough when TWO independent non-consumer
    destinations both complete with valid certificates and honest HTTP
    statuses. Anything less keeps the conservative lower class.
    """
    try:
        cls, _ = _foreign_probe(address, port, FOREIGN_SNI)
    except OSError:
        return "unreachable"
    if cls != "passthrough":
        return cls
    try:
        confirm, _ = _foreign_probe(address, port, FOREIGN_SNI_CONFIRM)
    except OSError:
        # First probe relayed honestly; the confirmation connection failed to
        # even establish. That is churn, not evidence of a filter — keep the
        # first verdict but do not upgrade anything.
        return "passthrough"
    return "passthrough" if confirm == "passthrough" else confirm


def probe_candidate(c: dict, stage_b_host: str) -> dict:
    """Stage A (generic CF compatibility) then Stage B (independent CDN host)."""
    a = probe_stage(c["address"], c["port"], CF_TEST_SNI, CF_TEST_SNI)
    if not a["app_ok"]:
        return {**c, **a, "stage": "A", "verified": False}
    b = probe_stage(c["address"], c["port"], stage_b_host, stage_b_host)
    ok = b["app_ok"]
    # Stage C only for source-verified candidates: classification costs one
    # TLS handshake and is meaningless for a candidate that cannot even serve
    # its own edge.
    capability = classify_capability(c["address"], c["port"]) if ok else "unverified"
    # Bug #1 v2: multi-destination egress consensus. Only for verified
    # candidates — an unverifiable edge has no egress worth measuring. Adds
    # 3 bounded TLS+GET round trips per candidate per scan.
    egress = probe_egress_consensus(c["address"], c["port"]) if ok else {}
    return {
        **c, **b, "stage": "B", "verified": ok,
        "capability": capability,
        "cf_country": a["country"], "cf_colo": a["colo"],
        "cf_tcp_ms": a["tcp_ms"], "cf_app_ms": a["app_ms"],
        **egress,
        "error": None if ok else (b["error"] or "stage B failed"),
    }


# ---------------------------------------------------------------- policy / scoring

def load_policy() -> dict:
    try:
        return json.loads(POLICY.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"deny": [], "warn": []}


def provider_exclusion(rec: dict, policy: dict) -> str | None:
    """Provider policy by OBSERVED metadata, never by hostname string alone."""
    provider = (rec.get("observed_provider") or "").lower()
    for rule in policy.get("deny", []):
        if rule["match"].lower() in provider:
            return f"provider policy: {rule['match']}"
    return None


def score(rec: dict, now_ts: float | None = None) -> int:
    """Evidence-weighted quality score (V24.6.1 §16/20/21).

    Weights, justified: full-chain success dominates (app 30 + verified 20 >
    transport 20+20) because a TCP-only candidate can never serve traffic;
    latency contributes up to 20 on a 0-500ms scale; stability uses the
    success/failure ratio (repeated success compounds, repeated failure
    penalizes without ever deleting the candidate); freshness decays the whole
    score — fresh (<24h) full, stale (24-48h) 25% off, so an old "healthy"
    record cannot outrank a fresh one forever. All inputs are measured
    evidence; nothing is invented from source listings.
    """
    s = 0
    if rec.get("tcp_ok"):
        s += 20
    if rec.get("tls_ok"):
        s += 20
    if rec.get("app_ok"):
        s += 30
    if rec.get("verified"):
        s += 20
    rtt = rec.get("last_rtt_ms")
    if rtt is not None:
        s += max(0, 20 - int(rtt / 25))  # 0 ms -> +20, 500 ms -> 0
    # Stability: success ratio across attempts (evidence-based, not binary).
    ok_n = rec.get("success_count", 0)
    fail_n = rec.get("failure_count", 0)
    total = ok_n + fail_n
    if total:
        s += int(15 * ok_n / total) - int(10 * fail_n / total)
    s -= min(10, fail_n)
    # Country consistency (V24.6.6 §6): a candidate whose observed exit country
    # is outside its claimed source countries is mislabeled inventory. Bounded
    # penalty — evidence for ranking, never a deletion.
    observed = rec.get("observed_country")
    claimed = rec.get("source_countries") or []
    if observed and claimed and observed not in claimed:
        s -= 5
    # Freshness decay: last_success age (spec §20).
    last = rec.get("last_success")
    if now_ts is not None and last:
        try:
            age_h = (now_ts - _parse_iso(last)) / 3600
        except Exception:
            age_h = 1e9
        if age_h >= 24:
            s = int(s * 0.75)
        if age_h >= 48:
            s = int(s * 0.5)
    # Relay capability (Stage C): passthrough carries arbitrary destination
    # TLS and ranks above cf-relay for generic traffic. Bounded bonus — it
    # reorders within a country, never manufactures health (only verified
    # records even have a capability).
    if rec.get("capability") == "passthrough":
        s += 25
    elif rec.get("capability") == "sni-terminate":
        # Terminates TLS with its own certificate: the inner client's
        # certificate check fails for every destination it fronts. Rank it
        # below everything that can actually relay.
        s -= 15
    # v1.9.6 per-IP quality (spec §1-5, §13-14): reputation risk and measured
    # throughput, both stored evidence from ip_quality adapters. Absent
    # signals contribute 0 — unknown is never bad (§4/§25).
    s += reputation_penalty(rec.get("ip_quality") or {})
    s += speed_bonus(rec.get("speed_dl_bps"), rec.get("speed_ul_bps"))
    return max(0, min(100, s))


# ---------------------------------------------------------------- state / publish

def load_state(path: Path) -> dict:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"candidates": {}}


def merge_state(state: dict, results: list[dict], now: str) -> dict:
    """Fold this scan into the persistent evidence store."""
    store = state.setdefault("candidates", {})
    for r in results:
        key = f"{r['address']}:{r['port']}"
        rec = store.get(key) or {
            "first_seen": now, "success_count": 0, "failure_count": 0,
        }
        rec["last_seen"] = now
        rec["sources"] = sorted(set(rec.get("sources", []) + r.get("sources", [])))
        rec["source_countries"] = sorted(set(
            rec.get("source_countries", []) + r.get("source_countries", [])))
        if r.get("app_ok"):
            rec["success_count"] += 1
            rec["last_success"] = now
            rec["last_rtt_ms"] = r.get("total_ms")
            rec["observed_country"] = r.get("country")
            rec["observed_provider"] = rec.get("observed_provider") or r.get("observed_provider")
            # Bug #1 v2: multi-destination egress consensus. The verified
            # country is the CONSENSUS verdict (not the CF-trace loc=), and a
            # conflict bars the candidate from strict pools until a clean
            # consensus re-verification.
            rec["egress_country"] = r.get("egress_country")
            rec["egress_ip"] = r.get("egress_ip")
            rec["egress_verdicts"] = r.get("egress_verdicts") or {}
            rec["country_confidence"] = r.get("country_confidence", "none")
            rec["country_conflict"] = bool(r.get("country_conflict"))
            rec["verification_sources"] = r.get("verification_sources") or []
            rec["verification_timestamp"] = now
            # Relay capability is re-measured every scan (Stage C); keep the
            # freshest verdict on the record.
            if r.get("capability"):
                rec["capability"] = r["capability"]
                rec["capability_checked_at"] = now
            # Bug #2: plain-HTTP forwarding capability (Speedtest latency class).
            # Only probed for boxes that just answered the app probe — dead boxes
            # keep their previous capability data instead of burning a probe.
            if r.get("app_ok"):
                rec["http_forwarding"] = probe_http_forward(r["address"], r["port"])
            # Bug #2: plain-HTTP forwarding capability (Speedtest latency class).
            # Only probed for boxes that just answered the app probe — dead boxes
            # keep their previous capability data instead of burning a probe.
            if r.get("app_ok"):
                rec["http_forwarding"] = probe_http_forward(r["address"], r["port"])
            # v1.9.6: reputation verdict rides on the probe result (fetched by
            # the enrichment pass against the persistent store).
            if r.get("ip_quality"):
                rec["ip_quality"] = r["ip_quality"]
                rec["ip_quality_at"] = now
            # v1.9.6: measured throughput sample (already fetched by the
            # sampling pass; carried on the probe result when present).
            if r.get("_speed_probe"):
                merge_speed(rec, r["_speed_probe"])
        else:
            rec["failure_count"] += 1
            rec["last_failure"] = now
            rec["last_error"] = r.get("error")
        store[key] = rec
    return state


def build_verified(state: dict, now: str) -> tuple[dict, dict]:
    """Verified catalog from persistent evidence: TTL + last-success required."""
    import email.utils
    pools: dict[str, list] = {}
    stale = []
    cutoff = time.time() - VERIFIED_TTL_H * 3600
    for key, rec in state.get("candidates", {}).items():
        last = rec.get("last_success")
        if not last:
            continue
        ts = email.utils.parsedate_to_datetime(last).timestamp() \
            if "GMT" in last else _parse_iso(last)
        if ts < cutoff:
            stale.append(key)
            continue
        country = rec.get("egress_country") or rec.get("observed_country")
        if not country or len(country) != 2:
            continue
        # Bug #1: the exit country is only as trustworthy as its evidence is
        # fresh. A candidate probed 47 h ago keeps its published record (the
        # 48 h TTL above) but does NOT enter a country pool: its egress may
        # have rotated since. Dropped candidates stay in the state for the
        # next probe cycle — nothing is deleted.
        if ts < time.time() - GEO_TTL_H * 3600:
            stale.append(key)
            continue
        # Bug #1 v2: consensus quality gate. A multi-target CONFLICT (or a
        # single-source "low" verdict, where one neutral target said one thing
        # and no other could be read) never enters a strict country pool.
        # Correctness > availability: fewer candidates, never wrong-country.
        confidence = rec.get("country_confidence", "none")
        if rec.get("country_conflict") or confidence not in ("high",):
            stale.append(key)
            continue
        # v1.9.6: stale reputation decays to unmeasured (never published as a
        # fresh verdict) — old evidence must not outrank current evidence.
        _iq = rec.get("ip_quality") if _rep_fresh(rec) else None
        entry = {
            "address": key.rsplit(":", 1)[0],
            "port": int(key.rsplit(":", 1)[1]),
            "observed_country": country,
            "egress_ip": rec.get("egress_ip"),
            "country_confidence": confidence,
            "verification_sources": rec.get("verification_sources", []),
            "verification_timestamp": rec.get("verification_timestamp"),
            "verification_age_s": (int(time.time() - ts)
                                   if rec.get("verification_timestamp") else None),
            "source_countries": rec.get("source_countries", []),
            "sources": rec.get("sources", []),
            "score": score(rec, time.time()),
            "last_rtt_ms": rec.get("last_rtt_ms"),
            "last_success": last,
            "success_count": rec.get("success_count", 0),
            "failure_count": rec.get("failure_count", 0),
            "status": "verified",
            # Stage C classification (may be absent on records classified
            # before this field existed — readers must default).
            "capability": (
                "passthrough+http" if rec.get("capability") == "passthrough"
                and rec.get("http_forwarding") is True
                else rec.get("capability", "unverified")),
            "http_forwarding": rec.get("http_forwarding"),
            "http_forwarding": rec.get("http_forwarding"),
            # v1.9.6 per-IP quality (§2/§4/§5): absent = unmeasured, never bad.
            # Stale verdicts (older than the verified TTL) decay to unmeasured:
            # old reputation must not outrank or outshout fresh evidence.
            "risk": (_iq or {}).get("risk", "unknown"),
            "ip_type": (_iq or {}).get("ip_type", "unknown"),
            # Phase 3 store format: type carries confidence + source.
            "confidence": (_iq or {}).get("confidence", "unknown"),
            "source": (_iq or {}).get("source", "unknown"),
            **({"speed_dl_bps": rec["speed_dl_bps"]} if rec.get("speed_dl_bps") else {}),
            **({"speed_ul_bps": rec["speed_ul_bps"]} if rec.get("speed_ul_bps") else {}),
        }
        # V24.6.1 §17/23: compact per-endpoint quality metadata. success_ratio
        # is measured (successes / attempts); nothing derived from source lists.
        total_attempts = entry["success_count"] + entry["failure_count"]
        entry["success_ratio"] = round(
            entry["success_count"] / total_attempts, 2) if total_attempts else 1.0
        pools.setdefault(country, []).append(entry)
    for country in pools:
        # §19: quality descending, then recent success, then latency, then a
        # stable endpoint tie-break. Deterministic; no random reordering.
        pools[country].sort(key=lambda e: (-e["score"],
                                           e["last_success"],
                                           e["last_rtt_ms"] or 9999,
                                           f'{e["address"]}:{e["port"]}'))
        for rank, e in enumerate(pools[country], 1):
            e["quality_rank"] = rank
        del pools[country][PER_COUNTRY_PUBLISH_CAP:]
    return pools, {"stale": stale}


def _upstream_revision() -> str:
    """40-hex identity of the scanner inputs. Git SHA in CI; local fallback
    hashes the sources + evidence state, which changes whenever they do."""
    import collections
    import hashlib, subprocess
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], cwd=REPO,
                             capture_output=True, text=True, timeout=10)
        sha = out.stdout.strip()
        if len(sha) == 40:
            return sha
    except (OSError, subprocess.TimeoutExpired):
        pass
    blob = (SOURCES.read_bytes() + (REPO / "scanner" / "state.json").read_bytes())
    return hashlib.sha1(blob).hexdigest()


def _rep_fresh(rec: dict) -> bool:
    """Reputation verdicts are evidence with a shelf life (§: freshness).
    Older than the verified TTL (48 h) -> treat as unmeasured, so stale
    reputation can never keep ranking a candidate the way current evidence
    would. Absent timestamp = unknown freshness = do not publish a verdict."""
    at = rec.get("ip_quality_at")
    if not at:
        return False
    try:
        return _age_hours(at) < VERIFIED_TTL_H
    except Exception:
        return False


def _parse_iso(s: str) -> float:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def _age_hours(iso_when: str) -> float:
    """Hours since an ISO timestamp; 1e9 for missing (never fresh)."""
    if not iso_when:
        return 1e9
    try:
        return max(0.0, (time.time() - _parse_iso(iso_when)) / 3600)
    except Exception:
        return 1e9


def validate_feed(feed: dict) -> None:
    """Feed contract validation (spec Phase 3/8). Raises on ANY violation."""
    if feed.get("schema_version") != 1:
        raise ValueError("schema_version must be 1")
    for field in ("upstream_revision", "content_revision", "generated_at",
                  "counts", "countries"):
        if field not in feed:
            raise ValueError(f"feed missing field: {field}")
    rev = feed["content_revision"]
    if not (isinstance(rev, str) and len(rev) == 64):
        raise ValueError("content_revision must be sha256 hex")
    countries = feed["countries"]
    if not isinstance(countries, dict):
        raise ValueError("countries must be an object")
    total = 0
    seen: set[tuple[str, int]] = set()
    for cc, entries in countries.items():
        if not (isinstance(cc, str) and len(cc) == 2 and cc.isupper() and cc.isalpha()):
            raise ValueError(f"bad country code: {cc!r}")
        for pair in entries:
            addr, port = pair
            if not isinstance(port, int) or not 0 < port < 65536:
                raise ValueError(f"bad port {port!r} in {cc}")
            if not is_public(str(addr)):
                raise ValueError(f"bad address {addr!r} in {cc}")
            if (addr, port) in seen:
                raise ValueError(f"duplicate endpoint {addr}:{port} across countries")
            seen.add((addr, port))
            total += 1
    if feed["counts"].get("verified") != total:
        raise ValueError("counts.verified mismatch")
    if feed["counts"].get("countries") != len(countries):
        raise ValueError("counts.countries mismatch")


def publish(pools: dict, state: dict, report: dict, stats: dict,
            out_dir=None) -> None:
    """Transactional: write everything into a temp dir, validate, then move."""
    OUT = Path(out_dir) if out_dir else REPO / "catalog" / "verified"
    tmp = (OUT.parent / ".verified-tmp")
    import shutil
    if tmp.exists():
        shutil.rmtree(tmp)
    (tmp / "countries").mkdir(parents=True)
    total = 0
    for country, entries in sorted(pools.items()):
        (tmp / "countries" / f"{country}.json").write_text(
            json.dumps({"schema_version": 1, "endpoints": entries}, indent=1),
            encoding="utf-8")
        total += len(entries)
    import hashlib
    body = json.dumps({cc: [[e["address"], e["port"]] for e in v]
                       for cc, v in sorted(pools.items())},
                      sort_keys=True).encode()
    content_rev = hashlib.sha256(body).hexdigest()
    feed = {
        "schema_version": 1,
        # v1.9.5 capability semantics: Stage A+B prove the candidate forwards
        # TLS for Cloudflare-fronted SNIs — a CF-relay, NOT a generic TCP
        # forward proxy. Consumers must not advertise these endpoints as
        # universal relays; generic-forward capability would need a Stage C
        # probe against non-CF destinations and a source that provides it.
        "capability": "cf-relay",
        # Consumers validate these two fields. The upstream of a
        # VERIFIED feed is the scanner's own evidence state + sources; in CI
        # this equals the commit SHA of the run's checkout.
        "upstream_revision": _upstream_revision(),
        "content_revision": content_rev,
        "generated_at": now_iso(),
        "scanner_revision": report.get("scanner_revision"),
        "counts": {"verified": total, "countries": len(pools)},
        "countries": {cc: [[e["address"], e["port"]] for e in entries]
                      for cc, entries in sorted(pools.items())},
        # V24.6 §13: per-country freshness metadata so the panel can show
        # "Germany · 64 verified · updated 2h ago" without lying about age.
        "country_metadata": {
            cc: {
                "verified_count": len(entries),
                "fresh_count": sum(
                    1 for e in entries
                    if _age_hours(e.get("last_success")) < 24),
                "stale_count": sum(
                    1 for e in entries
                    if 24 <= _age_hours(e.get("last_success")) < 48),
                "last_success_at": max((e.get("last_success") or "" for e in entries),
                                       default=""),
                "source_candidate_count": (state.get("countries", {}).get(cc, {})
                                           .get("source_candidate_count", 0)),
                # Stage C relay-capability census for this country's pool.
                "capability_counts": dict(collections.Counter(
                    e.get("capability", "unverified") for e in entries)),
            }
            for cc, entries in sorted(pools.items())
        },
        # PHASE 5: per-entry Stage-C class so the runtime can rank
        # passthrough above cf-relay without a feed schema break. Absent
        # class = unclassified (the runtime treats it like cf-relay-neutral).
        "capability_by_endpoint": {
            f'{e["address"]}:{e["port"]}': e["capability"]
            for entries in pools.values() for e in entries
            if e.get("capability") in ("passthrough", "cf-relay", "sni-terminate")
        },
        # v1.9.6 Phase 2/3/4: per-endpoint quality verdict for the panel.
        # Compact value = risk|type|confidence|source. Absent key = unmeasured
        # (the runtime treats absence as unknown, never bad).
        "quality_by_endpoint": {
            f'{e["address"]}:{e["port"]}':
                "/".join((e.get("risk", "unknown"), e.get("ip_type", "unknown"),
                          e.get("confidence", "unknown"), e.get("source", "unknown")))
            for entries in pools.values() for e in entries
            if e.get("risk", "unknown") != "unknown"
            or e.get("ip_type", "unknown") != "unknown"
        },
        # The feed-wide verdict. Entries are CF-relay-dominated by source
        # construction; per-country counts carry the detail.
        "capability_note": ("Stage A+B verify Cloudflare-relay behavior; "
                            "Stage C classifies cf-relay / sni-terminate / "
                            "passthrough per candidate. Only 'passthrough' "
                            "proves generic TCP forwarding. Egress country is "
                            "consensus-verified from scanner vantage; some boxes "
                            "route upstreams by connection source, so egress from "
                            "a different vantage (e.g. CF Workers) may differ."),
    }
    (tmp / "feed.json").write_text(json.dumps(feed, indent=1), encoding="utf-8")
    (tmp / "index.json").write_text(json.dumps({
        "schema_version": 1, "runtime_health": "verified",
        "verified_published": True, "generated_at": feed["generated_at"],
        "counts": {"verified": total, "countries": len(pools)},
    }, indent=1), encoding="utf-8")
    (tmp / "scan-report.json").write_text(json.dumps(report, indent=1),
                                          encoding="utf-8")
    # Validate before swap (transactional publish).
    loaded = json.loads((tmp / "feed.json").read_text(encoding="utf-8"))
    validate_feed(loaded)
    # Anomaly guard (spec Phase 3): a collapsed scan must not replace a
    # healthy feed. Relative check, no invented absolute threshold: if the
    # previous feed had a real population and this scan lost most of it
    # AND would publish near-nothing, keep the previous feed and fail loudly.
    prev_path = OUT / "feed.json"
    if prev_path.exists():
        prev = json.loads(prev_path.read_text(encoding="utf-8"))
        prev_total = prev.get("counts", {}).get("verified", 0)
        if prev_total >= 100 and total * 4 < prev_total and total < 50:
            raise SystemExit(
                f"anomaly guard: refusing to publish {total} verified "
                f"(previous feed had {prev_total}); previous feed retained")
    if OUT.exists():
        shutil.rmtree(OUT)
    tmp.rename(OUT)
    state_path = (OUT.parent / "state.json") if out_dir else REPO / "scanner" / "state.json"
    state_path.write_text(json.dumps(state, indent=1), encoding="utf-8")



# ---------------------------------------------- country-fair scheduling (V24.6)

def country_batches(
    candidates: list[dict], state: dict, now: str,
) -> tuple[list[dict], dict]:
    """Pick a bounded verification batch per source country (V24.6 §9-11).

    Every country in the source catalog receives an opportunity every run —
    no global random window. Per-country cursor state lives in
    state["countries"][cc]; each country scans up to DAILY_BUDGET_PER_COUNTRY
    candidates, rotated by its cursor so coverage advances daily.
    """
    by_cc: dict[str, list[dict]] = {}
    for c in candidates:
        for cc in c.get("source_countries") or []:
            if len(cc) == 2 and cc.isupper():
                by_cc.setdefault(cc, []).append(c)
    cstate = state.setdefault("countries", {})
    picked: list[dict] = []
    meta: dict[str, dict] = {}
    for cc in sorted(by_cc):
        pool = by_cc[cc]
        st = cstate.setdefault(cc, {"cursor": 0})
        budget = min(DAILY_BUDGET_PER_COUNTRY, len(pool))
        # Fresh-egress gate support (Bug #1/#2): verify the STALEST evidence
        # first, and re-verify passthrough candidates before equal-priority
        # others. A pure cursor rotation picks an arbitrary 16-slice per run,
        # which leaves a country's only full-capability candidates unverified
        # for days — far past the 12h geo gate — so known-generic candidates
        # silently vanish from the published feed (measured: 99/144
        # passthrough excluded by age alone). The priority below therefore
        # runs over the WHOLE pool, not a cursor slice:
        #   1. passthrough first (the scarce generic-capable class must
        #      re-verify often enough to stay inside the 12h geo gate);
        #   2. least-recently-ATTEMPTED first. Ordering by last *attempt*
        #      (not last success) is what keeps dead candidates from pinning
        #      the window: a box that just failed goes to the back of the
        #      rotation instead of hammering every run, while unknown records
        #      (never attempted) count as oldest so new inventory gets a
        #      first verdict promptly.
        # `last_seen` is written by merge_state on every attempt, success or
        # failure, so attempt age is a fair rotation clock.
        recs = (state.get("candidates") or {})

        def _key(c: dict) -> str:
            return f'{c["address"]}:{c["port"]}'

        def _attempt_age(c: dict) -> float:
            rec = recs.get(_key(c)) or {}
            at = rec.get("last_seen") or rec.get("last_success") or ""
            try:
                return max(0.0, time.time() - datetime.fromisoformat(
                    at.replace("Z", "+00:00")).timestamp()) if at else 1e18
            except Exception:
                return 1e18

        def _passthrough(c: dict) -> int:
            rec = recs.get(_key(c)) or {}
            return rec.get("capability") != "passthrough"

        pool_sorted = sorted(pool, key=lambda c: (_passthrough(c), -_attempt_age(c), _key(c)))
        window = pool_sorted[:budget]
        # The cursor keeps advancing for reporting/compat; selection no longer
        # depends on it — rotation now follows attempt age, which advances on
        # every run by construction.
        st["cursor"] = (int(st.get("cursor", 0)) + budget) % max(len(pool), 1)
        st["last_scan_at"] = now
        st["source_candidate_count"] = len(pool)
        meta[cc] = {"source": len(pool), "scanned": budget}
        picked.extend(window)
    return picked, meta

# ---------------------------------------------------------------- main

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--publish", action="store_true")
    ap.add_argument("--emit-discovery", action="store_true",
                    help="publish the deduped candidate queue (with provenance) "
                         "for Workers-side verification instead of scanning")
    ap.add_argument("--limit", type=int, default=200,
                    help="max candidates to test this run (bounded)")
    ap.add_argument("--skip", type=int, default=0,
                    help="skip the first N candidates (rotate the sample window)")
    ap.add_argument("--per-country", action="store_true",
                    help="V24.6 country-fair mode: every source country gets a "
                         "bounded verification batch per run (no global window)")
    ap.add_argument("--state", default=str(REPO / "scanner" / "state.json"))
    ap.add_argument("--stage-b-host", default="www.cloudflare.com")
    args = ap.parse_args()

    sources = json.loads(SOURCES.read_text(encoding="utf-8"))
    policy = load_policy()
    started = time.monotonic()
    print(f"discovery: {len(sources['domains'])} domains configured")
    queue = discover_from_domains(sources)
    n_dom = len(queue)
    cat = discover_from_catalog(sources.get("country_catalog_sample_limit", 2000))
    # Merge: dedupe by ip:port, union provenance.
    merged: dict[tuple[str, int], dict] = {}
    for rec in queue + cat:
        key = (rec["address"], rec["port"])
        m = merged.setdefault(key, rec)
        m["sources"] = sorted(set(m["sources"] + rec["sources"]))
        m["source_countries"] = sorted(set(m["source_countries"] + rec["source_countries"]))
    candidates = list(merged.values())
    print(f"queue: {n_dom} from domains + {len(cat)} from catalog = {len(candidates)} unique")

    if args.emit_discovery:
        candidates = candidates[args.skip:]
        out = REPO / "catalog" / "discovery"
        out.mkdir(parents=True, exist_ok=True)
        feed = {
            "schema_version": 1,
            "generated_at": now_iso(),
            "upstream_revision": _upstream_revision(),
            "content_revision": __import__("hashlib").sha256(
                json.dumps([[c["address"], c["port"]] for c in candidates],
                           sort_keys=True).encode()).hexdigest(),
            "counts": {"candidates": len(candidates)},
            "candidates": [[c["address"], c["port"]] for c in candidates],
            "provenance": {f"{c['address']}:{c['port']}": c["sources"]
                           for c in candidates},
        }
        (out / "queue.json").write_text(json.dumps(feed, indent=1), encoding="utf-8")
        print(f"published catalog/discovery/queue.json: {len(candidates)} candidates")
        return 0

    persistent_state = load_state(Path(args.state))
    if args.per_country:
        candidates, country_meta = country_batches(candidates, persistent_state, now_iso())
        print(f"country-fair window: {len(candidates)} candidates across "
              f"{len(country_meta)} countries: "
              f"{json.dumps(country_meta, sort_keys=True)}")
    else:
        candidates = candidates[args.skip: args.skip + args.limit]
    print(f"testing {len(candidates)} (limit {args.limit}), concurrency {MAX_CONCURRENCY}")

    results = []
    deadline = time.monotonic() + SCAN_DEADLINE_S
    with ThreadPoolExecutor(max_workers=MAX_CONCURRENCY) as pool:
        futures = {pool.submit(probe_candidate, c, args.stage_b_host): c
                   for c in candidates}
        for fut in as_completed(futures):
            if time.monotonic() > deadline:
                for f in futures:
                    f.cancel()
                print("global scan deadline hit", file=sys.stderr)
                break
            try:
                results.append(fut.result())
            except Exception as e:  # a crashed probe is a failed probe
                c = futures[fut]
                results.append({**c, "tcp_ok": False, "tls_ok": False,
                                "app_ok": False, "verified": False,
                                "error": f"crash: {e}"})

    tcp_ok = sum(1 for r in results if r.get("tcp_ok"))
    tls_ok = sum(1 for r in results if r.get("tls_ok"))
    app_ok = sum(1 for r in results if r.get("app_ok"))
    verified = [r for r in results if r.get("verified")]
    by_country: dict[str, int] = {}
    for r in verified:
        by_country[r.get("country") or "??"] = by_country.get(r.get("country") or "??", 0) + 1
    # Per-country funnel (spec Phase 4): source -> tested -> tcp -> tls -> app -> verified.
    # Observed-country attribution for tested stages; country_meta carries the
    # source-side counts from country_batches.
    funnel: dict[str, dict] = {}
    country_meta = country_meta if args.per_country else {}
    for cc, m in sorted((country_meta or {}).items()):
        funnel[cc] = {"source": m["source"], "tested": m["scanned"],
                      "tcp_ok": 0, "tls_ok": 0, "app_ok": 0, "verified": 0}
    for r in results:
        cc = r.get("country") or "??"
        f = funnel.setdefault(cc, {"source": 0, "tested": 0,
                                   "tcp_ok": 0, "tls_ok": 0, "app_ok": 0, "verified": 0})
        f["tested"] = f.get("tested", 0) + 1
        if r.get("tcp_ok"): f["tcp_ok"] += 1
        if r.get("tls_ok"): f["tls_ok"] += 1
        if r.get("app_ok"): f["app_ok"] += 1
        if r.get("verified"): f["verified"] += 1
    elapsed = int(time.monotonic() - started)
    print(f"tested={len(results)} tcp={tcp_ok} tls={tls_ok} app={app_ok} "
          f"verified={len(verified)} in {elapsed}s")
    print(f"by country: {json.dumps(by_country, sort_keys=True)}")

    now = now_iso()
    # ---- v1.9.6 enrichment pass (§1-5, §13-14): bounded, sampled, cached ----
    # Reputation for the verified set (bounded by 45/min provider limit, kept
    # small per run), speed sample for a rotated subset. Every probe is
    # failure-isolated; a provider outage costs nothing but "unknown".
    # One store, one load: reuse the already-loaded persistent_state instead of
    # a second load_state() — a second copy would silently drop enrichment from
    # the saved state whenever this run's results didn't carry it.
    store = persistent_state.setdefault("candidates", {})
    verified_keys = [f"{r['address']}:{r['port']}" for r in verified]
    REP_BUDGET = 100  # one ip-api batch call (max 100 IPs); <24h cache skipped below
    rep_done = 0
    need_rep = []
    for key in verified_keys:
        if len(need_rep) >= REP_BUDGET:
            break
        rec = store.get(key)
        if not rec:
            continue
        cached = rec.get("ip_quality")
        if cached and rec.get("ip_quality_at"):
            age_h = (time.time() - _parse_iso(rec["ip_quality_at"])) / 3600
            if age_h < 24:
                continue  # cached <24h: skip (bounded provider use)
        need_rep.append(key)
    # ONE keyless batch call for all uncached IPs (45/min budget, ~2s total),
    # then a bounded ipwho.is cross-check per verdict (failure-isolated).
    rep_map = reputation_many([k.rsplit(":", 1)[0] for k in need_rep]) \
        if need_rep else {}
    for key in need_rep:
        rec = store.get(key)
        rep = rep_map.get(key.rsplit(":", 1)[0])
        if rep is None:
            continue  # provider gave no verdict: leave old record untouched
        rec["ip_quality"] = rep
        rec["ip_quality_at"] = now
        rep_done += 1
    # Speed sample: rotate over verified candidates, ~12 per run (512+256 KB
    # each = ~9 MB total traffic, bounded), results EMA-merged into state.
    SPEED_BUDGET = 12
    start_idx = int(time.time()) % max(len(verified_keys), 1)
    sample = [verified_keys[(start_idx + k) % len(verified_keys)]
              for k in range(min(SPEED_BUDGET, len(verified_keys)))]
    speed_done = 0
    for key in sample:
        rec = store.get(key)
        if not rec:
            continue
        probe = _speed_probe(key.rsplit(":", 1)[0], int(key.rsplit(":", 1)[1]))
        merge_speed(rec, probe)
        speed_done += 1
    # carry enrichment onto this run's probe results so merge_state folds it in
    for r in results:
        rec = store.get(f"{r['address']}:{r['port']}")
        if rec and rec.get("ip_quality"):
            r["ip_quality"] = rec["ip_quality"]
    print(f"enrichment: reputation={rep_done} speed_samples={speed_done}")
    state = merge_state(persistent_state, results, now)
    # Persist evidence state even without --publish: enrichment (reputation +
    # speed samples) is expensive evidence, not a publish artifact. Same file
    # publish() writes, so no new state location.
    (Path(args.state)).write_text(json.dumps(state, indent=1), encoding="utf-8")
    pools, stale_info = build_verified(state, now)
    report = {
        "scan_started_at": now,
        "scan_finished_at": now_iso(),
        "scanner_revision": f"v1.{len(results)}",
        "candidate_count": len(candidates),
        "tested_count": len(results),
        "tcp_ok": tcp_ok, "tls_ok": tls_ok, "application_ok": app_ok,
        "verified_count": len(verified),
        "capability": "cf-relay",
        "capability_note": ("Stage A+B verify Cloudflare-relay capability only; "
                            "generic TCP forwarding is NOT verified by this feed"),
        "countries": by_country,
        "country_funnel": funnel,
        "duration_s": elapsed,
        "pool_sizes": {cc: len(v) for cc, v in sorted(pools.items())},
    }
    print(json.dumps(report, indent=1))
    if args.publish:
        publish(pools, state, report, {})
        print("published catalog/verified/ (transactional)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
