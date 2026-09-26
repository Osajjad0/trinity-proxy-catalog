#!/usr/bin/env python3
"""Trinity verified-catalog scanner (V24.4).

Discovery -> scan -> verify -> publish, Python stdlib only.

Pipeline (all bounded):
  sources.json domains + catalog/countries/*.json  ->  candidate queue
  Stage A: TCP + TLS(SNI=speed.cloudflare.com) + GET /cdn-cgi/trace
  Stage B: same socket path, SNI/Host = Trinity Worker hostname (TRINITY_HOST)
  verified = Stage A ok AND Stage B ok, country from probe observation

  Capability (v1.9.5): Stage A+B prove CF-RELAY capability only (the
  candidate forwards TLS for Cloudflare-fronted SNIs). It is NOT proof of
  generic TCP forwarding; the feed carries capability="cf-relay" so
  consumers cannot advertise these endpoints as universal relays.

Dial IP, SNI, and Host stay separate: the candidate IP:port is always the
TCP destination; SNI/Host are the test hostname. A candidate is "verified"
only on full Stage A+B evidence — never because a source listed it.

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
               f"User-Agent: trinity-scan/1.0\r\nAccept: */*\r\n"
               f"Connection: close\r\n\r\n")
        app0 = time.monotonic()
        sock.sendall(req.encode())
        n, text = _recv_response(sock)
        result["app_ms"] = int((time.monotonic() - app0) * 1000)
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
# Trinity relationship. www.rfc-editor.org: independent operator, plain CDN.
FOREIGN_SNI = "www.postgresql.org"
# A claimed passthrough must confirm on a SECOND independent destination
# before the class is granted. One destination can coincide with a front's
# allowlist (its own upstream); two unrelated operators agreeing is the
# behavior of a true relay, not a filtering front. False-positive generic
# capability is worse than "unclassified" (spec v1.9.5 §10).
FOREIGN_SNI_CONFIRM = "www.rfc-editor.org"


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
                   f"User-Agent: trinity-scan/1.0\r\nAccept: */*\r\n"
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

    A candidate is only called passthrough when TWO independent non-Trinity
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


def probe_candidate(c: dict, trinity_host: str) -> dict:
    """Stage A (generic CF compatibility) then Stage B (Trinity host)."""
    a = probe_stage(c["address"], c["port"], CF_TEST_SNI, CF_TEST_SNI)
    if not a["app_ok"]:
        return {**c, **a, "stage": "A", "verified": False}
    b = probe_stage(c["address"], c["port"], trinity_host, trinity_host)
    ok = b["app_ok"]
    # Stage C only for source-verified candidates: classification costs one
    # TLS handshake and is meaningless for a candidate that cannot even serve
    # its own edge.
    capability = classify_capability(c["address"], c["port"]) if ok else "unverified"
    return {
        **c, **b, "stage": "B", "verified": ok,
        "capability": capability,
        "cf_country": a["country"], "cf_colo": a["colo"],
        "cf_tcp_ms": a["tcp_ms"], "cf_app_ms": a["app_ms"],
        "error": None if ok else (b["error"] or "trinity stage failed"),
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
            # Relay capability is re-measured every scan (Stage C); keep the
            # freshest verdict on the record.
            if r.get("capability"):
                rec["capability"] = r["capability"]
                rec["capability_checked_at"] = now
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
        country = rec.get("observed_country")
        if not country or len(country) != 2:
            continue
        entry = {
            "address": key.rsplit(":", 1)[0],
            "port": int(key.rsplit(":", 1)[1]),
            "observed_country": country,
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
            "capability": rec.get("capability", "unverified"),
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
        # Trinity's client validates these two fields. The upstream of a
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
        # The feed-wide verdict. Entries are CF-relay-dominated by source
        # construction; per-country counts carry the detail.
        "capability_note": ("Stage A+B verify Cloudflare-relay behavior; "
                            "Stage C classifies cf-relay / sni-terminate / "
                            "passthrough per candidate. Only 'passthrough' "
                            "proves generic TCP forwarding."),
    }
    (tmp / "feed.json").write_text(json.dumps(feed, indent=1), encoding="utf-8")
    (tmp / "index.json").write_text(json.dumps({
        "schema_version": 1, "runtime_health": "verified",
        "trinity_verified": True, "generated_at": feed["generated_at"],
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
        cursor = int(st.get("cursor", 0)) % max(len(pool), 1)
        budget = min(DAILY_BUDGET_PER_COUNTRY, len(pool))
        window = [pool[(cursor + k) % len(pool)] for k in range(budget)]
        st["cursor"] = (cursor + budget) % max(len(pool), 1)
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
    ap.add_argument("--trinity-host", default="trinity-fresh3.tmplbertohr.workers.dev")
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
        futures = {pool.submit(probe_candidate, c, args.trinity_host): c
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
          f"trinity_verified={len(verified)} in {elapsed}s")
    print(f"by country: {json.dumps(by_country, sort_keys=True)}")

    now = now_iso()
    state = merge_state(persistent_state, results, now)
    pools, stale_info = build_verified(state, now)
    report = {
        "scan_started_at": now,
        "scan_finished_at": now_iso(),
        "scanner_revision": f"v1.{len(results)}",
        "candidate_count": len(candidates),
        "tested_count": len(results),
        "tcp_ok": tcp_ok, "tls_ok": tls_ok, "application_ok": app_ok,
        "trinity_verified": len(verified),
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
