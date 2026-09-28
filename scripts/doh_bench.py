#!/usr/bin/env python3
"""DoH resolver benchmark (v1.9.6 §15/§16). Stdlib only. Repeatable.

Measures per resolver: query latency (median of N), success rate, timeout rate,
and ad/tracker blocking EFFECTIVENESS — a resolver only counts as ad-blocking
when it actually refuses the configured test domains (NXDOMAIN/refused).

Usage: python scripts/doh_bench.py [--runs 3] [--json out.json]
"""
from __future__ import annotations
import argparse, base64, json, statistics, time, urllib.request, urllib.error

RESOLVERS = {
    # name: DoH endpoint (RFC 8484 GET with ?dns= base64url)
    "adguard":          "https://dns.adguard-dns.com/dns-query",
    "adguard-unfiltered":"https://unfiltered.adguard-dns.com/dns-query",
    "controld-p2":      "https://freedns.controld.com/p2",
    "cloudflare":       "https://cloudflare-dns.com/dns-query",
    "quad9":            "https://dns.quad9.net/dns-query",
}
# representative set (§16): normal / CDN / media / app / ads / trackers
DOMAINS = {
    "normal": ["example.com", "www.wikipedia.org", "github.com"],
    "cdn":    ["ajax.googleapis.com", "cdn.jsdelivr.net"],
    "media":  ["www.youtube.com", "i.ytimg.com"],
    "app":    ["api.github.com", "registry.npmjs.org"],
    "ad":     ["doubleclick.net", "googleadservices.com", "adnxs.com"],
    "tracker":["google-analytics.com", "scorecardresearch.com"],
}
ADS = DOMAINS["ad"] + DOMAINS["tracker"]

def q(name: str, endpoint: str, timeout: float = 4.0) -> tuple[str, float]:
    """RFC 8484 GET. Returns (status, seconds).
    status: ok|nxdomain|blocked|empty|error. `blocked` = NXDOMAIN or an A
    answer of 0.0.0.0 — the two ways ad-blocking resolvers refuse a domain."""
    # build minimal DNS query packet: header + question
    import struct
    tid = 0
    flags = 0x0100
    header = struct.pack(">HHHHHH", tid, flags, 1, 0, 0, 0)
    qname = b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"
    pkt = header + qname + struct.pack(">HH", 1, 1)  # A, IN
    b64 = base64.urlsafe_b64encode(pkt).decode().rstrip("=")
    url = f"{endpoint}?dns={b64}"
    t0 = time.monotonic()
    try:
        req = urllib.request.Request(url, headers={"accept": "application/dns-message"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
        dt = time.monotonic() - t0
        if len(body) < 12:
            return "error", dt
        rcode = body[3] & 0x0F
        ancount = struct.unpack(">H", body[6:8])[0]
        if rcode == 3:
            return "nxdomain", dt
        if rcode == 0 and ancount > 0:
            # parse A answers; 0.0.0.0 = sinkholed (blocked)
            i = 12
            while body[i] != 0:
                i += body[i] + 1
            i += 5
            while i < len(body):
                if body[i] & 0xC0 == 0xC0:
                    i += 2
                else:
                    while body[i] != 0:
                        i += body[i] + 1
                    i += 1
                rtype, _, _, rdlen = struct.unpack(">HHIH", body[i:i + 10])
                i += 10
                rd = body[i:i + rdlen]
                i += rdlen
                if rtype == 1 and rd == b"\x00\x00\x00\x00":
                    return "blocked", dt
            return "ok", dt
        return "empty", dt
    except (urllib.error.URLError, OSError, ValueError):
        return "error", time.monotonic() - t0

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--json", dest="json_out", default=None)
    args = ap.parse_args()
    results = {}
    for name, endpoint in RESOLVERS.items():
        lat, ok, err, blocked = [], 0, 0, []
        for run in range(args.runs):
            for group, names in DOMAINS.items():
                for d in names:
                    status, dt = q(d, endpoint)
                    if group in ("ad", "tracker"):
                        if status in ("nxdomain", "blocked"):
                            blocked.append(d)
                        lat.append(dt)  # blocked queries still measure latency
                    if status in ("ok", "empty", "nxdomain", "blocked"):
                        ok += 1  # blocked = resolver refused an ad domain: still success
                        if group not in ("ad", "tracker"):
                            lat.append(dt)
                    else:
                        err += 1
                    time.sleep(0.05)
        total_q = args.runs * sum(len(v) for v in DOMAINS.values())
        results[name] = {
            "success_rate": round(ok / total_q, 3),
            "error_rate": round(err / total_q, 3),
            "median_latency_ms": int(statistics.median(lat) * 1000) if lat else None,
            "blocked_ads": sorted(set(blocked)),
            "ad_block_effective": len(set(blocked)) >= len(ADS) - 1,  # allow 1 miss
            "queries": total_q,
        }
        print(name, json.dumps(results[name]))
    print("\nVerdict: ad-blocking =",
          [n for n, r in results.items() if r["ad_block_effective"]])
    if args.json_out:
        import pathlib
        pathlib.Path(args.json_out).write_text(json.dumps({
            # vantage matters: an Iran-vantage run measures reachability+filtering
            # together; a GitHub-runner run measures filtering only. Never mix.
            "measured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "note": "vantage-dependent: run location determines what this proves",
            "resolvers": results,
        }, indent=1))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
