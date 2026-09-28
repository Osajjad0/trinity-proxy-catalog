"""Per-IP quality signals for the scanner (v1.9.6 §1-5, §13, §14).

One module, stdlib only. Three signal families, all bounded and failure-isolated:

  reputation(ip)  -> {risk: low|medium|high|unknown, ip_type, confidence}
                     ip-api.com (keyless, 45 req/min) + RDAP (keyless, no limit
                     concern at our volume). Unknown provider answers never
                     block the scan (§25): every adapter swallows its own
                     failures and returns "unknown".
  speed_sample()  -> bounded download/upload throughput THROUGH a verified
                     candidate (CF-relay path: SNI/Host = speed.cloudflare.com),
                     sampled per run, rotated across scans (§13).

Results are cached in the scanner's persistent state under
candidates[key]["ip_quality"] so one successful lookup is never repeated.
"""
from __future__ import annotations

import json
import socket
import ssl
import time
import urllib.error
import urllib.request

# ---- provider bounds (§3: rate limits, timeout, failure isolation) --------
IPAPI_RPS_MIN = 1.6          # one request per 1.6s: 45/min limit with margin
PROVIDER_TIMEOUT_S = 8
SPEED_DL_BYTES = 512_000     # bounded: 512 KB download sample
SPEED_UL_BYTES = 256_000     # bounded: 256 KB upload sample
SPEED_TIMEOUT_S = 20
SNI = "speed.cloudflare.com"  # same relay path the runtime uses


_last_ipapi_ts = 0.0


def _http_json(url: str, timeout: int = PROVIDER_TIMEOUT_S) -> dict | None:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "proxy-catalog-scan/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, OSError, ValueError):
        return None


# ---- reputation -----------------------------------------------------------

def _parse_ipwho(d: dict) -> dict | None:
    """ipwho.is (keyless) -> independent ASN/org cross-check signal."""
    if not d or not d.get("success"):
        return None
    conn = d.get("connection") or {}
    return {"as": f'AS{conn["asn"]} {conn.get("isp") or conn.get("org") or ""}'.strip()
            if conn.get("asn") else None,
            "provider": conn.get("isp") or conn.get("org")}


def reputation(ip: str, *, allow_network: bool = True) -> dict:
    """Single-IP convenience wrapper around reputation_many (§3 adapter shape)."""
    out = reputation_many([ip], allow_network=allow_network)
    return out.get(ip) or {"risk": "unknown", "ip_type": "unknown",
                           "confidence": "unknown", "as": None, "provider": None}


def reputation_many(ips: list[str], *, allow_network: bool = True) -> dict[str, dict]:
    """Verdicts for up to 100 IPs in ONE keyless batch call (ip-api.com /batch),
    cross-checked against ipwho.is (independent ASN/org). Never raises; an IP
    with no answer stays "unknown" (§25: unknown != bad). Rate limit: the batch
    counts as one request of the 45/min budget; ipwho is a second bounded call.

    risk semantics (§4): proxy=True -> high; hosting=True -> datacenter type
    but NOT a risk penalty (§5: a candidate can be high quality without being
    residential). confidence: high = two providers agree on the operator;
    medium = single-source or mismatch; unknown = no provider answered.
    """
    unknown = {"risk": "unknown", "ip_type": "unknown",
               "confidence": "unknown", "as": None, "provider": None}
    if not allow_network or not ips:
        return {}
    out: dict[str, dict] = {}
    global _last_ipapi_ts
    wait = IPAPI_RPS_MIN - (time.monotonic() - _last_ipapi_ts)
    if wait > 0:
        time.sleep(wait)
    _last_ipapi_ts = time.monotonic()
    req = urllib.request.Request(
        "http://ip-api.com/batch?fields=status,query,as,isp,org,proxy,hosting",
        data=json.dumps(ips[:100]).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "proxy-catalog-scan/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=PROVIDER_TIMEOUT_S) as resp:
            rows = json.loads(resp.read().decode("utf-8", "replace"))
    except (urllib.error.URLError, OSError, ValueError):
        rows = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict) or row.get("status") != "success":
            continue
        ip = row.get("query")
        if not ip:
            continue
        proxy = bool(row.get("proxy"))
        hosting = bool(row.get("hosting"))
        rec = {"as": row.get("as"), "provider": row.get("isp") or row.get("org"),
               "confidence": "medium", "source": "ip-api"}
        if proxy:
            rec["risk"], rec["ip_type"] = "high", "vpn/proxy"
        elif hosting:
            rec["risk"], rec["ip_type"] = "low", "datacenter"
        else:
            rec["risk"], rec["ip_type"] = "low", "isp"
        out[ip] = rec
    # Cross-check (Phase 3): independent second source on ASN/org. One bounded
    # call for the whole batch's first verified IP is pointless — probe each
    # only when a verdict exists and confidence could still be upgraded.
    for ip, rec in list(out.items()):
        who = _parse_ipwho(_http_json(f"https://ipwho.is/{ip}"))
        if who is None:
            continue  # provider down: verdict stands at medium (failure isolation)
        same = (rec.get("as") or "").split()[0] == (who.get("as") or "").split()[0] \
            if (rec.get("as") and who.get("as")) else \
            (rec.get("provider") or "").lower() == (who.get("provider") or "").lower()
        rec["confidence"] = "high" if same else "medium"
        rec["source"] = "ip-api+ipwho" if same else "ip-api"
    return out


def reputation_penalty(rep: dict) -> int:
    """Score contribution (§4: unknown must not mean bad)."""
    risk = rep.get("risk")
    if risk == "high":
        return -25
    if risk == "low":
        return 5
    return 0  # unknown: no bonus, no penalty


# ---- bounded speed sample (§13/§14) ---------------------------------------

def _speed_probe(address: str, port: int) -> dict:
    """Download+upload sample through the candidate, CF-relay path. Bounded."""
    out = {"dl_bps": None, "ul_bps": None, "error": None}
    try:
        raw = socket.create_connection((address, port), timeout=8)
        ctx = ssl.create_default_context()
        sock = ctx.wrap_socket(raw, server_hostname=SNI)
    except (OSError, ssl.SSLError) as e:
        out["error"] = f"connect: {e}"
        return out
    try:
        # download
        req = (f"GET /__down?bytes={SPEED_DL_BYTES} HTTP/1.1\r\n"
               f"Host: {SNI}\r\nUser-Agent: proxy-catalog-scan/1.0\r\n"
               f"Accept: */*\r\nConnection: close\r\n\r\n")
        t0 = time.monotonic()
        sock.sendall(req.encode())
        got = 0
        while time.monotonic() - t0 < SPEED_TIMEOUT_S:
            part = sock.recv(65_536)
            if not part:
                break
            got += len(part)
        dt = time.monotonic() - t0
        if got >= SPEED_DL_BYTES // 2:
            out["dl_bps"] = int(got / dt)
        else:
            out["error"] = f"dl short: {got}"
            return out
        # upload (same connection would be closed by Connection: close; new one)
        sock.close()
        raw = socket.create_connection((address, port), timeout=8)
        sock = ctx.wrap_socket(raw, server_hostname=SNI)
        body = b"x" * SPEED_UL_BYTES
        req = (f"POST /__up HTTP/1.1\r\nHost: {SNI}\r\n"
               f"User-Agent: proxy-catalog-scan/1.0\r\nAccept: */*\r\n"
               f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n")
        t0 = time.monotonic()
        sock.sendall(req.encode() + body)
        resp = b""
        while time.monotonic() - t0 < SPEED_TIMEOUT_S:
            part = sock.recv(16_384)
            if not part:
                break
            resp += part
        dt = time.monotonic() - t0
        status = resp.split(b" ", 2)[1] if b" " in resp else b""
        if status.startswith(b"2"):
            out["ul_bps"] = int(len(body) / dt)
        else:
            out["error"] = f"up status {status!r}"
    except (OSError, ssl.SSLError) as e:
        out["error"] = f"speed: {e}"
    finally:
        try:
            sock.close()
        except OSError:
            pass
        try:
            raw.close()
        except OSError:
            pass
    return out


def speed_bonus(dl_bps: int | None, ul_bps: int | None) -> int:
    """Throughput -> bounded score contribution. 1 MB/s dl == full 10 points;
    upload counts at half weight (§14 both matter, download dominates)."""
    s = 0
    if dl_bps:
        s += min(10, int(dl_bps / 100_000))
    if ul_bps:
        s += min(5, int(ul_bps / 200_000))
    return s


def merge_speed(rec: dict, probe: dict) -> None:
    """Fold a speed sample into a persistent candidate record (EMA, evidence
    never deleted). Missing fields leave the previous value untouched."""
    if probe.get("dl_bps"):
        prev = rec.get("speed_dl_bps")
        rec["speed_dl_bps"] = int(probe["dl_bps"]) if prev is None else int(0.5 * prev + 0.5 * probe["dl_bps"])
    if probe.get("ul_bps"):
        prev = rec.get("speed_ul_bps")
        rec["speed_ul_bps"] = int(probe["ul_bps"]) if prev is None else int(0.5 * prev + 0.5 * probe["ul_bps"])
    if probe.get("error"):
        rec["last_speed_error"] = probe["error"]
    rec["last_speed_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
