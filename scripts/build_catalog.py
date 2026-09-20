"""Public-source candidate catalog. No endpoint connections or DNS lookups."""
import ipaddress
import re
import csv
import datetime as dt
import hashlib
import io
import json
from urllib.parse import unquote

COUNTRIES = set('AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW'.split())
BASE = 'https://raw.githubusercontent.com/NiREvil/vless/'
DAILY = 'sub/ProxyIP-Daily.md'
CSV = 'sub/country_proxies/02_proxies.csv'
LEGACY = 'edge/assets/p-legacies.csv'
UPDATED = 'sub/country_proxies/01_last_update.txt'
ALL = 'sub/country_proxies/03_proxies.txt'
REQUIRED = {DAILY, CSV, LEGACY, UPDATED, ALL}


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2) + '\n').encode('utf-8')


def digest(value):
    return hashlib.sha256(value).hexdigest()


def daily_timestamp(text):
    match = re.search(r'Last_Update-(.*?)-[A-Fa-f0-9]{6}', text)
    if not match:
        raise ValueError('daily generation timestamp missing')
    raw = unquote(match[1])
    parsed = dt.datetime.strptime(raw, '%a, %d %b %Y %H:%M (UTC+3:30)')
    return raw, (parsed - dt.timedelta(hours=3, minutes=30)).isoformat(timespec='seconds') + 'Z'


def build(files, revision, config):
    if not re.fullmatch('[0-9a-f]{40}', revision) or not REQUIRED <= files.keys():
        raise ValueError('incomplete immutable snapshot')
    text = {p: b.decode('utf-8-sig', errors='strict') for p, b in files.items()}
    if any(not t.strip() for t in text.values()):
        raise ValueError('empty required source')
    updated = text[UPDATED].splitlines()[0]
    if not updated.startswith('Last updated: '):
        raise ValueError('country update marker missing')
    daily_raw, daily_at = daily_timestamp(text[DAILY])
    sources = {}
    for path in sorted(files):
        sources[path] = {
            'url': BASE + revision + '/' + path, 'revision': revision,
            'sha256': digest(files[path]), 'bytes': len(files[path]),
            'checked_at': None, 'source_updated_at': None,
            'source_updated_raw': updated if path.startswith('sub/country_proxies/') else None,
            'feed_generated_at': daily_at if path == DAILY else None,
            'feed_generated_raw': daily_raw if path == DAILY else None,
            'method': 'source-reported scanner results; unauthenticated geo metadata' if path == DAILY else 'candidate inventory; generator/check time unknown',
        }
    rows, rejected, unresolved, first = {}, [], [], {}

    def evidence(path, line, original, label=None, **extra):
        return dict(source_path=path, line=line, original=original,
                    source_country_label=label, checked_at=None, **extra)

    def reject(ev, reason):
        rejected.append(dict(ev, reason=reason, runtime_health='unknown', trinity_verified=False))

    def add(address, port, label, ev):
        try:
            host, port, kind = endpoint(address, port)
        except ValueError as error:
            reject(ev, str(error))
            return None
        key = ('[' + host + ']' if kind == 'IPV6' else host) + ':' + str(port)
        if key not in rows:
            rows[key] = dict(endpoint=key, address=host, port=port, kind=kind,
                             country_claims=[], unrecognized_labels=[], evidence=[],
                             runtime_health='unknown', checked_at=None, trinity_verified=False)
        row = rows[key]
        if label:
            field = 'country_claims' if label in COUNTRIES else 'unrecognized_labels'
            if label not in row[field]:
                row[field].append(label)
        row['evidence'].append(ev)
        return host, port

    for path, label_column in [(CSV, 3), (LEGACY, 2)]:
        lines = text[path].splitlines()
        header = [x.strip() for x in next(csv.reader([lines[0]]))]
        if header[:2] != ['IP Address', 'Port'] or len(header) <= label_column:
            raise ValueError('unexpected CSV schema: ' + path)
        for line_no, original in enumerate(lines[1:], 2):
            if not original.strip() or original.startswith('#'):
                continue
            parts = [x.strip() for x in next(csv.reader([original], strict=True))]
            ev = evidence(path, line_no, original)
            # Reserve first-seen IP even for malformed rows: never substitute a later port.
            new_scanner_input = False
            if len(parts) >= 2:
                try:
                    scanner_host, _, scanner_kind = endpoint(parts[0], '443')
                    if scanner_kind != 'HOST' and (path == CSV or parts[1] == '443'):
                        new_scanner_input = scanner_host not in first
                        first.setdefault(scanner_host, None)
                except ValueError:
                    pass
            if len(parts) != len(header):
                reject(ev, 'CSV column count mismatch')
                continue
            label = parts[label_column]
            ev['source_country_label'] = label
            result = add(parts[0], parts[1], label, ev)
            # Scanner dedup is IP-only: primary CSV first; legacy only port 443.
            if result and new_scanner_input:
                first[result[0]] = dict(port=result[1], source_path=path, line=line_no)
    country_files = sorted(p for p in files if re.fullmatch(r'sub/country_proxies/[A-Z0-9]{2}\.txt', p))
    if not country_files:
        raise ValueError('no country files')
    for path in [ALL] + country_files:
        label = path.rsplit('/', 1)[1][:-4] if path != ALL else None
        for line_no, original in enumerate(text[path].splitlines(), 1):
            if not original.strip():
                continue
            ev = evidence(path, line_no, original, label)
            parts = original.split()
            if len(parts) != 2:
                reject(ev, 'expected address and port')
            else:
                add(*parts, label, ev)
    label, section, daily_rows = None, None, 0
    for line_no, original in enumerate(text[DAILY].splitlines(), 1):
        if original.startswith('## '):
            section, label = original[3:], None
            flag = re.search('[\U0001f1e6-\U0001f1ff]{2}', section)
            if flag:
                label = ''.join(chr(ord(c) - 0x1f1e6 + ord('A')) for c in flag[0])
        if not original.startswith('|') or '<code>' not in original:
            continue
        daily_rows += 1
        match = re.search(r'<pre><code>([^<]+)</code></pre>', original)
        ev = evidence(DAILY, line_no, original, label, section=section, source_reported_check=True)
        if not match:
            reject(ev, 'unrecognized daily row')
            continue
        address = match[1]
        try:
            host, _, kind = endpoint(address, '443')
            if kind == 'HOST':
                raise ValueError('daily row must be an IP literal')
        except ValueError as error:
            reject(ev, str(error))
            continue
        mapping = first.get(host)
        if not mapping:
            unresolved.append(dict(ev, address=host, port=None, reason='no public first-seen scanner input port; secret/DNS inputs not consulted', runtime_health='unknown', trinity_verified=False))
        else:
            ev['port_resolution'] = mapping
            add(address, str(mapping['port']), label, ev)
    if not daily_rows:
        raise ValueError('daily table missing')
    for item in config['dynamic_hosts']:
        ev = evidence('sources.json', None, item['host'], port_origin='explicit configured default; not an upstream observation', dynamic_dns=True)
        if endpoint(item['host'], str(item['configured_port']))[2] != 'HOST':
            raise ValueError('dynamic candidate must be a hostname')
        add(item['host'], str(item['configured_port']), None, ev)
    sources['sources.json'] = dict(url=None, revision=None, sha256=digest(encoded(config)), bytes=len(encoded(config)), checked_at=None, source_updated_at=None, source_updated_raw=None, feed_generated_at=None, feed_generated_raw=None, method='user-requested hostname candidates, configured ports')
    docs = {name: {'schema_version': 1, 'endpoints': []} for name in ['conflicts.json', 'unassigned.json']}
    for key, row in sorted(rows.items()):
        row['country_claims'].sort()
        row['unrecognized_labels'].sort()
        # Unknown/nonstandard labels are deliberately not assigned, even with another valid claim.
        name = ('conflicts.json' if len(row['country_claims']) > 1 else
                'unassigned.json' if not row['country_claims'] or row['unrecognized_labels'] else
                'countries/' + row['country_claims'][0] + '.json')
        docs.setdefault(name, {'schema_version': 1, 'endpoints': []})['endpoints'].append(row)
    docs['rejected.json'] = {'schema_version': 1, 'rows': rejected}
    docs['unresolved.json'] = {'schema_version': 1, 'rows': unresolved}
    counts = dict(endpoints=len(rows), countries=sum(p.startswith('countries/') for p in docs),
                  assigned=sum(len(d['endpoints']) for p, d in docs.items() if p.startswith('countries/')),
                  conflicts=len(docs['conflicts.json']['endpoints']), unassigned=len(docs['unassigned.json']['endpoints']),
                  rejected=len(rejected), unresolved=len(unresolved), healthy=0,
                  evidence=sum(len(r['evidence']) for r in rows.values()), daily_rows=daily_rows)
    index = dict(schema_version=1, upstream_revision=revision, sources=sources, counts=counts,
                 runtime_health='unknown', trinity_verified=False,
                 files={p: dict(sha256=digest(encoded(d)), count=len(d.get('endpoints', d.get('rows')))) for p, d in sorted(docs.items())})
    index['content_revision'] = digest(encoded(index))
    docs['index.json'] = index
    validate(docs)
    return docs


def validate(docs):
    def require(condition, message):
        if not condition:
            raise ValueError(message)
    idx = docs['index.json']
    require(idx['schema_version'] == 1 and idx['runtime_health'] == 'unknown' and idx['trinity_verified'] is False, 'invalid index schema/health')
    require(re.fullmatch('[0-9a-f]{40}', idx['upstream_revision']), 'invalid revision')
    unhashed = {k: v for k, v in idx.items() if k not in {'content_revision', 'generated_at'}}
    require(digest(encoded(unhashed)) == idx['content_revision'], 'content revision mismatch')
    require(set(idx['files']) == set(docs) - {'index.json'}, 'file manifest mismatch')
    seen, evidence_count, assigned, countries = set(), 0, 0, 0
    for path, meta in idx['sources'].items():
        require(re.fullmatch('[0-9a-f]{64}', meta['sha256']) and meta['bytes'] > 0, 'invalid source hash/size')
        require(meta['checked_at'] is None, 'source check timestamp invented')
        if path != 'sources.json':
            require(meta['revision'] == idx['upstream_revision'] and meta['url'] == BASE + idx['upstream_revision'] + '/' + path, 'source revision/URL mismatch')
    for path, doc in docs.items():
        if path == 'index.json':
            continue
        require(doc['schema_version'] == 1, 'invalid document schema')
        require(digest(encoded(doc)) == idx['files'][path]['sha256'], 'file hash mismatch')
        entries = doc.get('endpoints', doc.get('rows'))
        require(isinstance(entries, list) and len(entries) == idx['files'][path]['count'], 'file count mismatch')
        if 'endpoints' not in doc:
            continue
        if path.startswith('countries/'):
            countries += 1
            assigned += len(entries)
        for row in entries:
            host, port, kind = endpoint(row['address'], str(row['port']))
            key = ('[' + host + ']' if kind == 'IPV6' else host) + ':' + str(port)
            require(key == row['endpoint'] and kind == row['kind'] and key not in seen, 'invalid/duplicate endpoint')
            seen.add(key)
            require(row['runtime_health'] == 'unknown' and row['checked_at'] is None and row['trinity_verified'] is False, 'runtime health claim forbidden')
            claims = row['country_claims']
            require(claims == sorted(set(claims)) and all(c in COUNTRIES for c in claims), 'invalid country claims')
            expected = ('conflicts.json' if len(claims) > 1 else 'unassigned.json' if not claims or row['unrecognized_labels'] else 'countries/' + claims[0] + '.json')
            require(path == expected, 'country quarantine violation')
            require(bool(row['evidence']), 'missing provenance')
            for ev in row['evidence']:
                require(ev['source_path'] in idx['sources'] and ev['checked_at'] is None and isinstance(ev['original'], str), 'invalid evidence')
            evidence_count += len(row['evidence'])
    counts = idx['counts']
    expected = dict(endpoints=len(seen), countries=countries, assigned=assigned, conflicts=len(docs['conflicts.json']['endpoints']), unassigned=len(docs['unassigned.json']['endpoints']), rejected=len(docs['rejected.json']['rows']), unresolved=len(docs['unresolved.json']['rows']), healthy=0, evidence=evidence_count)
    require(all(counts[k] == v for k, v in expected.items()), 'aggregate count mismatch')
    audit_rows = docs['rejected.json']['rows'] + docs['unresolved.json']['rows']
    for row in audit_rows:
        require(row['runtime_health'] == 'unknown' and row['trinity_verified'] is False and row['checked_at'] is None, 'audit health claim forbidden')
        require(row['source_path'] in idx['sources'] and isinstance(row['original'], str) and bool(row['reason']), 'invalid audit evidence')
    observed_daily = sum(ev['source_path'] == DAILY for doc in docs.values() for row in doc.get('endpoints', []) for ev in row['evidence']) + sum(row['source_path'] == DAILY for row in audit_rows)
    require(counts['daily_rows'] == observed_daily, 'daily row count mismatch')


def endpoint(address, port):
    if not isinstance(address, str) or address != address.strip() or '%' in address:
        raise ValueError('invalid address syntax')
    if not re.fullmatch(r'[1-9][0-9]{0,4}', str(port)) or not 1 <= int(port) <= 65535:
        raise ValueError('invalid port')
    bracketed = address.startswith('[') and address.endswith(']')
    host = address[1:-1] if bracketed else address
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        if bracketed or ':' in host or re.match(r'^[0-9]+\.', host):
            raise ValueError('malformed IP literal')
        labels = host.split('.')
        if (len(host) > 253 or len(labels) < 2 or
            any(not re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', x) for x in labels) or
            not re.fullmatch(r'[A-Za-z]{2,63}', labels[-1]) or
            labels[-1].lower() in {'local', 'localhost', 'invalid', 'test', 'example', 'internal', 'onion'} or
            host.lower() in {'example.com', 'example.net', 'example.org'}):
            raise ValueError('invalid or reserved hostname')
        return host.lower(), int(port), 'HOST'
    if bracketed and ip.version != 6:
        raise ValueError('only IPv6 may be bracketed')
    if not ip.is_global or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
        raise ValueError('non-public IP')
    return ip.compressed, int(port), 'IPV' + str(ip.version)


import argparse
import concurrent.futures
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit
import zipfile

MAX_FILE = 8 * 1024 * 1024
MAX_ARCHIVE = 48 * 1024 * 1024
MAX_TOTAL = 64 * 1024 * 1024
MAX_FILES = 400
API = 'https://api.github.com/repos/NiREvil/vless/'


def relevant(path):
    return path in REQUIRED or bool(re.fullmatch(r'sub/country_proxies/[A-Z0-9]{2}\.txt', path))


def allowed_url(url):
    parts = urlsplit(url)
    if parts.scheme != 'https' or parts.username or parts.password or parts.port not in (None, 443) or parts.fragment:
        return False
    if parts.hostname == 'api.github.com':
        return bool(re.fullmatch(r'/repos/NiREvil/vless/(commits/main|git/trees/[0-9a-f]{40})', parts.path)) and parts.query in ('', 'recursive=1')
    if parts.hostname == 'raw.githubusercontent.com':
        match = re.fullmatch(r'/NiREvil/vless/([0-9a-f]{40})/(.+)', parts.path)
        return bool(match and relevant(match[2]) and not parts.query)
    if parts.hostname == 'codeload.github.com':
        return bool(re.fullmatch(r'/NiREvil/vless/zip/[0-9a-f]{40}', parts.path)) and not parts.query
    return False


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not allowed_url(newurl):
            raise ValueError('redirect outside upstream allowlist')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url, limit=MAX_FILE, deadline=None):
    if not allowed_url(url):
        raise ValueError('URL outside upstream allowlist')
    deadline = deadline or time.monotonic() + 65
    # No authorization header, token lookup, netrc or cookie handler.
    opener = urllib.request.build_opener(SafeRedirect())
    for attempt in range(2):
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('snapshot deadline exceeded')
            request = urllib.request.Request(url, headers={'User-Agent': 'trinity-proxy-catalog/1', 'Accept': 'application/vnd.github+json' if url.startswith(API) else '*/*'})
            with opener.open(request, timeout=min(20, remaining)) as response:
                if not allowed_url(response.url):
                    raise ValueError('response URL outside upstream allowlist')
                length = response.headers.get('Content-Length')
                if length and int(length) > limit:
                    raise ValueError('upstream size limit exceeded')
                data = bytearray()
                while True:
                    if time.monotonic() > deadline:
                        raise TimeoutError('snapshot deadline exceeded')
                    chunk = response.read(min(65536, limit + 1 - len(data)))
                    if not chunk:
                        break
                    data.extend(chunk)
                    if len(data) > limit:
                        raise ValueError('upstream size limit exceeded')
                return bytes(data)
        except (OSError, urllib.error.URLError):
            if attempt or time.monotonic() >= deadline:
                raise
            time.sleep(0.5)


def archive_files(data, revision):
    if len(data) > MAX_ARCHIVE:
        raise ValueError('archive compressed limit exceeded')
    prefix, files = 'vless-' + revision + '/', {}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        if len(archive.infolist()) > 5000:
            raise ValueError('archive entry limit exceeded')
        for info in archive.infolist():
            if not info.filename.startswith(prefix):
                raise ValueError('archive root does not match revision')
            path = info.filename[len(prefix):]
            if not relevant(path):
                continue
            if path in files or info.file_size > MAX_FILE or info.flag_bits & 1:
                raise ValueError('duplicate, oversized or encrypted archive member')
            if (info.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError('archive symlink forbidden')
            if len(files) >= MAX_FILES or sum(len(b) for b in files.values()) + info.file_size > MAX_TOTAL:
                raise ValueError('archive selected content limit exceeded')
            # Read only selected bytes in memory; never extract filesystem paths.
            files[path] = archive.read(info)
    if not REQUIRED <= files.keys() or not any(p not in REQUIRED for p in files):
        raise ValueError('archive missing required sources/country inventory')
    return files


def snapshot():
    deadline = time.monotonic() + 600
    revision = json.loads(fetch(API + 'commits/main', deadline=deadline))['sha']
    if not re.fullmatch('[0-9a-f]{40}', revision):
        raise ValueError('main did not resolve to a commit SHA')
    try:
        tree = json.loads(fetch(API + 'git/trees/' + revision + '?recursive=1', deadline=deadline))
        if tree.get('truncated') is not False:
            raise ValueError('truncated source tree')
        entries = [x for x in tree['tree'] if relevant(x['path'])]
        paths = [x['path'] for x in entries]
        if (not REQUIRED <= set(paths) or len(paths) <= len(REQUIRED) or len(paths) > MAX_FILES or
            len(set(paths)) != len(paths) or any(x['type'] != 'blob' or x.get('mode') == '120000' or x.get('size', MAX_FILE+1) > MAX_FILE for x in entries)):
            raise ValueError('invalid source tree inventory')
        if sum(x['size'] for x in entries) > MAX_TOTAL:
            raise ValueError('source total size exceeded')
        with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
            bodies = list(pool.map(lambda p: fetch(BASE + revision + '/' + p, deadline=deadline), paths))
        files = dict(zip(paths, bodies))
        # Git blob hashes prove raw bytes correspond to the immutable tree.
        for entry in entries:
            body = files[entry['path']]
            blob_hash = hashlib.sha1(b'blob ' + str(len(body)).encode() + b'\0' + body).hexdigest()
            if blob_hash != entry['sha']:
                raise ValueError('upstream blob hash mismatch')
        return files, revision
    except (OSError, urllib.error.URLError) as error:
        print('Raw/API retrieval failed; trying same-SHA public archive: ' + str(error), file=sys.stderr)
        data = fetch('https://codeload.github.com/NiREvil/vless/zip/' + revision, MAX_ARCHIVE, deadline)
        return archive_files(data, revision), revision


def read_catalog(directory):
    return {p.relative_to(directory).as_posix(): json.loads(p.read_bytes()) for p in directory.rglob('*.json')}


def refresh(root, loader=snapshot):
    root = Path(root)
    target, backup = root / 'catalog', root / '.catalog-backup'
    if backup.exists():
        raise ValueError('interrupted publish backup exists; recover/review it before refresh')
    files, revision = loader()
    config = json.loads((root / 'sources.json').read_bytes())
    docs = build(files, revision, config)
    if target.exists():
        previous = read_catalog(target)
        if previous['index.json']['content_revision'] == docs['index.json']['content_revision']:
            validate(previous)
            return False
    docs['index.json']['generated_at'] = dt.datetime.now(dt.timezone.utc).isoformat(timespec='seconds').replace('+00:00', 'Z')
    stage = Path(tempfile.mkdtemp(prefix='.catalog-stage-', dir=root))
    try:
        for path, content in docs.items():
            destination = stage / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(encoded(content))
        validate(read_catalog(stage))
        # ponytail: serialized refreshes; workflow concurrency prevents writers racing.
        if target.exists():
            os.replace(target, backup)
        try:
            os.replace(stage, target)
        except BaseException:
            if backup.exists():
                os.replace(backup, target)
            raise
        if backup.exists():
            shutil.rmtree(backup)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--validate', action='store_true', help='validate existing catalog without network')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    try:
        changed = False if args.validate else refresh(root)
        docs = read_catalog(root / 'catalog')
        validate(docs)
        print(json.dumps(dict(changed=changed, revision=docs['index.json']['upstream_revision'], content_revision=docs['index.json']['content_revision'], counts=docs['index.json']['counts']), sort_keys=True))
        return 0
    except (OSError, ValueError, KeyError, TypeError, csv.Error, zipfile.BadZipFile) as error:
        print('Catalog unchanged / refresh failed: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
