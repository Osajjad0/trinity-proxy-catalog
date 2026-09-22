import importlib.util
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]

class EndpointTests(unittest.TestCase):
    def test_strict_public_endpoints(self):
        path = ROOT / 'scripts/build_catalog.py'
        self.assertTrue(path.exists(), 'catalog implementation missing')
        spec = importlib.util.spec_from_file_location('catalog', path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(module.endpoint('180.149.44.124', '8443'), ('180.149.44.124', 8443, 'IPV4'))
        self.assertEqual(module.endpoint('[2606:4700::1111]', '443'), ('2606:4700::1111', 443, 'IPV6'))
        self.assertEqual(module.endpoint('BPB.yousef.isegaro.com', '443'), ('bpb.yousef.isegaro.com', 443, 'HOST'))
        for address, port in [('1.2.3.999','443'), ('01.2.3.4','443'), ('1.2.3.4junk','443'),
                              ('127.0.0.1','443'), ('10.0.0.1','443'), ('192.0.2.1','443'),
                              ('224.0.0.1','443'), ('[::1]','443'), ('fe80::1%eth0','443'),
                              ('bad_host.example','443'), ('-bad.example','443'), ('localhost','443'),
                              ('host.local','443'), ('host.test','443'), ('host.example','443'),
                              ('8.8.8.8','0'), ('8.8.8.8','65536'), ('8.8.8.8','+443'),
                              ('8.8.8.8','0443'), ('8.8.8.8','443junk'), (' 8.8.8.8','443')]:
            with self.subTest(address=address, port=port), self.assertRaises(ValueError):
                module.endpoint(address, port)

def module():
    spec = importlib.util.spec_from_file_location('catalog', ROOT / 'scripts/build_catalog.py')
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def fixture():
    return {
        'sub/country_proxies/01_last_update.txt': b'Last updated: Tue, 15 Sep 2026 20:00:41 \xe2\x80\x93 IRN\n',
        'sub/country_proxies/02_proxies.csv': b'IP Address, Port, TLS, Data Center, Region, City, ASN, latency\n8.8.8.8,2053,true,US,x,x,Org,-\n8.8.8.8,443,true,US,x,x,Org,-\n',
        'edge/assets/p-legacies.csv': b'IP Address,Port,Region,ASN\n8.8.8.8,443,US,Org\n9.9.9.9,443,US,Org\n',
        'sub/country_proxies/03_proxies.txt': b'180.149.44.124 8443\n85.185.86.111 2053\n',
        'sub/country_proxies/AZ.txt': b'180.149.44.124 8443\n85.185.86.111 2053\n',
        'sub/country_proxies/US.txt': b'8.8.8.8 2053\n',
        'sub/country_proxies/T1.txt': b'1.1.1.1 443\n',
        'sub/country_proxies/DE.txt': b'9.9.9.9 443\n1.2.3.999 443\n10.0.0.1 443\n',
        'sub/ProxyIP-Daily.md': ('Last_Update-Sun%2C%2020%20Sep%202026%2013%3A15%20%28UTC%2B3%3A30%29-966600\n'
            '## <img alt="Google" /> Google (1)\n| <pre><code>8.8.8.8</code></pre> | Org | London | risk |\n'
            '## 🇬🇧 United Kingdom (2 proxies)\n| <pre><code>8.8.8.8</code></pre> | Org | London | risk |\n'
            '| <pre><code>4.2.2.2</code></pre> | Org | London | risk |\n').encode(),
    }


class CatalogTests(unittest.TestCase):
    def test_snapshot_catalog_evidence_and_quarantine(self):
        m = module()
        self.assertTrue(hasattr(m, 'build'), 'snapshot builder missing')
        config = {'dynamic_hosts': [{'host': 'turk.diam4.ggff.net', 'configured_port': 443}]}
        docs = m.build(fixture(), 'a' * 40, config)
        idx = docs['index.json']
        self.assertEqual(idx['counts']['healthy'], 0)
        self.assertEqual([r['port'] for r in docs['countries/AZ.json']['endpoints']], [8443, 2053])
        conflict = {r['endpoint']: r for r in docs['conflicts.json']['endpoints']}
        self.assertEqual(conflict['8.8.8.8:2053']['country_claims'], ['GB', 'US'])
        self.assertEqual(len([e for e in conflict['8.8.8.8:2053']['evidence'] if e['source_path'] == 'sub/ProxyIP-Daily.md']), 2)
        self.assertIn('9.9.9.9:443', conflict)
        self.assertEqual(len(docs['unresolved.json']['rows']), 1)
        self.assertEqual(len(docs['rejected.json']['rows']), 2)
        unassigned = {r['endpoint']: r for r in docs['unassigned.json']['endpoints']}
        self.assertEqual(unassigned['1.1.1.1:443']['unrecognized_labels'], ['T1'])
        self.assertEqual(unassigned['turk.diam4.ggff.net:443']['country_claims'], [])
        daily = idx['sources']['sub/ProxyIP-Daily.md']
        self.assertEqual(daily['feed_generated_at'], '2026-09-20T09:45:00Z')
        self.assertIsNone(daily['checked_at'])
        country = idx['sources']['sub/country_proxies/AZ.txt']
        self.assertIsNone(country['checked_at'])
        self.assertIsNone(country['source_updated_at'])
        self.assertIn('IRN', country['source_updated_raw'])
        m.validate(docs)
        self.assertEqual(docs, m.build(fixture(), 'a' * 40, config))
        import copy
        corrupted = copy.deepcopy(docs)
        corrupted['countries/AZ.json']['endpoints'][0]['runtime_health'] = 'healthy'
        with self.assertRaises(ValueError):
            m.validate(corrupted)
        corrupted = copy.deepcopy(docs)
        corrupted['index.json']['counts']['endpoints'] += 1
        with self.assertRaises(ValueError):
            m.validate(corrupted)
        corrupted = copy.deepcopy(docs)
        corrupted['index.json']['sources']['sub/ProxyIP-Daily.md']['sha256'] = 'broken'
        with self.assertRaises(ValueError):
            m.validate(corrupted)


class BoundaryTests(unittest.TestCase):
    def test_malformed_first_seen_port_is_not_repaired_by_later_input(self):
        m = module()
        data = fixture()
        data['sub/country_proxies/02_proxies.csv'] = data['sub/country_proxies/02_proxies.csv'].replace(b'8.8.8.8,2053', b'8.8.8.8,bad')
        docs = m.build(data, 'a'*40, {'dynamic_hosts': []})
        daily_evidence = [ev for doc in docs.values() for row in doc.get('endpoints', []) for ev in row['evidence'] if ev['source_path'] == m.DAILY]
        self.assertFalse(daily_evidence, 'malformed first-seen scanner input must stay unresolved, not move to later port')
        self.assertEqual(len(docs['unresolved.json']['rows']), 3)

    def test_audit_rows_explicit_health_and_daily_counts(self):
        m = module()
        docs = m.build(fixture(), 'a'*40, {'dynamic_hosts': []})
        for name in ['unresolved.json', 'rejected.json']:
            for row in docs[name]['rows']:
                self.assertEqual(row.get('runtime_health'), 'unknown')
                self.assertIs(row.get('trinity_verified'), False)
        # Rehash deliberately to test semantic validation, not only integrity.
        docs['index.json']['counts']['daily_rows'] += 1
        base = {k:v for k,v in docs['index.json'].items() if k != 'content_revision'}
        docs['index.json']['content_revision'] = m.digest(m.encoded(base))
        with self.assertRaises(ValueError):
            m.validate(docs)


class RefreshTests(unittest.TestCase):
    def test_transaction_preserves_previous_catalog_and_noop(self):
        m = module()
        self.assertTrue(hasattr(m, 'refresh'), 'transactional refresh missing')
        import tempfile
        import json
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'sources.json').write_text(json.dumps({'dynamic_hosts': []}))
            source = lambda: (fixture(), 'a' * 40)
            self.assertTrue(m.refresh(root, source))
            before = {p.relative_to(root): p.read_bytes() for p in (root / 'catalog' / 'raw').rglob('*') if p.is_file()}
            self.assertFalse(m.refresh(root, source))
            def broken():
                raise OSError('required upstream failure')
            with self.assertRaises(OSError):
                m.refresh(root, broken)
            bad = fixture()
            del bad['sub/country_proxies/03_proxies.txt']
            with self.assertRaises(ValueError):
                m.refresh(root, lambda: (bad, 'b' * 40))
            def failing_validation(docs):
                raise ValueError('schema failure')
            with patch.object(m, 'validate', failing_validation), self.assertRaises(ValueError):
                m.refresh(root, source)
            self.assertEqual(before, {p.relative_to(root): p.read_bytes() for p in (root / 'catalog' / 'raw').rglob('*') if p.is_file()})
            changed = fixture()
            changed['sub/country_proxies/AZ.txt'] += b'8.8.4.4 443\n'
            real_replace = m.os.replace
            def fail_install(src, dst):
                if pathlib.Path(src).name.startswith('.catalog-stage-'):
                    raise OSError('simulated publish failure')
                return real_replace(src, dst)
            with patch.object(m.os, 'replace', fail_install), self.assertRaises(OSError):
                m.refresh(root, lambda: (changed, 'b' * 40))
            self.assertEqual(before, {p.relative_to(root): p.read_bytes() for p in (root / 'catalog' / 'raw').rglob('*') if p.is_file()})

    def test_fetch_redirect_limits_and_retry_are_bounded(self):
        m = module()
        from unittest.mock import patch
        import urllib.request
        import urllib.error
        with self.assertRaises(ValueError):
            m.SafeRedirect().redirect_request(urllib.request.Request(m.API+'commits/main'), None, 302, 'redirect', {}, 'https://evil.test/')
        class Response:
            url = m.API + 'commits/main'
            headers = {}
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, size): return b'x' * size
        class Opener:
            calls = 0
            def open(self, *args, **kwargs):
                self.calls += 1
                return Response()
        opener = Opener()
        with patch.object(m.urllib.request, 'build_opener', return_value=opener), self.assertRaises(ValueError):
            m.fetch(m.API+'commits/main', limit=8)
        self.assertEqual(opener.calls, 1)
        class Broken(Opener):
            def open(self, *args, **kwargs):
                self.calls += 1
                raise urllib.error.URLError('offline')
        broken = Broken()
        with patch.object(m.urllib.request, 'build_opener', return_value=broken), patch.object(m.time, 'sleep'), self.assertRaises(urllib.error.URLError):
            m.fetch(m.API+'commits/main')
        self.assertEqual(broken.calls, 2)

    def test_allowlist_and_archive_selective_limits(self):
        m = module()
        self.assertTrue(hasattr(m, 'allowed_url'), 'bounded fetch missing')
        for url in ['http://api.github.com/repos/NiREvil/vless/commits/main',
                    'https://api.github.com.evil.test/repos/NiREvil/vless/commits/main',
                    'https://user:pass@api.github.com/repos/NiREvil/vless/commits/main',
                    'https://api.github.com/repos/other/private', 'https://127.0.0.1/',
                    'https://raw.githubusercontent.com/NiREvil/vless/main/secrets',
                    'https://raw.githubusercontent.com/NiREvil/vless/' + 'a'*40 + '/../secrets']:
            self.assertFalse(m.allowed_url(url), url)
        self.assertTrue(m.allowed_url('https://api.github.com/repos/NiREvil/vless/commits/main'))
        import io, zipfile
        output = io.BytesIO()
        with zipfile.ZipFile(output, 'w') as archive:
            for path, body in fixture().items():
                archive.writestr('vless-' + 'a'*40 + '/' + path, body)
            archive.writestr('vless-' + 'a'*40 + '/unrelated.txt', b'not extracted')
        self.assertEqual(m.archive_files(output.getvalue(), 'a'*40), fixture())
        with self.assertRaises(ValueError):
            m.archive_files(output.getvalue(), 'b'*40)


class FeedTests(unittest.TestCase):
    def build(self, m, **changes):
        data = fixture()
        data.update(changes)
        return m.build(data, 'a' * 40, {'dynamic_hosts': [{'host': 'turk.diam4.ggff.net', 'configured_port': 443}]})

    def pairs(self, docs, prefix):
        return {p[len(prefix):-5]: sorted([r['address'], r['port']] for r in docs[p]['endpoints'])
                for p in docs if p.startswith(prefix)}

    def test_feed_schema_matches_catalog_documents(self):
        m = module()
        docs = self.build(m)
        feed, idx = docs['feed.json'], docs['index.json']
        self.assertEqual(set(feed), {'schema_version', 'upstream_revision', 'content_revision',
                                     'counts', 'countries', 'unassigned', 'auto'})
        self.assertEqual(feed['schema_version'], 1)
        self.assertEqual(feed['upstream_revision'], 'a' * 40)
        self.assertEqual(feed['content_revision'], idx['content_revision'])
        self.assertEqual(feed['counts'], idx['counts'])
        self.assertEqual(feed['countries'], self.pairs(docs, 'countries/'))
        self.assertEqual(feed['unassigned'], sorted(sum(self.pairs(docs, 'unassigned.').values(), [])))
        expected_auto = []
        for cc in sorted(feed['countries']):
            expected_auto += feed['countries'][cc][:2]
        self.assertEqual(feed['auto'], expected_auto[:48])
        self.assertEqual(docs, m.build(fixture(), 'a' * 40, {'dynamic_hosts': [{'host': 'turk.diam4.ggff.net', 'configured_port': 443}]}))

    def test_feed_excludes_conflicts_unresolved_and_rejected(self):
        m = module()
        docs = self.build(m)
        feed = docs['feed.json']
        pairs = {tuple(pair) for array in [feed['unassigned'], feed['auto']] for pair in array}
        pairs |= {tuple(pair) for arr in feed['countries'].values() for pair in arr}
        self.assertNotIn(('8.8.8.8', 2053), pairs)  # conflict: claimed GB and US
        self.assertNotIn(('9.9.9.9', 443), pairs)   # conflict: claimed DE and US
        self.assertNotIn(('4.2.2.2', 443), pairs)   # unresolved daily row, no public port
        for rejected in [('1.2.3.999', 443), ('10.0.0.1', 443)]:
            self.assertNotIn(rejected, pairs)
        self.assertIn(['8.8.8.8', 443], feed['countries']['US'])      # same IP, non-conflicting port stays assigned
        self.assertIn(['1.1.1.1', 443], feed['unassigned'])
        self.assertIn(['turk.diam4.ggff.net', 443], feed['unassigned'])

    def test_feed_addresses_are_bare_including_ipv6(self):
        m = module()
        data = fixture()
        data['sub/country_proxies/AZ.txt'] += b'2606:4700::1111 8443\n'
        docs = self.build(m, **data)
        self.assertIn(['2606:4700::1111', 8443], docs['feed.json']['countries']['AZ'])
        feed = docs['feed.json']
        addresses = ([pair[0] for arr in feed['countries'].values() for pair in arr] +
                     [pair[0] for pair in feed['unassigned']] + [pair[0] for pair in feed['auto']])
        self.assertTrue(addresses)
        self.assertTrue(all('[' not in a and ']' not in a for a in addresses))

    def test_feed_auto_spread_cap_and_determinism(self):
        m = module()
        data = fixture()
        codes = [cc for cc in sorted(m.COUNTRIES) if cc not in {'AZ', 'US', 'DE'}][:30]
        for i, cc in enumerate(codes):
            data['sub/country_proxies/' + cc + '.txt'] = ''.join('101.%d.%d.1 443' % (i, j) + '\n' for j in range(3)).encode()
        docs = m.build(data, 'a' * 40, {'dynamic_hosts': []})
        feed = docs['feed.json']
        self.assertEqual(len(feed['auto']), 48)
        owner = {(pair[0], pair[1]): cc for cc, arr in feed['countries'].items() for pair in arr}
        per = {}
        for pair in feed['auto']:
            cc = owner[(pair[0], pair[1])]
            per[cc] = per.get(cc, 0) + 1
            self.assertLessEqual(per[cc], 2)
        codes = list(dict.fromkeys(owner[(pair[0], pair[1])] for pair in feed['auto']))
        self.assertEqual(codes, sorted(codes))

    def test_feed_validated_and_published_with_generated_at(self):
        m = module()
        import copy
        import tempfile
        docs = self.build(m)
        def bump_counts(feed):
            feed['counts'] = dict(feed['counts'], endpoints=feed['counts']['endpoints'] + 1)
        for corrupt in [lambda f: f['countries'].popitem(), lambda f: f['countries']['AZ'].pop(),
                        bump_counts, lambda f: f['auto'].append(['8.8.8.8', 2053]),
                        lambda f: f.__setitem__('schema_version', 2)]:
            broken = copy.deepcopy(docs)
            corrupt(broken['feed.json'])
            with self.assertRaises(ValueError):
                m.validate(broken)
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            (root / 'sources.json').write_text(json.dumps({'dynamic_hosts': []}))
            self.assertTrue(m.refresh(root, lambda: (fixture(), 'a' * 40)))
            feed = json.loads((root / 'catalog' / 'raw' / 'feed.json').read_text())
            idx = json.loads((root / 'catalog' / 'raw' / 'index.json').read_text())
            self.assertRegex(feed['generated_at'], r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$')
            self.assertEqual(feed['generated_at'], idx['generated_at'])
            before = {p.relative_to(root): p.read_bytes() for p in (root / 'catalog' / 'raw').rglob('*') if p.is_file()}
            self.assertFalse(m.refresh(root, lambda: (fixture(), 'a' * 40)))
            self.assertEqual(before, {p.relative_to(root): p.read_bytes() for p in (root / 'catalog' / 'raw').rglob('*') if p.is_file()})
            # Poisoned on-disk feed fails offline validation.
            poisoned = json.loads((root / 'catalog' / 'raw' / 'feed.json').read_text())
            poisoned['countries'].popitem()
            (root / 'catalog' / 'raw' / 'feed.json').write_text(json.dumps(poisoned))
            with self.assertRaises(ValueError):
                m.validate(m.read_catalog(root / 'catalog' / 'raw'))


if __name__ == '__main__':
    unittest.main()
