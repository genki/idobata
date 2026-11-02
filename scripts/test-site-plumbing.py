#!/usr/bin/env python3
"""Static-site delivery tests; no cluster, publisher keys or external requests."""
import base64
from contextlib import redirect_stdout
import copy
import importlib.util
import io
import json
import re
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


DEPLOY = load('deploy-site')
PREVIEW = load('preview-site')
ROUTES = {**DEPLOY.AGENT_ROUTES, **DEPLOY.ANALYTICS_ROUTES}


class SiteDelivery(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.site = self.root / 'site'
        self.site.mkdir()
        for relative in DEPLOY.FILES.values():
            p = self.root / relative
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(b'fixture\n')
        (self.site / 'publisher.json').write_text('{}')
        (self.site / 'posts.json').write_text('{"signed":{"revision":1}}')
        (self.site / 'agents.md').write_bytes('# Agent\r\n日本語\r\n'.encode())
        (self.site / 'llms.txt').write_bytes(b'# Index\r\n/agents.md\r\n')
        (self.site / 'agent.json').write_bytes(b'{"formal_standard":false}\r\n')
        (self.site / 'icon.webp').write_bytes(b'not-an-image-fixture')
        (self.site / 'verify-feed.js').write_text('// verifier fixture')
        (self.site / 'nginx.conf').write_text('# BEGIN IDOBATA SITE\nserver {}\n# END IDOBATA SITE\n')

    def tearDown(self):
        self.tmp.cleanup()

    def test_preview_get_head_mime_alias_and_no_write(self):
        class Quiet(PREVIEW.Handler):
            def log_message(self, *_):
                pass
        before = {p.name: p.read_bytes() for p in self.site.iterdir() if p.is_file()}
        with patch.object(PREVIEW, 'ROOT', self.root):
            server = PREVIEW.ThreadingHTTPServer(('127.0.0.1', 0), Quiet)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                base = f'http://127.0.0.1:{server.server_port}'
                for route, (name, expected_type) in ROUTES.items():
                    filename = DEPLOY.FILES[name].split('/')[-1]
                    content = (self.site / filename).read_bytes()
                    for method in ['GET', 'HEAD']:
                        with urlopen(Request(base + route + '?preview=1', method=method)) as response:
                            self.assertEqual(response.status, 200)
                            self.assertEqual(response.headers.get_content_type(), expected_type)
                            self.assertEqual(response.headers['Referrer-Policy'], 'no-referrer')
                            self.assertEqual(response.headers['X-Content-Type-Options'], 'nosniff')
                            frame = route == '/analytics-frame.html'
                            self.assertEqual(response.headers['X-Frame-Options'], 'SAMEORIGIN' if frame else 'DENY')
                            self.assertEqual(response.headers['Content-Security-Policy'], PREVIEW.Handler.FRAME_CSP if frame else PREVIEW.Handler.MAIN_CSP)
                            if expected_type.startswith('text/'):
                                self.assertEqual(response.headers.get_content_charset(), 'utf-8')
                            self.assertEqual(int(response.headers['Content-Length']), len(content))
                            self.assertEqual(response.read(), content if method == 'GET' else b'')
                    for method in ['POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS']:
                        with self.assertRaises(HTTPError) as error:
                            urlopen(Request(base + route, data=b'not-a-post', method=method))
                        self.assertEqual(error.exception.code, 405)
            finally:
                server.shutdown()
                server.server_close()
                thread.join()
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.site.iterdir() if p.is_file()})

    def apply_fixture(self):
        existing_feed = {'posts.json': '{"signed":{"revision":99}}',
                         'publisher.json': '{"fixture":"preserve"}',
                         'tuf-root.json': 'immutable-root',
                         'tuf-targets.json': 'immutable-targets',
                         'bootstrap.json': 'existing-bootstrap'}
        shared = {'metadata': {'resourceVersion': '1'},
                  'data': {'nginx.conf': 'http {\nserver { server_name sibling.example; }\n}\n',
                           'foreign.txt': 'foreign'},
                  'binaryData': {'foreign.bin': base64.b64encode(b'foreign').decode()}}
        deployment = {'metadata': {'resourceVersion': '2'}, 'spec': {'template': {'spec': {
            'volumes': [{'name': 'foreign', 'emptyDir': {}}],
            'containers': [{'name': 'nginx', 'image': 'unchanged', 'env': [{'name': 'KEEP', 'value': 'public-fixture'}],
                            'volumeMounts': [{'name': 'foreign', 'mountPath': '/foreign'}]}]}}}}
        applied = []
        patched = []
        captured_assets = {}

        def run(command, data=None):
            if command[0] == '/trusted/idobata':
                return '{"policy_id":"fixture"}' if command[-1] == 'profile' else '{}'
            if command[0] == 'curl':
                route = command[-1]
                if route.endswith('/revision.json'):
                    return captured_assets['idobata-revision.json']
                if route.endswith('/posts.json'):
                    return existing_feed['posts.json']
                return '<!doctype html>'
            if 'get' in command and 'configmap' in command:
                return json.dumps(shared)
            if 'get' in command and 'pods' in command:
                return '{"items":[{"metadata":{"name":"fixture"},"status":{"conditions":[{"type":"Ready","status":"True"}]}}]}'
            if 'get' in command and 'deployment' in command:
                return json.dumps(deployment)
            if 'exec' in command:
                return ''
            if 'apply' in command:
                obj = json.loads(data)
                applied.append(obj)
                if obj['metadata']['name'] == 'idobata-site':
                    captured_assets.update(obj['data'])
                return ''
            if 'patch' in command:
                patched.append((command, json.loads(data)))
                return ''
            raise AssertionError('unexpected command category')

        def child(command, **kwargs):
            if 'get' in command and 'idobata-feed' in command:
                return subprocess.CompletedProcess(command, 0, json.dumps({'data': existing_feed}), '')
            if 'rollout' in command:
                return subprocess.CompletedProcess(command, 0, '', '')
            if command[0] == 'curl':
                route = command[-1].removeprefix('https://idobata.s21g.com')
                name, mime = ROUTES[route]
                if mime.startswith('text/'):
                    mime += '; charset=utf-8'
                body = b'headers-only' if '--head' in command else captured_assets[name].encode()
                return subprocess.CompletedProcess(command, 0, body + b'\n200\n' + mime.encode(), b'')
            raise AssertionError('unexpected subprocess category')

        with patch.object(DEPLOY, 'ROOT', self.root), patch.object(DEPLOY, 'run', side_effect=run), \
                patch.object(DEPLOY.subprocess, 'run', side_effect=child), \
                patch('sys.argv', ['deploy-site', '--context', 'fixture', '--binary', '/trusted/idobata', '--apply']), \
                redirect_stdout(io.StringIO()):
            DEPLOY.main()
        self.assertEqual([obj['metadata']['name'] for obj in applied], ['idobata-site'])
        self.assertNotIn('idobata-posts.json', captured_assets)
        self.assertNotIn('idobata-publisher.json', captured_assets)
        for _, (name, _) in ROUTES.items():
            self.assertEqual(captured_assets[name].encode(), (self.root / DEPLOY.FILES[name]).read_bytes())
        config_patch = next(body for command, body in patched if 'configmap' in command)
        rendered = next(row['value'] for row in config_patch if row['path'] == '/data/nginx.conf')
        self.assertIn('server_name sibling.example;', rendered)
        self.assertTrue(all(row['path'] in ['/metadata/resourceVersion', '/data/nginx.conf'] for row in config_patch))
        container_patch = next(body for command, body in patched if 'deployment' in command)
        containers = next(row['value'] for row in container_patch if row['path'].endswith('/containers'))
        expected = copy.deepcopy(deployment['spec']['template']['spec']['containers'])
        for c in containers:
            c['volumeMounts'] = [m for m in c['volumeMounts'] if m['name'] not in ['idobata-site', 'idobata-feed']]
        self.assertEqual(containers, expected)
        return json.loads(captured_assets['idobata-revision.json'])['revision']

    def test_normal_apply_packs_exact_agent_bytes_preserves_feed_and_foreign_configuration(self):
        self.apply_fixture()

    def test_each_agent_asset_changes_deployment_revision(self):
        previous = self.apply_fixture()
        for _, (name, _) in ROUTES.items():
            with (self.root / DEPLOY.FILES[name]).open('ab') as file:
                file.write(b'\n')
            current = self.apply_fixture()
            self.assertNotEqual(previous, current)
            previous = current

    def test_public_verification_rejects_changed_bytes_or_mime(self):
        assets = {name: (self.root / DEPLOY.FILES[name]).read_bytes().decode()
                  for name, _ in ROUTES.values()}
        for fault in ['bytes', 'mime', 'charset']:
            def child(command, **_):
                route = command[-1].removeprefix('https://idobata.s21g.com')
                name, mime = ROUTES[route]
                if mime.startswith('text/') and fault != 'charset':
                    mime += '; charset=utf-8'
                body = assets[name].encode() + (b'changed' if fault == 'bytes' else b'')
                if fault == 'mime':
                    mime = 'application/octet-stream'
                return subprocess.CompletedProcess(command, 0, body + b'\n200\n' + mime.encode(), b'')
            with self.subTest(fault=fault), patch.object(DEPLOY.subprocess, 'run', side_effect=child):
                with self.assertRaises(ValueError):
                    DEPLOY.verify_agent_routes('192.0.2.1', assets)

    def test_nginx_agent_aliases_and_existing_readonly_surface(self):
        source = Path(__file__).resolve().parents[1]
        config = (source / 'site/nginx.conf').read_text()
        policies = re.findall(r'add_header Content-Security-Policy "([^"]+)" always;', config)
        self.assertEqual(policies, [PREVIEW.Handler.MAIN_CSP, PREVIEW.Handler.FRAME_CSP])
        self.assertNotIn('google', policies[0])
        self.assertIn("img-src https://www.google-analytics.com https://region1.google-analytics.com;", policies[1])
        for route, (name, mime) in ROUTES.items():
            self.assertRegex(config, r'location = ' + re.escape(route) + r' \{\s+alias /srv/idobata/site/' + re.escape(name) + r';\s+default_type ' + re.escape(mime) + ';')
            if mime in ['text/markdown', 'text/plain', 'text/javascript']:
                self.assertIn(f'default_type {mime}; charset utf-8; charset_types {mime};', config)
        self.assertIn('if ($request_method !~ ^(GET|HEAD)$) { return 405; }', config)
        self.assertIn("connect-src 'self'; frame-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'", config)
        self.assertEqual(config.count('return 302 https://github.com/genki/idobata/releases/download/'), 9)
        for route in ['/posts.json', '/publisher.json', '/updates/root.json', '/updates/targets.json',
                      '/updates/snapshot.json', '/updates/timestamp.json', '/.well-known/idobata/bootstrap.json']:
            self.assertIn('location = ' + route + ' ', config)
        self.assertIn('User-agent: *\\nAllow: /\\nSitemap: https://idobata.s21g.com/sitemap.xml', config)
        self.assertIn('server_name idobata-peer.s21g.com;', config)
        self.assertIn('proxy_pass http://home_web;', config)


if __name__ == '__main__':
    unittest.main()
