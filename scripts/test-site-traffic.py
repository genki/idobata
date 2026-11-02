#!/usr/bin/env python3
"""Source-derived map/privacy and report tests; no production traffic/log reads."""
from contextlib import redirect_stdout
import importlib.util
import io
import json
from pathlib import Path
import re
import subprocess
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('traffic', Path(__file__).with_name('report-site-traffic.py'))
REPORT = importlib.util.module_from_spec(spec)
spec.loader.exec_module(REPORT)
CONFIG = (ROOT / 'site/nginx.conf').read_text()
MAPS = re.findall(r'map (.*?) \$(idobata_http_\w+) \{\n(.*?)\n\}', CONFIG, re.S)
FORMAT = ''.join(re.findall(r"'([^']*)'", re.search(r'log_format idobata_http_v1 escape=json\s+(.*?);', CONFIG, re.S)[1]))
SAFE = {'idobata_http_route', 'idobata_http_ua', 'idobata_http_referrer',
        'idobata_http_traffic', 'idobata_http_method', 'status', 'body_bytes_sent', 'request_time'}


def expand(value, variables):
    return re.sub(r'\$(\w+)', lambda match: variables[match[1]], value)


def mapped(source, variables):
    """Evaluate this config's exact/regex maps; not an nginx runtime substitute."""
    value = expand(source[0].strip('"'), variables)
    default, regular = None, []
    for line in source[1].splitlines():
        key, output = line.strip().removesuffix(';').rsplit(None, 1)
        key = key.strip('"')
        if key == 'default':
            default = output
        elif key.startswith('~'):
            regular.append((key, output))
        elif key.lower() == value.lower():
            return output
    for expression, output in regular:
        insensitive = expression.startswith('~*')
        if re.search(expression[2 if insensitive else 1:], value, re.I if insensitive else 0):
            return output
    return default


def event(uri='/', ua='curl/8.0', referrer='', method='GET', diagnostic=''):
    args = parse_qs(urlsplit(uri).query)
    values = {'request_uri': uri, 'uri': '/idobata-index.html', 'http_user_agent': ua,
              'http_referer': referrer, 'request_method': method,
              'arg_analytics': args.get('analytics', [''])[0],
              'http_x_idobata_diagnostic': diagnostic,
              'status': '200', 'body_bytes_sent': '123', 'request_time': '0.004'}
    for source, name, body in MAPS:
        values[name] = mapped((source, body), values)
    row = json.loads(expand(FORMAT, values))
    REPORT.validate(row)
    return row


def entry(row):
    return {'jsonPayload': row}


class TrafficPrivacy(unittest.TestCase):
    def test_log_format_variables_are_only_fixed_maps_and_numbers(self):
        self.assertEqual(set(re.findall(r'\$(\w+)', FORMAT)), SAFE)
        self.assertEqual(CONFIG.count('access_log /dev/stdout idobata_http_v1;'), 2)
        self.assertIn('server_name idobata-peer.s21g.com;', CONFIG)
        self.assertIn('access_log off;', CONFIG)
        self.assertNotIn('error_log ', CONFIG)
        self.assertNotRegex(FORMAT, r'\$(?:remote_addr|http_\w+|request(?:_uri|_method)?|uri|args)(?![a-z_])')

    def test_actual_config_maps_do_not_echo_injected_raw_values(self):
        marker = 'SYNTHETIC_PRIVATE_VALUE_\"_DO_NOT_LOG'
        for uri in ['/?q=' + marker, '/docs/?token=' + marker, '/agents.md?key=' + marker,
                    '/private/' + marker, '/posts.json?search=' + marker]:
            with self.subTest(uri_category=urlsplit(uri).path.split('/')[1]):
                row = event(uri, 'Mozilla/5.0 ChatGPT-User ' + marker,
                            'https://www.google.com/?q=' + marker, 'SECRET-METHOD-' + marker)
                self.assertNotIn(marker, json.dumps(row))
                self.assertEqual(row['ua_class'], 'ai_agent')
                self.assertEqual(row['referrer_class'], 'search')
                self.assertEqual(row['method'], 'other')
        self.assertEqual(event('/')['route'], 'home')
        self.assertEqual(event('/docs/?query=private')['route'], 'docs')
        self.assertEqual(event('/.well-known/idobata/agent.json')['route'], 'descriptor')

    def test_referrer_host_spoof_and_unknown_user_agent_remain_other(self):
        for value in ['https://google.com.attacker.invalid/private',
                      'https://github.com@attacker.invalid/private',
                      'https://evil.invalid/?next=https://claude.ai/']:
            self.assertEqual(event(referrer=value)['referrer_class'], 'other')
        self.assertEqual(event(ua='curl/8.0')['ua_class'], 'other')
        self.assertEqual(event(ua='custom-fetch-client')['ua_class'], 'other')
        self.assertEqual(event(ua='Mozilla/5.0 Googlebot')['ua_class'], 'search_bot')
        self.assertEqual(event(referrer='https://chatgpt.com/c/private')['referrer_class'], 'ai')
        self.assertEqual(event(referrer='https://websh.s21g.com/private')['referrer_class'], 's21g')

    def test_diagnostics_poll_assets_health_and_redirects_are_not_views(self):
        rows = [event('/'), event('/', method='HEAD'), event('/posts.json'),
                event('/analytics-frame.html'), event('/healthz'),
                event('/?analytics=off'), event('/docs/', diagnostic='1')]
        redirect = event('/')
        redirect['status'] = 308
        rows.append(redirect)
        result = REPORT.aggregate([entry(row) for row in rows], 100)
        self.assertEqual(result['total_http_requests_including_diagnostic'], 8)
        self.assertEqual(result['diagnostic_requests'], 2)
        self.assertEqual(result['successful_document_get_requests'], 1)
        self.assertEqual(result['document_head_requests'], 1)
        self.assertEqual(result['redirect_requests'], 1)
        for key in ['unique_peers', 'unique_visitors', 'verified_ai_agents']:
            self.assertIsNone(result[key])
        self.assertFalse(result['partial'])

    def test_report_rejects_raw_fields_instead_of_printing_them(self):
        for field in ['ip', 'ua', 'url', 'path', 'query', 'referrer', 'headers']:
            row = event()
            row[field] = 'SYNTHETIC_PRIVATE_VALUE'
            with self.subTest(field=field), self.assertRaises(ValueError):
                REPORT.aggregate([entry(row)], 100)
        for key, value in [('route', '/secret'), ('ua_class', 'raw agent'),
                           ('status', '200 secret'), ('bytes', True),
                           ('request_seconds', float('nan')), ('request_seconds', float('inf'))]:
            row = event()
            row[key] = value
            with self.subTest(field=key), self.assertRaises(ValueError):
                REPORT.aggregate([entry(row)], 100)

    def invoke(self, result=None, error=None, limit='10'):
        out = io.StringIO()
        with patch.object(REPORT.subprocess, 'run', return_value=result, side_effect=error) as child, redirect_stdout(out):
            code = REPORT.main(['--start', '2026-11-03T00:00:00+09:00',
                                '--end', '2026-11-03T01:00:00+09:00', '--limit', limit])
        self.assertNotIn('SYNTHETIC_PRIVATE_VALUE', out.getvalue())
        return code, json.loads(out.getvalue()), child

    def test_cloud_read_failure_is_nonzero_unknown_not_zero(self):
        error = subprocess.CalledProcessError(1, ['gcloud'], output=b'SYNTHETIC_PRIVATE_VALUE', stderr=b'SYNTHETIC_PRIVATE_VALUE')
        code, report, _ = self.invoke(error=error)
        self.assertEqual(code, 2)
        self.assertEqual(report['reason'], 'logging_read_failed')
        self.assertTrue(report['counts_unavailable'])
        self.assertNotIn('total_http_requests_including_diagnostic', report)

    def test_limit_is_partial_and_projection_fetches_only_sanitized_payload(self):
        result = subprocess.CompletedProcess([], 0, json.dumps([entry(event())]).encode(), b'')
        code, report, child = self.invoke(result, limit='1')
        self.assertEqual(code, 10)
        self.assertTrue(report['partial'])
        command = child.call_args.args[0]
        self.assertIn('--format=json(jsonPayload)', command)
        self.assertIn('jsonPayload.schema="idobata_http_v1"', command[3])
        self.assertIn('timestamp>=', command[3])
        self.assertIn('timestamp<', command[3])
        self.assertEqual(report['period']['start_inclusive'], '2026-11-02T15:00:00+00:00')

    def test_unknown_cloud_payload_is_rejected_without_raw_output(self):
        row = event()
        row['url'] = 'SYNTHETIC_PRIVATE_VALUE'
        code, report, _ = self.invoke(subprocess.CompletedProcess([], 0, json.dumps([entry(row)]).encode(), b''))
        self.assertEqual(code, 2)
        self.assertEqual(report['reason'], 'traffic_schema_rejected')


if __name__ == '__main__':
    unittest.main()
