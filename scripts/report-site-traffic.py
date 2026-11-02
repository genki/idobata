#!/usr/bin/env python3
"""Aggregate only idobata_http_v1 from existing GKE Cloud Logging.

No raw log output/files, identifiers or uniqueness estimates. New access logs
are sanitized; existing nginx error logs are a separate, unchanged surface.
GKE logging retention is inherited and is not assumed to be a particular length.
Refs: https://nginx.org/en/docs/http/ngx_http_log_module.html
https://cloud.google.com/sdk/gcloud/reference/logging/read
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import json
import math
import re
import subprocess
import sys

SCHEMA = 'idobata_http_v1'
FIELDS = {'schema', 'route', 'ua_class', 'referrer_class', 'traffic_class',
          'method', 'status', 'bytes', 'request_seconds'}
DOCUMENTS = {'home', 'docs', 'agents', 'llms', 'descriptor'}
ROUTES = DOCUMENTS | {'release', 'feed', 'update', 'bootstrap', 'health', 'asset', 'other'}
UAS = {'ai_agent', 'search_bot', 'browser', 'other'}
REFERRERS = {'search', 'github', 'ai', 's21g', 'other', 'direct'}
TRAFFIC = {'document', 'poll', 'release', 'asset', 'health', 'other', 'diagnostic'}
METHODS = {'GET', 'HEAD', 'other'}


def validate(row):
    if not isinstance(row, dict) or set(row) != FIELDS or row['schema'] != SCHEMA:
        raise ValueError('invalid_schema')
    for name, allowed in [('route', ROUTES), ('ua_class', UAS), ('referrer_class', REFERRERS),
                          ('traffic_class', TRAFFIC), ('method', METHODS)]:
        if not isinstance(row[name], str) or row[name] not in allowed:
            raise ValueError('invalid_category')
    if type(row['status']) is not int or not 100 <= row['status'] <= 599:
        raise ValueError('invalid_status')
    if type(row['bytes']) is not int or not 0 <= row['bytes'] <= 2**63 - 1:
        raise ValueError('invalid_bytes')
    value = row['request_seconds']
    if type(value) not in [int, float] or not math.isfinite(value) or not 0 <= value <= 10**9:
        raise ValueError('invalid_duration')
    expected = ('document' if row['route'] in DOCUMENTS else
                'poll' if row['route'] in {'feed', 'update', 'bootstrap'} else
                row['route'] if row['route'] in {'release', 'asset', 'health'} else 'other')
    if row['traffic_class'] not in {expected, 'diagnostic'}:
        raise ValueError('inconsistent_category')
    return row


def aggregate(entries, limit):
    rows = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {'jsonPayload'}:
            raise ValueError('invalid_envelope')
        rows.append(validate(entry['jsonPayload']))
    ordinary = [row for row in rows if row['traffic_class'] != 'diagnostic']
    documents = [row for row in ordinary if row['route'] in DOCUMENTS
                 and row['method'] == 'GET' and 200 <= row['status'] < 300]
    grouped = lambda items, field: dict(sorted(Counter(row[field] for row in items).items()))
    partial = len(rows) >= limit
    return {
        'version': 1, 'schema': SCHEMA, 'status': 'partial' if partial else 'ok',
        'partial': partial, 'limit_reached': partial,
        'total_http_requests_including_diagnostic': len(rows),
        'diagnostic_requests': len(rows) - len(ordinary),
        'non_diagnostic_http_requests': len(ordinary),
        'successful_document_get_requests': len(documents),
        'document_head_requests': sum(row['route'] in DOCUMENTS and row['method'] == 'HEAD' for row in ordinary),
        'redirect_requests': sum(300 <= row['status'] < 400 for row in ordinary),
        'all_non_diagnostic_requests_by': {name: grouped(ordinary, name)
                                          for name in ['route', 'ua_class', 'referrer_class', 'traffic_class', 'method', 'status']},
        'successful_document_get_requests_by': {name: grouped(documents, name)
                                               for name in ['route', 'ua_class', 'referrer_class']},
        'non_diagnostic_response_bytes': sum(row['bytes'] for row in ordinary),
        'mean_request_seconds': round(sum(row['request_seconds'] for row in ordinary) / len(ordinary), 6) if ordinary else None,
        'unique_visitors': None, 'unique_peers': None, 'verified_ai_agents': None,
        'classification_is_self_reported_not_identity': True,
        'zero_results_prove_no_historical_visits': False,
        'retention_days': None,
        'counts_scope': 'matching retained Cloud Logging entries only; requests are not people, peers or unique visits',
    }


def timestamp(value):
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None:
        raise ValueError('timezone_required')
    return result.astimezone(timezone.utc)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--start', required=True, help='inclusive RFC3339 timestamp with timezone')
    parser.add_argument('--end', required=True, help='exclusive RFC3339 timestamp with timezone')
    parser.add_argument('--project', default='s21g-twpro')
    parser.add_argument('--cluster', default='moon')
    parser.add_argument('--namespace', default='default')
    parser.add_argument('--limit', type=int, default=10000)
    args = parser.parse_args(argv)
    try:
        start, end = timestamp(args.start), timestamp(args.end)
        if start >= end or not 1 <= args.limit <= 100000:
            raise ValueError('invalid_bounds')
        if not all(re.fullmatch(r'[a-zA-Z0-9_-]{1,63}', value)
                   for value in [args.project, args.cluster, args.namespace]):
            raise ValueError('invalid_resource_selector')
    except (ValueError, TypeError, OverflowError):
        print(json.dumps({'status': 'failed', 'reason': 'invalid_arguments', 'counts_unavailable': True}))
        return 2
    start_text, end_text = start.isoformat(), end.isoformat()
    log_filter = ('resource.type="k8s_container" AND '
                  f'resource.labels.cluster_name="{args.cluster}" AND '
                  f'resource.labels.namespace_name="{args.namespace}" AND '
                  'resource.labels.container_name="nginx" AND '
                  f'jsonPayload.schema="{SCHEMA}" AND '
                  f'timestamp>="{start_text}" AND timestamp<"{end_text}"')
    try:
        result = subprocess.run(['gcloud', 'logging', 'read', log_filter,
                                 '--project=' + args.project, '--format=json(jsonPayload)',
                                 '--order=asc', '--limit=' + str(args.limit)],
                                capture_output=True, check=True, timeout=120)
    except (OSError, subprocess.SubprocessError):
        print(json.dumps({'status': 'failed', 'reason': 'logging_read_failed', 'counts_unavailable': True}))
        return 2
    try:
        if len(result.stdout) > 64 * 1024 * 1024:
            raise ValueError('response_limit')
        entries = json.loads(result.stdout)
        if not isinstance(entries, list) or len(entries) > args.limit:
            raise ValueError('response_shape')
        report = aggregate(entries, args.limit)
    except (ValueError, TypeError, OverflowError):
        print(json.dumps({'status': 'failed', 'reason': 'traffic_schema_rejected', 'counts_unavailable': True}))
        return 2
    report['period'] = {'start_inclusive': start_text, 'end_exclusive': end_text}
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 10 if report['partial'] else 0


if __name__ == '__main__':
    sys.exit(main())
