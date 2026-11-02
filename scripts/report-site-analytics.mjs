#!/usr/bin/env node
// Read-only GA Data / optional existing Search Console reports. No test events.
import { writeFile } from 'node:fs/promises';
import { parseArgs } from 'node:util';
import { pathToFileURL } from 'node:url';
import { googleClient, publicError, PROPERTY_NAME, SITE } from './setup-site-analytics.mjs';

const DEFAULT_PROPERTY = '561646052';
const EVENTS = ['page_view', 'navigation_click'];
const DESTINATIONS = ['agent_guide', 'llms_index', 'agent_descriptor', 'participation_question',
  'repository', 'release', 'copy_install'];
const SOURCES = ['direct', 'other', 'internal', 'google', 'bing', 'github', 'chatgpt', 'claude',
  'gemini', 'deepseek', 's21g'];
const PUBLIC_GA_SOURCES = new Set(['(direct)', '(not set)', 'google', 'bing', 'github.com',
  'chatgpt.com', 'chat.openai.com', 'claude.ai', 'gemini.google.com', 'chat.deepseek.com',
  's21g.com', 'www.s21g.com', 'idobata.s21g.com', 'www.google.com', 'www.bing.com']);
const MEDIUMS = new Set(['(none)', '(not set)', 'referral', 'organic', 'social', 'email', 'cpc', 'paid', 'other']);
const CHANNELS = new Set(['Direct', 'Organic Search', 'Organic Social', 'Organic Video',
  'Organic Shopping', 'Referral', 'Email', 'Paid Search', 'Paid Social', 'Paid Video',
  'Paid Shopping', 'Display', 'Cross-network', 'Affiliates', 'Audio', 'SMS', 'Mobile Push Notifications',
  'Unassigned', '(not set)']);
const PAGES = new Set(['/', '/docs/', '/agents.md', '/llms.txt', '/agent.json', '(not set)']);
const DATA = 'https://analyticsdata.googleapis.com/v1beta/';
const ADMIN = 'https://analyticsadmin.googleapis.com/v1alpha/';
const assert = (condition, label) => { if (!condition) throw new Error(label); };

export function dates(start, end) {
  for (const value of [start, end]) {
    assert(typeof value === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(value)
      && Number.isFinite(Date.parse(value + 'T00:00:00Z'))
      && new Date(value + 'T00:00:00Z').toISOString().slice(0, 10) === value, 'invalid_report_date');
  }
  assert(start <= end && Date.parse(end) - Date.parse(start) <= 366 * 86400000, 'invalid_report_range');
  return { startDate: start, endDate: end };
}

function safeValue(name, value) {
  if (name === 'sessionSource') return PUBLIC_GA_SOURCES.has(value) ? value : 'other';
  if (name === 'sessionMedium') return MEDIUMS.has(value) ? value : 'other';
  if (name === 'sessionDefaultChannelGroup') return CHANNELS.has(value) ? value : 'other';
  if (name === 'landingPage') return PAGES.has(value) ? value : 'other';
  if (value === '(not set)' || value === '') return '(not set)';
  if (name === 'eventName') return EVENTS.includes(value) ? value : 'other';
  if (name === 'customEvent:destination') return DESTINATIONS.includes(value) ? value : 'other';
  if (name === 'customEvent:source_category') return SOURCES.includes(value) ? value : 'other';
  if (name === 'customEvent:page_kind') return ['home', 'docs'].includes(value) ? value : 'other';
  return 'other';
}

export function rows(report) {
  const dimensions = (report.dimensionHeaders || []).map(item => item.name);
  const metrics = (report.metricHeaders || []).map(item => item.name);
  const grouped = new Map();
  for (const row of report.rows || []) {
    const values = Object.fromEntries(dimensions.map((name, index) => [name, safeValue(name, row.dimensionValues[index]?.value || '')]));
    const key = JSON.stringify(values);
    const existing = grouped.get(key) || values;
    for (const [index, name] of metrics.entries()) {
      const count = Number(row.metricValues[index]?.value);
      assert(Number.isFinite(count) && count >= 0, 'invalid_analytics_metric');
      existing[name] = (existing[name] || 0) + count;
    }
    grouped.set(key, existing);
  }
  return [...grouped.values()];
}

function metadata(value = {}) {
  return Object.fromEntries(['subjectToThresholding', 'dataLossFromOtherRow', 'emptyReason',
    'timeZone', 'samplingMetadatas', 'currencyCode', 'firstIncompleteDate', 'firstIncompleteHour']
    .filter(key => value[key] !== undefined)
    .map(key => [key, value[key]]));
}

export function request(range, dimensions, metrics) {
  return { dateRanges: [range], dimensions: dimensions.map(name => ({ name })),
    metrics: metrics.map(name => ({ name })), limit: '1000',
    dimensionFilter: { filter: { fieldName: 'eventName', inListFilter: { values: EVENTS } } },
    returnPropertyQuota: true };
}

export async function report(api, { propertyId = DEFAULT_PROPERTY, start, end, gsc = false }) {
  assert(/^\d+$/.test(propertyId), 'invalid_analytics_property');
  const range = dates(start, end);
  const property = 'properties/' + propertyId;
  const identity = await api(ADMIN + property);
  assert(identity.displayName === PROPERTY_NAME && identity.timeZone === 'Asia/Tokyo',
    'unexpected_analytics_property');
  const registered = await api(DATA + property + '/metadata');
  const available = new Set((registered.dimensions || []).map(value => value.apiName));
  const specifications = [
    { name: 'totals', dimensions: [], metrics: ['activeUsers', 'sessions', 'engagedSessions', 'screenPageViews', 'eventCount'] },
    { name: 'source_medium_channel', dimensions: ['sessionSource', 'sessionMedium', 'sessionDefaultChannelGroup'], metrics: ['sessions', 'engagedSessions', 'eventCount'] },
    { name: 'landing', dimensions: ['landingPage'], metrics: ['sessions', 'engagedSessions', 'eventCount'] },
    { name: 'source_categories', dimensions: ['customEvent:source_category', 'customEvent:page_kind'], metrics: ['eventCount'] },
    { name: 'event_destinations', dimensions: ['eventName', 'customEvent:destination', 'customEvent:page_kind', 'customEvent:source_category'], metrics: ['eventCount'] },
  ];
  const reports = {};
  for (const specification of specifications) {
    const missing = specification.dimensions.filter(name => name.startsWith('customEvent:') && !available.has(name));
    if (missing.length) {
      reports[specification.name] = { status: 'custom_dimensions_pending', missingDimensions: missing, rows: null };
      continue;
    }
    try {
      const value = await api(DATA + property + ':runReport', {
        method: 'POST', body: request(range, specification.dimensions, specification.metrics),
      });
      const observed = rows(value);
      reports[specification.name] = { status: observed.length ? 'observed' : 'empty',
        rows: observed, apiRowCount: value.rowCount || 0,
        truncated: (value.rowCount || 0) > (value.rows || []).length,
        metadata: metadata(value.metadata) };
    } catch (error) {
      reports[specification.name] = { status: 'api_error', httpStatus: error.status || null, rows: null };
    }
  }
  let searchConsole = { status: 'not_requested' };
  if (gsc) {
    try {
      const base = 'https://www.googleapis.com/webmasters/v3/';
      const inventory = await api(base + 'sites');
      const properties = (inventory.siteEntry || []).map(value => value.siteUrl);
      const site = properties.includes(SITE + '/') ? SITE + '/'
        : properties.includes('sc-domain:s21g.com') ? 'sc-domain:s21g.com' : null;
      if (!site) searchConsole = { status: 'existing_site_not_authorized' };
      else {
        const result = await api(base + 'sites/' + encodeURIComponent(site) + '/searchAnalytics/query', {
          method: 'POST', body: { ...range, dimensions: ['date'], type: 'web', dataState: 'final',
            rowLimit: 1000, dimensionFilterGroups: [{ filters: [{ dimension: 'page', operator: 'includingRegex',
              expression: '^https://idobata\\.s21g\\.com(?:/|$)' }] }] },
        });
        searchConsole = { status: result.rows?.length ? 'observed' : 'empty', site,
          rows: (result.rows || []).map(value => {
            const date = value.keys?.[0];
            assert(/^\d{4}-\d{2}-\d{2}$/.test(date), 'invalid_search_console_date');
            return { date, clicks: value.clicks, impressions: value.impressions, ctr: value.ctr, position: value.position };
          }), metadata: metadata(result.metadata), queryTextRequested: false };
      }
    } catch (error) { searchConsole = { status: 'api_error', httpStatus: error.status || null, rows: null }; }
  }
  return { version: 1, fetchedAt: new Date().toISOString(), propertyId, site: SITE, range, timeZone: 'Asia/Tokyo',
    status: Object.values(reports).some(value => value.status === 'api_error') ? 'partial' : 'completed',
    allowedEvents: EVENTS, reports, searchConsole,
    interpretation: ['Empty means no reported rows, not proof of no visits. Recent data and custom dimensions may be delayed.',
      'Thresholding, sampling and truncation are reported separately; API errors are never converted to zero.',
      'No synthetic events are sent by these tools; QA must suppress collection before network dispatch.',
      'Only fixed public categories are retained; unknown sources and paths are combined as other.',
      'Users/sessions are analytics estimates, not authenticated Agent identities or P2P contributions.'] };
}

export async function selfTest() {
  const range = dates('2026-11-01', '2026-11-03');
  for (const pair of [['2026-02-30', '2026-11-03'], ['2026-11-03', '2026-11-01']]) {
    let rejected = false;
    try { dates(...pair); } catch { rejected = true; }
    assert(rejected, 'invalid_date_was_accepted');
  }
  const prepared = request(range, ['landingPage'], ['sessions']);
  assert(!JSON.stringify(prepared).includes('PlusQueryString') && prepared.dimensionFilter.filter.inListFilter.values.length === 2,
    'report_includes_query_or_unapproved_events');
  const masked = rows({ dimensionHeaders: [{ name: 'landingPage' }, { name: 'sessionSource' }], metricHeaders: [{ name: 'sessions' }],
    rows: [{ dimensionValues: [{ value: '/private/path?secret=sentinel' }, { value: 'unknown-private-host' }], metricValues: [{ value: '2' }] }] });
  assert(masked[0].landingPage === 'other' && masked[0].sessionSource === 'other', 'private_dimension_leaked');
  const api = async url => {
    if (url.startsWith(ADMIN)) return { displayName: PROPERTY_NAME, timeZone: 'Asia/Tokyo' };
    if (url.endsWith('/metadata')) return { dimensions: [] };
    return { rows: [], rowCount: 0, metadata: { subjectToThresholding: true } };
  };
  const result = await report(api, { propertyId: '2', start: range.startDate, end: range.endDate });
  assert(result.reports.totals.status === 'empty' && result.reports.totals.metadata.subjectToThresholding,
    'empty_or_threshold_state_lost');
  assert(result.reports.event_destinations.status === 'custom_dimensions_pending', 'pending_dimensions_reported_as_zero');
  const failing = await report(async url => {
    if (url.endsWith(':runReport')) throw Object.assign(new Error('private API response'), { status: 403 });
    return api(url);
  }, { propertyId: '2', start: range.startDate, end: range.endDate });
  assert(failing.status === 'partial' && failing.reports.totals.status === 'api_error'
    && !JSON.stringify(failing).includes('private API response'), 'api_error_reported_as_zero_or_leaked');
  return { status: 'passed', checks: ['date_bounds', 'fixed_event_filter', 'no_query_dimension',
    'unknown_sources_paths_redacted', 'empty_threshold_separate', 'pending_dimensions_not_zero', 'api_error_not_zero'], liveRequests: 0 };
}

async function main() {
  let args;
  try { args = parseArgs({ options: { property: { type: 'string', default: DEFAULT_PROPERTY },
    start: { type: 'string' }, end: { type: 'string' }, output: { type: 'string' },
    gsc: { type: 'boolean', default: false }, 'self-test': { type: 'boolean', default: false } } }).values; }
  catch { throw new Error('invalid_report_arguments'); }
  if (args['self-test']) return console.log(JSON.stringify(await selfTest()));
  dates(args.start, args.end);
  const scopes = ['https://www.googleapis.com/auth/analytics.readonly'];
  if (args.gsc) scopes.push('https://www.googleapis.com/auth/webmasters.readonly');
  const result = await report(await googleClient(scopes), { propertyId: args.property, ...args });
  if (args.output) await writeFile(args.output, JSON.stringify(result, null, 2) + '\n', { mode: 0o600 });
  console.log(JSON.stringify(result));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => { console.error(JSON.stringify({ status: 'failed', error: publicError(error) })); process.exitCode = 1; });
}
