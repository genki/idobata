#!/usr/bin/env node
// Default: inventory/plan only. --apply changes only idobata's dedicated GA4 property.
import { readFile, writeFile } from 'node:fs/promises';
import { createSign } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';

export const SITE = 'https://idobata.s21g.com';
export const PROPERTY_NAME = 'idobata.s21g.com - GA4';
export const DIMENSIONS = ['destination', 'source_category', 'page_kind'];
export function publicError(error) {
  return typeof error?.message === 'string' && /^[a-z0-9_]+$/.test(error.message)
    ? error.message : 'site_analytics_failed';
}
const ADMIN = 'https://analyticsadmin.googleapis.com/v1alpha/';
const ENHANCED = ['streamEnabled', 'scrollsEnabled', 'outboundClicksEnabled', 'siteSearchEnabled',
  'videoEngagementEnabled', 'fileDownloadsEnabled', 'pageChangesEnabled', 'formInteractionsEnabled'];
const snake = value => value.replace(/[A-Z]/g, letter => '_' + letter.toLowerCase());
const assert = (condition, label) => { if (!condition) throw new Error(label); };

// Same service-account JWT flow as the existing s21g provisioner. Credentials
// and access tokens remain in process memory and are never logged or saved.
export async function googleClient(scopes) {
  assert(process.env.GOOGLE_APPLICATION_CREDENTIALS, 'google_application_credentials_required');
  let key;
  try { key = JSON.parse(await readFile(process.env.GOOGLE_APPLICATION_CREDENTIALS, 'utf8')); }
  catch { throw new Error('google_credentials_unreadable'); }
  assert(key.type === 'service_account' && key.client_email && key.private_key,
    'service_account_credentials_required');
  const now = Math.floor(Date.now() / 1000);
  const encode = value => Buffer.from(JSON.stringify(value)).toString('base64url');
  const assertion = encode({ alg: 'RS256', typ: 'JWT' }) + '.' + encode({
    iss: key.client_email, scope: scopes.join(' '), aud: 'https://oauth2.googleapis.com/token',
    iat: now, exp: now + 3600,
  });
  const signature = createSign('RSA-SHA256').update(assertion).sign(key.private_key, 'base64url');
  const authenticated = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST', body: new URLSearchParams({ grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: assertion + '.' + signature }), signal: AbortSignal.timeout(30000),
  });
  assert(authenticated.ok, 'google_oauth_http_' + authenticated.status);
  const token = (await authenticated.json()).access_token;
  assert(typeof token === 'string' && token, 'google_oauth_token_missing');
  return async (url, { method = 'GET', body } = {}) => {
    const endpoint = new URL(url);
    assert(endpoint.protocol === 'https:' && [
      'analyticsadmin.googleapis.com', 'analyticsdata.googleapis.com', 'www.googleapis.com',
    ].includes(endpoint.hostname), 'google_api_endpoint_not_allowed');
    const response = await fetch(endpoint, {
      method, headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      signal: AbortSignal.timeout(45000), redirect: 'error',
    });
    let value;
    try { value = await response.json(); } catch { throw new Error('google_api_non_json'); }
    if (!response.ok) {
      const error = new Error('google_api_http_' + response.status);
      error.status = response.status;
      throw error;
    }
    return value;
  };
}

async function list(api, path, field) {
  const values = [];
  let next = '';
  for (let count = 0; count < 100; count++) {
    const url = new URL(path, ADMIN);
    url.searchParams.set('pageSize', '200');
    if (next) url.searchParams.set('pageToken', next);
    const page = await api(url.href);
    values.push(...page[field] || []);
    if (!page.nextPageToken) return values;
    assert(page.nextPageToken !== next, 'google_api_pagination_stalled');
    next = page.nextPageToken;
  }
  throw new Error('google_api_page_limit');
}

export async function setup(api, { apply = false, onIdentifiers = () => {} } = {}) {
  const changes = [];
  const mutate = async (path, method, body, label) => {
    assert(apply, 'read_only_setup_attempted_write');
    const value = await api(new URL(path, ADMIN).href, { method, body });
    changes.push(label);
    return value;
  };
  const accounts = await list(api, 'accountSummaries', 'accountSummaries');
  const selected = accounts.filter(account => account.displayName === 's21g.com');
  assert(selected.length === 1, 's21g_account_missing_or_ambiguous');
  const account = selected[0].account || selected[0].name.replace(/^accountSummaries\//, 'accounts/');
  assert(/^accounts\/\d+$/.test(account), 'invalid_account_resource');
  const properties = await list(api, 'properties?filter=' + encodeURIComponent('parent:' + account), 'properties');
  const candidates = properties.filter(property => property.displayName === PROPERTY_NAME);
  assert(candidates.length <= 1, 'idobata_property_ambiguous');
  assert(!properties.some(property => /idobata/i.test(property.displayName || '')
    && property.displayName !== PROPERTY_NAME), 'unexpected_idobata_property_name');
  let property = candidates[0];
  const result = { version: 1, checkedAt: new Date().toISOString(), mode: apply ? 'apply' : 'read_only',
    account, site: SITE, propertyDisplayName: PROPERTY_NAME, accountCount: accounts.length,
    existingPropertyCount: properties.length, changes, plans: [] };
  if (!property) {
    if (!apply) return { ...result, plans: ['create_dedicated_property', 'create_web_stream', 'disable_automatic_measurement', 'disable_google_signals', 'create_fixed_event_dimensions'] };
    property = await mutate('properties', 'POST', { parent: account, displayName: PROPERTY_NAME,
      timeZone: 'Asia/Tokyo', currencyCode: 'JPY', industryCategory: 'OTHER' }, 'create_property');
  }
  assert(/^properties\/\d+$/.test(property.name), 'invalid_property_resource');
  assert(property.parent === account || property.account === account, 'property_account_changed');
  const base = property.name;
  result.propertyId = base.split('/')[1];
  if (property.timeZone !== 'Asia/Tokyo' || property.currencyCode !== 'JPY') {
    result.plans.push('set_timezone_currency');
    if (apply) property = await mutate(base + '?updateMask=time_zone,currency_code', 'PATCH',
      { timeZone: 'Asia/Tokyo', currencyCode: 'JPY' }, 'set_timezone_currency');
  }
  result.timeZone = property.timeZone;
  result.currencyCode = property.currencyCode;
  const streams = await list(api, base + '/dataStreams', 'dataStreams');
  assert(streams.every(stream => stream.type === 'WEB_DATA_STREAM'
    && stream.webStreamData?.defaultUri?.replace(/\/$/, '') === SITE), 'dedicated_property_has_other_streams');
  assert(streams.length <= 1, 'idobata_web_stream_ambiguous');
  let stream = streams[0];
  if (!stream) {
    if (!apply) return { ...result, plans: [...result.plans, 'create_web_stream'] };
    stream = await mutate(base + '/dataStreams', 'POST', { displayName: 'idobata Web',
      type: 'WEB_DATA_STREAM', webStreamData: { defaultUri: SITE } }, 'create_web_stream');
  }
  assert(new RegExp('^' + base + '/dataStreams/\\d+$').test(stream.name), 'invalid_web_stream_resource');
  assert(/^G-[A-Z0-9]+$/.test(stream.webStreamData?.measurementId), 'measurement_id_missing');
  result.streamId = stream.name.split('/').at(-1);
  result.measurementId = stream.webStreamData.measurementId;
  onIdentifiers({ propertyId: result.propertyId, streamId: result.streamId, measurementId: result.measurementId });
  const enhancedPath = stream.name + '/enhancedMeasurementSettings';
  let enhanced = await api(ADMIN + enhancedPath);
  if (ENHANCED.some(field => enhanced[field] === true)) {
    result.plans.push('disable_enhanced_measurement');
    if (apply) enhanced = await mutate(enhancedPath + '?updateMask=' + ENHANCED.map(snake).join(','),
      'PATCH', Object.fromEntries(ENHANCED.map(field => [field, false])), 'disable_enhanced_measurement');
  }
  result.enhancedMeasurement = Object.fromEntries(ENHANCED.map(field => [field, enhanced[field] === true]));
  const signalsPath = base + '/googleSignalsSettings';
  let signals = await api(ADMIN + signalsPath);
  if (signals.state !== 'GOOGLE_SIGNALS_DISABLED') {
    result.plans.push('disable_google_signals');
    if (apply) signals = await mutate(signalsPath + '?updateMask=state', 'PATCH',
      { state: 'GOOGLE_SIGNALS_DISABLED' }, 'disable_google_signals');
  }
  result.googleSignalsState = signals.state || 'GOOGLE_SIGNALS_STATE_UNSPECIFIED';
  const userProvided = await api(ADMIN + base + '/userProvidedDataSettings');
  result.userProvidedData = {
    userProvidedDataCollectionEnabled: userProvided.userProvidedDataCollectionEnabled === true,
    automaticallyDetectedDataCollectionEnabled: userProvided.automaticallyDetectedDataCollectionEnabled === true,
    apiUpdateAvailable: false,
  };
  const links = await list(api, base + '/googleAdsLinks', 'googleAdsLinks');
  result.googleAdsLinkCount = links.length;
  result.adsConfigurationLimit = 'No generic ads-data-collection/personalization update field in the current Admin API. Client consent/flags and any required UI setting are separate.';
  let dimensions = await list(api, base + '/customDimensions', 'customDimensions');
  for (const parameterName of DIMENSIONS) {
    const existing = dimensions.filter(dimension => dimension.parameterName === parameterName);
    assert(existing.length <= 1 && existing.every(dimension => dimension.scope === 'EVENT'), 'custom_dimension_conflict');
    if (!existing.length) {
      result.plans.push('create_dimension_' + parameterName);
      if (apply) dimensions.push(await mutate(base + '/customDimensions', 'POST', {
        parameterName, displayName: parameterName, scope: 'EVENT',
        description: 'Fixed allow-listed public navigation category; no URL, query, text or identifier.',
      }, 'create_dimension_' + parameterName));
    }
  }
  result.eventCustomDimensions = dimensions.filter(dimension => DIMENSIONS.includes(dimension.parameterName))
    .map(({ parameterName, scope }) => ({ parameterName, scope,
      adsPersonalizationSetting: 'not_applicable_EVENT_scope' }));
  result.apiPrivacyChecksPassed = ENHANCED.every(field => enhanced[field] !== true)
    && signals.state === 'GOOGLE_SIGNALS_DISABLED'
    && !result.userProvidedData.userProvidedDataCollectionEnabled
    && !result.userProvidedData.automaticallyDetectedDataCollectionEnabled
    && links.length === 0;
  if (apply) {
    const checked = await api(ADMIN + enhancedPath);
    assert(ENHANCED.every(field => checked[field] !== true), 'enhanced_measurement_still_enabled');
    assert((await api(ADMIN + signalsPath)).state === 'GOOGLE_SIGNALS_DISABLED', 'google_signals_still_enabled');
    assert(result.apiPrivacyChecksPassed, 'privacy_settings_require_separate_operator_action');
  }
  return result;
}

async function main() {
  let args;
  try { args = parseArgs({ options: { apply: { type: 'boolean', default: false },
    output: { type: 'string' }, 'self-test': { type: 'boolean', default: false } } }).values; }
  catch { throw new Error('invalid_setup_arguments'); }
  if (args['self-test']) return console.log(JSON.stringify(await selfTest()));
  const { apply, output } = args;
  const scopes = ['https://www.googleapis.com/auth/analytics.readonly'];
  if (apply) scopes.push('https://www.googleapis.com/auth/analytics.edit');
  const api = await googleClient(scopes);
  const result = await setup(api, { apply, onIdentifiers: identifiers => console.log(JSON.stringify({ stage: 'ga4_identifiers', ...identifiers })) });
  if (output) await writeFile(output, JSON.stringify(result, null, 2) + '\n', { mode: 0o600 });
  console.log(JSON.stringify(result));
}

export async function selfTest() {
  const state = { property: null, stream: null, enhanced: Object.fromEntries(ENHANCED.map(field => [field, true])),
    signals: { state: 'GOOGLE_SIGNALS_ENABLED' }, dimensions: [] };
  const mutations = [];
  const api = async (url, { method = 'GET', body } = {}) => {
    const { pathname } = new URL(url);
    const path = pathname.replace('/v1alpha/', '');
    if (method !== 'GET') mutations.push({ path, method });
    if (path === 'accountSummaries') return { accountSummaries: [{ name: 'accountSummaries/1', account: 'accounts/1', displayName: 's21g.com' }] };
    if (path === 'properties' && method === 'GET') return { properties: [
      { name: 'properties/99', parent: 'accounts/1', displayName: 'unrelated-service' }, ...(state.property ? [state.property] : []),
    ] };
    if (path === 'properties' && method === 'POST') return state.property = { ...body, name: 'properties/2' };
    if (path === 'properties/2/dataStreams' && method === 'GET') return { dataStreams: state.stream ? [state.stream] : [] };
    if (path === 'properties/2/dataStreams' && method === 'POST') return state.stream = { ...body, name: 'properties/2/dataStreams/3', webStreamData: { ...body.webStreamData, measurementId: 'G-TEST' } };
    if (path.endsWith('/enhancedMeasurementSettings')) {
      if (method === 'PATCH') state.enhanced = { ...state.enhanced, ...body };
      return state.enhanced;
    }
    if (path.endsWith('/googleSignalsSettings')) {
      if (method === 'PATCH') state.signals = { ...state.signals, ...body };
      return state.signals;
    }
    if (path.endsWith('/userProvidedDataSettings')) return {};
    if (path.endsWith('/googleAdsLinks')) return {};
    if (path.endsWith('/customDimensions') && method === 'GET') return { customDimensions: state.dimensions };
    if (path.endsWith('/customDimensions') && method === 'POST') {
      const result = { ...body, name: 'properties/2/customDimensions/' + state.dimensions.length };
      state.dimensions.push(result);
      return result;
    }
    throw new Error('unexpected_mock_admin_request');
  };
  const planned = await setup(api);
  assert(mutations.length === 0 && !planned.propertyId, 'default_mode_mutated_property');
  const created = await setup(api, { apply: true });
  assert(created.apiPrivacyChecksPassed && created.measurementId === 'G-TEST', 'mock_setup_not_configured');
  assert(created.eventCustomDimensions.length === 3 && mutations.length === 7, 'unexpected_setup_mutations');
  assert(mutations.every(value => value.path === 'properties' || value.path.startsWith('properties/2/')),
    'setup_modified_another_property');
  const before = mutations.length;
  const repeated = await setup(api, { apply: true });
  assert(mutations.length === before && repeated.changes.length === 0, 'setup_not_idempotent');
  const readonly = await setup(api);
  assert(mutations.length === before && readonly.apiPrivacyChecksPassed, 'read_only_mode_mutated_existing_property');
  return { status: 'passed', checks: ['default_read_only', 'dedicated_property_only', 'privacy_settings_readback',
    'three_event_dimensions', 'repeat_apply_no_mutations', 'existing_property_read_only'], liveRequests: 0 };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => { console.error(JSON.stringify({ status: 'failed', error: publicError(error) })); process.exitCode = 1; });
}
