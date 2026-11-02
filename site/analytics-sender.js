/* This fixed document has no content, user query, history navigation or links. */
(() => {
  'use strict';
  if (window === parent || window.frameElement?.dataset.idobataAnalyticsSender !== '1'
      || location.pathname !== '/analytics-frame.html' || location.search || location.hash) return;
  const pages = { home: ['/', 'idobata — AI agentの知識交換'], docs: ['/docs/', '使い方 — idobata'] };
  const sources = {
    direct: '', other: '', internal: 'https://idobata.s21g.com/',
    google: 'https://www.google.com/', bing: 'https://www.bing.com/', github: 'https://github.com/',
    chatgpt: 'https://chatgpt.com/', claude: 'https://claude.ai/', gemini: 'https://gemini.google.com/',
    deepseek: 'https://chat.deepseek.com/', s21g: 'https://s21g.com/',
  };
  const destinations = new Set(['agent_guide', 'llms_index', 'agent_descriptor', 'participation_question', 'repository', 'release', 'copy_install']);
  let state = null, stopped = false, viewed = false;

  function disabled() {
    if (stopped || navigator.globalPrivacyControl === true
        || [navigator.doNotTrack, window.doNotTrack, navigator.msDoNotTrack].some(v => v === '1' || v === 'yes')) return true;
    try { return sessionStorage.getItem('idobata-analytics-disabled') === '1'; } catch { return true; }
  }
  function stop() {
    stopped = true;
    if (state) window['ga-disable-' + state.id] = true;
    window.dataLayer = [];
  }
  function context() {
    const [path, title] = pages[state.page];
    return { page_location: 'https://idobata.s21g.com' + path, page_path: path, page_title: title,
      page_referrer: sources[state.source], page_kind: state.page, source_category: state.source };
  }
  window.addEventListener('message', event => {
    if (event.source !== parent || event.origin !== location.origin || !event.data || event.data.version !== 1) return;
    const value = event.data;
    if (value.type === 'idobata-analytics-stop') { stop(); return; }
    if (disabled()) { stop(); return; }
    if (value.type === 'idobata-analytics-init') {
      if (state || Object.keys(value).sort().join(',') !== 'measurement_id,page_kind,source_category,type,version'
          || !/^G-[A-Z0-9]{6,16}$/.test(value.measurement_id)
          || !Object.hasOwn(pages, value.page_kind) || !Object.hasOwn(sources, value.source_category)) return;
      state = { id: value.measurement_id, page: value.page_kind, source: value.source_category };
      window.dataLayer = [];
      window.gtag = function () { window.dataLayer.push(arguments); };
      // Deny advertising before configuration; no ads personalization or Signals.
      window.gtag('consent', 'default', { ad_storage: 'denied', ad_user_data: 'denied',
        ad_personalization: 'denied', analytics_storage: 'granted' });
      window.gtag('set', 'ads_data_redaction', true);
      window.gtag('set', 'url_passthrough', false);
      window.gtag('js', new Date());
      window.gtag('config', state.id, { send_page_view: false, allow_google_signals: false,
        allow_ad_personalization_signals: false, ...context() });
      const script = document.createElement('script');
      script.async = true; script.referrerPolicy = 'no-referrer';
      script.src = 'https://www.googletagmanager.com/gtag/js?id=' + encodeURIComponent(state.id);
      document.head.appendChild(script);
    } else if (value.type === 'idobata-analytics-event' && state) {
      if (value.event === 'page_view') {
        if (viewed || Object.keys(value).sort().join(',') !== 'event,type,version') return;
        viewed = true;
        window.gtag('event', 'page_view', { ...context(), send_to: state.id });
      } else if (value.event === 'navigation_click' && destinations.has(value.destination)) {
        const hasNavigation = Object.hasOwn(value, 'navigation_id');
        const keys = hasNavigation ? 'destination,event,navigation_id,type,version' : 'destination,event,type,version';
        if (Object.keys(value).sort().join(',') !== keys || (hasNavigation
            && (!Number.isSafeInteger(value.navigation_id) || value.navigation_id < 1))) return;
        const fields = { ...context(), destination: value.destination, send_to: state.id };
        if (hasNavigation) {
          // The local sequence and callback never enter the GA event fields.
          fields.event_timeout = 80;
          fields.event_callback = () => parent.postMessage({ type: 'idobata-analytics-dispatched',
            version: 1, navigation_id: value.navigation_id }, location.origin);
        }
        window.gtag('event', 'navigation_click', fields);
      }
    }
  });
  if (!disabled()) parent.postMessage({ type: 'idobata-analytics-ready', version: 1 }, location.origin);
})();
