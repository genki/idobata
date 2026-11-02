/* Only fixed page and navigation categories cross into the GA sender frame. */
(() => {
  'use strict';
  const STOP_KEY = 'idobata-analytics-disabled';
  const destinations = new Set(['agent_guide', 'llms_index', 'agent_descriptor', 'participation_question', 'repository', 'release', 'copy_install']);
  const pageKind = ({ '/': 'home', '/docs/': 'docs' })[location.pathname];
  const id = document.querySelector('meta[name="idobata-ga-measurement-id"]')?.content.trim() || '';
  let frame = null, ready = false, stopped = false, navigation = null, navigationSerial = 0;
  const pending = [];

  function disabled() {
    if (stopped || window.__IDOBATA_ANALYTICS_DISABLED__ === true
        || navigator.globalPrivacyControl === true
        || [navigator.doNotTrack, window.doNotTrack, navigator.msDoNotTrack].some(v => v === '1' || v === 'yes')) return true;
    try {
      if (new URLSearchParams(location.search).getAll('analytics').includes('off')) {
        sessionStorage.setItem(STOP_KEY, '1'); return true;
      }
      return sessionStorage.getItem(STOP_KEY) === '1';
    } catch { return true; }
  }

  function sourceCategory(value) {
    if (!value) return 'direct';
    try {
      const u = new URL(value);
      if (!['https:', 'http:'].includes(u.protocol) || u.username || u.password) return 'other';
      const groups = {
        google: ['google.com', 'www.google.com', 'google.co.jp', 'www.google.co.jp'],
        bing: ['bing.com', 'www.bing.com'], github: ['github.com', 'www.github.com'],
        chatgpt: ['chatgpt.com', 'www.chatgpt.com', 'chat.openai.com'], claude: ['claude.ai', 'www.claude.ai'],
        gemini: ['gemini.google.com'], deepseek: ['deepseek.com', 'www.deepseek.com', 'chat.deepseek.com'],
        s21g: ['s21g.com', 'www.s21g.com', 'tenki.s21g.com'], internal: ['idobata.s21g.com'],
      };
      return Object.keys(groups).find(key => groups[key].includes(u.hostname)) || 'other';
    } catch { return 'other'; }
  }

  function status(text) {
    document.querySelectorAll('[data-analytics-status]').forEach(node => { node.textContent = text; });
  }

  function stop() {
    stopped = true; pending.length = 0;
    try { sessionStorage.setItem(STOP_KEY, '1'); } catch { /* In-memory stop still applies. */ }
    if (frame) {
      try {
        // Set synchronously before removal; an async message may lose the
        // race with the sender's unload flush.
        frame.contentWindow['ga-disable-' + id] = true;
        frame.contentWindow.postMessage({ type: 'idobata-analytics-stop', version: 1 }, location.origin);
      } catch { /* Removal still stops future sender work. */ }
      frame.remove(); frame = null;
    }
    ready = false;
    status('このセッションのブラウザ解析（GA4）は停止しています。');
    document.querySelectorAll('[data-analytics-disable]').forEach(node => { node.disabled = true; });
    navigation?.finish();
  }

  document.querySelectorAll('[data-analytics-disable]').forEach(node => node.addEventListener('click', stop));
  if (disabled()) { stop(); return; }
  if (!pageKind || !/^G-[A-Z0-9]{6,16}$/.test(id)) { status('ブラウザ解析（GA4）は未設定です。'); return; }
  if (window.gtag || document.querySelector('script[src*="googletagmanager.com"]')) {
    status('ブラウザ解析（GA4）は起動していません。'); return;
  }

  function send(event, destination, navigationId) {
    if (disabled()) { stop(); return; }
    const message = { type: 'idobata-analytics-event', version: 1, event };
    if (event === 'navigation_click') {
      if (!destinations.has(destination)) return;
      message.destination = destination;
      if (navigationId) message.navigation_id = navigationId;
    }
    if (ready && frame) frame.contentWindow.postMessage(message, location.origin);
    else if (pending.length < 32) pending.push(message);
  }

  window.addEventListener('message', event => {
    if (!frame || event.source !== frame.contentWindow || event.origin !== location.origin || event.data?.version !== 1) return;
    if (event.data.type === 'idobata-analytics-dispatched') {
      if (navigation && event.data.navigation_id === navigation.id) navigation.finish();
      return;
    }
    if (event.data.type !== 'idobata-analytics-ready' || ready) return;
    if (disabled()) { stop(); return; }
    frame.contentWindow.postMessage({ type: 'idobata-analytics-init', version: 1,
      measurement_id: id, page_kind: pageKind, source_category: sourceCategory(document.referrer) }, location.origin);
    ready = true;
    for (const message of pending.splice(0)) frame.contentWindow.postMessage(message, location.origin);
    status('ブラウザ解析（GA4）が有効です。下の操作でこのセッション中は停止できます。');
  });
  document.addEventListener('click', event => {
    const node = event.target.closest?.('[data-analytics-destination]');
    if (!node) return;
    const destination = node.getAttribute('data-analytics-destination');
    if (!destinations.has(destination)) return;
    const anchor = node.closest('a');
    let url;
    try { if (anchor) url = new URL(anchor.href); } catch { /* Preserve ordinary navigation. */ }
    if (!ready || disabled() || event.defaultPrevented || event.button !== 0
        || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey
        || !anchor || anchor.hasAttribute('download') || (anchor.target && anchor.target !== '_self')
        || !url || !['http:', 'https:'].includes(url.protocol)
        || (url.origin === location.origin && url.pathname === location.pathname && url.search === location.search)) {
      send('navigation_click', destination); return;
    }
    // Same-tab unload can beat an asynchronous frame message. Wait only for
    // the SDK callback, capped at 100ms; never hold up an unready/blocked tag.
    event.preventDefault(); navigation?.cancel();
    const number = ++navigationSerial;
    let finished = false;
    const finish = () => {
      if (finished) return;
      finished = true; clearTimeout(timer);
      if (navigation?.id === number) navigation = null;
      location.assign(url.href);
    };
    const timer = setTimeout(finish, 100);
    navigation = { id: number, finish, cancel() { finished = true; clearTimeout(timer); navigation = null; } };
    try { send('navigation_click', destination, number); } catch { finish(); }
  });
  frame = document.createElement('iframe');
  frame.src = '/analytics-frame.html';
  frame.hidden = true; frame.tabIndex = -1;
  frame.title = 'Browser analytics sender';
  frame.referrerPolicy = 'no-referrer';
  frame.dataset.idobataAnalyticsSender = '1';
  frame.setAttribute('aria-hidden', 'true');
  send('page_view');
  document.body.appendChild(frame);
})();
