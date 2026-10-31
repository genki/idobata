'use strict';
const list = document.getElementById('post-list');
const status = document.getElementById('feed-status');
const updated = document.getElementById('feed-updated');
const more = document.getElementById('more-posts');
const refresh = document.getElementById('refresh');
const kinds = { observation: '開発ノート', question: '問い', answer: '回答', proposal: '提案' };
const formatter = new Intl.DateTimeFormat('ja-JP', { timeZone: 'Asia/Tokyo', year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false });
let posts = [];
let visible = 5;
let checkpoint = null;
let verifiedExpiry = 0;
const checkpointKey = 'idobata-feed-checkpoint:' + (window.IDOBATA_TRUST.root || window.IDOBATA_TRUST.publisher);
const cacheKey = 'idobata-feed-cache:' + (window.IDOBATA_TRUST.root || window.IDOBATA_TRUST.publisher);
try { checkpoint = JSON.parse(localStorage.getItem(checkpointKey) || 'null'); } catch { /* 保存不能時はセッション内で照合する。 */ }
const query = document.getElementById('post-query');
const kindFilter = document.getElementById('post-kind');
function filteredPosts() {
  const q = query.value.trim().toLocaleLowerCase();
  return posts.filter(p => (!kindFilter.value || p.content.kind === kindFilter.value)
    && (!q || (p.content.title + '\n' + p.content.body).toLocaleLowerCase().includes(q)));
}
function node(tag, text, className) {
  const e = document.createElement(tag);
  if (text !== undefined) e.textContent = text;
  if (className) e.className = className;
  return e;
}
function validTime(t) { return Number.isSafeInteger(t) && t > 0 && t <= Date.now() / 1000 + 300; }
function safeURL(value) {
  try {
    const u = new URL(value);
    return ['https:', 'http:'].includes(u.protocol) && !u.username && !u.password ? u : null;
  } catch { return null; }
}
function validateFeed(data) {
  if (data?.version !== 1 || !validTime(data.updated_at) || !Array.isArray(data.posts) || data.posts.length > 50) throw new Error('feed');
  const ids = new Set();
  let previous = data.updated_at;
  for (const envelope of data.posts) {
    const p = envelope?.signed;
    const d = p?.content;
    if (p?.version !== 1 || !/^[0-9a-f]{64}$/.test(p.id) || ids.has(p.id)
      || !validTime(p.published_at) || p.published_at > previous
      || typeof d?.title !== 'string' || !d.title.length || d.title.length > 256
      || typeof d?.body !== 'string' || !d.body.length || d.body.length > 8192
      || !Object.hasOwn(kinds, d.kind) || !Array.isArray(d.references) || d.references.length > 4
      || d.references.some(r => typeof r !== 'string' || r.length > 2048 || !safeURL(r))) throw new Error('post');
    ids.add(p.id);
    previous = p.published_at;
  }
  return data.posts.map(e => e.signed).filter(p => p.published_at + 30 * 86400 >= Date.now() / 1000);
}
function render() {
  list.replaceChildren();
  const selected = filteredPosts();
  document.getElementById('filter-status').textContent = posts.length && !selected.length ? '条件に合う公開投稿はありません。保持範囲は最新50件・最大30日です。' : '';
  for (const p of selected.slice(0, visible)) {
    const d = p.content;
    const article = node('article', undefined, 'post');
    article.id = 'post-' + p.id;
    const meta = node('div', undefined, 'post-meta');
    const time = node('time', formatter.format(new Date(p.published_at * 1000)) + ' JST');
    time.dateTime = new Date(p.published_at * 1000).toISOString();
    meta.append(time, node('span', p.origin && d.kind === 'observation' ? '観測' : kinds[d.kind], 'post-kind'));
    const heading = node('h3');
    const link = node('a', d.title);
    link.href = '#post-' + p.id;
    heading.append(link);
    article.append(meta, heading, node('p', d.body, 'post-body'));
    if (p.origin?.reply_to) {
      const reply = node('a', '返信先を表示 →', 'text-link');
      reply.href = '#post-' + p.origin.reply_to;
      if (posts.some(p => p.id === reply.hash.slice(6))) article.append(reply);
      else article.append(node('p', '返信先は現在の保持範囲外です。', 'fine'));
    }
    if (d.kind === 'question') {
      const children = posts.filter(child => child.origin?.reply_to === p.id).slice().reverse();
      let questionState = '未解決';
      for (const child of children) {
        if (child.origin.resolution) questionState = child.origin.resolution === 'resolved' ? '解決済み' : '未解決';
        else if (child.content.kind === 'answer' && questionState !== '解決済み') questionState = '回答あり';
      }
      meta.append(node('span', questionState, 'post-kind'));
    }
    if (d.references.length) {
      const links = node('div', undefined, 'post-links');
      for (const ref of d.references) {
        const u = safeURL(ref);
        const a = node('a', (u.hostname === 'github.com' ? '関連するソース・仕様' : u.hostname) + ' ↗');
        a.href = u.href;
        a.rel = 'noreferrer';
        links.append(a);
      }
      article.append(links);
    }
    const author = node('div', undefined, 'post-author');
    const icon = node('img');
    icon.src = '/icon.webp'; icon.alt = ''; icon.width = 17; icon.height = 17;
    author.append(icon, node('span', p.origin ? p.origin.author + ' · 公開P2P' : 'idobata 開発'));
    article.append(author);
    list.append(article);
  }
  more.hidden = visible >= selected.length;
}
function revealHash() {
  if (!location.hash.startsWith('#post-')) return;
  const index = posts.findIndex(p => '#post-' + p.id === location.hash);
  if (index < 0) return;
  if (query.value || kindFilter.value) { query.value = ''; kindFilter.value = ''; render(); }
  if (index >= visible) { visible = index + 1; render(); }
  document.getElementById('post-' + posts[index].id)?.scrollIntoView();
}
async function loadPosts() {
  refresh.disabled = true;
  status.className = '';
  status.textContent = '公開投稿を読み込んでいます…';
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 12000);
  try {
    const response = await fetch('/posts.json', { signal: controller.signal, cache: 'no-cache', credentials: 'omit' });
    if (!response.ok) throw new Error('http');
    const text = await response.text();
    if (new TextEncoder().encode(text).length > 256 * 1024) throw new Error('size');
    const data = JSON.parse(text);
    const verified = await window.verifyIdobataFeed(data, checkpoint);
    const next = validateFeed(verified.feed);
    verifiedExpiry = verified.expires;
    posts = next;
    visible = 5;
    render();
    checkpoint = verified.checkpoint;
    try { localStorage.setItem(checkpointKey, JSON.stringify(checkpoint)); localStorage.setItem(cacheKey, text); } catch { /* 同じセッションでは照合を継続する。 */ }
    updated.textContent = '投稿更新 ' + formatter.format(new Date(verified.feed.updated_at * 1000)) + ' JST / 一覧検証済み rev.' + checkpoint.revision + ' / 生成 ' + formatter.format(new Date(verified.generated * 1000)) + ' JST';
    status.textContent = posts.length ? '' : '公開投稿はまだありません。';
    revealHash();
  } catch {
    posts = posts.filter(p => p.published_at + 30 * 86400 >= Date.now() / 1000); render();
    if (!posts.length) {
      try {
        const cached = JSON.parse(localStorage.getItem(cacheKey) || 'null');
        const previous = await window.verifyIdobataFeed(cached, checkpoint, true);
        posts = validateFeed(previous.feed); render();
        updated.textContent = '保存済み一覧 rev.' + previous.checkpoint.revision + ' / 生成 ' + formatter.format(new Date(previous.generated * 1000)) + ' JST' + (previous.expired ? ' / 有効期限切れ' : '');
      } catch { /* 検証できない保存内容は表示しない。 */ }
    }
    if (verifiedExpiry && verifiedExpiry <= Date.now()/1000 && !updated.textContent.includes('有効期限切れ')) updated.textContent += ' / 有効期限切れ';
    status.className = 'feed-error';
    status.textContent = posts.length ? '最新の投稿を取得できませんでした。前回取得した内容を表示しています。「投稿を再取得」でやり直せます。' : '公開投稿を取得できませんでした。「投稿を再取得」でやり直せます。';
  } finally {
    clearTimeout(timeout);
    refresh.disabled = false;
  }
}
if (list) {
  for (const control of [query, kindFilter]) control.addEventListener('input', () => { visible = 5; render(); });
  refresh.addEventListener('click', loadPosts);
  more.addEventListener('click', () => { visible += 5; render(); });
  window.addEventListener('hashchange', revealHash);
  loadPosts();
  const autoRefresh = setInterval(() => { if (!document.hidden && !refresh.disabled) loadPosts(); }, 60000);
  window.addEventListener('pagehide', () => clearInterval(autoRefresh), { once: true });
}
const copy = document.getElementById('copy-install');
copy?.addEventListener('click', async () => {
  const result = document.getElementById('copy-status');
  try {
    await navigator.clipboard.writeText(document.getElementById('install-command').textContent);
    result.textContent = 'ビルド手順をコピーしました。';
  } catch {
    result.textContent = 'コピーできませんでした。上の手順を選択してコピーしてください。';
  }
});
