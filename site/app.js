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
  return data.posts.map(e => e.signed);
}
function render() {
  list.replaceChildren();
  for (const p of posts.slice(0, visible)) {
    const d = p.content;
    const article = node('article', undefined, 'post');
    article.id = 'post-' + p.id;
    const meta = node('div', undefined, 'post-meta');
    const time = node('time', formatter.format(new Date(p.published_at * 1000)) + ' JST');
    time.dateTime = new Date(p.published_at * 1000).toISOString();
    meta.append(time, node('span', kinds[d.kind], 'post-kind'));
    const heading = node('h3');
    const link = node('a', d.title);
    link.href = '#post-' + p.id;
    heading.append(link);
    article.append(meta, heading, node('p', d.body, 'post-body'));
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
    icon.src = '/icon.png'; icon.alt = ''; icon.width = 17; icon.height = 17;
    author.append(icon, node('span', 'idobata 開発'));
    article.append(author);
    list.append(article);
  }
  more.hidden = visible >= posts.length;
}
function revealHash() {
  if (!location.hash.startsWith('#post-')) return;
  const index = posts.findIndex(p => '#post-' + p.id === location.hash);
  if (index < 0) return;
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
    if (text.length > 256 * 1024) throw new Error('size');
    const data = JSON.parse(text);
    const next = validateFeed(data);
    posts = next;
    visible = 5;
    render();
    updated.textContent = '公開更新 ' + formatter.format(new Date(data.updated_at * 1000)) + ' JST';
    status.textContent = posts.length ? '' : '公開投稿はまだありません。';
    revealHash();
  } catch {
    status.className = 'feed-error';
    status.textContent = posts.length ? '最新の投稿を取得できませんでした。前回取得した内容を表示しています。「投稿を再取得」でやり直せます。' : '公開投稿を取得できませんでした。「投稿を再取得」でやり直せます。';
  } finally {
    clearTimeout(timeout);
    refresh.disabled = false;
  }
}
if (list) {
  refresh.addEventListener('click', loadPosts);
  more.addEventListener('click', () => { visible += 5; render(); });
  window.addEventListener('hashchange', revealHash);
  loadPosts();
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
