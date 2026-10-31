'use strict';
// 信頼の起点は配備時に固定する。feed内の鍵を自動的に採用しない。
const b64bytes = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
function canonical(value) {
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  if (value && typeof value === 'object') return '{' + Object.keys(value).sort().map(k => JSON.stringify(k) + ':' + canonical(value[k])).join(',') + '}';
  return JSON.stringify(value);
}
async function verifySigned(doc, domain, trusted) {
  if (doc?.public_key !== trusted || typeof doc.signature !== 'string') throw Error('signer');
  const protobuf = b64bytes(trusted);
  if (protobuf.length !== 36 || protobuf[0] !== 8 || protobuf[1] !== 1 || protobuf[2] !== 18 || protobuf[3] !== 32) throw Error('key');
  const key = await crypto.subtle.importKey('raw', protobuf.slice(4), { name: 'Ed25519' }, false, ['verify']);
  const input = new TextEncoder().encode(domain + '\0' + canonical(doc.signed));
  if (!await crypto.subtle.verify('Ed25519', key, b64bytes(doc.signature), input)) throw Error('signature');
}
window.verifyIdobataFeed = async function (doc, old, allowExpired = false) {
  const trust = window.IDOBATA_TRUST;
  let authorizedKeys = null;
  let trustCheckpoint = null;
  if (trust.root) {
    await verifySigned(trust.bundle, 'idobata.trust.v1', trust.root);
    const t = trust.bundle.signed;
    const now = Date.now() / 1000;
    if (t.version !== 1 || !Number.isSafeInteger(t.revision) || t.revision < 1 || t.issued_at > now + 300
      || t.expires_at <= now || t.expires_at - t.issued_at > 90 * 86400
      || !Array.isArray(t.keys) || !t.keys.length || t.keys.length > 16 || !Array.isArray(t.revoked)) throw Error('trust');
    const hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical(t)))))
      .map(b => b.toString(16).padStart(2, '0')).join('');
    if (old?.trust_revision && (t.revision < old.trust_revision || (t.revision === old.trust_revision && hash !== old.trust_digest))) throw Error('trust rollback');
    authorizedKeys = (key, at) => !t.revoked.includes(key) && t.keys.some(g => g.public_key === key && g.not_before <= at && at < g.not_after);
    trustCheckpoint = { trust_revision: t.revision, trust_digest: hash };
    if (!authorizedKeys(doc.public_key, now)) throw Error('revoked signer');
  }
  const trusted = authorizedKeys ? doc.public_key : trust.publisher;
  await verifySigned(doc, 'idobata.public-feed.v2', trusted);
  const m = doc.signed;
  const now = Date.now() / 1000;
  const at = allowExpired ? Math.min(now, m.expires_at - 1) : now;
  if (m.version !== 2 || !Number.isSafeInteger(m.revision) || m.revision < 1
    || !Number.isSafeInteger(m.issued_at) || !Number.isSafeInteger(m.expires_at)
    || m.issued_at > now + 300 || m.expires_at <= at || m.expires_at <= m.issued_at
    || m.expires_at - m.issued_at > 604800 || !Array.isArray(m.feed?.posts)
    || m.count !== m.feed.posts.length || m.feed.updated_at > m.issued_at
    || !Array.isArray(m.withdrawn) || m.withdrawn.length > 4096
    || m.withdrawn.some(id => !/^[a-f0-9]{64}$/.test(id))) throw Error('manifest');
  const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(canonical(m)))))
    .map(b => b.toString(16).padStart(2, '0')).join('');
  if (old && (m.revision < old.revision || (m.revision === old.revision && digest !== old.digest))) throw Error('rollback');
  for (const post of m.feed.posts) {
    if (post.signed?.policy_id !== window.IDOBATA_TRUST.policy || m.withdrawn.includes(post.signed?.id)) throw Error('policy');
    if (authorizedKeys && !authorizedKeys(post.public_key, post.signed.published_at)) throw Error('post key revoked');
    await verifySigned(post, 'idobata.public-post.v1', authorizedKeys ? post.public_key : trusted);
  }
  return { feed: m.feed, checkpoint: { revision: m.revision, digest, ...trustCheckpoint }, generated: m.issued_at, expires: m.expires_at, expired: m.expires_at <= now };
};
