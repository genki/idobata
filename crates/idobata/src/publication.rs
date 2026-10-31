//! 明示的な公開投稿。P2Pの状態・受信箱・接続情報は読み取らない。
use crate::{
    crypto,
    error::{Error, INVALID, Result},
    scanner::Scanner,
    types::{Draft, Resolution, Signed},
    util,
};
use libp2p::identity;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const MAX_FEED_BYTES: u64 = 256 * 1024;
pub const MAX_POSTS: usize = 50;
const DOMAIN: &str = "idobata.public-post.v1";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicPost {
    pub version: u32,
    pub id: String,
    pub published_at: u64,
    pub policy_id: String,
    pub content: Draft,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin: Option<Origin>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Origin {
    pub message_id: String,
    pub author: String,
    pub reply_to: Option<String>,
    pub resolution: Option<Resolution>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublicEntry {
    pub content: Draft,
    pub published_at: u64,
    pub origin: Origin,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub version: u32,
    pub revision: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub count: usize,
    pub feed: Feed,
    pub withdrawn: Vec<String>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub revision: u64,
    pub digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_revision: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_digest: Option<String>,
}
pub fn seal(
    feed: Feed,
    withdrawn: Vec<String>,
    revision: u64,
    key: &identity::Keypair,
    at: u64,
    ttl: u64,
) -> Result<Signed<Manifest>> {
    seal_with_keys(
        feed,
        withdrawn,
        revision,
        key,
        at,
        ttl,
        &[crypto::public(key)],
    )
}
pub fn seal_with_keys(
    feed: Feed,
    withdrawn: Vec<String>,
    revision: u64,
    key: &identity::Keypair,
    at: u64,
    ttl: u64,
    post_keys: &[String],
) -> Result<Signed<Manifest>> {
    verify_with_keys(&feed, post_keys, at)?;
    if revision == 0
        || revision > 9_007_199_254_740_991
        || !(60..=604800).contains(&ttl)
        || withdrawn.len() > 4096
        || withdrawn.iter().any(|id| !util::valid_id(id))
    {
        return Err(INVALID);
    }
    let signed = Manifest {
        version: 2,
        revision,
        issued_at: at,
        expires_at: at + ttl,
        count: feed.posts.len(),
        feed,
        withdrawn,
    };
    let result = Signed {
        signature: crypto::sign(key, "idobata.public-feed.v2", &signed)?,
        public_key: crypto::public(key),
        signed,
    };
    if util::canonical(&result)?.len() as u64 > MAX_FEED_BYTES {
        return Err(INVALID);
    }
    Ok(result)
}
pub fn verify_manifest(
    doc: &Signed<Manifest>,
    trusted: &str,
    at: u64,
    checkpoint: Option<&Checkpoint>,
) -> Result<Checkpoint> {
    verify_manifest_with_keys(doc, trusted, &[trusted.to_string()], at, checkpoint)
}
pub fn verify_manifest_with_keys(
    doc: &Signed<Manifest>,
    trusted: &str,
    post_keys: &[String],
    at: u64,
    checkpoint: Option<&Checkpoint>,
) -> Result<Checkpoint> {
    let m = &doc.signed;
    if doc.public_key != trusted
        || m.version != 2
        || m.revision == 0
        || m.revision > 9_007_199_254_740_991
        || m.issued_at > at.saturating_add(300)
        || m.expires_at <= at
        || m.expires_at <= m.issued_at
        || m.expires_at - m.issued_at > 604800
        || m.count != m.feed.posts.len()
        || m.feed.updated_at > m.issued_at
        || m.withdrawn.len() > 4096
        || m.withdrawn.iter().any(|id| !util::valid_id(id))
        || m.feed
            .posts
            .iter()
            .any(|p| m.withdrawn.contains(&p.signed.id))
    {
        return Err(INVALID);
    }
    crypto::verify(
        &crypto::public_key(trusted)?,
        "idobata.public-feed.v2",
        m,
        &doc.signature,
    )?;
    verify_with_keys(&m.feed, post_keys, at)?;
    let digest = util::hash(&util::canonical(m)?);
    if let Some(old) = checkpoint
        && (m.revision < old.revision || (m.revision == old.revision && digest != old.digest))
    {
        return Err(Error::new(30, "public_feed_rollback"));
    }
    Ok(Checkpoint {
        revision: m.revision,
        digest,
        trust_revision: None,
        trust_digest: None,
    })
}
pub fn decode(
    bytes: &[u8],
    trusted: &str,
    at: u64,
    allow_expired: bool,
) -> Result<(Feed, Vec<String>, u64)> {
    if let Ok(doc) = serde_json::from_slice::<Signed<Manifest>>(bytes) {
        let check_at = if allow_expired {
            at.min(doc.signed.expires_at.saturating_sub(1))
        } else {
            at
        };
        verify_manifest(&doc, trusted, check_at, None)?;
        Ok((doc.signed.feed, doc.signed.withdrawn, doc.signed.revision))
    } else {
        let feed: Feed = serde_json::from_slice(bytes).map_err(|_| INVALID)?;
        verify(&feed, trusted, at)?;
        Ok((feed, vec![], 0))
    }
}

pub fn import(
    feed: &mut Feed,
    key: &identity::Keypair,
    entries: Vec<PublicEntry>,
    at: u64,
) -> Result<()> {
    import_with_keys(feed, key, entries, at, &[crypto::public(key)])
}
pub fn import_with_keys(
    feed: &mut Feed,
    key: &identity::Keypair,
    entries: Vec<PublicEntry>,
    at: u64,
    post_keys: &[String],
) -> Result<()> {
    verify_with_keys(feed, post_keys, at)?;
    let scanner = Scanner::new()?;
    for e in entries.into_iter().rev() {
        if feed.posts.iter().any(|p| {
            p.signed
                .origin
                .as_ref()
                .is_some_and(|o| o.message_id == e.origin.message_id)
        }) {
            continue;
        }
        validate_origin(&e.origin)?;
        if e.published_at > at + 300 || e.published_at + 30 * 86400 < at {
            return Err(INVALID);
        }
        inspect(&scanner, &e.content)?;
        let signed = PublicPost {
            version: 1,
            id: e.origin.message_id.clone(),
            published_at: e.published_at,
            policy_id: Scanner::policy_id(),
            content: e.content,
            origin: Some(e.origin),
        };
        feed.posts.push(Signed {
            signature: crypto::sign(key, DOMAIN, &signed)?,
            public_key: crypto::public(key),
            signed,
        });
    }
    feed.posts
        .retain(|p| p.signed.published_at + 30 * 86400 >= at);
    feed.posts
        .sort_by_key(|p| std::cmp::Reverse(p.signed.published_at));
    feed.posts.truncate(MAX_POSTS);
    feed.updated_at = feed
        .updated_at
        .max(feed.posts.first().map_or(at, |p| p.signed.published_at));
    Ok(())
}
fn validate_origin(o: &Origin) -> Result<()> {
    if !util::valid_id(&o.message_id)
        || o.author.len() != 14
        || !o.author.starts_with("agent-")
        || !o.author[6..].bytes().all(|b| b.is_ascii_hexdigit())
        || o.reply_to.as_ref().is_some_and(|id| !util::valid_id(id))
        || (o.resolution.is_some() && o.reply_to.is_none())
    {
        return Err(INVALID);
    }
    Ok(())
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Feed {
    pub version: u32,
    pub updated_at: u64,
    pub posts: Vec<Signed<PublicPost>>,
}

fn inspect(scanner: &Scanner, draft: &Draft) -> Result<()> {
    crypto::validate_draft(draft)?;
    let report = scanner.scan(draft, false)?;
    if report.code != 0 {
        // 原文・検知値・そのhashは診断へ出さない。
        return Err(Error::new(report.code, "publication_blocked"));
    }
    Ok(())
}

pub fn verify(feed: &Feed, trusted_key: &str, at: u64) -> Result<()> {
    verify_with_keys(feed, &[trusted_key.to_string()], at)
}
pub fn verify_with_keys(feed: &Feed, keys: &[String], at: u64) -> Result<()> {
    if keys.is_empty()
        || keys.len() > 16
        || feed.version != 1
        || feed.updated_at > at.saturating_add(300)
        || feed.posts.len() > MAX_POSTS
    {
        return Err(INVALID);
    }
    for encoded in keys {
        if crypto::public_key(encoded)?.key_type() != identity::KeyType::Ed25519 {
            return Err(INVALID);
        }
    }
    let scanner = Scanner::new()?;
    let policy = Scanner::policy_id();
    let mut ids = BTreeSet::new();
    let mut previous = feed.updated_at;
    for post in &feed.posts {
        let p = &post.signed;
        if !keys.contains(&post.public_key)
            || p.version != 1
            || !util::valid_id(&p.id)
            || !ids.insert(&p.id)
            || p.published_at > previous
            || p.policy_id != policy
        {
            return Err(INVALID);
        }
        let key = crypto::public_key(&post.public_key)?;
        if key.key_type() != identity::KeyType::Ed25519 {
            return Err(INVALID);
        }
        crypto::verify(&key, DOMAIN, p, &post.signature)?;
        if let Some(origin) = &p.origin {
            validate_origin(origin)?;
        }
        inspect(&scanner, &p.content)?;
        previous = p.published_at;
    }
    Ok(())
}

pub fn append(
    existing: Option<Feed>,
    key: &identity::Keypair,
    draft: Draft,
    confirmed_public: bool,
    at: u64,
) -> Result<Feed> {
    append_with_keys(
        existing,
        key,
        draft,
        confirmed_public,
        at,
        &[crypto::public(key)],
    )
}
pub fn append_with_keys(
    existing: Option<Feed>,
    key: &identity::Keypair,
    draft: Draft,
    confirmed_public: bool,
    at: u64,
    post_keys: &[String],
) -> Result<Feed> {
    if !confirmed_public {
        return Err(Error::new(30, "confirm_public_required"));
    }
    inspect(&Scanner::new()?, &draft)?;
    let public_key = crypto::public(key);
    let mut feed = existing.unwrap_or(Feed {
        version: 1,
        updated_at: at,
        posts: vec![],
    });
    verify_with_keys(&feed, post_keys, at)?;
    if at < feed.updated_at {
        return Err(Error::new(30, "publication_clock_rollback"));
    }
    let signed = PublicPost {
        version: 1,
        id: util::random_id(),
        published_at: at,
        policy_id: Scanner::policy_id(),
        content: draft,
        origin: None,
    };
    let signature = crypto::sign(key, DOMAIN, &signed)?;
    feed.posts.insert(
        0,
        Signed {
            signed,
            public_key,
            signature,
        },
    );
    feed.posts.truncate(MAX_POSTS);
    feed.updated_at = at;
    if util::canonical(&feed)?.len() as u64 > MAX_FEED_BYTES {
        return Err(Error::new(22, "public_feed_limit"));
    }
    Ok(feed)
}
