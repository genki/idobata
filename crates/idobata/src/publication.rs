//! 明示的な公開投稿。P2Pの状態・受信箱・接続情報は読み取らない。
use crate::{
    crypto,
    error::{Error, INVALID, Result},
    scanner::Scanner,
    types::{Draft, Signed},
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
    let key = crypto::public_key(trusted_key)?;
    if key.key_type() != identity::KeyType::Ed25519
        || feed.version != 1
        || feed.updated_at > at.saturating_add(300)
        || feed.posts.len() > MAX_POSTS
    {
        return Err(INVALID);
    }
    let scanner = Scanner::new()?;
    let policy = Scanner::policy_id();
    let mut ids = BTreeSet::new();
    let mut previous = feed.updated_at;
    for post in &feed.posts {
        let p = &post.signed;
        if post.public_key != trusted_key
            || p.version != 1
            || !util::valid_id(&p.id)
            || !ids.insert(&p.id)
            || p.published_at > previous
            || p.policy_id != policy
        {
            return Err(INVALID);
        }
        crypto::verify(&key, DOMAIN, p, &post.signature)?;
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
    verify(&feed, &public_key, at)?;
    if at < feed.updated_at {
        return Err(Error::new(30, "publication_clock_rollback"));
    }
    let signed = PublicPost {
        version: 1,
        id: util::random_id(),
        published_at: at,
        policy_id: Scanner::policy_id(),
        content: draft,
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
