//! オフラインrootが認可する公開用鍵。失効鍵をfeedから再登録しない。
use crate::{
    crypto,
    error::{INVALID, Result},
    types::Signed,
    util,
};
use libp2p::identity;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub public_key: String,
    pub not_before: u64,
    pub not_after: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trust {
    pub version: u32,
    pub revision: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub keys: Vec<Grant>,
    pub revoked: Vec<String>,
}
pub fn create(
    root: &identity::Keypair,
    keys: Vec<Grant>,
    revoked: Vec<String>,
    revision: u64,
    at: u64,
) -> Result<Signed<Trust>> {
    let signed = Trust {
        version: 1,
        revision,
        issued_at: at,
        expires_at: at + 90 * 86400,
        keys,
        revoked,
    };
    let doc = Signed {
        signature: crypto::sign(root, "idobata.trust.v1", &signed)?,
        public_key: crypto::public(root),
        signed,
    };
    verify(&doc, &crypto::public(root), at, None)?;
    Ok(doc)
}
pub fn verify(
    doc: &Signed<Trust>,
    root: &str,
    at: u64,
    checkpoint: Option<&crate::publication::Checkpoint>,
) -> Result<crate::publication::Checkpoint> {
    let t = &doc.signed;
    if doc.public_key != root
        || t.version != 1
        || t.revision == 0
        || t.revision > 9_007_199_254_740_991
        || t.issued_at > at + 300
        || t.expires_at <= at
        || t.expires_at <= t.issued_at
        || t.expires_at - t.issued_at > 90 * 86400
        || t.keys.is_empty()
        || t.keys.len() > 16
        || t.revoked.len() > 64
    {
        return Err(INVALID);
    }
    crypto::verify(
        &crypto::public_key(root)?,
        "idobata.trust.v1",
        t,
        &doc.signature,
    )?;
    let mut seen = BTreeSet::new();
    for g in &t.keys {
        let key = crypto::public_key(&g.public_key)?;
        if key.key_type() != identity::KeyType::Ed25519
            || !seen.insert(&g.public_key)
            || g.not_after <= g.not_before
        {
            return Err(INVALID);
        }
    }
    for revoked in &t.revoked {
        if crypto::public_key(revoked)?.key_type() != identity::KeyType::Ed25519 {
            return Err(INVALID);
        }
    }
    let digest = util::hash(&util::canonical(t)?);
    if let Some(old) = checkpoint
        && (t.revision < old.revision || (t.revision == old.revision && digest != old.digest))
    {
        return Err(INVALID);
    }
    Ok(crate::publication::Checkpoint {
        revision: t.revision,
        digest,
        trust_revision: None,
        trust_digest: None,
    })
}
pub fn allowed(doc: &Signed<Trust>, key: &str, at: u64) -> bool {
    !doc.signed.revoked.iter().any(|k| k == key)
        && doc
            .signed
            .keys
            .iter()
            .any(|g| g.public_key == key && g.not_before <= at && at < g.not_after)
}
pub fn verify_feed(
    doc: &Signed<crate::publication::Manifest>,
    trust: &Signed<Trust>,
    root: &str,
    at: u64,
    checkpoint: Option<&crate::publication::Checkpoint>,
) -> Result<crate::publication::Checkpoint> {
    let previous = checkpoint.and_then(|c| {
        Some(crate::publication::Checkpoint {
            revision: c.trust_revision?,
            digest: c.trust_digest.clone()?,
            trust_revision: None,
            trust_digest: None,
        })
    });
    let trust_checkpoint = verify(trust, root, at, previous.as_ref())?;
    if !allowed(trust, &doc.public_key, at) {
        return Err(INVALID);
    }
    let keys = trust
        .signed
        .keys
        .iter()
        .filter(|g| !trust.signed.revoked.contains(&g.public_key))
        .map(|g| g.public_key.clone())
        .collect::<Vec<_>>();
    for p in &doc.signed.feed.posts {
        if !allowed(trust, &p.public_key, p.signed.published_at) {
            return Err(INVALID);
        }
    }
    let mut next =
        crate::publication::verify_manifest_with_keys(doc, &doc.public_key, &keys, at, checkpoint)?;
    next.trust_revision = Some(trust_checkpoint.revision);
    next.trust_digest = Some(trust_checkpoint.digest);
    Ok(next)
}
