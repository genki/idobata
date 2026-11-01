use crate::{
    error::{INVALID, Result, STORAGE},
    types::*,
    util,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use libp2p::{Multiaddr, PeerId, identity, multiaddr::Protocol};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeSet, VecDeque},
    path::Path,
    sync::{Mutex, OnceLock},
};
pub const MAX_WIRE: usize = 16384;
pub fn encode(b: &[u8]) -> String {
    B64.encode(b)
}
pub fn decode(s: &str) -> Result<Vec<u8>> {
    B64.decode(s).map_err(|_| INVALID)
}
pub fn public(key: &identity::Keypair) -> String {
    encode(&key.public().encode_protobuf())
}
pub fn public_key(encoded: &str) -> Result<identity::PublicKey> {
    identity::PublicKey::try_decode_protobuf(&decode(encoded)?).map_err(|_| INVALID)
}
pub fn sign<T: serde::Serialize>(
    key: &identity::Keypair,
    domain: &str,
    value: &T,
) -> Result<String> {
    let mut bytes = domain.as_bytes().to_vec();
    bytes.push(0);
    bytes.extend(util::canonical(value)?);
    key.sign(&bytes).map(|s| encode(&s)).map_err(|_| INVALID)
}
const MAX_VERIFIED_SIGNATURES: usize = 2048;
#[derive(Default)]
struct SignatureCache {
    verified: BTreeSet<[u8; 32]>,
    order: VecDeque<[u8; 32]>,
}
impl SignatureCache {
    fn remember(&mut self, fingerprint: [u8; 32]) {
        if self.verified.contains(&fingerprint) {
            return;
        }
        while self.verified.len() >= MAX_VERIFIED_SIGNATURES {
            if let Some(old) = self.order.pop_front() {
                self.verified.remove(&old);
            }
        }
        self.verified.insert(fingerprint);
        self.order.push_back(fingerprint);
    }
}
fn signature_fingerprint(key: &identity::PublicKey, bytes: &[u8], signature: &[u8]) -> [u8; 32] {
    let public = key.encode_protobuf();
    let mut hash = Sha256::new();
    hash.update(b"idobata.verified-signature-cache.v1\0");
    for part in [public.as_slice(), bytes, signature] {
        hash.update((part.len() as u64).to_be_bytes());
        hash.update(part);
    }
    hash.finalize().into()
}
fn verify_signature_cached(
    key: &identity::PublicKey,
    bytes: &[u8],
    signature: &[u8],
    cache: &Mutex<SignatureCache>,
) -> Result<()> {
    let fingerprint = signature_fingerprint(key, bytes, signature);
    if cache
        .lock()
        .ok()
        .is_some_and(|c| c.verified.contains(&fingerprint))
    {
        return Ok(());
    }
    if !key.verify(bytes, signature) {
        return Err(INVALID);
    }
    // Pure signature validity is timeless. Authorization, membership, policy,
    // expiry and admission checks belong to callers and are never cached here.
    // A poisoned performance cache falls back to the complete signature check.
    if let Ok(mut cache) = cache.lock() {
        cache.remember(fingerprint);
    }
    Ok(())
}
pub fn verify<T: serde::Serialize>(
    key: &identity::PublicKey,
    domain: &str,
    value: &T,
    sig: &str,
) -> Result<()> {
    let mut bytes = domain.as_bytes().to_vec();
    bytes.push(0);
    bytes.extend(util::canonical(value)?);
    let signature = decode(sig)?;
    static VERIFIED: OnceLock<Mutex<SignatureCache>> = OnceLock::new();
    verify_signature_cached(
        key,
        &bytes,
        &signature,
        VERIFIED.get_or_init(Default::default),
    )
}
pub fn load_key(home: &Path) -> Result<identity::Keypair> {
    let p = home.join("identity.key");
    util::protected(&p)?;
    identity::Keypair::from_protobuf_encoding(&util::read_bounded(&p, 1024)?).map_err(|_| STORAGE)
}
pub fn address(s: &str, listen: bool) -> Result<Multiaddr> {
    let addr: Multiaddr = s.parse().map_err(|_| INVALID)?;
    let mut parts = addr.iter();
    let first = parts.next();
    let dns = matches!(&first,Some(Protocol::Dns4(name)) if &**name=="idobata-peer.s21g.com");
    if !(matches!(first, Some(Protocol::Ip4(_) | Protocol::Ip6(_))) || dns && !listen) {
        return Err(INVALID);
    }
    if !matches!(parts.next(),Some(Protocol::Tcp(p)) if listen||p>0) {
        return Err(INVALID);
    }
    match parts.next() {
        None if !dns => {}
        Some(Protocol::Ws(path)) if !dns && &*path == "/" && parts.next().is_none() => {}
        Some(Protocol::Wss(path)) if dns && &*path == "/" && parts.next().is_none() => {}
        _ => return Err(INVALID),
    }
    Ok(addr)
}
pub fn member_valid(m: &Member) -> Result<()> {
    let key = public_key(&m.public_key)?;
    if key.key_type() != identity::KeyType::Ed25519
        || key.to_peer_id().to_string() != m.peer_id
        || m.addresses.len() > 4
    {
        return Err(INVALID);
    }
    for a in &m.addresses {
        address(a, false)?;
    }
    Ok(())
}
pub fn validate_room(room: &TrustedRoom, policy: &str, at: u64) -> Result<()> {
    let cert = &room.certificate;
    let r = &cert.signed;
    if r.version
        != if r.knowledge_operators.is_some() {
            4
        } else if r.knowledge_automation_required {
            3
        } else if r.public {
            2
        } else {
            1
        }
        || !util::valid_id(&r.room_id)
        || r.epoch == 0
        || r.epoch > 9_007_199_254_740_991
        || r.issued_at > at + 300
        || r.expires_at <= at
        || r.expires_at <= r.issued_at
        || r.expires_at - r.issued_at > 7 * 86400
        || r.policy_id != policy
        || r.members.is_empty()
        || r.members.len() > 32
    {
        return Err(INVALID);
    }
    if let Some(claims) = &r.knowledge_operators {
        claims.validate().map_err(|_| INVALID)?;
        if claims
            .bindings
            .keys()
            .any(|peer| !r.members.iter().any(|member| &member.peer_id == peer))
        {
            return Err(INVALID);
        }
    }
    // Only an already verified certificate may be cached. Time and policy checks
    // above are always repeated, and every byte of the trust pin is in the key.
    static VERIFIED: std::sync::OnceLock<
        std::sync::Mutex<std::collections::BTreeMap<String, u64>>,
    > = std::sync::OnceLock::new();
    let fingerprint = util::hash(&util::canonical(room)?);
    let cache = VERIFIED.get_or_init(Default::default);
    if cache
        .lock()
        .map_err(|_| INVALID)?
        .contains_key(&fingerprint)
    {
        return Ok(());
    }
    let key = public_key(&cert.public_key)?;
    if key.to_peer_id().to_string() != room.authority_peer_id
        || key.key_type() != identity::KeyType::Ed25519
    {
        return Err(INVALID);
    }
    verify(&key, "idobata.room.v1", &cert.signed, &cert.signature)?;
    let mut ids = BTreeSet::new();
    for m in &r.members {
        member_valid(m)?;
        if !ids.insert(&m.peer_id) {
            return Err(INVALID);
        }
    }
    let mut cache = cache.lock().map_err(|_| INVALID)?;
    cache.retain(|_, expires| *expires > at);
    if cache.len() >= 128 {
        cache.clear();
    }
    cache.insert(fingerprint, r.expires_at);
    Ok(())
}
pub fn validate_draft(d: &Draft) -> Result<()> {
    if d.body.is_empty()
        || d.body.len() > 8192
        || d.title.is_empty()
        || d.title.len() > 256
        || d.references.len() > 4
        || !["observation", "question", "answer", "proposal"].contains(&d.kind.as_str())
    {
        return Err(INVALID);
    }
    let mut unique = BTreeSet::new();
    for r in &d.references {
        if r.len() > 2048 || !unique.insert(r) {
            return Err(INVALID);
        }
        let u = url::Url::parse(r).map_err(|_| INVALID)?;
        if !["http", "https"].contains(&u.scheme())
            || u.host_str().is_none()
            || !u.username().is_empty()
            || u.password().is_some()
        {
            return Err(INVALID);
        }
    }
    Ok(())
}
pub fn verify_message(
    env: &Envelope,
    peer: &PeerId,
    room: &TrustedRoom,
    policy: &str,
    at: u64,
) -> Result<()> {
    validate_room(room, policy, at)?;
    let p = &env.payload;
    let r = &room.certificate.signed;
    if p.version != if p.options.is_empty() { 1 } else { 2 }
        || (p.options.public && !r.public)
        || p.options
            .reply_to
            .as_ref()
            .is_some_and(|id| !util::valid_id(id))
        || (p.options.resolution.is_some() && p.options.reply_to.is_none())
        || !util::valid_id(&p.message_id)
        || p.sender_peer_id != peer.to_string()
        || p.room_id != r.room_id
        || p.membership_epoch != r.epoch
        || p.policy_id != policy
        || p.created_at > at + 300
        || p.expires_at <= at
        || p.expires_at <= p.created_at
        || p.expires_at - p.created_at > 86400
        || p.created_at < r.issued_at.saturating_sub(300)
        || p.expires_at > r.expires_at
    {
        return Err(INVALID);
    }
    validate_draft(&p.draft())?;
    let m = r
        .members
        .iter()
        .find(|m| m.peer_id == p.sender_peer_id)
        .ok_or(INVALID)?;
    verify(
        &public_key(&m.public_key)?,
        "idobata.message.v1",
        p,
        &env.signature,
    )
}
pub fn new_envelope(
    key: &identity::Keypair,
    room: &Room,
    policy: &str,
    draft: Draft,
) -> Result<Envelope> {
    new_envelope_with_options(key, room, policy, draft, PostOptions::default())
}
pub fn new_envelope_with_options(
    key: &identity::Keypair,
    room: &Room,
    policy: &str,
    draft: Draft,
    options: PostOptions,
) -> Result<Envelope> {
    if options.public && !room.public {
        return Err(INVALID);
    }
    let at = util::now();
    let payload = Payload {
        version: if options.is_empty() { 1 } else { 2 },
        message_id: util::random_id(),
        sender_peer_id: key.public().to_peer_id().to_string(),
        room_id: room.room_id.clone(),
        membership_epoch: room.epoch,
        policy_id: policy.into(),
        created_at: at,
        expires_at: (at + 86400).min(room.expires_at),
        kind: draft.kind,
        title: draft.title,
        body: draft.body,
        references: draft.references,
        options,
    };
    let signature = sign(key, "idobata.message.v1", &payload)?;
    let env = Envelope { payload, signature };
    if util::canonical(&env)?.len() > MAX_WIRE {
        return Err(INVALID);
    }
    Ok(env)
}

#[cfg(test)]
mod signature_cache_tests {
    use super::*;
    use serde_json::json;

    fn signed_bytes(domain: &str, value: &serde_json::Value) -> Vec<u8> {
        let mut bytes = domain.as_bytes().to_vec();
        bytes.push(0);
        bytes.extend(util::canonical(value).unwrap());
        bytes
    }
    #[test]
    fn verified_cache_separates_public_key_domain_message_and_signature_and_never_remembers_invalid()
     {
        let key = identity::Keypair::generate_ed25519();
        let other = identity::Keypair::generate_ed25519();
        let value = json!({"amount":1,"nonce":1});
        let domain = "idobata.ledger.transaction.v1";
        let bytes = signed_bytes(domain, &value);
        let signature = decode(&sign(&key, domain, &value).unwrap()).unwrap();
        let cache = Mutex::new(SignatureCache::default());
        let mut changed_signature = signature.clone();
        changed_signature[0] ^= 1;
        assert!(
            verify_signature_cached(&key.public(), &bytes, &changed_signature, &cache).is_err()
        );
        assert!(cache.lock().unwrap().verified.is_empty());
        verify_signature_cached(&key.public(), &bytes, &signature, &cache).unwrap();
        verify_signature_cached(&key.public(), &bytes, &signature, &cache).unwrap();
        assert_eq!(cache.lock().unwrap().verified.len(), 1);
        for (public, bytes, signature) in [
            (other.public(), bytes.clone(), signature.clone()),
            (
                key.public(),
                signed_bytes("idobata.ledger.acceptance-vote.v1", &value),
                signature.clone(),
            ),
            (
                key.public(),
                signed_bytes(domain, &json!({"amount":2,"nonce":1})),
                signature.clone(),
            ),
            (key.public(), bytes.clone(), changed_signature),
        ] {
            assert!(verify_signature_cached(&public, &bytes, &signature, &cache).is_err());
            assert_eq!(cache.lock().unwrap().verified.len(), 1);
        }
    }
    #[test]
    fn signature_cache_has_fixed_capacity_and_poison_cannot_change_signature_validity() {
        let mut cache = SignatureCache::default();
        for n in 0..MAX_VERIFIED_SIGNATURES + 17 {
            cache.remember(Sha256::digest(n.to_be_bytes()).into());
        }
        assert_eq!(cache.verified.len(), MAX_VERIFIED_SIGNATURES);
        assert_eq!(cache.order.len(), MAX_VERIFIED_SIGNATURES);
        let oldest: [u8; 32] = Sha256::digest(0usize.to_be_bytes()).into();
        let newest: [u8; 32] = Sha256::digest((MAX_VERIFIED_SIGNATURES + 16).to_be_bytes()).into();
        assert!(!cache.verified.contains(&oldest));
        assert!(cache.verified.contains(&newest));
        let cache = Mutex::new(cache);
        let _ = std::panic::catch_unwind(|| {
            let _guard = cache.lock().unwrap();
            panic!("synthetic cache poison");
        });
        let key = identity::Keypair::generate_ed25519();
        let bytes = b"complete domain-separated test bytes";
        let signature = key.sign(bytes).unwrap();
        verify_signature_cached(&key.public(), bytes, &signature, &cache).unwrap();
        assert!(
            verify_signature_cached(&key.public(), b"different bytes", &signature, &cache).is_err()
        );
    }
    #[test]
    fn cached_room_signature_never_bypasses_expiry_or_policy_or_changed_certificate() {
        let key = identity::Keypair::generate_ed25519();
        let now = util::now();
        let signed = Room {
            version: 1,
            room_id: util::random_id(),
            epoch: 1,
            issued_at: now,
            expires_at: now + 60,
            policy_id: crate::scanner::Scanner::policy_id(),
            members: vec![Member {
                peer_id: key.public().to_peer_id().to_string(),
                public_key: public(&key),
                addresses: vec![],
            }],
            public: false,
            knowledge_automation_required: false,
            knowledge_operators: None,
        };
        let mut room = TrustedRoom {
            authority_peer_id: key.public().to_peer_id().to_string(),
            certificate: Signed {
                signature: sign(&key, "idobata.room.v1", &signed).unwrap(),
                public_key: public(&key),
                signed,
            },
        };
        let policy = crate::scanner::Scanner::policy_id();
        validate_room(&room, &policy, now).unwrap();
        validate_room(&room, &policy, now).unwrap();
        assert!(validate_room(&room, &policy, now + 60).is_err());
        assert!(validate_room(&room, "different-policy", now).is_err());
        room.certificate.signed.epoch += 1;
        assert!(validate_room(&room, &policy, now).is_err());
    }
}
