use crate::{
    error::{INVALID, Result, STORAGE},
    types::*,
    util,
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use libp2p::{Multiaddr, PeerId, identity, multiaddr::Protocol};
use std::{collections::BTreeSet, path::Path};
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
pub fn verify<T: serde::Serialize>(
    key: &identity::PublicKey,
    domain: &str,
    value: &T,
    sig: &str,
) -> Result<()> {
    let mut bytes = domain.as_bytes().to_vec();
    bytes.push(0);
    bytes.extend(util::canonical(value)?);
    if !key.verify(&bytes, &decode(sig)?) {
        return Err(INVALID);
    }
    Ok(())
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
    if r.version != if r.public { 2 } else { 1 }
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
