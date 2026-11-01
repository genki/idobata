//! Private provenance and bounded public views of explicitly public knowledge.
//!
//! Raw source packets stay in the protected daemon cache. Only `PublicEntry`
//! values cross the publication boundary; room proofs, peer IDs, endpoints and
//! retrieval requests are never serialized into the public feed.
use crate::{
    crypto,
    error::{Error, INVALID, Result, STORAGE},
    knowledge::{self, KnowledgeHit},
    knowledge_abuse::OperatorGroup,
    publication::{self, Origin, PublicEntry},
    scanner::Scanner,
    types::{Draft, Envelope, OperatorBindingHistory, TrustedRoom},
    util,
};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

pub const WINDOW_SECONDS: u64 = 30 * 86400;
pub const CACHE_BYTES: usize = 4 * 1024 * 1024;
pub const CACHE_SOURCES: usize = 256;
const CACHE_MAGIC: &[u8] = b"idobata.public-projection.v1\0";
const CACHE_OVERHEAD: usize = CACHE_MAGIC.len() + 24 + 16;
const MAX_INTEGER: u64 = 9_007_199_254_740_991;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Cursor {
    pub promoted: bool,
    pub created_at: u64,
    pub id: String,
}
impl Cursor {
    pub fn validate(&self) -> Result<()> {
        if self.created_at > MAX_INTEGER || !util::valid_id(&self.id) {
            return Err(INVALID);
        }
        Ok(())
    }
    pub fn contains_after(&self, promoted: bool, created_at: u64, id: &str) -> bool {
        (self.promoted && !promoted)
            || (self.promoted == promoted
                && (created_at < self.created_at
                    || (created_at == self.created_at && id > self.id.as_str())))
    }
}

/// This enum is private-cache / authenticated P2P data, NEVER public-feed data.
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum Source {
    Knowledge {
        hit: Box<KnowledgeHit>,
    },
    Legacy {
        envelope: Box<Envelope>,
        certificate: Box<TrustedRoom>,
        received_at: u64,
    },
}
impl Source {
    pub fn room_id(&self) -> &str {
        match self {
            Self::Knowledge { hit } => &hit.packet.record.signed.room_id,
            Self::Legacy { envelope, .. } => &envelope.payload.room_id,
        }
    }
    pub fn created_at(&self) -> u64 {
        match self {
            Self::Knowledge { hit } => hit.packet.record.signed.created_at,
            Self::Legacy { envelope, .. } => envelope.payload.created_at,
        }
    }
    pub fn source_id(&self) -> &str {
        match self {
            Self::Knowledge { hit } => &hit.packet.record.signed.id,
            Self::Legacy { envelope, .. } => &envelope.payload.message_id,
        }
    }
    pub fn public_id(&self) -> String {
        match self {
            Self::Knowledge { hit } => public_record_id(&hit.packet.record.signed.id),
            Self::Legacy { envelope, .. } => envelope.payload.message_id.clone(),
        }
    }
    fn certificate(&self) -> &TrustedRoom {
        match self {
            Self::Knowledge { hit } => &hit.packet.certificate,
            Self::Legacy { certificate, .. } => certificate,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Knowledge,
    Legacy,
}

/// Not deserializable: classification and resource attribution are produced only
/// after local signature, admission, current-authority and scanner validation.
#[derive(Clone)]
pub struct Verified {
    source: Source,
    entry: PublicEntry,
    group: OperatorGroup,
    promoted: bool,
    kind: Kind,
    observed_at: u64,
}
impl Verified {
    pub fn entry(&self) -> &PublicEntry {
        &self.entry
    }
    pub fn source(&self) -> &Source {
        &self.source
    }
    pub fn promoted(&self) -> bool {
        self.promoted
    }
    pub fn kind(&self) -> Kind {
        self.kind
    }
    pub fn group(&self) -> &OperatorGroup {
        &self.group
    }
    pub fn cursor(&self) -> Cursor {
        Cursor {
            promoted: self.promoted,
            created_at: self.entry.published_at,
            id: self.source.source_id().into(),
        }
    }
    pub fn observed_at(&self) -> u64 {
        self.observed_at
    }
    pub fn with_observed_at(mut self, at: u64) -> Self {
        self.observed_at = at;
        self
    }
}

pub fn public_record_id(id: &str) -> String {
    util::hash(format!("idobata.knowledge.public.v1\0{id}").as_bytes())
}
fn same_pin(old: &TrustedRoom, current: &TrustedRoom) -> bool {
    let a = &old.certificate.signed;
    let b = &current.certificate.signed;
    old.authority_peer_id == current.authority_peer_id
        && old.certificate.public_key == current.certificate.public_key
        && a.room_id == b.room_id
        && a.policy_id == b.policy_id
        && a.public == b.public
        && a.epoch <= b.epoch
}
fn scanner() -> Result<&'static Scanner> {
    static SCANNER: std::sync::OnceLock<Result<Scanner>> = std::sync::OnceLock::new();
    SCANNER
        .get_or_init(Scanner::new)
        .as_ref()
        .map_err(Clone::clone)
}
fn inspect(draft: &Draft) -> Result<()> {
    crypto::validate_draft(draft)?;
    let report = scanner()?.scan(draft, false)?;
    if report.code != 0 {
        return Err(Error::new(report.code, "public_projection_blocked"));
    }
    Ok(())
}
fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_unspecified()
                && !ip.is_broadcast()
                && !ip.is_multicast()
                && ip.octets()[0] != 0
                && !(ip.octets()[0] == 100 && (64..=127).contains(&ip.octets()[1]))
        }
        IpAddr::V6(ip) => ip.to_ipv4_mapped().map_or_else(
            || {
                !ip.is_loopback()
                    && !ip.is_unspecified()
                    && !ip.is_unique_local()
                    && !ip.is_unicast_link_local()
                    && !ip.is_multicast()
            },
            |v4| public_ip(IpAddr::V4(v4)),
        ),
    }
}
fn public_host(host: &str) -> bool {
    let host = host
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if let Ok(ip) = host.parse::<IpAddr>() {
        return public_ip(ip);
    }
    host.contains('.')
        && ![
            "localhost",
            ".localhost",
            ".local",
            ".internal",
            ".lan",
            ".home",
            ".consul",
        ]
        .iter()
        .any(|suffix| host == *suffix || host.ends_with(suffix))
}
fn private_identifier(draft: &Draft, original: &TrustedRoom, current: &TrustedRoom) -> bool {
    let texts = std::iter::once(draft.title.as_str())
        .chain(std::iter::once(draft.body.as_str()))
        .chain(draft.references.iter().map(String::as_str))
        .collect::<Vec<_>>();
    for room in [original, current] {
        if texts.iter().any(|text| {
            text.contains(&room.authority_peer_id)
                || text.contains(&room.certificate.public_key)
                || text.contains(&room.certificate.signed.room_id)
        }) {
            return true;
        }
        for member in &room.certificate.signed.members {
            if texts
                .iter()
                .any(|text| text.contains(&member.peer_id) || text.contains(&member.public_key))
            {
                return true;
            }
            for address in &member.addresses {
                if texts.iter().any(|text| text.contains(address)) {
                    return true;
                }
                let parts = address.split('/').collect::<Vec<_>>();
                for pair in parts.windows(2) {
                    if ["ip4", "ip6", "dns", "dns4", "dns6"].contains(&pair[0])
                        && !public_host(pair[1])
                        && texts.iter().any(|text| text.contains(pair[1]))
                    {
                        return true;
                    }
                }
            }
        }
    }
    private_route(draft)
}
fn private_route(draft: &Draft) -> bool {
    let texts = std::iter::once(draft.title.as_str())
        .chain(std::iter::once(draft.body.as_str()))
        .chain(draft.references.iter().map(String::as_str));
    for reference in &draft.references {
        let Ok(url) = url::Url::parse(reference) else {
            return true;
        };
        if !url.host_str().is_some_and(public_host) {
            return true;
        }
    }
    // The check is deterministic and uses no DNS, environment, host secrets or
    // private files. Known routing metadata above is never copied into output.
    for text in texts {
        for token in text.split(|c: char| !c.is_ascii_alphanumeric() && !".:/[]_-?=%".contains(c)) {
            if token.is_empty() {
                continue;
            }
            if let Ok(url) = url::Url::parse(token)
                && ["http", "https", "ws", "wss"].contains(&url.scheme())
            {
                if !url.host_str().is_some_and(public_host) {
                    return true;
                }
                // A path ending in .local is data on the verified public host,
                // not a second bare connection endpoint.
                continue;
            }
            let parts = token.split('/').collect::<Vec<_>>();
            for pair in parts.windows(2) {
                if ["ip4", "ip6", "dns", "dns4", "dns6"].contains(&pair[0]) && !public_host(pair[1])
                {
                    return true;
                }
            }
            let ip = token
                .trim_matches(['[', ']'])
                .parse::<IpAddr>()
                .ok()
                .or_else(|| {
                    token
                        .parse::<std::net::SocketAddr>()
                        .ok()
                        .map(|value| value.ip())
                });
            if ip.is_some_and(|ip| !public_ip(ip)) {
                return true;
            }
            let normalized = token.to_ascii_lowercase();
            let bare = normalized.trim_end_matches('.');
            let (host, port) = bare
                .rsplit_once(':')
                .filter(|(host, port)| {
                    !host.is_empty() && !port.is_empty() && port.bytes().all(|b| b.is_ascii_digit())
                })
                .map_or((bare, false), |(host, _)| {
                    (host.trim_end_matches('.'), true)
                });
            if !token.contains('/')
                && (port || host == "localhost" || host.contains('.'))
                && !public_host(host)
            {
                return true;
            }
        }
    }
    false
}
fn truncate_utf8(text: &str, bytes: usize) -> String {
    let mut end = text.len().min(bytes);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}
fn resource_group(
    original: &TrustedRoom,
    current: &TrustedRoom,
    author: &str,
    histories: &BTreeMap<String, OperatorBindingHistory>,
) -> Result<OperatorGroup> {
    let mut group = knowledge::resource_group(current, author, histories);
    if group == OperatorGroup::Unknown {
        group = knowledge::registry(original).group(author);
    }
    knowledge::storage_bucket(current, &group)
}

pub fn verify_and_project(
    source: Source,
    current: &TrustedRoom,
    histories: &BTreeMap<String, OperatorBindingHistory>,
    at: u64,
) -> Result<Verified> {
    crypto::validate_room(current, &Scanner::policy_id(), at)?;
    let original = source.certificate();
    if !current.certificate.signed.public
        || !original.certificate.signed.public
        || !same_pin(original, current)
        || source.created_at() > at
        || source.created_at().saturating_add(WINDOW_SECONDS) < at
    {
        return Err(INVALID);
    }
    let (mut entry, group, promoted, kind) = match &source {
        Source::Knowledge { hit } => {
            if !hit.packet.record.signed.public
                || hit.reviews.len() > knowledge::MAX_REVIEWERS
                || hit.review_conflicts.len() > knowledge::MAX_REVIEWERS
            {
                return Err(INVALID);
            }
            knowledge::validate_record(&hit.packet, current, at)?;
            for review in &hit.reviews {
                knowledge::validate_review_for_verified_record(review, &hit.packet, current, at)?;
            }
            knowledge::validate_conflicts(&hit.packet, &hit.review_conflicts, current, at)?;
            let evidence = knowledge::verified_evidence_with_conflicts(
                &hit.packet,
                &hit.reviews,
                &hit.review_conflicts,
                current,
            );
            let assessment = knowledge::assess_evidence_with_history(
                &hit.packet,
                current,
                &evidence,
                histories.get(&current.certificate.signed.room_id),
            );
            let record = &hit.packet.record.signed;
            let raw = Draft {
                kind: "answer".into(),
                title: truncate_utf8(&record.problem, 256),
                body: format!(
                    "{}\n{}\n{}",
                    record.problem, record.solution, record.context
                ),
                references: record.references.clone(),
            };
            if private_identifier(&raw, original, current) {
                return Err(Error::new(30, "public_projection_private_identifier"));
            }
            let group = resource_group(original, current, &record.author_peer_id, histories)?;
            let label = if assessment.promoted {
                "外部支持の条件を満たす共有知識"
            } else {
                "未確認の共有知識"
            };
            let kind = if record.kind == "hint" {
                "ヒント"
            } else {
                "解決方法"
            };
            let body = format!(
                "{label}。署名の確認は内容の真実性を保証しません。\n\n問題\n{}\n\n{kind}\n{}{}{}",
                record.problem,
                record.solution,
                if record.context.is_empty() {
                    ""
                } else {
                    "\n\n適用条件\n"
                },
                record.context
            );
            if body.len() > 8192 {
                return Err(Error::new(30, "public_projection_oversize"));
            }
            let draft = Draft {
                kind: "answer".into(),
                title: truncate_utf8(&record.problem, 256),
                body,
                references: record.references.clone(),
            };
            (
                PublicEntry {
                    content: draft,
                    published_at: record.created_at,
                    origin: Origin {
                        message_id: public_record_id(&record.id),
                        author: format!(
                            "agent-{}",
                            &util::hash(record.author_peer_id.as_bytes())[..8]
                        ),
                        reply_to: None,
                        resolution: None,
                    },
                },
                group,
                assessment.promoted,
                Kind::Knowledge,
            )
        }
        Source::Legacy {
            envelope,
            certificate,
            received_at,
        } => {
            let p = &envelope.payload;
            if !p.options.public || p.room_id != current.certificate.signed.room_id {
                return Err(INVALID);
            }
            let peer = p.sender_peer_id.parse().map_err(|_| INVALID)?;
            crypto::verify_message(
                envelope,
                &peer,
                certificate,
                &Scanner::policy_id(),
                *received_at,
            )?;
            inspect(&p.draft())?;
            if private_identifier(&p.draft(), original, current) {
                return Err(Error::new(30, "public_projection_private_identifier"));
            }
            let group = resource_group(original, current, &p.sender_peer_id, histories)?;
            let body = format!(
                "未確認の互換通知。署名の確認は内容の真実性を保証しません。\n\n{}",
                p.body
            );
            if body.len() > 8192 {
                return Err(Error::new(30, "public_projection_oversize"));
            }
            (
                PublicEntry {
                    content: Draft { body, ..p.draft() },
                    published_at: p.created_at,
                    origin: Origin {
                        message_id: p.message_id.clone(),
                        author: format!("agent-{}", &util::hash(p.sender_peer_id.as_bytes())[..8]),
                        // Parent metadata is restored only after the complete
                        // explicitly-public selected parent is known below.
                        reply_to: None,
                        resolution: None,
                    },
                },
                group,
                false,
                Kind::Legacy,
            )
        }
    };
    inspect(&entry.content)?;
    if private_identifier(&entry.content, original, current) {
        return Err(Error::new(30, "public_projection_private_identifier"));
    }
    // Nothing other than this explicit whitelist becomes a PublicEntry.
    entry.content.references.shrink_to_fit();
    Ok(Verified {
        source,
        entry,
        group,
        promoted,
        kind,
        observed_at: at,
    })
}

pub fn select(mut candidates: Vec<Verified>, limit: usize) -> Vec<Verified> {
    let limit = limit.min(publication::MAX_POSTS);
    // Same source ID is immutable. Prefer the earliest valid signed timestamp
    // across replicas so re-posting identical content cannot refresh its age.
    let mut unique = BTreeMap::<String, Verified>::new();
    for candidate in candidates.drain(..) {
        let id = candidate.entry.origin.message_id.clone();
        if unique
            .get(&id)
            .is_none_or(|old| candidate.entry.published_at < old.entry.published_at)
        {
            unique.insert(id, candidate);
        }
    }
    let mut candidates = unique.into_values().collect::<Vec<_>>();
    candidates.sort_by(|a, b| {
        b.promoted
            .cmp(&a.promoted)
            .then_with(|| (b.kind == Kind::Knowledge).cmp(&(a.kind == Kind::Knowledge)))
            .then_with(|| b.entry.published_at.cmp(&a.entry.published_at))
            .then_with(|| a.entry.origin.message_id.cmp(&b.entry.origin.message_id))
    });
    let mut unconfirmed = 0;
    let mut groups = BTreeSet::new();
    let mut out = Vec::new();
    for candidate in candidates {
        if out.len() >= limit {
            break;
        }
        if !candidate.promoted {
            if unconfirmed >= 2 || !groups.insert(candidate.group.clone()) {
                continue;
            }
            unconfirmed += 1;
        }
        out.push(candidate);
    }
    let parents = out
        .iter()
        .filter_map(|entry| match entry.source() {
            Source::Legacy { envelope, .. } => Some((
                envelope.payload.message_id.clone(),
                (
                    envelope.payload.room_id.clone(),
                    envelope.payload.sender_peer_id.clone(),
                    envelope.payload.kind.clone(),
                ),
            )),
            _ => None,
        })
        .collect::<BTreeMap<_, _>>();
    for entry in &mut out {
        if let Source::Legacy { envelope, .. } = &entry.source
            && let Some(parent) = &envelope.payload.options.reply_to
            && let Some((room, sender, kind)) = parents.get(parent)
            && room == &envelope.payload.room_id
        {
            entry.entry.origin.reply_to = Some(parent.clone());
            if kind == "question"
                && sender == &envelope.payload.sender_peer_id
                && envelope.payload.kind == "observation"
            {
                entry.entry.origin.resolution = envelope.payload.options.resolution;
            }
        }
    }
    out
}

/// Rebuild automatic imports under the current policy while retaining explicit
/// publisher-key administrator notes as a separate provenance class. A P2P
/// payload cannot construct an administrator note by supplying JSON in its body.
/// Older v0.3 automatic posts have no recoverable operator proof: only one may
/// survive when no newly verified automatic source is available, including
/// after the legacy seven-day inbox expires. It competes with every group and
/// is explicitly historical/unconfirmed, never a current authorization proof.
pub fn refresh_imported(
    existing: publication::Feed,
    key: &libp2p::identity::Keypair,
    entries: Vec<PublicEntry>,
    withdrawn: &[String],
    _partial: bool,
    at: u64,
    post_keys: &[String],
) -> Result<publication::Feed> {
    publication::verify_with_keys(&existing, post_keys, at)?;
    if at < existing.updated_at {
        return Err(Error::new(30, "publication_clock_rollback"));
    }
    if withdrawn.len() > 4096 || withdrawn.iter().any(|id| !util::valid_id(id)) {
        return Err(INVALID);
    }
    let mut automatic = entries;
    if automatic.is_empty()
        && let Some(old) = existing.posts.iter().find(|p| {
            p.signed.origin.is_some()
                && p.signed.published_at.saturating_add(WINDOW_SECONDS) >= at
                && !withdrawn.contains(&p.signed.id)
        })
    {
        let mut entry = PublicEntry {
            content: old.signed.content.clone(),
            published_at: old.signed.published_at,
            origin: old.signed.origin.clone().ok_or(INVALID)?,
        };
        const HISTORICAL_LABEL: &str =
            "過去に公開署名を確認した互換通知です。現在のP2P認可と有用性は未確認です。\n\n";
        if !entry.content.body.starts_with(HISTORICAL_LABEL) {
            entry.content.body = format!("{HISTORICAL_LABEL}{}", entry.content.body);
        }
        if entry.content.body.len() <= 8192
            && inspect(&entry.content).is_ok()
            && !private_route(&entry.content)
        {
            automatic.push(entry);
        }
    }
    let mut feed = publication::Feed {
        version: 1,
        updated_at: at,
        posts: Vec::new(),
    };
    let mut ids = BTreeSet::new();
    let fits = |candidate: &publication::Feed| -> Result<bool> {
        // Ed25519 signature size is fixed. Maximal safe integer widths reserve
        // all manifest revision/time overhead before the final real signature.
        let doc = crate::types::Signed {
            public_key: crypto::public(key),
            signature: "x".repeat(86),
            signed: publication::Manifest {
                version: 2,
                revision: MAX_INTEGER,
                issued_at: MAX_INTEGER,
                expires_at: MAX_INTEGER,
                count: candidate.posts.len(),
                feed: candidate.clone(),
                withdrawn: withdrawn.to_vec(),
            },
        };
        Ok(util::canonical(&doc)?.len() as u64 <= publication::MAX_FEED_BYTES)
    };
    for entry in automatic {
        if feed.posts.len() >= publication::MAX_POSTS {
            break;
        }
        if withdrawn.contains(&entry.origin.message_id)
            || entry.published_at > at
            || entry.published_at.saturating_add(WINDOW_SECONDS) < at
        {
            continue;
        }
        inspect(&entry.content)?;
        if private_route(&entry.content) {
            return Err(Error::new(30, "public_projection_private_identifier"));
        }
        if !ids.insert(entry.origin.message_id.clone()) {
            return Err(INVALID);
        }
        let post = publication::PublicPost {
            version: 1,
            id: entry.origin.message_id.clone(),
            published_at: entry.published_at,
            policy_id: Scanner::policy_id(),
            content: entry.content,
            origin: Some(entry.origin),
        };
        feed.posts.push(crate::types::Signed {
            signature: crypto::sign(key, "idobata.public-post.v1", &post)?,
            public_key: crypto::public(key),
            signed: post,
        });
        if !fits(&feed)? {
            feed.posts.pop();
        }
    }
    for post in existing
        .posts
        .into_iter()
        .filter(|p| p.signed.origin.is_none())
    {
        if feed.posts.len() >= publication::MAX_POSTS {
            break;
        }
        if withdrawn.contains(&post.signed.id)
            || post.signed.published_at.saturating_add(WINDOW_SECONDS) < at
            || !ids.insert(post.signed.id.clone())
        {
            continue;
        }
        feed.posts.push(post);
        if !fits(&feed)? {
            feed.posts.pop();
        }
    }
    feed.posts.sort_by(|a, b| {
        b.signed
            .published_at
            .cmp(&a.signed.published_at)
            .then_with(|| a.signed.id.cmp(&b.signed.id))
    });
    publication::verify_with_keys(&feed, post_keys, at)?;
    Ok(feed)
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CachedSource {
    source: Source,
    observed_at: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheSlot {
    owner: String,
    room_id: String,
    authority: String,
    observed_at: u64,
    withdrawn: BTreeSet<String>,
    sources: Vec<CachedSource>,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CacheState {
    version: u32,
    slots: Vec<CacheSlot>,
}

pub struct Cache {
    path: PathBuf,
    key: Zeroizing<Vec<u8>>,
    state: CacheState,
    write_generation: u64,
}
fn authority_pin(room: &TrustedRoom) -> Result<String> {
    Ok(util::hash(&util::canonical(&(
        &room.authority_peer_id,
        &room.certificate.public_key,
    ))?))
}
impl Cache {
    pub fn open(home: &Path) -> Result<Self> {
        util::protected(home)?;
        let key_path = home.join("storage.key");
        util::protected(&key_path)?;
        let key = util::read_bounded(&key_path, 32)?;
        if key.len() != 32 {
            return Err(STORAGE);
        }
        let path = home.join("public-projection.enc");
        let state = if path.exists() {
            util::protected(&path)?;
            let bytes = util::read_bounded(&path, CACHE_BYTES as u64)?;
            if bytes.len() < CACHE_OVERHEAD || !bytes.starts_with(CACHE_MAGIC) {
                return Err(STORAGE);
            }
            let cipher = XChaCha20Poly1305::new_from_slice(&key).map_err(|_| STORAGE)?;
            let plain = Zeroizing::new(
                cipher
                    .decrypt(
                        XNonce::from_slice(&bytes[CACHE_MAGIC.len()..CACHE_MAGIC.len() + 24]),
                        Payload {
                            msg: &bytes[CACHE_MAGIC.len() + 24..],
                            aad: CACHE_MAGIC,
                        },
                    )
                    .map_err(|_| STORAGE)?,
            );
            let state: CacheState = serde_json::from_slice(&plain).map_err(|_| STORAGE)?;
            let mut slots = BTreeSet::new();
            if state.version != 1
                || state.slots.len() > 16
                || state.slots.iter().map(|s| s.sources.len()).sum::<usize>() > CACHE_SOURCES
                || state.slots.iter().any(|s| {
                    s.owner.is_empty()
                        || s.owner.len() > 256
                        || !util::valid_id(&s.room_id)
                        || !util::valid_id(&s.authority)
                        || !slots.insert((&s.owner, &s.room_id))
                        || s.observed_at > MAX_INTEGER
                        || s.withdrawn.len() > 4096
                        || s.withdrawn.iter().any(|id| !util::valid_id(id))
                        || s.sources.iter().any(|source| {
                            source.observed_at > MAX_INTEGER || source.source.room_id() != s.room_id
                        })
                })
            {
                return Err(STORAGE);
            }
            state
        } else {
            CacheState {
                version: 1,
                slots: Vec::new(),
            }
        };
        Ok(Self {
            path,
            key,
            state,
            write_generation: 0,
        })
    }
    pub fn write_generation(&self) -> u64 {
        self.write_generation
    }
    #[cfg(test)]
    pub(crate) fn test_destination(&mut self, path: PathBuf) {
        self.path = path;
    }
    pub fn sources(&self, owner: &str, room_id: &str) -> Vec<(Source, u64)> {
        self.state
            .slots
            .iter()
            .find(|s| s.owner == owner && s.room_id == room_id)
            .map(|s| {
                s.sources
                    .iter()
                    .map(|row| (row.source.clone(), row.observed_at))
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn withdrawn(&self, owner: &str, room_id: &str) -> BTreeSet<String> {
        self.state
            .slots
            .iter()
            .find(|s| s.owner == owner && s.room_id == room_id)
            .map(|s| s.withdrawn.clone())
            .unwrap_or_default()
    }
    pub fn metrics(&self) -> (usize, usize) {
        (
            self.state.slots.iter().map(|s| s.sources.len()).sum(),
            self.path.metadata().map_or(0, |m| m.len() as usize),
        )
    }
    /// Publication moderator state is scoped to the authenticated local IPC
    /// owner. Another agent's cache request cannot withdraw a publisher's view.
    pub fn forget(
        &mut self,
        owner: &str,
        room: &TrustedRoom,
        ids: &[String],
        reset: bool,
        at: u64,
    ) -> Result<()> {
        if ids.len() > 256 || ids.iter().any(|id| !util::valid_id(id)) {
            return Err(INVALID);
        }
        let mut state = self.state.clone();
        let pin = authority_pin(room)?;
        let previous = state
            .slots
            .iter()
            .position(|s| s.owner == owner && s.room_id == room.certificate.signed.room_id);
        let mut slot = previous
            .map(|i| state.slots.remove(i))
            .filter(|s| s.authority == pin)
            .unwrap_or(CacheSlot {
                owner: owner.into(),
                room_id: room.certificate.signed.room_id.clone(),
                authority: pin,
                observed_at: at,
                withdrawn: BTreeSet::new(),
                sources: Vec::new(),
            });
        if reset {
            slot.withdrawn.clear();
        }
        slot.withdrawn.extend(ids.iter().cloned());
        if slot.withdrawn.len() > 4096 {
            return Err(INVALID);
        }
        slot.sources
            .retain(|row| !slot.withdrawn.contains(&row.source.public_id()));
        slot.observed_at = at;
        state.slots.insert(0, slot);
        self.bound_and_save(state)?;
        Ok(())
    }
    pub fn replace_room(
        &mut self,
        owner: &str,
        room: &TrustedRoom,
        entries: &[Verified],
        at: u64,
    ) -> Result<bool> {
        // A complete legal witness may not fit this owner's cache at all. Keep
        // the existing cache unchanged and let the fresh verified view proceed.
        if !entries.is_empty()
            && entries.iter().all(|entry| {
                util::canonical(entry.source()).map_or(usize::MAX, |b| b.len()) > 1024 * 1024 - 4096
            })
        {
            return Ok(false);
        }
        let mut state = self.state.clone();
        let pin = authority_pin(room)?;
        let previous = state
            .slots
            .iter()
            .position(|s| s.owner == owner && s.room_id == room.certificate.signed.room_id);
        let previous = previous
            .map(|i| state.slots.remove(i))
            .filter(|s| s.authority == pin);
        let withdrawn = previous
            .as_ref()
            .map(|s| s.withdrawn.clone())
            .unwrap_or_default();
        let mut sources = entries
            .iter()
            .filter(|e| {
                e.source.room_id() == room.certificate.signed.room_id
                    && !withdrawn.contains(&e.entry.origin.message_id)
            })
            .map(|entry| CachedSource {
                source: entry.source.clone(),
                observed_at: entry.observed_at,
            })
            .collect::<Vec<_>>();
        // Retaining a private source is distinct from emitting it. Partial fetch
        // or a work limit cannot erase all prior verified public provenance;
        // each future emission still revalidates its complete proof.
        if let Some(previous) = previous {
            let mut ids = sources
                .iter()
                .map(|s| s.source.public_id())
                .collect::<BTreeSet<_>>();
            for row in previous.sources {
                if row.source.created_at().saturating_add(WINDOW_SECONDS) >= at
                    && same_pin(row.source.certificate(), room)
                    && !withdrawn.contains(&row.source.public_id())
                    && ids.insert(row.source.public_id())
                {
                    sources.push(row);
                }
            }
        }
        let before = sources.len();
        // One legal full proof can exceed the cache's owner allowance. Do not
        // evict all older sources trying to make that impossible item fit.
        sources.retain(|row| util::canonical(row).is_ok_and(|b| b.len() <= 1024 * 1024 - 4096));
        let skipped_large = sources.len() != before;
        state.slots.insert(
            0,
            CacheSlot {
                owner: owner.into(),
                room_id: room.certificate.signed.room_id.clone(),
                authority: pin,
                observed_at: at,
                withdrawn,
                sources,
            },
        );
        self.bound_and_save(state)
            .map(|complete| complete && !skipped_large)
    }
    /// Configuration changes remove the private cache too, including authority
    /// changes and rooms for which the daemon is no longer an authorized member.
    /// Every surviving source is still fully revalidated before reuse.
    pub fn reconcile_rooms(&mut self, rooms: &[TrustedRoom], at: u64) -> Result<()> {
        let mut state = self.state.clone();
        state.slots.retain_mut(|slot| {
            let Some(room) = rooms.iter().find(|room| {
                room.certificate.signed.room_id == slot.room_id
                    && room.certificate.signed.public
                    && crypto::validate_room(room, &Scanner::policy_id(), at).is_ok()
                    && authority_pin(room).ok().as_ref() == Some(&slot.authority)
            }) else {
                return false;
            };
            slot.sources.retain(|row| {
                same_pin(row.source.certificate(), room)
                    && row.source.created_at().saturating_add(WINDOW_SECONDS) >= at
                    && match &row.source {
                        Source::Knowledge { hit }
                            if room.certificate.signed.knowledge_automation_required =>
                        {
                            hit.packet.admission.is_some()
                                && hit.reviews.iter().all(|review| review.admission.is_some())
                                && hit.review_conflicts.iter().all(|proof| {
                                    proof.first.admission.is_some()
                                        && proof.second.admission.is_some()
                                })
                        }
                        _ => true,
                    }
            });
            true
        });
        if util::canonical(&state)? != util::canonical(&self.state)? {
            self.save_state(&state)?;
            self.state = state;
        }
        Ok(())
    }
    fn bound_and_save(&mut self, mut state: CacheState) -> Result<bool> {
        let Some(first) = state.slots.first() else {
            return Err(INVALID);
        };
        if first.owner.is_empty() || first.owner.len() > 256 || first.observed_at > MAX_INTEGER {
            return Err(INVALID);
        }
        // The authenticated owner precedes the opaque per-feed scope. Creating
        // many feed namespaces cannot consume another local UID's allowance.
        let owner = first.owner.split('|').next().unwrap_or("").to_owned();
        let owns = |s: &CacheSlot| s.owner.split('|').next() == Some(owner.as_str());
        let mut complete = true;
        loop {
            let own_slots = state.slots.iter().filter(|s| owns(s)).count();
            let own_sources = state
                .slots
                .iter()
                .filter(|s| owns(s))
                .map(|s| s.sources.len())
                .sum::<usize>();
            let own_bytes =
                util::canonical(&state.slots.iter().filter(|s| owns(s)).collect::<Vec<_>>())?.len();
            let full = state.slots.len() > 16
                || state.slots.iter().map(|s| s.sources.len()).sum::<usize>() > CACHE_SOURCES
                || util::canonical(&state)?
                    .len()
                    .saturating_add(CACHE_OVERHEAD)
                    > CACHE_BYTES;
            if own_slots <= 4 && own_sources <= 64 && own_bytes <= 1024 * 1024 && !full {
                break;
            }
            complete = false;
            // Only this owner's state may be evicted. Existing sources and
            // moderation state belonging to another UID remain untouched.
            if let Some(index) = state
                .slots
                .iter()
                .enumerate()
                .rev()
                .find(|(i, s)| *i != 0 && owns(s))
                .map(|(i, _)| i)
            {
                state.slots.remove(index);
            } else if let Some(slot) = state.slots.first_mut() {
                if slot.sources.pop().is_none() {
                    return Err(Error::new(30, "public_projection_cache_quota"));
                }
            } else {
                return Err(STORAGE);
            }
        }
        self.save_state(&state)?;
        self.state = state;
        Ok(complete)
    }
    fn save_state(&mut self, state: &CacheState) -> Result<()> {
        let plain = Zeroizing::new(util::canonical(state)?);
        let mut nonce = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let cipher = XChaCha20Poly1305::new_from_slice(&self.key).map_err(|_| STORAGE)?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: CACHE_MAGIC,
                },
            )
            .map_err(|_| STORAGE)?;
        let mut bytes = CACHE_MAGIC.to_vec();
        bytes.extend(nonce);
        bytes.extend(ciphertext);
        if bytes.len() > CACHE_BYTES {
            return Err(STORAGE);
        }
        util::atomic_write(&self.path, &bytes)?;
        self.write_generation = self.write_generation.wrapping_add(1);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        knowledge::{KnowledgeInput, ReviewInput},
        knowledge_abuse::OperatorClaims,
        types::{Member, PostOptions, Room, Signed},
    };
    use libp2p::identity;
    struct Fixture {
        _dir: tempfile::TempDir,
        home: PathBuf,
        keys: Vec<identity::Keypair>,
        authority: identity::Keypair,
        room: TrustedRoom,
        at: u64,
    }
    impl Fixture {
        fn new(size: usize, one_group: bool) -> Self {
            let dir = tempfile::tempdir().unwrap();
            let home = dir.path().join("private");
            util::private_dir(&home).unwrap();
            util::atomic_write(&home.join("storage.key"), &[7; 32]).unwrap();
            let keys = (0..size)
                .map(|_| identity::Keypair::generate_ed25519())
                .collect::<Vec<_>>();
            let authority = identity::Keypair::generate_ed25519();
            let at = util::now();
            let bindings = keys
                .iter()
                .enumerate()
                .map(|(i, k)| {
                    (
                        k.public().to_peer_id().to_string(),
                        if one_group {
                            "one-operator".into()
                        } else {
                            format!("operator-{i}")
                        },
                    )
                })
                .collect::<BTreeMap<_, _>>();
            let credits = bindings.values().map(|v| (v.clone(), 1000)).collect();
            let body = Room {
                version: 4,
                room_id: util::hash(b"public projection test room"),
                epoch: 1,
                issued_at: at - 60,
                expires_at: at + 86400,
                policy_id: Scanner::policy_id(),
                members: keys
                    .iter()
                    .enumerate()
                    .map(|(i, k)| Member {
                        peer_id: k.public().to_peer_id().to_string(),
                        public_key: crypto::public(k),
                        addresses: vec![format!("/ip4/127.0.0.1/tcp/{}", 39130 + i)],
                    })
                    .collect(),
                public: true,
                knowledge_automation_required: false,
                knowledge_operators: Some(OperatorClaims { bindings, credits }),
            };
            let room = TrustedRoom {
                authority_peer_id: authority.public().to_peer_id().to_string(),
                certificate: Signed {
                    signature: crypto::sign(&authority, "idobata.room.v1", &body).unwrap(),
                    public_key: crypto::public(&authority),
                    signed: body,
                },
            };
            Self {
                _dir: dir,
                home,
                keys,
                authority,
                room,
                at,
            }
        }
        fn resign(&self, room: &mut TrustedRoom) {
            room.certificate.signature =
                crypto::sign(&self.authority, "idobata.room.v1", &room.certificate.signed).unwrap();
        }
        fn source(&self, problem: &str, promoted: bool) -> Source {
            let packet = knowledge::create_record(
                &self.keys[0],
                &self.room,
                KnowledgeInput {
                    problem: problem.into(),
                    solution: "Save the completed result and return it for the same request."
                        .into(),
                    context:
                        "Use this when the saved result and request can be committed together."
                            .into(),
                    references: vec!["https://example.com/guide".into()],
                    kind: "answer".into(),
                },
                true,
                self.at,
            )
            .unwrap();
            let reviews = if promoted {
                (1..=3)
                    .map(|i| {
                        knowledge::create_review(
                            &self.keys[i],
                            &self.room,
                            &packet,
                            ReviewInput {
                                verdict: "useful".into(),
                                evidence: "Checked the documented behavior.".into(),
                                references: vec![],
                            },
                            1,
                            self.at,
                        )
                        .unwrap()
                    })
                    .collect()
            } else {
                vec![]
            };
            Source::Knowledge {
                hit: Box::new(KnowledgeHit {
                    quality: crate::knowledge_rating::quality(
                        &packet.record.signed.id,
                        &packet.record.signed.author_peer_id,
                        &[],
                    ),
                    packet,
                    reviews,
                    review_conflicts: vec![],
                    score: 1e200,
                }),
            }
        }
        fn project(&self, source: Source) -> Verified {
            verify_and_project(
                source,
                &self.room,
                &BTreeMap::new(),
                util::now().max(self.at),
            )
            .unwrap()
        }
        fn legacy(&self, index: usize) -> Source {
            let envelope = crypto::new_envelope_with_options(
                &self.keys[index],
                &self.room.certificate.signed,
                &Scanner::policy_id(),
                Draft {
                    kind: "observation".into(),
                    title: "A public development note".into(),
                    body: "The documented retry behavior was checked.".into(),
                    references: vec![],
                },
                PostOptions {
                    public: true,
                    ..PostOptions::default()
                },
            )
            .unwrap();
            Source::Legacy {
                envelope: Box::new(envelope),
                certificate: Box::new(self.room.clone()),
                received_at: util::now(),
            }
        }
    }
    #[test]
    fn public_projection_is_whitelisted_and_signature_is_not_quality() {
        let fixture = Fixture::new(4, false);
        let unconfirmed = fixture.project(fixture.source("How should a retry be handled?", false));
        assert!(!unconfirmed.promoted());
        assert!(unconfirmed.entry().content.body.contains("未確認"));
        let confirmed =
            fixture.project(fixture.source("How should a completed operation be retried?", true));
        assert!(confirmed.promoted());
        assert!(confirmed.entry().content.body.contains("外部支持の条件"));
        for projection in [unconfirmed, confirmed] {
            let bytes = String::from_utf8(util::canonical(projection.entry()).unwrap()).unwrap();
            for member in &fixture.room.certificate.signed.members {
                assert!(!bytes.contains(&member.peer_id));
                assert!(!bytes.contains(&member.public_key));
                for address in &member.addresses {
                    assert!(!bytes.contains(address));
                }
            }
            assert!(!bytes.contains("certificate"));
            assert!(!bytes.contains("room_id"));
            assert!(projection.entry().origin.author.starts_with("agent-"));
        }
    }
    #[test]
    fn double_public_permission_current_authority_and_signature_are_required() {
        let fixture = Fixture::new(4, false);
        let mut private = fixture.source("How is explicit publication selected?", false);
        if let Source::Knowledge { hit } = &mut private {
            hit.packet.record.signed.public = false;
        }
        assert!(verify_and_project(private, &fixture.room, &BTreeMap::new(), fixture.at).is_err());
        let mut current = fixture.room.clone();
        current.certificate.signed.public = false;
        fixture.resign(&mut current);
        assert!(
            verify_and_project(
                fixture.source("How is a private room excluded?", false),
                &current,
                &BTreeMap::new(),
                fixture.at
            )
            .is_err()
        );
        let mut forged = fixture.source("How is a forged signature excluded?", false);
        if let Source::Knowledge { hit } = &mut forged {
            hit.packet.record.signature = "invalid".into();
        }
        assert!(verify_and_project(forged, &fixture.room, &BTreeMap::new(), fixture.at).is_err());
        let foreign = Fixture::new(4, false);
        assert!(
            verify_and_project(
                fixture.source("How is a different authority excluded?", false),
                &foreign.room,
                &BTreeMap::new(),
                fixture.at
            )
            .is_err()
        );
    }
    #[test]
    fn full_solution_and_conditions_are_never_silently_truncated() {
        let fixture = Fixture::new(4, false);
        let mut input = KnowledgeInput {
            problem: "How can a large answer retain every condition?".into(),
            solution: "Check the complete documented procedure. ".repeat(160),
            context: "Only proceed when the saved state is consistent. ".repeat(30),
            references: vec![],
            kind: "hint".into(),
        };
        let packet = knowledge::create_record(
            &fixture.keys[0],
            &fixture.room,
            input.clone(),
            true,
            fixture.at,
        )
        .unwrap();
        let source = Source::Knowledge {
            hit: Box::new(KnowledgeHit {
                quality: crate::knowledge_rating::quality(
                    &packet.record.signed.id,
                    &packet.record.signed.author_peer_id,
                    &[],
                ),
                packet,
                reviews: vec![],
                review_conflicts: vec![],
                score: 0.0,
            }),
        };
        let result = verify_and_project(source, &fixture.room, &BTreeMap::new(), fixture.at);
        assert!(result.is_err());
        assert_eq!(result.err().unwrap().error, "public_projection_oversize");
        input.solution = "Use the documented procedure.".into();
        let packet = knowledge::create_record(
            &fixture.keys[0],
            &fixture.room,
            input.clone(),
            true,
            fixture.at,
        )
        .unwrap();
        let source = Source::Knowledge {
            hit: Box::new(KnowledgeHit {
                quality: crate::knowledge_rating::quality(
                    &packet.record.signed.id,
                    &packet.record.signed.author_peer_id,
                    &[],
                ),
                packet,
                reviews: vec![],
                review_conflicts: vec![],
                score: 0.0,
            }),
        };
        let projected = fixture.project(source);
        assert!(projected.entry().content.body.contains(&input.context));
        assert!(projected.entry().content.body.contains(&input.problem));
    }
    #[test]
    fn legacy_cannot_bypass_unknown_slots_and_knowledge_wins_same_operator() {
        let fixture = Fixture::new(4, true);
        let knowledge = fixture
            .project(fixture.source("How does durable knowledge receive a public slot?", false));
        let id = knowledge.entry().origin.message_id.clone();
        let mut pool = (0..50)
            .map(|index| fixture.project(fixture.legacy(index % 4)))
            .collect::<Vec<_>>();
        pool.push(knowledge);
        let selected = select(pool, 50);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].entry().origin.message_id, id);
        assert_eq!(selected[0].kind(), Kind::Knowledge);
        let fixture = Fixture::new(4, false);
        let pool = (0..4).map(|i| fixture.project(fixture.legacy(i))).collect();
        assert_eq!(select(pool, 50).len(), 2);
    }
    #[test]
    fn scanner_and_private_routing_identifiers_are_checked_before_projection() {
        let fixture = Fixture::new(4, false);
        for reference in [
            "http://127.0.0.1/",
            "http://100.80.1.2/",
            "https://localhost/",
            "http://[::1]/",
            "http://node.internal/",
        ] {
            let mut source = fixture.source("How are routing endpoints kept private?", false);
            if let Source::Knowledge { hit } = &mut source {
                hit.packet.record.signed.references = vec![reference.into()];
            }
            // Re-sign a valid immutable source rather than relying on a bad
            // signature to test publication-only routing checks.
            let input = KnowledgeInput {
                problem: "How are routing endpoints kept private?".into(),
                solution: "Use only the documented public reference.".into(),
                context: String::new(),
                references: vec![reference.into()],
                kind: "answer".into(),
            };
            let packet =
                knowledge::create_record(&fixture.keys[0], &fixture.room, input, true, fixture.at)
                    .unwrap();
            let source = Source::Knowledge {
                hit: Box::new(KnowledgeHit {
                    quality: crate::knowledge_rating::quality(
                        &packet.record.signed.id,
                        &packet.record.signed.author_peer_id,
                        &[],
                    ),
                    packet,
                    reviews: vec![],
                    review_conflicts: vec![],
                    score: 0.0,
                }),
            };
            assert!(
                verify_and_project(source, &fixture.room, &BTreeMap::new(), fixture.at).is_err()
            );
        }
        let source = fixture.source("How is the currently inspected policy kept fixed?", false);
        let mut bad = source.clone();
        if let Source::Knowledge { hit } = &mut bad {
            hit.packet.record.signed.policy_id = util::hash(b"another profile");
        }
        assert!(verify_and_project(bad, &fixture.room, &BTreeMap::new(), fixture.at).is_err());
        let source = fixture.project(source);
        assert!(source.entry().content.body.contains("適用条件"));
    }
    #[test]
    fn private_cache_is_encrypted_distinct_bounded_and_withdrawn_entries_are_removed() {
        let fixture = Fixture::new(4, false);
        let source = fixture.source("How is the public cache kept separate?", true);
        let record_text = if let Source::Knowledge { hit } = &source {
            hit.packet.record.signed.problem.clone()
        } else {
            unreachable!()
        };
        let projected = fixture.project(source);
        let id = projected.entry().origin.message_id.clone();
        let mut cache = Cache::open(&fixture.home).unwrap();
        cache
            .replace_room("publisher", &fixture.room, &[projected], fixture.at)
            .unwrap();
        let bytes = std::fs::read(&cache.path).unwrap();
        assert!(
            !bytes
                .windows(record_text.len())
                .any(|w| w == record_text.as_bytes())
        );
        assert!(bytes.len() <= CACHE_BYTES);
        assert!(bytes.starts_with(CACHE_MAGIC));
        let reopened = Cache::open(&fixture.home).unwrap();
        assert_eq!(
            reopened
                .sources("publisher", &fixture.room.certificate.signed.room_id)
                .len(),
            1
        );
        cache
            .forget("publisher", &fixture.room, &[id], false, fixture.at)
            .unwrap();
        assert_eq!(Cache::open(&fixture.home).unwrap().metrics().0, 0);
        let mut corrupted = bytes;
        *corrupted.last_mut().unwrap() ^= 1;
        util::atomic_write(&cache.path, &corrupted).unwrap();
        assert!(Cache::open(&fixture.home).is_err());
    }
    #[test]
    fn automatic_selection_cannot_forge_manual_notes_and_respects_signed_manifest_limits() {
        let fixture = Fixture::new(4, false);
        let publisher = identity::Keypair::generate_ed25519();
        let draft = Draft {
            kind: "observation".into(),
            title: "Publisher administrator note".into(),
            body: "A deliberately published administrator note.".into(),
            references: vec![],
        };
        let feed = publication::append(None, &publisher, draft, true, fixture.at).unwrap();
        let manual_id = feed.posts[0].signed.id.clone();
        let mut source = fixture.legacy(1);
        if let Source::Legacy { envelope, .. } = &mut source {
            envelope.payload.body =
                "{\"origin\":null,\"promoted\":true,\"kind\":\"administrator\"}".into();
            // A malicious member can validly sign this text; it still cannot
            // construct the publisher-key administrator provenance class.
            envelope.signature =
                crypto::sign(&fixture.keys[1], "idobata.message.v1", &envelope.payload).unwrap();
        }
        let legacy = fixture.project(source);
        let entries = vec![
            fixture
                .project(fixture.source("How is a corroborated answer published?", true))
                .entry()
                .clone(),
            legacy.entry().clone(),
        ];
        let feed = refresh_imported(
            feed,
            &publisher,
            entries,
            &[],
            false,
            util::now(),
            &[crypto::public(&publisher)],
        )
        .unwrap();
        assert_eq!(
            feed.posts
                .iter()
                .filter(|p| p.signed.origin.is_none())
                .count(),
            1
        );
        assert!(feed.posts.iter().any(|p| p.signed.id == manual_id));
        assert_eq!(
            feed.posts
                .iter()
                .filter(|p| p.signed.origin.is_some())
                .count(),
            2
        );
        let sealed = publication::seal(feed, vec![], 1, &publisher, util::now(), 600).unwrap();
        assert!(util::canonical(&sealed).unwrap().len() <= publication::MAX_FEED_BYTES as usize);
        assert!(sealed.signed.count <= 50);
        publication::verify_manifest(&sealed, &crypto::public(&publisher), util::now(), None)
            .unwrap();
    }
    #[test]
    fn legacy_cache_migration_is_one_unknown_slot_and_new_verified_sources_win() {
        let fixture = Fixture::new(4, true);
        let key = identity::Keypair::generate_ed25519();
        let mut feed = publication::Feed {
            version: 1,
            updated_at: fixture.at,
            posts: vec![],
        };
        let entries = (0..4)
            .map(|i| fixture.project(fixture.legacy(i)).entry().clone())
            .collect();
        publication::import(&mut feed, &key, entries, util::now()).unwrap();
        let cache = refresh_imported(
            feed,
            &key,
            vec![],
            &[],
            true,
            util::now(),
            &[crypto::public(&key)],
        )
        .unwrap();
        assert_eq!(cache.posts.len(), 1);
        assert!(
            cache.posts[0]
                .signed
                .content
                .body
                .contains("現在のP2P認可と有用性は未確認")
        );
        let same = refresh_imported(
            cache.clone(),
            &key,
            vec![],
            &[],
            false,
            util::now(),
            &[crypto::public(&key)],
        )
        .unwrap();
        assert_eq!(
            same.posts[0].signed.content.body,
            cache.posts[0].signed.content.body
        );
        let source = fixture.project(fixture.source(
            "How does fresh provenance replace an old unknown cache?",
            false,
        ));
        let fresh = refresh_imported(
            cache,
            &key,
            vec![source.entry().clone()],
            &[],
            true,
            util::now(),
            &[crypto::public(&key)],
        )
        .unwrap();
        assert_eq!(fresh.posts.len(), 1);
        assert_eq!(fresh.posts[0].signed.id, source.entry().origin.message_id);
        let id = fresh.posts[0].signed.id.clone();
        let withdrawn = refresh_imported(
            fresh,
            &key,
            vec![source.entry().clone()],
            &[id],
            true,
            util::now(),
            &[crypto::public(&key)],
        )
        .unwrap();
        assert!(withdrawn.posts.is_empty());
    }
    #[test]
    fn cache_is_fair_between_ipc_owners_and_preserves_source_observation_time() {
        let fixture = Fixture::new(4, true);
        let source =
            fixture.project(fixture.source("How is a verified observation time retained?", false));
        let mut cache = Cache::open(&fixture.home).unwrap();
        cache
            .replace_room(
                "uid:2|official",
                &fixture.room,
                std::slice::from_ref(&source),
                fixture.at,
            )
            .unwrap();
        for i in 0..8 {
            cache
                .replace_room(
                    &format!("uid:1|namespace-{i}"),
                    &fixture.room,
                    std::slice::from_ref(&source),
                    fixture.at + 1,
                )
                .unwrap();
        }
        assert_eq!(
            cache
                .state
                .slots
                .iter()
                .filter(|s| s.owner.starts_with("uid:1|"))
                .count(),
            4
        );
        assert_eq!(
            cache
                .sources("uid:2|official", &fixture.room.certificate.signed.room_id)
                .len(),
            1
        );
        let old_observation = source.observed_at();
        cache
            .replace_room("uid:2|official", &fixture.room, &[source], fixture.at + 60)
            .unwrap();
        assert_eq!(
            cache.sources("uid:2|official", &fixture.room.certificate.signed.room_id)[0].1,
            old_observation
        );
        let id = cache.sources("uid:2|official", &fixture.room.certificate.signed.room_id)[0]
            .0
            .public_id();
        cache
            .forget(
                "uid:2|official",
                &fixture.room,
                &[id],
                false,
                fixture.at + 61,
            )
            .unwrap();
        assert!(
            cache
                .sources("uid:2|official", &fixture.room.certificate.signed.room_id)
                .is_empty()
        );
        assert_eq!(
            cache
                .sources(
                    "uid:1|namespace-7",
                    &fixture.room.certificate.signed.room_id
                )
                .len(),
            1
        );
        cache
            .forget("uid:2|official", &fixture.room, &[], true, fixture.at + 62)
            .unwrap();
        assert!(
            cache
                .withdrawn("uid:2|official", &fixture.room.certificate.signed.room_id)
                .is_empty()
        );
    }
    #[test]
    #[ignore = "explicit optimized public-proof quota boundary; full 32-member witnesses are CPU-heavy in debug"]
    fn legal_large_proof_remains_publishable_when_private_cache_cannot_retain_it() {
        use crate::automation::{self, AutomationAnswer, AutomationProof};
        let mut fixture = Fixture::new(32, false);
        let mut room = fixture.room.clone();
        room.certificate.signed.knowledge_automation_required = true;
        for member in &mut room.certificate.signed.members {
            // Leave room for the signed challenge, answer and receipt inside
            // the independent 16 KiB automation-proof bound. The certificate
            // is repeated in each complete review packet, so 31 legal reviews
            // still exceed the public cache's 1 MiB owner allowance.
            member.addresses = (1..=2)
                .map(|port| {
                    format!(
                        "/ip6/ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255/tcp/{}/ws",
                        65530 + port
                    )
                })
                .collect();
        }
        room.certificate.signed.knowledge_operators = Some(OperatorClaims {
            bindings: fixture
                .keys
                .iter()
                .enumerate()
                .map(|(i, key)| {
                    (
                        key.public().to_peer_id().to_string(),
                        format!("group{i:02}{}", "a".repeat(40)),
                    )
                })
                .collect(),
            credits: (0..32)
                .map(|i| (format!("group{i:02}{}", "a".repeat(40)), 1000))
                .collect(),
        });
        fixture.resign(&mut room);
        fixture.room = room;
        let prove = |subject: usize, issuer: usize, digest: &str, purpose: &str| {
            let challenge = automation::create_challenge(
                &fixture.keys[issuer],
                &fixture.room,
                &fixture.keys[subject].public().to_peer_id().to_string(),
                digest,
                purpose,
                fixture.at,
            )
            .unwrap();
            assert!(util::canonical(&challenge).unwrap().len() <= automation::MAX_PACKET_BYTES);
            let answers = automation::tasks(&challenge.challenge.signed)
                .into_iter()
                .map(|case| {
                    let mut values = case.values;
                    if case.sort == "ascending" {
                        values.sort_unstable();
                    } else if case.sort == "descending" {
                        values.sort_unstable_by(|a, b| b.cmp(a));
                    }
                    values.rotate_left(case.rotate_left as usize);
                    values
                        .into_iter()
                        .enumerate()
                        .fold(case.initial, |acc, (j, value)| {
                            acc.wrapping_mul(case.multiplier)
                                .wrapping_add((j as u32 + 1).wrapping_mul(value))
                                .rotate_left(((case.index + j as u32) % 31) + 1)
                        })
                })
                .collect();
            let answer = AutomationAnswer { challenge, answers };
            let proof = AutomationProof {
                receipt: automation::certify_answer(
                    &fixture.keys[issuer],
                    &fixture.room,
                    &answer,
                    fixture.at,
                )
                .unwrap(),
                answer,
            };
            assert!(util::canonical(&proof).unwrap().len() <= automation::MAX_PACKET_BYTES);
            proof
        };
        let mut packet=knowledge::prepare_record(&fixture.keys[0],&fixture.room,KnowledgeInput{problem:"How is a large public proof bundle published without losing evidence?".into(),solution:"Keep the complete verified proof on the authenticated transport and publish only the sanitized projection.".into(),context:"Cache capacity is separate from fresh publication eligibility.".into(),references:vec![],kind:"answer".into()},true,fixture.at).unwrap();
        packet.admission = Some(prove(0, 1, &packet.record.signed.id, "publish"));
        assert!(util::canonical(&packet).unwrap().len() <= knowledge::MAX_PACKET_BYTES);
        let input = ReviewInput {
            verdict: "useful".into(),
            evidence: "The documented behavior was independently checked.".repeat(16),
            references: vec![
                format!("https://example.org/{}", "a".repeat(1000)),
                format!("https://example.org/{}", "b".repeat(1000)),
            ],
        };
        let reviews = (1..32)
            .map(|i| {
                let mut review = knowledge::prepare_review(
                    &fixture.keys[i],
                    &fixture.room,
                    &packet,
                    input.clone(),
                    1,
                    fixture.at,
                )
                .unwrap();
                let digest = knowledge::review_action_digest_for_room(
                    &fixture.room,
                    &packet.record.signed.id,
                    &fixture.keys[i].public().to_peer_id().to_string(),
                    &input,
                )
                .unwrap();
                review.admission = Some(prove(i, 0, &digest, "evaluate"));
                assert!(util::canonical(&review).unwrap().len() <= knowledge::MAX_PACKET_BYTES);
                review
            })
            .collect::<Vec<_>>();
        assert_eq!(reviews.len(), 31);
        assert!(reviews.iter().all(|review| review.admission.is_some()));
        let maximum_proof_bytes = reviews
            .iter()
            .map(|review| {
                util::canonical(review.admission.as_ref().unwrap())
                    .unwrap()
                    .len()
            })
            .max()
            .unwrap();
        let hit = KnowledgeHit {
            quality: crate::knowledge_rating::quality(
                &packet.record.signed.id,
                &packet.record.signed.author_peer_id,
                &[],
            ),
            packet,
            reviews,
            review_conflicts: vec![],
            score: 0.0,
        };
        let source = Source::Knowledge { hit: Box::new(hit) };
        let bytes = util::canonical(&source).unwrap().len();
        assert!(
            bytes > 1024 * 1024,
            "fixture must exceed the per-owner cache allowance"
        );
        assert!(
            bytes < 3 * 1024 * 1024,
            "complete witness must fit authenticated transport"
        );
        eprintln!(
            "public_quota_stress aggregate_bytes={bytes} reviews=31 maximum_proof_bytes={maximum_proof_bytes}"
        );
        let projected = fixture.project(source);
        assert!(projected.promoted());
        let Source::Knowledge { hit } = projected.source() else {
            panic!("wrong source kind");
        };
        assert_eq!(
            hit.reviews.len(),
            31,
            "projection must retain every full review tail"
        );
        let mut old_packet = knowledge::prepare_record(
            &fixture.keys[1],
            &fixture.room,
            KnowledgeInput {
                problem:
                    "How is an older public cache source retained under a large-proof admission?"
                        .into(),
                solution:
                    "Keep the previously validated source when a different full witness cannot fit."
                        .into(),
                context:
                    "A private cache is bounded independently from the live public projection."
                        .into(),
                references: vec![],
                kind: "answer".into(),
            },
            true,
            fixture.at,
        )
        .unwrap();
        old_packet.admission = Some(prove(1, 0, &old_packet.record.signed.id, "publish"));
        let old = fixture.project(Source::Knowledge {
            hit: Box::new(KnowledgeHit {
                quality: crate::knowledge_rating::quality(
                    &old_packet.record.signed.id,
                    &old_packet.record.signed.author_peer_id,
                    &[],
                ),
                packet: old_packet,
                reviews: vec![],
                review_conflicts: vec![],
                score: 0.0,
            }),
        });
        let old_id = old.entry().origin.message_id.clone();
        let mut cache = Cache::open(&fixture.home).unwrap();
        cache
            .replace_room("uid:7|large-proof", &fixture.room, &[old], fixture.at)
            .unwrap();
        let previous_generation = cache.write_generation();
        assert!(
            !cache
                .replace_room(
                    "uid:7|large-proof",
                    &fixture.room,
                    std::slice::from_ref(&projected),
                    fixture.at
                )
                .unwrap()
        );
        assert_eq!(
            cache.write_generation(),
            previous_generation,
            "oversized skip is not an I/O attempt"
        );
        let retained = cache.sources(
            "uid:7|large-proof",
            &fixture.room.certificate.signed.room_id,
        );
        assert_eq!(retained.len(), 1);
        assert_eq!(retained[0].0.public_id(), old_id);
        let key = identity::Keypair::generate_ed25519();
        let feed = refresh_imported(
            publication::Feed {
                version: 1,
                updated_at: fixture.at,
                posts: vec![],
            },
            &key,
            vec![projected.entry().clone()],
            &[],
            true,
            util::now(),
            &[crypto::public(&key)],
        )
        .unwrap();
        assert_eq!(feed.posts.len(), 1);
        assert!(
            util::canonical(&publication::seal(feed, vec![], 1, &key, util::now(), 600).unwrap())
                .unwrap()
                .len()
                < 65536
        );
    }
    #[test]
    fn public_reply_links_require_selected_public_parent_and_resolution_authority() {
        let fixture = Fixture::new(4, false);
        let mut parent = fixture.legacy(0);
        if let Source::Legacy { envelope, .. } = &mut parent {
            envelope.payload.kind = "question".into();
            envelope.signature =
                crypto::sign(&fixture.keys[0], "idobata.message.v1", &envelope.payload).unwrap();
        }
        let parent_id = parent.public_id();
        let mut child = fixture.legacy(1);
        if let Source::Legacy { envelope, .. } = &mut child {
            envelope.payload.options.reply_to = Some(parent_id.clone());
            envelope.payload.options.resolution = Some(crate::types::Resolution::Resolved);
            envelope.signature =
                crypto::sign(&fixture.keys[1], "idobata.message.v1", &envelope.payload).unwrap();
        }
        let selected = select(
            vec![fixture.project(parent), fixture.project(child.clone())],
            50,
        );
        assert_eq!(selected.len(), 2);
        let reply = selected
            .iter()
            .find(|s| s.entry().origin.message_id == child.public_id())
            .unwrap();
        assert_eq!(
            reply.entry().origin.reply_to.as_deref(),
            Some(parent_id.as_str())
        );
        assert!(
            reply.entry().origin.resolution.is_none(),
            "another author cannot resolve a question"
        );
        let unknown_id = util::hash(b"unknown or private parent identifier");
        if let Source::Legacy { envelope, .. } = &mut child {
            envelope.payload.options.reply_to = Some(unknown_id.clone());
            envelope.signature =
                crypto::sign(&fixture.keys[1], "idobata.message.v1", &envelope.payload).unwrap();
        }
        let verified = fixture.project(child);
        assert!(verified.entry().origin.reply_to.is_none());
        let selected = select(vec![verified], 50);
        let public = String::from_utf8(util::canonical(selected[0].entry()).unwrap()).unwrap();
        assert!(!public.contains(&unknown_id));
        assert!(selected[0].entry().origin.resolution.is_none());
    }
    #[test]
    fn public_window_cache_revocation_and_future_creation_are_enforced() {
        let fixture = Fixture::new(4, false);
        let mut current = fixture.room.clone();
        current.certificate.signed.epoch = 2;
        fixture.resign(&mut current);
        let old_at = fixture.at - WINDOW_SECONDS;
        let mut historical = fixture.room.clone();
        historical.certificate.signed.issued_at = old_at - 60;
        historical.certificate.signed.expires_at = old_at + 3600;
        fixture.resign(&mut historical);
        let make = |room: &TrustedRoom, at: u64| {
            let packet = knowledge::create_record(
                &fixture.keys[0],
                room,
                KnowledgeInput {
                    problem: "How long is a public projection retained?".into(),
                    solution: "Keep the public listing within its explicit thirty-day window."
                        .into(),
                    context: "P2P retention is independent from the public listing window.".into(),
                    references: vec![],
                    kind: "answer".into(),
                },
                true,
                at,
            )
            .unwrap();
            Source::Knowledge {
                hit: Box::new(KnowledgeHit {
                    quality: crate::knowledge_rating::quality(
                        &packet.record.signed.id,
                        &packet.record.signed.author_peer_id,
                        &[],
                    ),
                    packet,
                    reviews: vec![],
                    review_conflicts: vec![],
                    score: 0.0,
                }),
            }
        };
        let old = make(&historical, old_at);
        let verified =
            verify_and_project(old.clone(), &current, &BTreeMap::new(), fixture.at).unwrap();
        assert!(verify_and_project(old, &current, &BTreeMap::new(), fixture.at + 1).is_err());
        let future = make(&current, fixture.at + 1);
        assert!(
            verify_and_project(future.clone(), &current, &BTreeMap::new(), fixture.at).is_err()
        );
        assert!(verify_and_project(future, &current, &BTreeMap::new(), fixture.at + 1).is_ok());
        let mut cache = Cache::open(&fixture.home).unwrap();
        cache
            .replace_room("publisher", &current, &[verified], fixture.at)
            .unwrap();
        cache
            .reconcile_rooms(std::slice::from_ref(&current), fixture.at + 1)
            .unwrap();
        assert_eq!(cache.metrics().0, 0);
        let verified = fixture.project(fixture.source(
            "How is changed public permission applied to a private cache?",
            false,
        ));
        cache
            .replace_room(
                "publisher",
                &fixture.room,
                std::slice::from_ref(&verified),
                fixture.at,
            )
            .unwrap();
        let mut private = current.clone();
        private.certificate.signed.public = false;
        fixture.resign(&mut private);
        cache.reconcile_rooms(&[private], fixture.at).unwrap();
        assert_eq!(cache.metrics().0, 0);
        cache
            .replace_room("publisher", &fixture.room, &[verified], fixture.at)
            .unwrap();
        cache.reconcile_rooms(&[], fixture.at).unwrap();
        assert_eq!(cache.metrics().0, 0);
    }
    #[test]
    fn private_bare_host_ports_are_blocked_without_treating_public_url_paths_as_hosts() {
        let draft = |body: &str| Draft {
            kind: "answer".into(),
            title: "Public routing boundary".into(),
            body: body.into(),
            references: vec![],
        };
        for endpoint in [
            "localhost:3132",
            "LOCALHOST.:3132",
            "NODE.LOCAL:8080",
            "node.local.:8080",
            "node.internal:443",
            "node.lan:9000",
            "127.0.0.1:3132",
            "[::1]:3132",
        ] {
            assert!(private_route(&draft(&format!(
                "Use {endpoint} for the connection."
            ))));
        }
        for url in [
            "https://example.org/manual.local",
            "https://example.org/docs/node.internal",
            "https://example.org/file.local?mode=1",
        ] {
            assert!(!private_route(&draft(&format!(
                "Read {url} for the public procedure."
            ))));
        }
        let fixture = Fixture::new(4, false);
        let packet = knowledge::create_record(
            &fixture.keys[0],
            &fixture.room,
            KnowledgeInput {
                problem: "How is a loopback development endpoint handled?".into(),
                solution: "Connect to localhost:3132 and check the local response.".into(),
                context: "A private development service.".into(),
                references: vec![],
                kind: "answer".into(),
            },
            true,
            fixture.at,
        )
        .unwrap();
        let source = Source::Knowledge {
            hit: Box::new(KnowledgeHit {
                quality: crate::knowledge_rating::quality(
                    &packet.record.signed.id,
                    &packet.record.signed.author_peer_id,
                    &[],
                ),
                packet,
                reviews: vec![],
                review_conflicts: vec![],
                score: 0.0,
            }),
        };
        assert!(verify_and_project(source, &fixture.room, &BTreeMap::new(), fixture.at).is_err());
    }
}
