//! Durable, signed knowledge, independent of short-lived message delivery.
//!
//! A caller must authorize the *current relayer* separately. Historical author
//! certificates prove authorship at creation; they do not authorize a connection.
use crate::{
    automation::{self, AutomationProof},
    crypto,
    error::{Error, INVALID, Result, STORAGE},
    knowledge_rating::{self, Evidence, Quality},
    scanner::Scanner,
    types::{Draft, Room, Signed, TrustedRoom},
    util,
};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use libp2p::identity;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

pub const REPLICAS: usize = 3;
pub const DEFAULT_QUOTA: usize = 64 * 1024 * 1024;
pub const MAX_OBJECTS: usize = 8192;
pub const MAX_REVIEWERS: usize = 32;
pub const MAX_PACKET_BYTES: usize = 64 * 1024;
const MAGIC: &[u8] = b"idobata.knowledge.v1\0";
const ENCRYPTION_OVERHEAD: usize = MAGIC.len() + 24 + 16;
const RECORD_DOMAIN: &str = "idobata.knowledge.record.v1";
const REVIEW_DOMAIN: &str = "idobata.knowledge.review.v1";
const MAX_SEQUENCE: u64 = 9_007_199_254_740_991;

fn answer_kind() -> String {
    "answer".into()
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeInput {
    pub problem: String,
    pub solution: String,
    #[serde(default)]
    pub context: String,
    #[serde(default)]
    pub references: Vec<String>,
    #[serde(default = "answer_kind")]
    pub kind: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeRecord {
    pub version: u32,
    pub id: String,
    pub room_id: String,
    pub author_peer_id: String,
    pub created_at: u64,
    pub policy_id: String,
    pub problem: String,
    pub solution: String,
    pub context: String,
    pub references: Vec<String>,
    pub public: bool,
    pub kind: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordPacket {
    pub record: Signed<KnowledgeRecord>,
    pub certificate: TrustedRoom,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission: Option<AutomationProof>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewInput {
    pub verdict: String,
    pub evidence: String,
    #[serde(default)]
    pub references: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeReview {
    pub version: u32,
    pub id: String,
    pub room_id: String,
    pub record_id: String,
    pub reviewer_peer_id: String,
    pub created_at: u64,
    pub sequence: u64,
    pub policy_id: String,
    pub verdict: String,
    pub evidence: String,
    pub references: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewPacket {
    pub review: Signed<KnowledgeReview>,
    pub certificate: TrustedRoom,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission: Option<AutomationProof>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredKnowledge {
    pub packet: RecordPacket,
    pub reviews: Vec<ReviewPacket>,
    pub stored_at: u64,
    pub staging: bool,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeState {
    pub version: u32,
    pub records: Vec<StoredKnowledge>,
}

impl Default for KnowledgeState {
    fn default() -> Self {
        Self {
            version: 1,
            records: vec![],
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeHit {
    pub packet: RecordPacket,
    pub reviews: Vec<ReviewPacket>,
    pub quality: Quality,
    pub score: f64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KnowledgeMetrics {
    pub objects: usize,
    pub reviews: usize,
    pub bytes: usize,
    pub quota_bytes: usize,
    pub max_objects: usize,
}

fn content_id<T: Serialize>(value: &T, record: bool) -> Result<String> {
    let mut value = serde_json::to_value(value).map_err(|_| INVALID)?;
    let fields = value.as_object_mut().ok_or(INVALID)?;
    fields.remove("id");
    if record {
        // A repost changes its signed creation claim, not its content identity.
        // The store retains the first accepted packet and all existing reviews.
        fields.remove("created_at");
    }
    Ok(util::hash(&util::canonical(&value)?))
}

fn scan_content(body: String, references: &[String]) -> Result<()> {
    let draft = Draft {
        kind: "answer".into(),
        title: "Knowledge contribution".into(),
        body,
        references: references.to_vec(),
    };
    crypto::validate_draft(&draft)?;
    // Engine/module compilation depends only on the fixed embedded WASM. Every
    // scan still receives a fresh isolated Store, fuel and memory limits.
    static SCANNER: std::sync::OnceLock<Result<Scanner>> = std::sync::OnceLock::new();
    let scanner = SCANNER
        .get_or_init(Scanner::new)
        .as_ref()
        .map_err(Clone::clone)?;
    let report = scanner.scan(&draft, false)?;
    if report.code != 0 {
        return Err(Error::new(report.code, "knowledge_content_rejected"));
    }
    Ok(())
}

fn scan_record(record: &KnowledgeRecord) -> Result<()> {
    if record.problem.is_empty()
        || record.problem.len() > 2048
        || record.solution.is_empty()
        || record.solution.len() > 8192
        || record.context.len() > 4096
        || !["answer", "hint"].contains(&record.kind.as_str())
    {
        return Err(INVALID);
    }
    // Inspect the concatenation as well as references, so context and boundaries
    // cannot hide a value that would have been rejected in an ordinary draft.
    scan_content(
        format!(
            "{}\n{}\n{}",
            record.problem, record.solution, record.context
        ),
        &record.references,
    )
}

fn scan_review(review: &KnowledgeReview) -> Result<()> {
    if !["useful", "incorrect", "outdated"].contains(&review.verdict.as_str())
        || review.evidence.len() > 1024
        || review.references.len() > 2
        || review
            .references
            .iter()
            .any(|reference| reference.len() > 1024)
    {
        return Err(INVALID);
    }
    scan_content(review.evidence.clone(), &review.references)
}

fn certificate_at(
    certificate: &TrustedRoom,
    peer: &str,
    public_key: &str,
    created_at: u64,
) -> Result<()> {
    if created_at > MAX_SEQUENCE {
        return Err(INVALID);
    }
    crypto::validate_room(certificate, &Scanner::policy_id(), created_at)?;
    let room = &certificate.certificate.signed;
    if created_at < room.issued_at.saturating_sub(300) || created_at >= room.expires_at {
        return Err(INVALID);
    }
    let key = crypto::public_key(public_key)?;
    if key.key_type() != identity::KeyType::Ed25519 || key.to_peer_id().to_string() != peer {
        return Err(INVALID);
    }
    if !room
        .members
        .iter()
        .any(|member| member.peer_id == peer && member.public_key == public_key)
    {
        return Err(INVALID);
    }
    Ok(())
}

fn matches_current(historical: &TrustedRoom, current: &TrustedRoom, at: u64) -> Result<()> {
    if at > MAX_SEQUENCE {
        return Err(INVALID);
    }
    crypto::validate_room(current, &Scanner::policy_id(), at)?;
    let old = &historical.certificate.signed;
    let now = &current.certificate.signed;
    if historical.authority_peer_id != current.authority_peer_id
        || historical.certificate.public_key != current.certificate.public_key
        || old.room_id != now.room_id
        || old.policy_id != now.policy_id
        || old.public != now.public
        || old.epoch > now.epoch
    {
        return Err(INVALID);
    }
    Ok(())
}

fn validate_record_historical(packet: &RecordPacket, at: u64) -> Result<()> {
    let record = &packet.record.signed;
    let room = &packet.certificate.certificate.signed;
    if record.version != 1
        || !util::valid_id(&record.id)
        || record.created_at > at.saturating_add(300)
        || record.created_at > MAX_SEQUENCE
        || record.room_id != room.room_id
        || record.policy_id != room.policy_id
        || (record.public && !room.public)
        || util::canonical(packet)?.len() > MAX_PACKET_BYTES
    {
        return Err(INVALID);
    }
    certificate_at(
        &packet.certificate,
        &record.author_peer_id,
        &packet.record.public_key,
        record.created_at,
    )?;
    scan_record(record)?;
    if record.id != content_id(record, true)? {
        return Err(INVALID);
    }
    crypto::verify(
        &crypto::public_key(&packet.record.public_key)?,
        RECORD_DOMAIN,
        record,
        &packet.record.signature,
    )?;
    record_admission(packet, &packet.certificate, at)
}

pub fn create_record(
    key: &identity::Keypair,
    room: &TrustedRoom,
    input: KnowledgeInput,
    public: bool,
    at: u64,
) -> Result<RecordPacket> {
    let packet = prepare_record(key, room, input, public, at)?;
    record_admission(&packet, room, at)?;
    Ok(packet)
}

/// Scan and sign an action in memory before requesting its admission proof.
/// A required-gate packet with no proof cannot be admitted by `Store::insert`.
pub fn prepare_record(
    key: &identity::Keypair,
    room: &TrustedRoom,
    input: KnowledgeInput,
    public: bool,
    at: u64,
) -> Result<RecordPacket> {
    if at > MAX_SEQUENCE {
        return Err(INVALID);
    }
    crypto::validate_room(room, &Scanner::policy_id(), at)?;
    let mut record = KnowledgeRecord {
        version: 1,
        id: String::new(),
        room_id: room.certificate.signed.room_id.clone(),
        author_peer_id: key.public().to_peer_id().to_string(),
        created_at: at,
        policy_id: Scanner::policy_id(),
        problem: input.problem,
        solution: input.solution,
        context: input.context,
        references: input.references,
        public,
        kind: input.kind,
    };
    if public && !room.certificate.signed.public {
        return Err(INVALID);
    }
    certificate_at(room, &record.author_peer_id, &crypto::public(key), at)?;
    scan_record(&record)?;
    record.id = content_id(&record, true)?;
    let packet = RecordPacket {
        record: Signed {
            signature: crypto::sign(key, RECORD_DOMAIN, &record)?,
            public_key: crypto::public(key),
            signed: record,
        },
        certificate: room.clone(),
        admission: None,
    };
    if util::canonical(&packet)?.len() > MAX_PACKET_BYTES {
        return Err(INVALID);
    }
    Ok(packet)
}

pub fn validate_record(packet: &RecordPacket, current: &TrustedRoom, at: u64) -> Result<()> {
    matches_current(&packet.certificate, current, at)?;
    validate_record_historical(packet, at)?;
    record_admission(packet, current, at)
}

fn record_admission(packet: &RecordPacket, current: &TrustedRoom, at: u64) -> Result<()> {
    let record = &packet.record.signed;
    match &packet.admission {
        Some(proof) => automation::verify_proof(
            proof,
            current,
            &record.author_peer_id,
            &record.id,
            "publish",
            record.created_at,
            at,
        ),
        None if packet
            .certificate
            .certificate
            .signed
            .knowledge_automation_required
            || current.certificate.signed.knowledge_automation_required =>
        {
            Err(INVALID)
        }
        None => Ok(()),
    }
}

fn review_digest(review: &KnowledgeReview) -> Result<String> {
    let input = ReviewInput {
        verdict: review.verdict.clone(),
        evidence: review.evidence.clone(),
        references: review.references.clone(),
    };
    Ok(util::hash(&util::canonical(&(
        &review.room_id,
        &review.record_id,
        &review.reviewer_peer_id,
        input,
    ))?))
}

/// Hash only a bounded, inspected evaluation action; sequence/time are claims
/// about a vote update and cannot amplify its admission identity.
pub fn review_action_digest(
    room_id: &str,
    record_id: &str,
    reviewer: &str,
    input: &ReviewInput,
) -> Result<String> {
    if !util::valid_id(room_id)
        || !util::valid_id(record_id)
        || reviewer.parse::<libp2p::PeerId>().is_err()
    {
        return Err(INVALID);
    }
    let review = KnowledgeReview {
        version: 1,
        id: String::new(),
        room_id: room_id.into(),
        record_id: record_id.into(),
        reviewer_peer_id: reviewer.into(),
        created_at: 0,
        sequence: 1,
        policy_id: Scanner::policy_id(),
        verdict: input.verdict.clone(),
        evidence: input.evidence.clone(),
        references: input.references.clone(),
    };
    scan_review(&review)?;
    review_digest(&review)
}

fn review_admission(packet: &ReviewPacket, current: &TrustedRoom, at: u64) -> Result<()> {
    let review = &packet.review.signed;
    match &packet.admission {
        Some(proof) => automation::verify_proof(
            proof,
            current,
            &review.reviewer_peer_id,
            &review_digest(review)?,
            "evaluate",
            review.created_at,
            at,
        ),
        None if packet
            .certificate
            .certificate
            .signed
            .knowledge_automation_required
            || current.certificate.signed.knowledge_automation_required =>
        {
            Err(INVALID)
        }
        None => Ok(()),
    }
}

fn validate_review_historical(packet: &ReviewPacket, record: &RecordPacket, at: u64) -> Result<()> {
    let review = &packet.review.signed;
    let original = &record.record.signed;
    let room = &packet.certificate.certificate.signed;
    if review.version != 1
        || !util::valid_id(&review.id)
        || review.sequence == 0
        || review.sequence > MAX_SEQUENCE
        || review.created_at > MAX_SEQUENCE
        || review.created_at > at.saturating_add(300)
        || review.created_at < original.created_at
        || review.record_id != original.id
        || review.room_id != original.room_id
        || review.room_id != room.room_id
        || review.policy_id != original.policy_id
        || review.policy_id != room.policy_id
        || review.reviewer_peer_id == original.author_peer_id
        || packet.certificate.authority_peer_id != record.certificate.authority_peer_id
        || packet.certificate.certificate.public_key != record.certificate.certificate.public_key
        || room.public != record.certificate.certificate.signed.public
        || util::canonical(packet)?.len() > MAX_PACKET_BYTES
    {
        return Err(INVALID);
    }
    certificate_at(
        &packet.certificate,
        &review.reviewer_peer_id,
        &packet.review.public_key,
        review.created_at,
    )?;
    scan_review(review)?;
    if review.id != content_id(review, false)? {
        return Err(INVALID);
    }
    crypto::verify(
        &crypto::public_key(&packet.review.public_key)?,
        REVIEW_DOMAIN,
        review,
        &packet.review.signature,
    )?;
    review_admission(packet, &packet.certificate, at)
}

pub fn create_review(
    key: &identity::Keypair,
    room: &TrustedRoom,
    record: &RecordPacket,
    input: ReviewInput,
    sequence: u64,
    at: u64,
) -> Result<ReviewPacket> {
    let packet = prepare_review(key, room, record, input, sequence, at)?;
    review_admission(&packet, room, at)?;
    Ok(packet)
}

pub fn prepare_review(
    key: &identity::Keypair,
    room: &TrustedRoom,
    record: &RecordPacket,
    input: ReviewInput,
    sequence: u64,
    at: u64,
) -> Result<ReviewPacket> {
    if at < record.record.signed.created_at {
        return Err(INVALID);
    }
    validate_record(record, room, at)?;
    let mut review = KnowledgeReview {
        version: 1,
        id: String::new(),
        room_id: record.record.signed.room_id.clone(),
        record_id: record.record.signed.id.clone(),
        reviewer_peer_id: key.public().to_peer_id().to_string(),
        created_at: at,
        sequence,
        policy_id: Scanner::policy_id(),
        verdict: input.verdict,
        evidence: input.evidence,
        references: input.references,
    };
    if sequence == 0
        || sequence > MAX_SEQUENCE
        || review.reviewer_peer_id == record.record.signed.author_peer_id
    {
        return Err(INVALID);
    }
    certificate_at(room, &review.reviewer_peer_id, &crypto::public(key), at)?;
    scan_review(&review)?;
    review.id = content_id(&review, false)?;
    let packet = ReviewPacket {
        review: Signed {
            signature: crypto::sign(key, REVIEW_DOMAIN, &review)?,
            public_key: crypto::public(key),
            signed: review,
        },
        certificate: room.clone(),
        admission: None,
    };
    if util::canonical(&packet)?.len() > MAX_PACKET_BYTES {
        return Err(INVALID);
    }
    Ok(packet)
}

pub fn validate_review(
    packet: &ReviewPacket,
    record: &RecordPacket,
    current: &TrustedRoom,
    at: u64,
) -> Result<()> {
    validate_record(record, current, at)?;
    validate_review_for_verified_record(packet, record, current, at)
}

/// A batch caller must first validate `record` against the same current room.
/// This avoids rescanning that immutable record once for every signed review.
pub(crate) fn validate_review_for_verified_record(
    packet: &ReviewPacket,
    record: &RecordPacket,
    current: &TrustedRoom,
    at: u64,
) -> Result<()> {
    matches_current(&packet.certificate, current, at)?;
    validate_review_historical(packet, record, at)?;
    review_admission(packet, current, at)
}

/// Highest-random-weight placement is stable under member ordering. No call can
/// request more than three replicas, including a caller supplying usize::MAX.
pub fn replica_peers(room: &Room, id: &str, replicas: usize) -> Vec<String> {
    let unique: BTreeSet<&str> = room
        .members
        .iter()
        .map(|member| member.peer_id.as_str())
        .collect();
    let mut weighted: Vec<_> = unique
        .into_iter()
        .map(|peer| {
            let input = ("idobata.knowledge.hrw.v1", &room.room_id, id, peer);
            let weight = util::hash(&util::canonical(&input).expect("fixed HRW tuple"));
            (weight, peer.to_owned())
        })
        .collect();
    weighted.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    weighted
        .into_iter()
        .take(replicas.min(REPLICAS))
        .map(|(_, peer)| peer)
        .collect()
}

fn evidence(state: &KnowledgeState, room_id: &str) -> Vec<Evidence> {
    state
        .records
        .iter()
        .filter(|stored| stored.packet.record.signed.room_id == room_id)
        .flat_map(|stored| {
            stored.reviews.iter().map(|packet| {
                let review = &packet.review.signed;
                Evidence {
                    record_id: stored.packet.record.signed.id.clone(),
                    author: stored.packet.record.signed.author_peer_id.clone(),
                    reviewer: review.reviewer_peer_id.clone(),
                    useful: review.verdict == "useful",
                    sequence: review.sequence,
                    created_at: review.created_at,
                }
            })
        })
        .collect()
}

fn snapshot_bytes(state: &KnowledgeState) -> Result<usize> {
    let base = serde_json::to_vec(&KnowledgeState::default())
        .map_err(|_| STORAGE)?
        .len();
    state.records.iter().try_fold(
        base + state.records.len().saturating_sub(1) + ENCRYPTION_OVERHEAD,
        |total, record| {
            total
                .checked_add(serde_json::to_vec(record).map_err(|_| STORAGE)?.len())
                .ok_or(STORAGE)
        },
    )
}

fn enforce_quota(state: &mut KnowledgeState, quota: usize, at: u64) -> Result<bool> {
    let mut bytes = snapshot_bytes(state)?;
    if bytes <= quota && state.records.len() <= MAX_OBJECTS {
        return Ok(true);
    }
    let mut histories: BTreeMap<(String, String), Vec<Evidence>> = BTreeMap::new();
    for stored in &state.records {
        let record = &stored.packet.record.signed;
        let history = histories
            .entry((record.room_id.clone(), record.author_peer_id.clone()))
            .or_default();
        for packet in &stored.reviews {
            let review = &packet.review.signed;
            history.push(Evidence {
                record_id: record.id.clone(),
                author: record.author_peer_id.clone(),
                reviewer: review.reviewer_peer_id.clone(),
                useful: review.verdict == "useful",
                sequence: review.sequence,
                created_at: review.created_at,
            });
        }
    }
    let mut priorities = Vec::with_capacity(state.records.len());
    for stored in &state.records {
        // Until the required owners acknowledge storage, staging is the only
        // durable acceptance guarantee. Capacity pressure must reject later
        // work rather than silently discard an accepted unpublished record.
        if stored.staging {
            continue;
        }
        let record = &stored.packet.record.signed;
        let history = histories
            .get(&(record.room_id.clone(), record.author_peer_id.clone()))
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let quality = knowledge_rating::quality(&record.id, &record.author_peer_id, history);
        priorities.push((
            knowledge_rating::retention_priority(&quality, record.created_at, at),
            record.id.clone(),
            serde_json::to_vec(stored).map_err(|_| STORAGE)?.len(),
        ));
    }
    priorities.sort_by(|a, b| a.0.total_cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let mut removed = BTreeSet::new();
    let mut count = state.records.len();
    for (_, id, size) in priorities {
        if bytes <= quota && count <= MAX_OBJECTS {
            break;
        }
        bytes = bytes.saturating_sub(size + usize::from(count > 1));
        count -= 1;
        removed.insert(id);
    }
    state
        .records
        .retain(|stored| !removed.contains(&stored.packet.record.signed.id));
    Ok(snapshot_bytes(state)? <= quota && state.records.len() <= MAX_OBJECTS)
}

pub struct Store {
    pub state: KnowledgeState,
    path: PathBuf,
    key: Zeroizing<Vec<u8>>,
    quota: usize,
}

impl Store {
    pub fn open(home: &Path) -> Result<Self> {
        Self::with_quota(home, DEFAULT_QUOTA)
    }

    pub fn with_quota(home: &Path, bytes: usize) -> Result<Self> {
        if bytes > DEFAULT_QUOTA || bytes < snapshot_bytes(&KnowledgeState::default())? {
            return Err(STORAGE);
        }
        util::protected(home)?;
        let key_path = home.join("storage.key");
        util::protected(&key_path)?;
        let key = util::read_bounded(&key_path, 32)?;
        if key.len() != 32 {
            return Err(STORAGE);
        }
        let mut store = Self {
            state: KnowledgeState::default(),
            path: home.join("knowledge.enc"),
            key,
            quota: bytes,
        };
        if store.path.exists() {
            util::protected(&store.path)?;
            let encrypted = util::read_bounded(&store.path, bytes as u64)?;
            if encrypted.len() < ENCRYPTION_OVERHEAD || !encrypted.starts_with(MAGIC) {
                return Err(STORAGE);
            }
            let offset = MAGIC.len();
            let cipher = XChaCha20Poly1305::new_from_slice(&store.key).map_err(|_| STORAGE)?;
            let plain = Zeroizing::new(
                cipher
                    .decrypt(
                        XNonce::from_slice(&encrypted[offset..offset + 24]),
                        Payload {
                            msg: &encrypted[offset + 24..],
                            aad: MAGIC,
                        },
                    )
                    .map_err(|_| STORAGE)?,
            );
            store.state = serde_json::from_slice(&plain).map_err(|_| STORAGE)?;
            store.validate_snapshot()?;
        }
        Ok(store)
    }

    fn validate_snapshot(&self) -> Result<()> {
        if self.state.version != 1
            || self.state.records.len() > MAX_OBJECTS
            || snapshot_bytes(&self.state)? > self.quota
        {
            return Err(STORAGE);
        }
        let mut ids = BTreeSet::new();
        for stored in &self.state.records {
            if !ids.insert(&stored.packet.record.signed.id) || stored.reviews.len() > MAX_REVIEWERS
            {
                return Err(STORAGE);
            }
            validate_record_historical(&stored.packet, util::now()).map_err(|_| STORAGE)?;
            let mut reviewers = BTreeSet::new();
            for review in &stored.reviews {
                if !reviewers.insert(&review.review.signed.reviewer_peer_id) {
                    return Err(STORAGE);
                }
                validate_review_historical(review, &stored.packet, util::now())
                    .map_err(|_| STORAGE)?;
            }
        }
        Ok(())
    }

    /// True means the record is present after admission (duplicates are harmless).
    /// The Runtime validates against its current room before calling this method.
    pub fn insert(&mut self, packet: RecordPacket, staging: bool, at: u64) -> Result<bool> {
        if let Some(existing) = self.get(&packet.record.signed.room_id, &packet.record.signed.id)
            && existing.staging == staging
            && util::canonical(&existing.packet)? == util::canonical(&packet)?
        {
            // Repeated repair of an already validated immutable packet does
            // not need content inspection, a state clone, or a disk write.
            return Ok(true);
        }
        validate_record_historical(&packet, at)?;
        let id = packet.record.signed.id.clone();
        if let Some(existing) = self.get(&packet.record.signed.room_id, &id)
            && existing.staging == staging
        {
            return Ok(true);
        }
        let mut candidate = self.state.clone();
        if let Some(existing) = candidate
            .records
            .iter_mut()
            .find(|stored| stored.packet.record.signed.id == id)
        {
            existing.staging = staging;
        } else {
            candidate.records.push(StoredKnowledge {
                packet,
                reviews: vec![],
                stored_at: at,
                staging,
            });
        }
        if !enforce_quota(&mut candidate, self.quota, at)? {
            return Ok(false);
        }
        if !candidate
            .records
            .iter()
            .any(|stored| stored.packet.record.signed.id == id)
        {
            return Ok(false);
        }
        self.save_state(&candidate)?;
        self.state = candidate;
        Ok(true)
    }

    /// One latest sequence per reviewer; a replay cannot accumulate voting power.
    /// The Runtime validates against its current room before calling this method.
    /// True means applied, including an update that causes its target's eviction.
    pub fn evaluate(&mut self, packet: ReviewPacket, at: u64) -> Result<bool> {
        let review = &packet.review.signed;
        let target = self
            .get(&review.room_id, &review.record_id)
            .ok_or(INVALID)?;
        validate_review_historical(&packet, &target.packet, at)?;
        if let Some(previous) = target
            .reviews
            .iter()
            .find(|old| old.review.signed.reviewer_peer_id == review.reviewer_peer_id)
        {
            if review.sequence < previous.review.signed.sequence {
                return Ok(false);
            }
            if review.sequence == previous.review.signed.sequence {
                return if review.id == previous.review.signed.id {
                    Ok(false)
                } else {
                    Err(INVALID)
                };
            }
            if review.created_at < previous.review.signed.created_at {
                return Err(INVALID);
            }
        } else if target.reviews.len() >= MAX_REVIEWERS {
            return Err(INVALID);
        }
        let id = review.record_id.clone();
        let reviewer = review.reviewer_peer_id.clone();
        let mut candidate = self.state.clone();
        let target = candidate
            .records
            .iter_mut()
            .find(|stored| stored.packet.record.signed.id == id)
            .ok_or(INVALID)?;
        target
            .reviews
            .retain(|old| old.review.signed.reviewer_peer_id != reviewer);
        target.reviews.push(packet);
        if !enforce_quota(&mut candidate, self.quota, at)? {
            return Ok(false);
        }
        // Applying a negative update may make its target the lowest-priority
        // object and evict it. Commit that eviction rather than restore an old
        // positive vote; true means applied, not guaranteed body retention.
        self.save_state(&candidate)?;
        self.state = candidate;
        Ok(true)
    }

    pub fn get(&self, room_id: &str, id: &str) -> Option<&StoredKnowledge> {
        self.state.records.iter().find(|stored| {
            stored.packet.record.signed.room_id == room_id && stored.packet.record.signed.id == id
        })
    }

    pub fn search(&self, room_id: &str, query: &str, limit: usize, _at: u64) -> Vec<KnowledgeHit> {
        if query.len() > 2048 {
            return vec![];
        }
        let evidence = evidence(&self.state, room_id);
        let mut hits: Vec<_> = self
            .state
            .records
            .iter()
            .filter(|stored| stored.packet.record.signed.room_id == room_id)
            .filter_map(|stored| {
                let record = &stored.packet.record.signed;
                let relevance = knowledge_rating::lexical_relevance(
                    &record.problem,
                    &record.solution,
                    &record.context,
                    query,
                );
                if !query.trim().is_empty() && relevance <= 0.0 {
                    return None;
                }
                let quality =
                    knowledge_rating::quality(&record.id, &record.author_peer_id, &evidence);
                let score = knowledge_rating::search_score(relevance, &quality);
                Some(KnowledgeHit {
                    packet: stored.packet.clone(),
                    reviews: stored.reviews.clone(),
                    quality,
                    score,
                })
            })
            .collect();
        hits.sort_by(|a, b| {
            b.score
                .total_cmp(&a.score)
                .then_with(|| a.packet.record.signed.id.cmp(&b.packet.record.signed.id))
        });
        hits.truncate(limit.min(100));
        hits
    }

    pub fn metrics(&self) -> KnowledgeMetrics {
        KnowledgeMetrics {
            objects: self.state.records.len(),
            reviews: self
                .state
                .records
                .iter()
                .map(|stored| stored.reviews.len())
                .sum(),
            bytes: snapshot_bytes(&self.state).unwrap_or(usize::MAX),
            quota_bytes: self.quota,
            max_objects: MAX_OBJECTS,
        }
    }

    /// Explicit management removal; a caller saving multiple removals can batch.
    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.state.records.len();
        self.state
            .records
            .retain(|stored| stored.packet.record.signed.id != id);
        self.state.records.len() != before
    }

    /// Persist a small, already verified replication handoff without inspecting
    /// or cloning every immutable body. An I/O failure restores ordering and
    /// staging flags, so the caller never loses its accepted source copy.
    pub fn transition_roles(
        &mut self,
        remove_ids: &[String],
        clear_staging_ids: &[String],
    ) -> Result<()> {
        if remove_ids.len() > 32 || clear_staging_ids.len() > 32 {
            return Err(INVALID);
        }
        let remove: BTreeSet<&str> = remove_ids.iter().map(String::as_str).collect();
        let clear: BTreeSet<&str> = clear_staging_ids.iter().map(String::as_str).collect();
        let mut removed = Vec::new();
        let mut cleared = Vec::new();
        for index in (0..self.state.records.len()).rev() {
            let record = &mut self.state.records[index];
            if remove.contains(record.packet.record.signed.id.as_str()) {
                removed.push((index, self.state.records.remove(index)));
            } else if record.staging && clear.contains(record.packet.record.signed.id.as_str()) {
                record.staging = false;
                cleared.push(record.packet.record.signed.id.clone());
            }
        }
        if removed.is_empty() && cleared.is_empty() {
            return Ok(());
        }
        if let Err(error) = self.save_state(&self.state) {
            for record in &mut self.state.records {
                if cleared.contains(&record.packet.record.signed.id) {
                    record.staging = true;
                }
            }
            removed.sort_by_key(|(index, _)| *index);
            for (index, record) in removed {
                self.state.records.insert(index, record);
            }
            return Err(error);
        }
        Ok(())
    }

    /// Pin a bounded set before ownership handoff or a locally accepted update.
    /// Metadata-only promotion never recompiles or rescans immutable content.
    pub fn protect_staging(&mut self, ids: &[String]) -> Result<()> {
        if ids.len() > 32 {
            return Err(INVALID);
        }
        let requested: BTreeSet<&str> = ids.iter().map(String::as_str).collect();
        let mut changed = Vec::new();
        for record in &mut self.state.records {
            if !record.staging && requested.contains(record.packet.record.signed.id.as_str()) {
                record.staging = true;
                changed.push(record.packet.record.signed.id.clone());
            }
        }
        if changed.is_empty() {
            return Ok(());
        }
        if let Err(error) = self.save_state(&self.state) {
            for record in &mut self.state.records {
                if changed.contains(&record.packet.record.signed.id) {
                    record.staging = false;
                }
            }
            return Err(error);
        }
        Ok(())
    }

    pub fn save(&self) -> Result<()> {
        self.validate_snapshot()?;
        self.save_state(&self.state)
    }

    fn save_state(&self, state: &KnowledgeState) -> Result<()> {
        if state.version != 1
            || state.records.len() > MAX_OBJECTS
            || snapshot_bytes(state)? > self.quota
        {
            return Err(STORAGE);
        }
        let plain = Zeroizing::new(serde_json::to_vec(state).map_err(|_| STORAGE)?);
        let mut nonce = [0u8; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let cipher = XChaCha20Poly1305::new_from_slice(&self.key).map_err(|_| STORAGE)?;
        let encrypted = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: MAGIC,
                },
            )
            .map_err(|_| STORAGE)?;
        let mut bytes = MAGIC.to_vec();
        bytes.extend(nonce);
        bytes.extend(encrypted);
        if bytes.len() > self.quota {
            return Err(STORAGE);
        }
        util::atomic_write(&self.path, &bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        _temp: tempfile::TempDir,
        home: PathBuf,
        authority: identity::Keypair,
        author: identity::Keypair,
        reviewer: identity::Keypair,
        room: TrustedRoom,
        at: u64,
    }

    fn trusted_room(
        authority: &identity::Keypair,
        members: &[&identity::Keypair],
        at: u64,
        epoch: u64,
    ) -> TrustedRoom {
        let room = Room {
            version: 1,
            room_id: util::hash(b"knowledge test room"),
            epoch,
            issued_at: at.saturating_sub(10),
            expires_at: at + 6 * 86400,
            policy_id: Scanner::policy_id(),
            members: members
                .iter()
                .map(|key| crate::types::Member {
                    peer_id: key.public().to_peer_id().to_string(),
                    public_key: crypto::public(key),
                    addresses: vec![],
                })
                .collect(),
            public: false,
            knowledge_automation_required: false,
        };
        TrustedRoom {
            authority_peer_id: authority.public().to_peer_id().to_string(),
            certificate: Signed {
                signature: crypto::sign(authority, "idobata.room.v1", &room).unwrap(),
                public_key: crypto::public(authority),
                signed: room,
            },
        }
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let home = temp.path().join("protected");
            util::private_dir(&home).unwrap();
            util::atomic_write(&home.join("storage.key"), &[7; 32]).unwrap();
            let authority = identity::Keypair::generate_ed25519();
            let author = identity::Keypair::generate_ed25519();
            let reviewer = identity::Keypair::generate_ed25519();
            let at = util::now().saturating_sub(90 * 86400);
            let room = trusted_room(&authority, &[&author, &reviewer], at, 1);
            Self {
                _temp: temp,
                home,
                authority,
                author,
                reviewer,
                room,
                at,
            }
        }

        fn input(&self, problem: &str) -> KnowledgeInput {
            KnowledgeInput {
                problem: problem.into(),
                solution: "Use the documented command and verify the result.".into(),
                context: "A normal development environment.".into(),
                references: vec!["https://example.org/manual".into()],
                kind: "answer".into(),
            }
        }

        fn record(&self, problem: &str) -> RecordPacket {
            create_record(
                &self.author,
                &self.room,
                self.input(problem),
                false,
                self.at,
            )
            .unwrap()
        }

        fn review(&self, record: &RecordPacket, sequence: u64, verdict: &str) -> ReviewPacket {
            create_review(
                &self.reviewer,
                &self.room,
                record,
                ReviewInput {
                    verdict: verdict.into(),
                    evidence: "I ran the procedure and checked its result.".into(),
                    references: vec![],
                },
                sequence,
                self.at + sequence,
            )
            .unwrap()
        }
    }

    #[test]
    fn content_address_and_signature_detect_tampering_and_unknown_fields() {
        let fixture = Fixture::new();
        let packet = fixture.record("How do I verify this task?");
        let same = fixture.record("How do I verify this task?");
        assert_eq!(packet.record.signed.id, same.record.signed.id);
        let repost = create_record(
            &fixture.author,
            &fixture.room,
            fixture.input("How do I verify this task?"),
            false,
            fixture.at + 1,
        )
        .unwrap();
        assert_eq!(packet.record.signed.id, repost.record.signed.id);
        assert_ne!(packet.record.signature, repost.record.signature);
        let mut store = Store::open(&fixture.home).unwrap();
        store.insert(packet.clone(), false, fixture.at).unwrap();
        let disk_before = std::fs::read(fixture.home.join("knowledge.enc")).unwrap();
        store.insert(packet.clone(), false, fixture.at + 1).unwrap();
        store.insert(repost, false, fixture.at + 1).unwrap();
        assert_eq!(store.metrics().objects, 1);
        assert_eq!(
            store.state.records[0].packet.record.signed.created_at,
            fixture.at
        );
        assert_eq!(
            disk_before,
            std::fs::read(fixture.home.join("knowledge.enc")).unwrap()
        );
        assert!(store.insert(packet.clone(), true, fixture.at + 2).unwrap());
        assert!(store.state.records[0].staging);
        let staged = std::fs::read(fixture.home.join("knowledge.enc")).unwrap();
        assert_ne!(disk_before, staged);
        assert!(store.insert(packet.clone(), true, fixture.at + 2).unwrap());
        assert_eq!(
            staged,
            std::fs::read(fixture.home.join("knowledge.enc")).unwrap()
        );
        validate_record(&packet, &fixture.room, fixture.at).unwrap();
        let mut tampered = packet.clone();
        tampered.record.signed.solution.push_str(" Modified.");
        assert!(validate_record(&tampered, &fixture.room, fixture.at).is_err());
        let mut forged = packet.clone();
        forged.record.public_key = crypto::public(&fixture.reviewer);
        assert!(validate_record(&forged, &fixture.room, fixture.at).is_err());
        let mut value = serde_json::to_value(&packet).unwrap();
        value["record"]["signed"]["unexpected"] = true.into();
        assert!(serde_json::from_value::<RecordPacket>(value).is_err());
    }

    #[test]
    fn historical_certificates_survive_delivery_and_membership_expiry() {
        let fixture = Fixture::new();
        let packet = fixture.record("How do I keep durable knowledge?");
        let current_at = fixture.at + 30 * 86400;
        let current = trusted_room(&fixture.authority, &[&fixture.reviewer], current_at, 2);
        validate_record(&packet, &current, current_at).unwrap();
        assert!(crypto::validate_room(&fixture.room, &Scanner::policy_id(), current_at).is_err());
        let impostor = identity::Keypair::generate_ed25519();
        let foreign = trusted_room(&impostor, &[&fixture.reviewer], current_at, 2);
        assert!(validate_record(&packet, &foreign, current_at).is_err());
        let review = create_review(
            &fixture.reviewer,
            &current,
            &packet,
            ReviewInput {
                verdict: "useful".into(),
                evidence: "The original procedure still works after renewal.".into(),
                references: vec![],
            },
            1,
            current_at,
        )
        .unwrap();
        validate_review(&review, &packet, &current, current_at).unwrap();
    }

    #[test]
    fn unauthorized_authors_public_promotion_and_self_reviews_fail() {
        let fixture = Fixture::new();
        let outsider = identity::Keypair::generate_ed25519();
        assert!(
            create_record(
                &outsider,
                &fixture.room,
                fixture.input("A normal question?"),
                false,
                fixture.at
            )
            .is_err()
        );
        assert!(
            create_record(
                &fixture.author,
                &fixture.room,
                fixture.input("A normal question?"),
                true,
                fixture.at
            )
            .is_err()
        );
        let packet = fixture.record("A normal question?");
        assert!(
            create_review(
                &fixture.author,
                &fixture.room,
                &packet,
                ReviewInput {
                    verdict: "useful".into(),
                    evidence: "I agree with my own answer.".into(),
                    references: vec![]
                },
                1,
                fixture.at + 1
            )
            .is_err()
        );
    }

    #[test]
    fn context_evidence_and_references_are_scanned_before_admission() {
        let fixture = Fixture::new();
        let secret = "9aK7mP2xQ8vR4zT6nJ1bW5sL3cF0hD9u";
        let mut input = fixture.input("A normal question?");
        input.context = secret.into();
        assert!(create_record(&fixture.author, &fixture.room, input, false, fixture.at).is_err());
        let mut input = fixture.input("A normal question?");
        input.references = vec![format!("https://example.org/?value={secret}")];
        assert!(create_record(&fixture.author, &fixture.room, input, false, fixture.at).is_err());
        let packet = fixture.record("A normal question?");
        assert!(
            create_review(
                &fixture.reviewer,
                &fixture.room,
                &packet,
                ReviewInput {
                    verdict: "useful".into(),
                    evidence: secret.into(),
                    references: vec![]
                },
                1,
                fixture.at + 1
            )
            .is_err()
        );
        let mut store = Store::open(&fixture.home).unwrap();
        let mut rejected = packet.clone();
        rejected.record.signed.context = secret.into();
        assert!(store.insert(rejected, true, fixture.at).is_err());
        assert_eq!(store.metrics().objects, 0);
        assert!(!fixture.home.join("knowledge.enc").exists());
    }

    #[test]
    fn review_evidence_and_references_have_small_scanned_bounds() {
        let fixture = Fixture::new();
        let packet = fixture.record("How should evidence be summarized?");
        let prefix = "https://example.org/";
        let reference = |letter: &str| format!("{prefix}{}", letter.repeat(1024 - prefix.len()));
        let input = ReviewInput {
            verdict: "useful".into(),
            evidence: "a".repeat(1024),
            references: vec![reference("a"), reference("b")],
        };
        create_review(
            &fixture.reviewer,
            &fixture.room,
            &packet,
            input.clone(),
            1,
            fixture.at + 1,
        )
        .unwrap();
        let mut oversized = input.clone();
        oversized.evidence.push('a');
        assert!(
            create_review(
                &fixture.reviewer,
                &fixture.room,
                &packet,
                oversized,
                1,
                fixture.at + 1
            )
            .is_err()
        );
        let mut oversized = input.clone();
        oversized.references[0].push('a');
        assert!(
            create_review(
                &fixture.reviewer,
                &fixture.room,
                &packet,
                oversized,
                1,
                fixture.at + 1
            )
            .is_err()
        );
        let mut oversized = input;
        oversized
            .references
            .push("https://example.org/third".into());
        assert!(
            create_review(
                &fixture.reviewer,
                &fixture.room,
                &packet,
                oversized,
                1,
                fixture.at + 1
            )
            .is_err()
        );
    }

    #[test]
    fn latest_review_sequence_replaces_and_replays_have_no_extra_weight() {
        let fixture = Fixture::new();
        let packet = fixture.record("Does this solution work?");
        let mut store = Store::open(&fixture.home).unwrap();
        store.insert(packet.clone(), false, fixture.at).unwrap();
        let useful = fixture.review(&packet, 1, "useful");
        assert!(store.evaluate(useful.clone(), fixture.at + 1).unwrap());
        assert!(!store.evaluate(useful, fixture.at + 1).unwrap());
        assert!(
            store
                .evaluate(fixture.review(&packet, 2, "incorrect"), fixture.at + 2)
                .unwrap()
        );
        assert!(
            !store
                .evaluate(fixture.review(&packet, 1, "useful"), fixture.at + 2)
                .unwrap()
        );
        assert!(
            store
                .evaluate(fixture.review(&packet, 2, "outdated"), fixture.at + 2)
                .is_err()
        );
        let stored = store
            .get(&packet.record.signed.room_id, &packet.record.signed.id)
            .unwrap();
        assert_eq!(stored.reviews.len(), 1);
        assert_eq!(stored.reviews[0].review.signed.verdict, "incorrect");
        let hits = store.search(
            &packet.record.signed.room_id,
            "solution",
            10,
            fixture.at + 2,
        );
        assert_eq!(hits[0].quality.useful_votes, 0);
        assert_eq!(hits[0].quality.negative_votes, 1);
    }

    #[test]
    fn encrypted_store_reopens_old_useful_records_without_seven_day_pruning() {
        let fixture = Fixture::new();
        let packet = fixture.record("How is durable storage preserved?");
        let mut store = Store::open(&fixture.home).unwrap();
        store.insert(packet.clone(), true, fixture.at).unwrap();
        store
            .evaluate(fixture.review(&packet, 1, "useful"), fixture.at + 1)
            .unwrap();
        store
            .insert(packet.clone(), false, fixture.at + 365 * 86400)
            .unwrap();
        let bytes = std::fs::read(fixture.home.join("knowledge.enc")).unwrap();
        assert!(
            !bytes
                .windows(packet.record.signed.solution.len())
                .any(|window| window == packet.record.signed.solution.as_bytes())
        );
        assert!(bytes.len() <= DEFAULT_QUOTA);
        assert_eq!(bytes.len(), store.metrics().bytes);
        let reopened = Store::open(&fixture.home).unwrap();
        let restored = reopened
            .get(&packet.record.signed.room_id, &packet.record.signed.id)
            .unwrap();
        assert_eq!(restored.reviews.len(), 1);
        assert!(!restored.staging);
        assert!(!fixture.home.join("state.enc").exists());
        let legacy = crate::storage::Storage::open(&fixture.home).unwrap();
        legacy
            .save(&crate::types::State {
                version: 1,
                ..Default::default()
            })
            .unwrap();
        let legacy_bytes = std::fs::read(fixture.home.join("state.enc")).unwrap();
        util::atomic_write(&fixture.home.join("knowledge.enc"), &legacy_bytes).unwrap();
        assert!(Store::open(&fixture.home).is_err());
        util::atomic_write(&fixture.home.join("state.enc"), &bytes).unwrap();
        assert!(legacy.load().is_err());
    }

    #[test]
    fn quota_evicts_old_unrated_records_and_keeps_useful_knowledge() {
        let fixture = Fixture::new();
        let useful = fixture.record("first question");
        let old = fixture.record("older question");
        let fresh_at = util::now();
        let fresh_room = trusted_room(
            &fixture.authority,
            &[&fixture.author, &fixture.reviewer],
            fresh_at,
            2,
        );
        let fresh = create_record(
            &fixture.author,
            &fresh_room,
            fixture.input("newer question"),
            false,
            fresh_at,
        )
        .unwrap();
        let review = fixture.review(&useful, 1, "useful");
        let expected = KnowledgeState {
            version: 1,
            records: vec![
                StoredKnowledge {
                    packet: useful.clone(),
                    reviews: vec![review.clone()],
                    stored_at: fixture.at,
                    staging: false,
                },
                StoredKnowledge {
                    packet: fresh.clone(),
                    reviews: vec![],
                    stored_at: fresh_at,
                    staging: false,
                },
            ],
        };
        let quota = snapshot_bytes(&expected).unwrap() + 64;
        let mut store = Store::with_quota(&fixture.home, quota).unwrap();
        store.insert(useful.clone(), false, fixture.at).unwrap();
        store.evaluate(review, fixture.at + 1).unwrap();
        store.insert(old.clone(), false, fixture.at).unwrap();
        assert!(store.insert(fresh.clone(), false, fresh_at).unwrap());
        assert!(
            store
                .get(&useful.record.signed.room_id, &useful.record.signed.id)
                .is_some()
        );
        assert!(
            store
                .get(&old.record.signed.room_id, &old.record.signed.id)
                .is_none()
        );
        assert!(
            store
                .get(&fresh.record.signed.room_id, &fresh.record.signed.id)
                .is_some()
        );
        assert!(store.metrics().bytes <= quota);
        assert_eq!(
            store.metrics().bytes,
            std::fs::metadata(fixture.home.join("knowledge.enc"))
                .unwrap()
                .len() as usize
        );
    }

    #[test]
    fn oversized_admission_is_transactional_and_cannot_bypass_quota() {
        let fixture = Fixture::new();
        let packet = fixture.record("A small question");
        let single = KnowledgeState {
            version: 1,
            records: vec![StoredKnowledge {
                packet: packet.clone(),
                reviews: vec![],
                stored_at: fixture.at,
                staging: false,
            }],
        };
        let quota = snapshot_bytes(&single).unwrap() + 64;
        let mut store = Store::with_quota(&fixture.home, quota).unwrap();
        assert!(store.insert(packet.clone(), false, fixture.at).unwrap());
        let before = std::fs::read(fixture.home.join("knowledge.enc")).unwrap();
        let mut input = fixture.input("A large question");
        input.solution = "Normal explanatory prose. ".repeat(150);
        let large =
            create_record(&fixture.author, &fixture.room, input, false, fixture.at).unwrap();
        assert!(!store.insert(large, false, fixture.at).unwrap());
        assert_eq!(store.metrics().objects, 1);
        assert_eq!(
            before,
            std::fs::read(fixture.home.join("knowledge.enc")).unwrap()
        );
        store.state.records[0]
            .packet
            .record
            .signed
            .solution
            .push_str(" Tampered.");
        assert!(store.save().is_err());
    }

    #[test]
    fn unreplicated_staging_is_not_evicted_by_later_admission() {
        let fixture = Fixture::new();
        let first = fixture.record("first question");
        let second = fixture.record("other question");
        let single = KnowledgeState {
            version: 1,
            records: vec![StoredKnowledge {
                packet: first.clone(),
                reviews: vec![],
                stored_at: fixture.at,
                staging: true,
            }],
        };
        let quota = snapshot_bytes(&single).unwrap() + 64;
        let mut store = Store::with_quota(&fixture.home, quota).unwrap();
        assert!(store.insert(first.clone(), true, fixture.at).unwrap());
        let before = std::fs::read(fixture.home.join("knowledge.enc")).unwrap();
        assert!(!store.insert(second.clone(), true, fixture.at + 1).unwrap());
        assert!(!store.insert(second, false, fixture.at + 1).unwrap());
        assert_eq!(store.metrics().objects, 1);
        assert!(store.state.records[0].staging);
        assert_eq!(
            store.state.records[0].packet.record.signed.id,
            first.record.signed.id
        );
        assert_eq!(
            before,
            std::fs::read(fixture.home.join("knowledge.enc")).unwrap()
        );
    }

    #[test]
    fn negative_feedback_can_commit_quota_eviction_without_restoring_old_vote() {
        let fixture = Fixture::new();
        let packet = fixture.record("Does this procedure work?");
        let useful = fixture.review(&packet, 1, "useful");
        let existing = KnowledgeState {
            version: 1,
            records: vec![StoredKnowledge {
                packet: packet.clone(),
                reviews: vec![useful.clone()],
                stored_at: fixture.at,
                staging: false,
            }],
        };
        let quota = snapshot_bytes(&existing).unwrap() + 32;
        let mut store = Store::with_quota(&fixture.home, quota).unwrap();
        store.insert(packet.clone(), false, fixture.at).unwrap();
        store.evaluate(useful, fixture.at + 1).unwrap();
        let negative = create_review(
            &fixture.reviewer,
            &fixture.room,
            &packet,
            ReviewInput {
                verdict: "incorrect".into(),
                evidence: "The updated procedure fails under the documented conditions. "
                    .repeat(10),
                references: vec![],
            },
            2,
            fixture.at + 2,
        )
        .unwrap();
        assert!(store.evaluate(negative, fixture.at + 2).unwrap());
        assert!(
            store
                .get(&packet.record.signed.room_id, &packet.record.signed.id)
                .is_none()
        );
        assert_eq!(
            Store::with_quota(&fixture.home, quota)
                .unwrap()
                .metrics()
                .objects,
            0
        );
    }

    #[test]
    fn role_handoff_is_durable_and_rolls_back_on_io_failure() {
        let fixture = Fixture::new();
        let first = fixture.record("first question");
        let second = fixture.record("other question");
        let first_id = first.record.signed.id.clone();
        let second_id = second.record.signed.id.clone();
        let mut store = Store::open(&fixture.home).unwrap();
        store.insert(first.clone(), true, fixture.at).unwrap();
        store.insert(second.clone(), true, fixture.at).unwrap();
        store
            .transition_roles(
                std::slice::from_ref(&first_id),
                std::slice::from_ref(&second_id),
            )
            .unwrap();
        assert!(store.get(&first.record.signed.room_id, &first_id).is_none());
        assert!(!Store::open(&fixture.home).unwrap().state.records[0].staging);
        store.insert(first.clone(), true, fixture.at).unwrap();
        store.insert(second, true, fixture.at).unwrap();
        let before = serde_json::to_vec(&store.state).unwrap();
        std::fs::remove_file(fixture.home.join("knowledge.enc")).unwrap();
        std::fs::create_dir(fixture.home.join("knowledge.enc")).unwrap();
        assert!(
            store
                .transition_roles(
                    std::slice::from_ref(&first_id),
                    std::slice::from_ref(&second_id)
                )
                .is_err()
        );
        assert_eq!(serde_json::to_vec(&store.state).unwrap(), before);
    }

    #[test]
    fn staging_promotion_is_durable_and_restores_flags_on_io_failure() {
        let fixture = Fixture::new();
        let packet = fixture.record("How do I pin an ownership handoff?");
        let id = packet.record.signed.id.clone();
        let mut store = Store::open(&fixture.home).unwrap();
        store.insert(packet, false, fixture.at).unwrap();
        store.protect_staging(std::slice::from_ref(&id)).unwrap();
        assert!(Store::open(&fixture.home).unwrap().state.records[0].staging);
        store
            .transition_roles(&[], std::slice::from_ref(&id))
            .unwrap();
        std::fs::remove_file(fixture.home.join("knowledge.enc")).unwrap();
        std::fs::create_dir(fixture.home.join("knowledge.enc")).unwrap();
        assert!(store.protect_staging(std::slice::from_ref(&id)).is_err());
        assert!(!store.state.records[0].staging);
    }

    #[test]
    fn placement_is_deterministic_bounded_and_member_order_independent() {
        let fixture = Fixture::new();
        let mut room = fixture.room.certificate.signed.clone();
        let mut keys = vec![];
        for _ in 0..4 {
            keys.push(identity::Keypair::generate_ed25519());
        }
        for key in &keys {
            room.members.push(crate::types::Member {
                peer_id: key.public().to_peer_id().to_string(),
                public_key: crypto::public(key),
                addresses: vec![],
            });
        }
        let id = util::hash(b"knowledge placement");
        let expected = replica_peers(&room, &id, usize::MAX);
        assert_eq!(expected.len(), REPLICAS);
        assert_eq!(expected.iter().collect::<BTreeSet<_>>().len(), REPLICAS);
        room.members.reverse();
        assert_eq!(expected, replica_peers(&room, &id, REPLICAS));
        assert!(replica_peers(&room, &id, 0).is_empty());
        assert_eq!(replica_peers(&room, &id, 1).len(), 1);
        assert!(expected.len() < room.members.len());
    }

    fn solve_test_challenge(
        challenge: automation::ChallengePacket,
    ) -> automation::AutomationAnswer {
        let answers = automation::tasks(&challenge.challenge.signed)
            .into_iter()
            .map(|case| {
                let mut values = case.values;
                match case.sort.as_str() {
                    "ascending" => values.sort_unstable(),
                    "descending" => values.sort_unstable_by(|a, b| b.cmp(a)),
                    _ => {}
                }
                values.rotate_left(case.rotate_left as usize);
                values
                    .iter()
                    .enumerate()
                    .fold(case.initial, |acc, (index, value)| {
                        acc.wrapping_mul(case.multiplier)
                            .wrapping_add((index as u32 + 1) * value)
                            .rotate_left((case.index + index as u32) % 31 + 1)
                    })
            })
            .collect();
        automation::AutomationAnswer { challenge, answers }
    }

    #[test]
    fn required_admission_binds_exact_scanned_record_and_survives_historical_expiry() {
        let fixture = Fixture::new();
        let legacy = fixture.record("How is automation admission bound?");
        let mut room = fixture.room.clone();
        room.certificate.signed.knowledge_automation_required = true;
        room.certificate.signed.version = 3;
        room.certificate.signed.epoch = 2;
        room.certificate.signature = crypto::sign(
            &fixture.authority,
            "idobata.room.v1",
            &room.certificate.signed,
        )
        .unwrap();
        assert!(validate_record(&legacy, &room, fixture.at).is_err());
        assert!(
            create_record(
                &fixture.author,
                &room,
                fixture.input("How is automation admission bound?"),
                false,
                fixture.at
            )
            .is_err()
        );
        let mut packet = prepare_record(
            &fixture.author,
            &room,
            fixture.input("How is automation admission bound?"),
            false,
            fixture.at,
        )
        .unwrap();
        let mut store = Store::open(&fixture.home).unwrap();
        assert!(store.insert(packet.clone(), true, fixture.at).is_err());
        let challenge = automation::create_challenge(
            &fixture.reviewer,
            &room,
            &packet.record.signed.author_peer_id,
            &packet.record.signed.id,
            "publish",
            fixture.at,
        )
        .unwrap();
        let answer = solve_test_challenge(challenge);
        let receipt =
            automation::certify_answer(&fixture.reviewer, &room, &answer, fixture.at).unwrap();
        packet.admission = Some(AutomationProof { answer, receipt });
        validate_record(&packet, &room, fixture.at).unwrap();
        store.insert(packet.clone(), true, fixture.at).unwrap();
        assert!(
            Store::open(&fixture.home).unwrap().state.records[0]
                .packet
                .admission
                .is_some()
        );
        let mut renewed = trusted_room(
            &fixture.authority,
            &[&fixture.author, &fixture.reviewer],
            fixture.at + 30 * 86400,
            3,
        );
        renewed.certificate.signed.knowledge_automation_required = true;
        renewed.certificate.signed.version = 3;
        renewed.certificate.signature = crypto::sign(
            &fixture.authority,
            "idobata.room.v1",
            &renewed.certificate.signed,
        )
        .unwrap();
        validate_record(&packet, &renewed, fixture.at + 30 * 86400).unwrap();
        let mut tampered = packet;
        tampered.admission.as_mut().unwrap().answer.answers[0] ^= 1;
        assert!(validate_record(&tampered, &room, fixture.at).is_err());
    }

    #[test]
    fn evaluation_action_identity_excludes_sequence_but_requires_its_own_proof() {
        let fixture = Fixture::new();
        let packet = fixture.record("How do evaluation proofs bind their input?");
        let input = ReviewInput {
            verdict: "useful".into(),
            evidence: "I checked the documented result.".into(),
            references: vec![],
        };
        let first = prepare_review(
            &fixture.reviewer,
            &fixture.room,
            &packet,
            input.clone(),
            1,
            fixture.at + 1,
        )
        .unwrap();
        let second = prepare_review(
            &fixture.reviewer,
            &fixture.room,
            &packet,
            input.clone(),
            2,
            fixture.at + 2,
        )
        .unwrap();
        assert_ne!(first.review.signed.id, second.review.signed.id);
        assert_eq!(
            review_digest(&first.review.signed).unwrap(),
            review_digest(&second.review.signed).unwrap()
        );
        let digest = review_action_digest(
            &packet.record.signed.room_id,
            &packet.record.signed.id,
            &first.review.signed.reviewer_peer_id,
            &input,
        )
        .unwrap();
        let challenge = automation::create_challenge(
            &fixture.author,
            &fixture.room,
            &first.review.signed.reviewer_peer_id,
            &digest,
            "evaluate",
            fixture.at + 1,
        )
        .unwrap();
        let answer = solve_test_challenge(challenge);
        let receipt =
            automation::certify_answer(&fixture.author, &fixture.room, &answer, fixture.at + 1)
                .unwrap();
        let mut reviewed = first;
        reviewed.admission = Some(AutomationProof { answer, receipt });
        validate_review(&reviewed, &packet, &fixture.room, fixture.at + 1).unwrap();
        reviewed.admission.as_mut().unwrap().receipt.signed.purpose = "publish".into();
        assert!(validate_review(&reviewed, &packet, &fixture.room, fixture.at + 1).is_err());
        let secret = ReviewInput {
            evidence: "9aK7mP2xQ8vR4zT6nJ1bW5sL3cF0hD9u".into(),
            ..input
        };
        assert!(
            review_action_digest(
                &packet.record.signed.room_id,
                &packet.record.signed.id,
                &reviewed.review.signed.reviewer_peer_id,
                &secret
            )
            .is_err()
        );
    }
}
