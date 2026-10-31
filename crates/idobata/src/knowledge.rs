//! Durable, signed knowledge, independent of short-lived message delivery.
//!
//! A caller must authorize the *current relayer* separately. Historical author
//! certificates prove authorship at creation; they do not authorize a connection.
use crate::{
    automation::{self, AutomationProof},
    crypto,
    error::{Error, INVALID, Result, STORAGE},
    knowledge_abuse::{
        self, Assessment, AuthorContext, CandidatePool, ExposureLimits, OperatorGroup,
        OperatorRegistry, PoolLimits, SearchMode, VerifiedEvidence,
    },
    knowledge_rating::{self, Evidence, Quality},
    scanner::Scanner,
    types::{Draft, OperatorBindingHistory, Room, Signed, TrustedRoom},
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_digest: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_digest: Option<String>,
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

/// Two independently validated admitted signatures by the same reviewer at the
/// same sequence for this record. A bare accusation never establishes a fork.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewConflict {
    pub first: ReviewPacket,
    pub second: ReviewPacket,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredKnowledge {
    pub packet: RecordPacket,
    pub reviews: Vec<ReviewPacket>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub review_conflicts: Vec<ReviewConflict>,
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub review_conflicts: Vec<ReviewConflict>,
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
    if !authorization_matches(
        record.version,
        record.authorization_digest.as_deref(),
        &packet.certificate,
    ) || !util::valid_id(&record.id)
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
    let authorization_digest = authorization_digest(room)?;
    let mut record = KnowledgeRecord {
        version: if authorization_digest.is_some() { 2 } else { 1 },
        id: String::new(),
        room_id: room.certificate.signed.room_id.clone(),
        author_peer_id: key.public().to_peer_id().to_string(),
        created_at: at,
        policy_id: Scanner::policy_id(),
        authorization_digest,
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
    if let Some(authorization) = &review.authorization_digest {
        return Ok(util::hash(&util::canonical(&(
            &review.room_id,
            &review.record_id,
            &review.reviewer_peer_id,
            input,
            authorization,
        ))?));
    }
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
        authorization_digest: None,
        verdict: input.verdict.clone(),
        evidence: input.evidence.clone(),
        references: input.references.clone(),
    };
    scan_review(&review)?;
    review_digest(&review)
}

pub fn authorization_digest(room: &TrustedRoom) -> Result<Option<String>> {
    if room.certificate.signed.knowledge_operators.is_some() {
        Ok(Some(util::hash(&util::canonical(&room.certificate)?)))
    } else {
        Ok(None)
    }
}

fn authorization_matches(version: u32, digest: Option<&str>, room: &TrustedRoom) -> bool {
    match (version, digest, authorization_digest(room)) {
        (1, None, Ok(None)) => true,
        (2, Some(actual), Ok(Some(expected))) => actual == expected,
        _ => false,
    }
}

/// Operator-policy admission is bound to the exact authority-signed room scope.
/// The legacy helper remains byte-compatible for pre-operator automation proofs.
pub fn review_action_digest_for_room(
    room: &TrustedRoom,
    record_id: &str,
    reviewer: &str,
    input: &ReviewInput,
) -> Result<String> {
    if !util::valid_id(&room.certificate.signed.room_id)
        || !util::valid_id(record_id)
        || reviewer.parse::<libp2p::PeerId>().is_err()
    {
        return Err(INVALID);
    }
    let review = KnowledgeReview {
        version: if room.certificate.signed.knowledge_operators.is_some() {
            2
        } else {
            1
        },
        id: String::new(),
        room_id: room.certificate.signed.room_id.clone(),
        record_id: record_id.into(),
        reviewer_peer_id: reviewer.into(),
        created_at: 0,
        sequence: 1,
        policy_id: Scanner::policy_id(),
        authorization_digest: authorization_digest(room)?,
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
    if !authorization_matches(
        review.version,
        review.authorization_digest.as_deref(),
        &packet.certificate,
    ) || !util::valid_id(&review.id)
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
    let authorization_digest = authorization_digest(room)?;
    let mut review = KnowledgeReview {
        version: if authorization_digest.is_some() { 2 } else { 1 },
        id: String::new(),
        room_id: record.record.signed.room_id.clone(),
        record_id: record.record.signed.id.clone(),
        reviewer_peer_id: key.public().to_peer_id().to_string(),
        created_at: at,
        sequence,
        policy_id: Scanner::policy_id(),
        authorization_digest,
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

/// Highest-random-weight placement is stable under member ordering. Registered
/// operator groups receive distinct copies before peer-level fallback, so adding
/// keys inside one group cannot increase that group's selection probability.
/// A room wholly owned by one registered group preserves legacy peer placement.
/// Credit controls voting, not storage identity. No call can request >3 copies.
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
    let count = replicas.min(REPLICAS);
    let mut selected = Vec::new();
    if let Some(claims) = room
        .knowledge_operators
        .as_ref()
        .filter(|c| c.validate().is_ok())
    {
        let mut groups: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
        for (_, peer) in &weighted {
            if let Some(group) = claims.bindings.get(peer) {
                groups.entry(group).or_default().push(peer);
            }
        }
        // A wholly registered single operator retains exact legacy placement.
        // If unknown peers exist, first protect the known operator's one copy.
        let registered_peers = groups.values().map(Vec::len).sum::<usize>();
        if groups.len() > 1 || (groups.len() == 1 && registered_peers < weighted.len()) {
            let mut ranked: Vec<_> = groups
                .into_iter()
                .map(|(group, peers)| {
                    let input = (
                        "idobata.knowledge.operator-hrw.v1",
                        &room.room_id,
                        id,
                        group,
                    );
                    (
                        util::hash(&util::canonical(&input).expect("fixed group HRW tuple")),
                        group,
                        peers,
                    )
                })
                .collect();
            ranked.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(b.1)));
            selected.extend(
                ranked
                    .into_iter()
                    .take(count)
                    .map(|(_, _, peers)| peers[0].to_owned()),
            );
        }
    }
    for (_, peer) in weighted {
        if selected.len() >= count {
            break;
        }
        if !selected.contains(&peer) {
            selected.push(peer);
        }
    }
    selected
}

/// Only use after the caller authenticates the current room. A missing/invalid
/// operator policy gives no identity credit; it never falls back to peer count.
pub fn registry(room: &TrustedRoom) -> OperatorRegistry {
    room.certificate
        .signed
        .knowledge_operators
        .as_ref()
        .and_then(|claims| {
            OperatorRegistry::from_verified(claims.bindings.clone(), claims.credits.clone()).ok()
        })
        .unwrap_or_default()
}

/// Internal resource namespace: one operator shares its quota across this
/// authority's rooms, while another authority's same label is independent.
pub fn storage_bucket(authority: &TrustedRoom, group: &OperatorGroup) -> Result<OperatorGroup> {
    match group {
        OperatorGroup::Unknown => Ok(OperatorGroup::Unknown),
        OperatorGroup::Registered(operator) => {
            Ok(OperatorGroup::Registered(util::hash(&util::canonical(&(
                "idobata.storage.operator.v1",
                &authority.authority_peer_id,
                operator,
            ))?)))
        }
    }
}

/// Resource-only binding, never a source of review credit. Same-authority local
/// immutable history is shared across rooms so legacy rooms do not open a second
/// unknown quota for a known operator's key.
pub fn resource_group(
    room: &TrustedRoom,
    peer: &str,
    histories: &BTreeMap<String, OperatorBindingHistory>,
) -> OperatorGroup {
    let current = registry(room).group(peer);
    if current != OperatorGroup::Unknown {
        return current;
    }
    for history in histories
        .values()
        .filter(|h| h.authority_peer_id == room.authority_peer_id)
    {
        if let Some(group) = history.bindings.get(peer) {
            return OperatorGroup::Registered(group.clone());
        }
    }
    OperatorGroup::Unknown
}

fn policy_pin(historical: &TrustedRoom, current: &TrustedRoom) -> bool {
    historical.authority_peer_id == current.authority_peer_id
        && historical.certificate.public_key == current.certificate.public_key
        && historical.certificate.signed.room_id == current.certificate.signed.room_id
        && historical.certificate.signed.policy_id == current.certificate.signed.policy_id
        && historical.certificate.signed.public == current.certificate.signed.public
        && historical.certificate.signed.epoch <= current.certificate.signed.epoch
}

/// Every input packet must already have passed signature/admission validation.
/// Return the SAME LENGTH/ORDER as reviews, including zero-credit legacy claims,
/// so review slot indices remain bound to their original signed packets.
pub fn verified_evidence(
    packet: &RecordPacket,
    reviews: &[ReviewPacket],
    current: &TrustedRoom,
) -> Vec<VerifiedEvidence> {
    verified_evidence_with_conflicts(packet, reviews, &[], current)
}

pub fn review_conflict_group(conflict: &ReviewConflict) -> OperatorGroup {
    let peer = &conflict.first.review.signed.reviewer_peer_id;
    let first = registry(&conflict.first.certificate).group(peer);
    let second = registry(&conflict.second.certificate).group(peer);
    if first == second {
        first
    } else {
        OperatorGroup::Unknown
    }
}

fn conflict_shape(packet: &RecordPacket, conflict: &ReviewConflict) -> Result<()> {
    let a = &conflict.first.review;
    let b = &conflict.second.review;
    if a.signed.record_id != packet.record.signed.id
        || b.signed.record_id != packet.record.signed.id
        || a.signed.reviewer_peer_id != b.signed.reviewer_peer_id
        || a.public_key != b.public_key
        || a.signed.sequence != b.signed.sequence
        || a.signed.id == b.signed.id
    {
        return Err(INVALID);
    }
    Ok(())
}

/// Caller first validates the immutable record against this same current room.
/// Both COMPLETE admitted packets are required; a signed pre-admission draft is
/// insufficient to revoke another operator's influence.
pub fn validate_conflicts(
    packet: &RecordPacket,
    conflicts: &[ReviewConflict],
    current: &TrustedRoom,
    at: u64,
) -> Result<()> {
    if conflicts.len() > MAX_REVIEWERS {
        return Err(INVALID);
    }
    let mut groups = BTreeSet::new();
    for conflict in conflicts {
        conflict_shape(packet, conflict)?;
        validate_review_for_verified_record(&conflict.first, packet, current, at)?;
        validate_review_for_verified_record(&conflict.second, packet, current, at)?;
        if !groups.insert(review_conflict_group(conflict)) {
            return Err(INVALID);
        }
    }
    Ok(())
}

fn normalized_conflict(conflict: &ReviewConflict) -> ReviewConflict {
    if conflict.first.review.signed.id < conflict.second.review.signed.id {
        conflict.clone()
    } else {
        ReviewConflict {
            first: conflict.second.clone(),
            second: conflict.first.clone(),
        }
    }
}

pub fn conflict_digest(conflict: &ReviewConflict) -> Result<String> {
    let conflict = normalized_conflict(conflict);
    Ok(util::hash(&util::canonical(&(
        "idobata.knowledge.fork.v1",
        &conflict.first.review.signed.id,
        &conflict.second.review.signed.id,
    ))?))
}

fn witness_order<T: Serialize>(value: &T) -> Result<(usize, Vec<u8>)> {
    let bytes = util::canonical(value)?;
    Ok((bytes.len(), bytes))
}

fn review_order(packet: &ReviewPacket) -> (u64, u64, bool, &str) {
    let review = &packet.review.signed;
    (
        review.sequence,
        review.created_at,
        review.verdict != "useful",
        &review.id,
    )
}

/// Pure metadata merge. Caller verifies every supplied packet and full fork
/// witness first. Sequence maxima and conflict knowledge are monotone; raw
/// witness differences do not change signed-claim or fork identities.
pub fn canonical_review_state(
    packet: &RecordPacket,
    current: &TrustedRoom,
    reviews: Vec<ReviewPacket>,
    conflicts: Vec<ReviewConflict>,
) -> Result<(Vec<ReviewPacket>, Vec<ReviewConflict>)> {
    if reviews.len() > MAX_REVIEWERS * 2 || conflicts.len() > MAX_REVIEWERS * 2 {
        return Err(INVALID);
    }
    let mut stream = reviews;
    for conflict in conflicts {
        conflict_shape(packet, &conflict)?;
        stream.push(conflict.first);
        stream.push(conflict.second);
    }
    let mut variants: BTreeMap<(String, u64), BTreeMap<String, ReviewPacket>> = BTreeMap::new();
    for review in stream {
        let claim = &review.review.signed;
        if claim.record_id != packet.record.signed.id
            || claim.room_id != packet.record.signed.room_id
        {
            return Err(INVALID);
        }
        let key = (claim.reviewer_peer_id.clone(), claim.sequence);
        let id = claim.id.clone();
        let bucket = variants.entry(key).or_default();
        let replace = if let Some(old) = bucket.get(&id) {
            witness_order(&review)? < witness_order(old)?
        } else {
            true
        };
        if replace {
            bucket.insert(id, review);
        }
    }
    let mut latest: BTreeMap<String, ReviewPacket> = BTreeMap::new();
    let mut proofs: BTreeMap<OperatorGroup, ReviewConflict> = BTreeMap::new();
    for ((peer, _), claims) in variants {
        if claims.len() >= 2 {
            let mut first_two = claims.values();
            let proof = ReviewConflict {
                first: first_two.next().unwrap().clone(),
                second: first_two.next().unwrap().clone(),
            };
            let group = review_conflict_group(&proof);
            let replace = if let Some(old) = proofs.get(&group) {
                conflict_order(&proof) < conflict_order(old)
                    || (conflict_order(&proof) == conflict_order(old)
                        && witness_order(&proof)? < witness_order(old)?)
            } else {
                true
            };
            if replace {
                proofs.insert(group, proof);
            }
        }
        for review in claims.into_values() {
            let replace = if let Some(old) = latest.get(&peer) {
                review_order(&review) > review_order(old)
                    || (review_order(&review) == review_order(old)
                        && witness_order(&review)? < witness_order(old)?)
            } else {
                true
            };
            if replace {
                latest.insert(peer.clone(), review);
            }
        }
    }
    if proofs.len() > MAX_REVIEWERS {
        return Err(INVALID);
    }
    let reviews = latest.into_values().collect::<Vec<_>>();
    let slots = review_slots(packet, &reviews, current, MAX_REVIEWERS);
    Ok((
        slots.into_iter().map(|i| reviews[i].clone()).collect(),
        proofs.into_values().collect(),
    ))
}

fn conflict_order(proof: &ReviewConflict) -> (&str, u64, &str, &str) {
    (
        &proof.first.review.signed.reviewer_peer_id,
        proof.first.review.signed.sequence,
        &proof.first.review.signed.id,
        &proof.second.review.signed.id,
    )
}

fn canonical_conflicts(
    packet: &RecordPacket,
    conflicts: impl IntoIterator<Item = ReviewConflict>,
    current: Option<&TrustedRoom>,
    at: u64,
) -> Result<Vec<ReviewConflict>> {
    let mut verified = Vec::new();
    for conflict in conflicts {
        conflict_shape(packet, &conflict)?;
        if let Some(current) = current {
            validate_review_for_verified_record(&conflict.first, packet, current, at)?;
            validate_review_for_verified_record(&conflict.second, packet, current, at)?;
        } else {
            validate_review_historical(&conflict.first, packet, at)?;
            validate_review_historical(&conflict.second, packet, at)?;
        }
        verified.push(conflict);
        if verified.len() > MAX_REVIEWERS * 2 {
            return Err(INVALID);
        }
    }
    Ok(canonical_review_state(
        packet,
        current.unwrap_or(&packet.certificate),
        Vec::new(),
        verified,
    )?
    .1)
}

/// Same positional contract as verified_evidence. Conflict flags are derived
/// only from already validated full proofs and suppress that operator/record.
pub fn verified_evidence_with_conflicts(
    packet: &RecordPacket,
    reviews: &[ReviewPacket],
    conflicts: &[ReviewConflict],
    current: &TrustedRoom,
) -> Vec<VerifiedEvidence> {
    let current_registry = registry(current);
    let contested: BTreeSet<_> = conflicts
        .iter()
        .map(review_conflict_group)
        .filter(|g| *g != OperatorGroup::Unknown)
        .collect();
    reviews
        .iter()
        .map(|packet_review| {
            let review = &packet_review.review.signed;
            let historical = registry(&packet_review.certificate);
            let group = historical.group(&review.reviewer_peer_id);
            let credit = historical
                .credit(&group)
                .min(current_registry.credit(&group));
            let applicable = policy_pin(&packet.certificate, current)
                && policy_pin(&packet_review.certificate, current)
                && review.room_id == packet.record.signed.room_id
                && review.record_id == packet.record.signed.id
                && review.version == 2
                && authorization_matches(
                    review.version,
                    review.authorization_digest.as_deref(),
                    &packet_review.certificate,
                )
                && authorization_matches(
                    packet.record.signed.version,
                    packet.record.signed.authorization_digest.as_deref(),
                    &packet.certificate,
                )
                && group == current_registry.group(&review.reviewer_peer_id);
            VerifiedEvidence {
                evidence: Evidence {
                    record_id: packet.record.signed.id.clone(),
                    author: packet.record.signed.author_peer_id.clone(),
                    reviewer: review.reviewer_peer_id.clone(),
                    useful: review.verdict == "useful",
                    sequence: review.sequence,
                    created_at: review.created_at,
                },
                historical_group: if applicable {
                    group
                } else {
                    OperatorGroup::Unknown
                },
                historical_credit: if applicable { credit } else { 0 },
                contested: contested.contains(&historical.group(&review.reviewer_peer_id)),
            }
        })
        .collect()
}

pub fn assess_evidence(
    packet: &RecordPacket,
    current: &TrustedRoom,
    evidence: &[VerifiedEvidence],
) -> Assessment {
    assess_evidence_with_history(packet, current, evidence, None)
}

/// Local history is authority-scoped exclusion evidence only; it never supplies
/// reviewer credit, registers an unknown author or overrides a signed binding.
pub fn assessment_context(
    packet: &RecordPacket,
    current: &TrustedRoom,
    history: Option<&OperatorBindingHistory>,
) -> AuthorContext {
    let mut context = AuthorContext::default();
    if policy_pin(&packet.certificate, current)
        && authorization_matches(
            packet.record.signed.version,
            packet.record.signed.authorization_digest.as_deref(),
            &packet.certificate,
        )
    {
        context.historical_group =
            registry(&packet.certificate).group(&packet.record.signed.author_peer_id);
    }
    if let Some(history) = history.filter(|h| h.authority_peer_id == current.authority_peer_id)
        && let Some(group) = history.bindings.get(&packet.record.signed.author_peer_id)
    {
        context
            .additional_exclusions
            .insert(OperatorGroup::Registered(group.clone()));
    }
    context
}

pub fn assessment_index(
    packet: &RecordPacket,
    current: &TrustedRoom,
    evidence: &[VerifiedEvidence],
    history: Option<&OperatorBindingHistory>,
) -> knowledge_abuse::AssessmentIndex {
    knowledge_abuse::AssessmentIndex::new(
        &registry(current),
        &packet.record.signed.author_peer_id,
        evidence,
        &assessment_context(packet, current, history),
    )
}

pub fn assess_evidence_with_history(
    packet: &RecordPacket,
    current: &TrustedRoom,
    evidence: &[VerifiedEvidence],
    history: Option<&OperatorBindingHistory>,
) -> Assessment {
    assessment_index(packet, current, evidence, history).assess(&packet.record.signed.id)
}

pub fn review_slots(
    packet: &RecordPacket,
    reviews: &[ReviewPacket],
    current: &TrustedRoom,
    limit: usize,
) -> Vec<usize> {
    knowledge_abuse::select_review_slots(
        &registry(current),
        &packet.record.signed.id,
        &packet.record.signed.author_peer_id,
        &verified_evidence(packet, reviews, current),
        limit,
    )
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

pub struct Store {
    pub state: KnowledgeState,
    path: PathBuf,
    key: Zeroizing<Vec<u8>>,
    quota: usize,
    rooms: BTreeMap<String, TrustedRoom>,
    operator_history: BTreeMap<String, OperatorBindingHistory>,
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
            rooms: BTreeMap::new(),
            operator_history: BTreeMap::new(),
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

    /// Ephemeral, already verified configuration; no configuration I/O or
    /// ciphertext rewrite, and no deletion when a new policy reduces quota.
    pub fn set_rooms(&mut self, rooms: impl IntoIterator<Item = TrustedRoom>) {
        self.rooms.clear();
        for room in rooms {
            self.rooms
                .entry(room.certificate.signed.room_id.clone())
                .or_insert(room);
        }
    }
    pub fn set_operator_history(&mut self, history: &BTreeMap<String, OperatorBindingHistory>) {
        self.operator_history = history.clone();
    }

    fn assessments(&self, state: &KnowledgeState) -> BTreeMap<String, Assessment> {
        let mut histories: BTreeMap<(&str, &str), Vec<VerifiedEvidence>> = BTreeMap::new();
        for stored in &state.records {
            let record = &stored.packet.record.signed;
            if let Some(current) = self
                .rooms
                .get(&record.room_id)
                .filter(|room| policy_pin(&stored.packet.certificate, room))
            {
                histories
                    .entry((&record.room_id, &record.author_peer_id))
                    .or_default()
                    .extend(verified_evidence_with_conflicts(
                        &stored.packet,
                        &stored.reviews,
                        &stored.review_conflicts,
                        current,
                    ));
            }
        }
        let mut indexes = BTreeMap::new();
        state
            .records
            .iter()
            .map(|stored| {
                let record = &stored.packet.record.signed;
                let assessment = if let Some(current) = self
                    .rooms
                    .get(&record.room_id)
                    .filter(|room| policy_pin(&stored.packet.certificate, room))
                {
                    let context = assessment_context(
                        &stored.packet,
                        current,
                        self.operator_history.get(&record.room_id),
                    );
                    indexes
                        .entry((&record.room_id, &record.author_peer_id, context.clone()))
                        .or_insert_with(|| {
                            knowledge_abuse::AssessmentIndex::new(
                                &registry(current),
                                &record.author_peer_id,
                                histories
                                    .get(&(record.room_id.as_str(), record.author_peer_id.as_str()))
                                    .map(Vec::as_slice)
                                    .unwrap_or(&[]),
                                &context,
                            )
                        })
                        .assess(&record.id)
                } else {
                    let historical_group =
                        registry(&stored.packet.certificate).group(&record.author_peer_id);
                    knowledge_abuse::assess_with_author_context(
                        &OperatorRegistry::default(),
                        &record.id,
                        &record.author_peer_id,
                        &[],
                        &AuthorContext {
                            historical_group,
                            additional_exclusions: BTreeSet::new(),
                        },
                    )
                };
                (record.id.clone(), assessment)
            })
            .collect()
    }

    fn resource_origin(
        &self,
        packet: &RecordPacket,
        peer: &str,
        certificate: &TrustedRoom,
    ) -> OperatorGroup {
        if let Some(current) = self
            .rooms
            .get(&packet.record.signed.room_id)
            .filter(|room| policy_pin(certificate, room))
        {
            let group = resource_group(current, peer, &self.operator_history);
            if group != OperatorGroup::Unknown {
                return group;
            }
        }
        let historical = registry(certificate).group(peer);
        if historical != OperatorGroup::Unknown {
            return historical;
        }
        resource_group(&packet.certificate, peer, &self.operator_history)
    }

    fn storage_charges(
        &self,
        state: &KnowledgeState,
        classes: &BTreeMap<String, Assessment>,
    ) -> Result<Vec<knowledge_abuse::StorageCharge>> {
        let base = snapshot_bytes(&KnowledgeState::default())?;
        let mut charges = vec![knowledge_abuse::StorageCharge {
            group: OperatorGroup::Unknown,
            bytes: (base - usize::from(!state.records.is_empty())) as u64,
            unconfirmed: false,
        }];
        for stored in &state.records {
            let record = &stored.packet.record.signed;
            let assessment = classes.get(&record.id).ok_or(STORAGE)?;
            let mut body = stored.clone();
            body.reviews.clear();
            body.review_conflicts.clear();
            body.staging = false;
            let origin = self.resource_origin(
                &stored.packet,
                &record.author_peer_id,
                &stored.packet.certificate,
            );
            charges.push(knowledge_abuse::StorageCharge {
                group: storage_bucket(&stored.packet.certificate, &origin)?,
                bytes: serde_json::to_vec(&body).map_err(|_| STORAGE)?.len() as u64 + 1,
                unconfirmed: !assessment.promoted,
            });
            for review in &stored.reviews {
                let origin = self.resource_origin(
                    &stored.packet,
                    &review.review.signed.reviewer_peer_id,
                    &review.certificate,
                );
                charges.push(knowledge_abuse::StorageCharge {
                    group: storage_bucket(&stored.packet.certificate, &origin)?,
                    bytes: serde_json::to_vec(review).map_err(|_| STORAGE)?.len() as u64 + 1,
                    unconfirmed: true,
                });
            }
            for proof in &stored.review_conflicts {
                let origin = self.resource_origin(
                    &stored.packet,
                    &proof.first.review.signed.reviewer_peer_id,
                    &proof.first.certificate,
                );
                charges.push(knowledge_abuse::StorageCharge {
                    group: storage_bucket(&stored.packet.certificate, &origin)?,
                    bytes: serde_json::to_vec(proof).map_err(|_| STORAGE)?.len() as u64
                        + b",\"review_conflicts\":[]".len() as u64
                        + 1,
                    unconfirmed: true,
                });
            }
        }
        Ok(charges)
    }

    fn policy_limits(&self) -> knowledge_abuse::QuotaLimits {
        let mut limits = knowledge_abuse::QuotaLimits::default();
        limits.total_bytes = self.quota as u64;
        limits.unconfirmed_bytes = limits.unconfirmed_bytes.min(limits.total_bytes);
        limits.operator_unconfirmed_bytes = limits
            .operator_unconfirmed_bytes
            .min(limits.unconfirmed_bytes);
        limits.unknown_unconfirmed_bytes = limits
            .unknown_unconfirmed_bytes
            .min(limits.unconfirmed_bytes);
        limits
    }

    fn admit_state(
        &self,
        state: &mut KnowledgeState,
        new_record: Option<&str>,
        at: u64,
    ) -> Result<bool> {
        let classes = self.assessments(state);
        // Reclassification of an existing immutable body is grandfathered in
        // both snapshots. New review/proof bytes still belong to their signer.
        let before = self.storage_charges(&self.state, &classes)?;
        let limits = self.policy_limits();
        let fits = |candidate: &KnowledgeState| -> Result<bool> {
            Ok(candidate.records.len() <= MAX_OBJECTS
                && snapshot_bytes(candidate)? <= self.quota
                && knowledge_abuse::check_storage_charges(
                    &before,
                    &self.storage_charges(candidate, &classes)?,
                    limits,
                    true,
                )
                .is_ok())
        };
        if fits(state)? {
            return Ok(true);
        }
        let Some(new_id) = new_record else {
            return Err(Error::new(30, "knowledge_metadata_quota_exceeded"));
        };
        let target = state
            .records
            .iter()
            .find(|row| row.packet.record.signed.id == new_id)
            .ok_or(STORAGE)?;
        let target_class = classes.get(new_id).ok_or(STORAGE)?;
        if !target_class.promoted
            && knowledge_abuse::check_storage_charges(&[], &before, limits, false).is_err()
        {
            return Err(Error::new(30, "knowledge_existing_policy_quota_exceeded"));
        }
        let target_group = storage_bucket(
            &target.packet.certificate,
            &self.resource_origin(
                &target.packet,
                &target.packet.record.signed.author_peer_id,
                &target.packet.certificate,
            ),
        )?;
        let priority = knowledge_rating::retention_priority(
            &target_class.quality,
            target.packet.record.signed.created_at,
            at,
        );
        let mut victims = Vec::new();
        for row in &state.records {
            let record = &row.packet.record.signed;
            let class = classes.get(&record.id).ok_or(STORAGE)?;
            if record.id == new_id || row.staging || class.promoted {
                continue;
            }
            let group = storage_bucket(
                &row.packet.certificate,
                &self.resource_origin(&row.packet, &record.author_peer_id, &row.packet.certificate),
            )?;
            let old_priority =
                knowledge_rating::retention_priority(&class.quality, record.created_at, at);
            if group == target_group && old_priority <= priority {
                victims.push((old_priority, record.id.clone()));
            }
        }
        victims.sort_by(|a, b| a.0.total_cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
        for (_, id) in victims {
            state
                .records
                .retain(|row| row.packet.record.signed.id != id);
            if fits(state)? {
                return Ok(true);
            }
        }
        Err(Error::new(30, "knowledge_operator_quota_exceeded"))
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
            if !ids.insert(&stored.packet.record.signed.id)
                || stored.reviews.len() > MAX_REVIEWERS
                || stored.review_conflicts.len() > MAX_REVIEWERS
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
            let canonical = canonical_conflicts(
                &stored.packet,
                stored.review_conflicts.clone(),
                None,
                util::now(),
            )
            .map_err(|_| STORAGE)?;
            if canonical.len() != stored.review_conflicts.len()
                || util::canonical(&canonical).map_err(|_| STORAGE)?
                    != util::canonical(&stored.review_conflicts).map_err(|_| STORAGE)?
            {
                return Err(STORAGE);
            }
        }
        Ok(())
    }

    /// True means the record is present after admission (duplicates are harmless).
    /// The Runtime validates against its current room before calling this method.
    pub fn insert(&mut self, packet: RecordPacket, staging: bool, at: u64) -> Result<bool> {
        self.insert_with_reviews_and_conflicts(packet, Vec::new(), Vec::new(), staging, at)
    }

    pub fn insert_with_reviews(
        &mut self,
        packet: RecordPacket,
        reviews: Vec<ReviewPacket>,
        staging: bool,
        at: u64,
    ) -> Result<bool> {
        self.insert_with_reviews_and_conflicts(packet, reviews, Vec::new(), staging, at)
    }

    /// Admit an immutable body and its COMPLETE mutable review state in one
    /// durable transaction. A third independent vote can therefore promote the
    /// incoming body before quota admission, rather than failing an empty-vote
    /// insertion first. Metadata updates never evict another accepted body.
    pub fn insert_with_reviews_and_conflicts(
        &mut self,
        packet: RecordPacket,
        reviews: Vec<ReviewPacket>,
        conflicts: Vec<ReviewConflict>,
        staging: bool,
        at: u64,
    ) -> Result<bool> {
        if reviews.len() > MAX_REVIEWERS * 2 || conflicts.len() > MAX_REVIEWERS {
            return Err(INVALID);
        }
        let id = packet.record.signed.id.clone();
        let room_id = packet.record.signed.room_id.clone();
        let existing = self.get(&room_id, &id);
        let exact = existing
            .is_some_and(|old| util::canonical(&old.packet).ok() == util::canonical(&packet).ok());
        if exact
            && reviews.is_empty()
            && conflicts.is_empty()
            && existing.is_some_and(|row| row.staging == staging)
        {
            return Ok(true);
        }
        if !exact {
            validate_record_historical(&packet, at)?;
        }
        let body = existing.map(|row| row.packet.clone()).unwrap_or(packet);
        let current = self
            .rooms
            .get(&room_id)
            .filter(|room| policy_pin(&body.certificate, room))
            .cloned();
        for review in &reviews {
            let known = existing.is_some_and(|row| {
                row.reviews
                    .iter()
                    .any(|old| util::canonical(old).ok() == util::canonical(review).ok())
            });
            if !known {
                if let Some(room) = &current {
                    validate_review_for_verified_record(review, &body, room, at)?;
                } else {
                    validate_review_historical(review, &body, at)?;
                }
            }
        }
        let verified_conflicts = canonical_conflicts(&body, conflicts, current.as_ref(), at)?;
        let mut all_reviews = existing.map(|row| row.reviews.clone()).unwrap_or_default();
        all_reviews.extend(reviews);
        // The caller can include its existing state in a bundle; deduplicate
        // identical signed claims before applying the bounded merge window.
        let mut by_id: BTreeMap<String, ReviewPacket> = BTreeMap::new();
        for review in all_reviews {
            let key = review.review.signed.id.clone();
            let replace = if let Some(old) = by_id.get(&key) {
                witness_order(&review)? < witness_order(old)?
            } else {
                true
            };
            if replace {
                by_id.insert(key, review);
            }
        }
        let mut all_conflicts = existing
            .map(|row| row.review_conflicts.clone())
            .unwrap_or_default();
        all_conflicts.extend(verified_conflicts);
        let (selected, selected_conflicts) = canonical_review_state(
            &body,
            current.as_ref().unwrap_or(&body.certificate),
            by_id.into_values().collect(),
            all_conflicts,
        )?;
        let is_new = existing.is_none();
        let mut candidate = self.state.clone();
        if let Some(row) = candidate
            .records
            .iter_mut()
            .find(|row| row.packet.record.signed.id == id)
        {
            row.staging = staging;
            row.reviews = selected;
            row.review_conflicts = selected_conflicts;
        } else {
            candidate.records.push(StoredKnowledge {
                packet: body,
                reviews: selected,
                review_conflicts: selected_conflicts,
                stored_at: at,
                staging,
            });
        }
        if util::canonical(&candidate)? == util::canonical(&self.state)? {
            return Ok(true);
        }
        self.admit_state(&mut candidate, is_new.then_some(id.as_str()), at)?;
        self.save_state(&candidate)?;
        self.state = candidate;
        Ok(true)
    }

    /// A valid fork is retained as signed conflict evidence rather than allowing
    /// the first positive claim to win. A stale lower sequence changes nothing.
    pub fn evaluate(&mut self, packet: ReviewPacket, at: u64) -> Result<bool> {
        let id = packet.review.signed.record_id.clone();
        let room = packet.review.signed.room_id.clone();
        let target = self.get(&room, &id).ok_or(INVALID)?;
        let before = util::canonical(target)?;
        let body = target.packet.clone();
        let staging = target.staging;
        self.insert_with_reviews_and_conflicts(body, vec![packet], Vec::new(), staging, at)?;
        let after = self.get(&room, &id).ok_or(STORAGE)?;
        Ok(before != util::canonical(after)?)
    }

    pub fn get(&self, room_id: &str, id: &str) -> Option<&StoredKnowledge> {
        self.state.records.iter().find(|stored| {
            stored.packet.record.signed.room_id == room_id && stored.packet.record.signed.id == id
        })
    }

    pub fn search(&self, room_id: &str, query: &str, limit: usize, at: u64) -> Vec<KnowledgeHit> {
        self.search_mode(room_id, query, limit, at, SearchMode::Normal)
    }

    pub fn search_mode(
        &self,
        room_id: &str,
        query: &str,
        limit: usize,
        _at: u64,
        mode: SearchMode,
    ) -> Vec<KnowledgeHit> {
        if query.len() > 2048 {
            return vec![];
        }
        let current = self.rooms.get(room_id);
        let registry = current.map(registry).unwrap_or_default();
        let mut histories: BTreeMap<&str, Vec<VerifiedEvidence>> = BTreeMap::new();
        if let Some(current) = current {
            for stored in self
                .state
                .records
                .iter()
                .filter(|stored| stored.packet.record.signed.room_id == room_id)
            {
                histories
                    .entry(&stored.packet.record.signed.author_peer_id)
                    .or_default()
                    .extend(verified_evidence_with_conflicts(
                        &stored.packet,
                        &stored.reviews,
                        &stored.review_conflicts,
                        current,
                    ));
            }
        }
        let mut pool =
            CandidatePool::new(PoolLimits::default()).expect("fixed bounded policy limits");
        let mut records = BTreeMap::new();
        let mut indexes = BTreeMap::new();
        for stored in self
            .state
            .records
            .iter()
            .filter(|stored| stored.packet.record.signed.room_id == room_id)
        {
            let record = &stored.packet.record.signed;
            if current.is_some_and(|room| !policy_pin(&stored.packet.certificate, room)) {
                continue;
            }
            let relevance = knowledge_rating::lexical_relevance(
                &record.problem,
                &record.solution,
                &record.context,
                query,
            );
            if !query.trim().is_empty() && relevance <= 0.0 {
                continue;
            }
            let evidence = histories
                .get(record.author_peer_id.as_str())
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            let assessment = if let Some(current) = current {
                let context =
                    assessment_context(&stored.packet, current, self.operator_history.get(room_id));
                indexes
                    .entry((&record.author_peer_id, context.clone()))
                    .or_insert_with(|| {
                        knowledge_abuse::AssessmentIndex::new(
                            &registry,
                            &record.author_peer_id,
                            evidence,
                            &context,
                        )
                    })
                    .assess(&record.id)
            } else {
                knowledge_abuse::assess(&registry, &record.id, &record.author_peer_id, &[])
            };
            pool.offer_assessed(
                &registry,
                &record.id,
                &record.author_peer_id,
                relevance,
                assessment,
            );
            records.insert(record.id.as_str(), stored);
        }
        pool.select(
            mode,
            ExposureLimits {
                total: limit.min(100),
                ..Default::default()
            },
        )
        .into_iter()
        .filter_map(|selected| {
            let stored = records.get(selected.id.as_str())?;
            Some(KnowledgeHit {
                packet: stored.packet.clone(),
                reviews: stored.reviews.clone(),
                review_conflicts: stored.review_conflicts.clone(),
                quality: selected.assessment.quality,
                score: selected.score,
            })
        })
        .collect()
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
            knowledge_operators: None,
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

    fn operator_room(
        authority: &identity::Keypair,
        members: &[&identity::Keypair],
        at: u64,
        epoch: u64,
    ) -> TrustedRoom {
        let mut room = trusted_room(authority, members, at, epoch);
        let bindings = members
            .iter()
            .map(|key| {
                let peer = key.public().to_peer_id().to_string();
                (peer.clone(), peer)
            })
            .collect::<BTreeMap<_, _>>();
        let credits = bindings
            .values()
            .map(|group| (group.clone(), 1000))
            .collect();
        room.certificate.signed.version = 4;
        room.certificate.signed.knowledge_operators =
            Some(knowledge_abuse::OperatorClaims { bindings, credits });
        room.certificate.signature =
            crypto::sign(authority, "idobata.room.v1", &room.certificate.signed).unwrap();
        room
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
                .unwrap()
        );
        let stored = store
            .get(&packet.record.signed.room_id, &packet.record.signed.id)
            .unwrap();
        assert_eq!(stored.reviews.len(), 1);
        assert_eq!(stored.reviews[0].review.signed.sequence, 2);
        assert_eq!(stored.review_conflicts.len(), 1);
        assert!(
            store
                .search(
                    &packet.record.signed.room_id,
                    "solution",
                    10,
                    fixture.at + 2
                )
                .is_empty()
        );
        let hits = store.search_mode(
            &packet.record.signed.room_id,
            "solution",
            10,
            fixture.at + 2,
            SearchMode::Explore,
        );
        assert_eq!(hits[0].quality.useful_votes, 0);
        assert_eq!(hits[0].quality.negative_votes, 0); // legacy claims grant no credit
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
        let mut fixture = Fixture::new();
        fixture.room = operator_room(
            &fixture.authority,
            &[&fixture.author, &fixture.reviewer],
            fixture.at,
            1,
        );
        let useful = fixture.record("first question");
        let old = fixture.record("older question");
        let fresh_at = util::now();
        let fresh_room = operator_room(
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
                    review_conflicts: vec![],
                    stored_at: fixture.at,
                    staging: false,
                },
                StoredKnowledge {
                    packet: fresh.clone(),
                    reviews: vec![],
                    review_conflicts: vec![],
                    stored_at: fresh_at,
                    staging: false,
                },
            ],
        };
        let quota = snapshot_bytes(&expected).unwrap() + 64;
        let mut store = Store::with_quota(&fixture.home, quota).unwrap();
        store.set_rooms([fixture.room.clone()]);
        store.insert(useful.clone(), false, fixture.at).unwrap();
        store.evaluate(review, fixture.at + 1).unwrap();
        store.insert(old.clone(), false, fixture.at).unwrap();
        store.set_rooms([fresh_room.clone()]);
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
                review_conflicts: vec![],
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
        assert!(matches!(store.insert(large,false,fixture.at),Err(error) if error.code==30));
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
                review_conflicts: vec![],
                stored_at: fixture.at,
                staging: true,
            }],
        };
        let quota = snapshot_bytes(&single).unwrap() + 64;
        let mut store = Store::with_quota(&fixture.home, quota).unwrap();
        assert!(store.insert(first.clone(), true, fixture.at).unwrap());
        let before = std::fs::read(fixture.home.join("knowledge.enc")).unwrap();
        assert!(
            matches!(store.insert(second.clone(),true,fixture.at+1),Err(error) if error.code==30)
        );
        assert!(matches!(store.insert(second,false,fixture.at+1),Err(error) if error.code==30));
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
    fn metadata_growth_rejects_atomically_without_evicting_an_accepted_body() {
        let fixture = Fixture::new();
        let packet = fixture.record("Does this procedure work?");
        let useful = fixture.review(&packet, 1, "useful");
        let existing = KnowledgeState {
            version: 1,
            records: vec![StoredKnowledge {
                packet: packet.clone(),
                reviews: vec![useful.clone()],
                review_conflicts: vec![],
                stored_at: fixture.at,
                staging: false,
            }],
        };
        let quota = snapshot_bytes(&existing).unwrap() + 32;
        let mut store = Store::with_quota(&fixture.home, quota).unwrap();
        store.insert(packet.clone(), false, fixture.at).unwrap();
        store.evaluate(useful, fixture.at + 1).unwrap();
        let before = std::fs::read(fixture.home.join("knowledge.enc")).unwrap();
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
        assert!(matches!(store.evaluate(negative,fixture.at+2),Err(error) if error.code==30));
        assert!(
            store
                .get(&packet.record.signed.room_id, &packet.record.signed.id)
                .is_some()
        );
        assert_eq!(
            Store::with_quota(&fixture.home, quota)
                .unwrap()
                .metrics()
                .objects,
            1
        );
        assert_eq!(
            before,
            std::fs::read(fixture.home.join("knowledge.enc")).unwrap()
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

    #[test]
    fn operator_placement_resists_key_multiplication_and_ignores_credit() {
        let fixture = Fixture::new();
        let keys = (0..32)
            .map(|_| identity::Keypair::generate_ed25519())
            .collect::<Vec<_>>();
        let members = keys.iter().collect::<Vec<_>>();
        let mut room = operator_room(&fixture.authority, &members, fixture.at, 1)
            .certificate
            .signed;
        let mut claims = knowledge_abuse::OperatorClaims {
            bindings: BTreeMap::new(),
            credits: BTreeMap::new(),
        };
        for (index, member) in room.members.iter().enumerate() {
            let group = if index < 24 {
                "large".to_owned()
            } else {
                format!("small-{index}")
            };
            claims
                .bindings
                .insert(member.peer_id.clone(), group.clone());
            claims.credits.insert(group, 0); // Storage identity is independent of voting credit.
        }
        room.knowledge_operators = Some(claims.clone());
        let mut reduced = room.clone();
        reduced.members.drain(1..24);
        let retained = reduced
            .members
            .iter()
            .map(|m| m.peer_id.clone())
            .collect::<BTreeSet<_>>();
        reduced
            .knowledge_operators
            .as_mut()
            .unwrap()
            .bindings
            .retain(|p, _| retained.contains(p));
        let groups = |peers: Vec<String>| {
            peers
                .into_iter()
                .map(|peer| claims.bindings[&peer].clone())
                .collect::<BTreeSet<_>>()
        };
        for n in 0..64 {
            let id = util::hash(format!("record-{n}").as_bytes());
            let selected = replica_peers(&room, &id, REPLICAS);
            assert_eq!(groups(selected.clone()).len(), REPLICAS);
            assert_eq!(
                groups(selected.clone()),
                groups(replica_peers(&reduced, &id, REPLICAS))
            );
            room.members.reverse();
            assert_eq!(selected, replica_peers(&room, &id, REPLICAS));
        }
        // Exactly three registered groups must occupy all slots ahead of unknowns.
        let mut three = room.clone();
        let policy = three.knowledge_operators.as_mut().unwrap();
        policy
            .bindings
            .retain(|_, g| g == "large" || g == "small-24" || g == "small-25");
        policy
            .credits
            .retain(|g, _| g == "large" || g == "small-24" || g == "small-25");
        let known = policy.bindings.keys().cloned().collect::<BTreeSet<_>>();
        for n in 0..16 {
            let chosen = replica_peers(&three, &format!("id-{n}"), REPLICAS);
            assert_eq!(
                chosen.iter().filter(|p| known.contains(*p)).count(),
                REPLICAS
            );
            assert_eq!(groups(chosen).len(), REPLICAS);
        }
    }

    #[test]
    fn single_operator_placement_preserves_three_legacy_hosts() {
        let fixture = Fixture::new();
        let keys = (0..4)
            .map(|_| identity::Keypair::generate_ed25519())
            .collect::<Vec<_>>();
        let mut room = operator_room(
            &fixture.authority,
            &keys.iter().collect::<Vec<_>>(),
            fixture.at,
            1,
        )
        .certificate
        .signed;
        let policy = room.knowledge_operators.as_mut().unwrap();
        for group in policy.bindings.values_mut() {
            *group = "one-owner".into();
        }
        policy.credits = BTreeMap::from([("one-owner".into(), 1000)]);
        for n in 0..32 {
            let id = format!("placement-{n}");
            let grouped = replica_peers(&room, &id, REPLICAS);
            let mut legacy = room.clone();
            legacy.knowledge_operators = None;
            assert_eq!(grouped, replica_peers(&legacy, &id, REPLICAS));
            assert_eq!(grouped.len(), REPLICAS);
        }
    }

    #[test]
    fn single_registered_operator_keeps_one_copy_ahead_of_unknown_peers() {
        let fixture = Fixture::new();
        let keys = (0..4)
            .map(|_| identity::Keypair::generate_ed25519())
            .collect::<Vec<_>>();
        let mut room = operator_room(
            &fixture.authority,
            &keys.iter().collect::<Vec<_>>(),
            fixture.at,
            1,
        )
        .certificate
        .signed;
        let id = util::hash(b"one-registered-operator-plus-unknown");
        let mut legacy = room.clone();
        legacy.knowledge_operators = None;
        let old = replica_peers(&legacy, &id, REPLICAS);
        let known = room
            .members
            .iter()
            .find(|m| !old.contains(&m.peer_id))
            .unwrap()
            .peer_id
            .clone();
        room.knowledge_operators = Some(knowledge_abuse::OperatorClaims {
            bindings: BTreeMap::from([(known.clone(), "registered".into())]),
            credits: BTreeMap::from([("registered".into(), 0)]),
        });
        let chosen = replica_peers(&room, &id, REPLICAS);
        assert_eq!(chosen.len(), REPLICAS);
        assert_eq!(chosen[0], known);
        assert_eq!(chosen[1..], old[..2]);
    }

    #[test]
    fn resource_namespace_is_authority_scoped_and_history_crosses_legacy_rooms_only_for_resources()
    {
        let fixture = Fixture::new();
        let registered = operator_room(
            &fixture.authority,
            &[&fixture.author, &fixture.reviewer],
            fixture.at,
            1,
        );
        let peer = fixture.author.public().to_peer_id().to_string();
        let group = registry(&registered).group(&peer);
        let mut other_room = registered.clone();
        other_room.certificate.signed.room_id = util::hash(b"another room");
        assert_eq!(
            storage_bucket(&registered, &group).unwrap(),
            storage_bucket(&other_room, &group).unwrap()
        );
        let other_authority = identity::Keypair::generate_ed25519();
        let outsider = operator_room(
            &other_authority,
            &[&fixture.author, &fixture.reviewer],
            fixture.at,
            1,
        );
        assert_ne!(
            storage_bucket(&registered, &group).unwrap(),
            storage_bucket(&outsider, &group).unwrap()
        );
        assert_eq!(
            storage_bucket(&registered, &OperatorGroup::Unknown).unwrap(),
            storage_bucket(&outsider, &OperatorGroup::Unknown).unwrap()
        );
        let histories = BTreeMap::from([(
            "other-room".into(),
            OperatorBindingHistory {
                authority_peer_id: registered.authority_peer_id.clone(),
                epoch: 1,
                certificate_digest: "local-verified-history".into(),
                public: false,
                automation_required: false,
                required: true,
                bindings: registered
                    .certificate
                    .signed
                    .knowledge_operators
                    .as_ref()
                    .unwrap()
                    .bindings
                    .clone(),
            },
        )]);
        assert_eq!(resource_group(&fixture.room, &peer, &histories), group);
        assert_eq!(registry(&fixture.room).group(&peer), OperatorGroup::Unknown);
        let other_legacy = trusted_room(&other_authority, &[&fixture.author], fixture.at, 1);
        assert_eq!(
            resource_group(&other_legacy, &peer, &histories),
            OperatorGroup::Unknown
        );
        let packet = fixture.record("Can old knowledge gain voting credit from local history?");
        let review = fixture.review(&packet, 1, "useful");
        let evidence = verified_evidence(&packet, &[review], &registered);
        assert_eq!(evidence[0].historical_credit, 0);
    }

    #[test]
    fn reviewer_and_fork_metadata_charge_only_the_verified_offender_bucket_once() {
        let mut fixture = Fixture::new();
        fixture.room = operator_room(
            &fixture.authority,
            &[&fixture.author, &fixture.reviewer],
            fixture.at,
            1,
        );
        let packet = fixture.record("Who pays for review metadata on another author's record?");
        let mut store = Store::open(&fixture.home).unwrap();
        store.set_rooms([fixture.room.clone()]);
        store.insert(packet.clone(), true, fixture.at).unwrap();
        let totals = |store: &Store| {
            let classes = store.assessments(&store.state);
            let charges = store.storage_charges(&store.state, &classes).unwrap();
            assert!(
                charges.iter().map(|c| c.bytes).sum::<u64>()
                    >= snapshot_bytes(&store.state).unwrap() as u64
            );
            let mut totals = BTreeMap::new();
            for charge in charges {
                *totals.entry(charge.group).or_insert(0u64) += charge.bytes;
            }
            totals
        };
        let author = storage_bucket(
            &fixture.room,
            &registry(&fixture.room).group(&fixture.author.public().to_peer_id().to_string()),
        )
        .unwrap();
        let reviewer = storage_bucket(
            &fixture.room,
            &registry(&fixture.room).group(&fixture.reviewer.public().to_peer_id().to_string()),
        )
        .unwrap();
        let before = totals(&store);
        let first = fixture.review(&packet, 1, "useful");
        store.evaluate(first.clone(), fixture.at + 1).unwrap();
        let after_review = totals(&store);
        assert_eq!(before[&author], after_review[&author]);
        assert!(after_review[&reviewer] > 0);
        let second = fixture.review(&packet, 1, "incorrect");
        let proof = ReviewConflict { first, second };
        store
            .insert_with_reviews_and_conflicts(
                packet.clone(),
                vec![],
                vec![proof.clone()],
                true,
                fixture.at + 1,
            )
            .unwrap();
        let after_proof = totals(&store);
        assert_eq!(before[&author], after_proof[&author]);
        assert!(after_proof[&reviewer] > after_review[&reviewer]);
        store
            .insert_with_reviews_and_conflicts(
                packet,
                vec![],
                vec![proof.clone(), proof],
                true,
                fixture.at + 1,
            )
            .unwrap();
        assert_eq!(totals(&store), after_proof);
        assert_eq!(store.state.records[0].review_conflicts.len(), 1);
    }

    #[test]
    fn signed_forks_converge_for_all_variant_arrival_orders_and_survive_reload() {
        let mut fixture = Fixture::new();
        fixture.room = operator_room(
            &fixture.authority,
            &[&fixture.author, &fixture.reviewer],
            fixture.at,
            1,
        );
        let packet = fixture.record("How does a fork retain bounded evidence?");
        let variants = (0..4)
            .map(|n| {
                create_review(
                    &fixture.reviewer,
                    &fixture.room,
                    &packet,
                    ReviewInput {
                        verdict: if n == 0 { "incorrect" } else { "useful" }.into(),
                        evidence: format!("I checked independent result number {n}."),
                        references: vec![],
                    },
                    7,
                    fixture.at + 7,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let mut ids = variants
            .iter()
            .map(|r| r.review.signed.id.clone())
            .collect::<Vec<_>>();
        ids.sort();
        let mut expected = None;
        for a in 0..4 {
            for b in 0..4 {
                for c in 0..4 {
                    for d in 0..4 {
                        if BTreeSet::from([a, b, c, d]).len() != 4 {
                            continue;
                        }
                        let mut reviews = vec![];
                        let mut proofs = vec![];
                        for index in [a, b, c, d] {
                            reviews.push(variants[index].clone());
                            (reviews, proofs) =
                                canonical_review_state(&packet, &fixture.room, reviews, proofs)
                                    .unwrap();
                        }
                        assert_eq!(proofs.len(), 1);
                        assert_eq!(proofs[0].first.review.signed.id, ids[0]);
                        assert_eq!(proofs[0].second.review.signed.id, ids[1]);
                        let digest = (
                            reviews[0].review.signed.id.clone(),
                            conflict_digest(&proofs[0]).unwrap(),
                        );
                        if let Some(prior) = &expected {
                            assert_eq!(prior, &digest);
                        } else {
                            expected = Some(digest);
                        }
                    }
                }
            }
        }
        let mut store = Store::open(&fixture.home).unwrap();
        store.set_rooms([fixture.room.clone()]);
        store
            .insert_with_reviews_and_conflicts(
                packet.clone(),
                variants[..2].to_vec(),
                vec![],
                true,
                fixture.at + 7,
            )
            .unwrap();
        let proof = store.state.records[0].review_conflicts[0].clone();
        let newest = fixture.review(&packet, 8, "useful");
        store.evaluate(newest, fixture.at + 8).unwrap();
        assert_eq!(store.state.records[0].review_conflicts.len(), 1);
        let mut reopened = Store::open(&fixture.home).unwrap();
        reopened.set_rooms([fixture.room.clone()]);
        assert_eq!(
            conflict_digest(&proof).unwrap(),
            conflict_digest(&reopened.state.records[0].review_conflicts[0]).unwrap()
        );
        let assessment = reopened.assessments(&reopened.state);
        assert_eq!(assessment[&packet.record.signed.id].positive_weight, 0);
        let other = fixture.record("A distinct record must not be accused by this proof.");
        assert!(
            validate_conflicts(
                &other,
                std::slice::from_ref(&proof),
                &fixture.room,
                fixture.at + 8
            )
            .is_err()
        );
        let mut forged = proof.clone();
        forged.second.review.signature = forged.first.review.signature.clone();
        assert!(validate_conflicts(&packet, &[forged], &fixture.room, fixture.at + 8).is_err());
        let mut wrong_sequence = proof;
        wrong_sequence.second = fixture.review(&packet, 9, "incorrect");
        assert!(
            validate_conflicts(&packet, &[wrong_sequence], &fixture.room, fixture.at + 9).is_err()
        );
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
    fn fork_identity_ignores_distinct_valid_admission_witnesses() {
        let mut fixture = Fixture::new();
        fixture.room = operator_room(
            &fixture.authority,
            &[&fixture.author, &fixture.reviewer],
            fixture.at,
            1,
        );
        fixture
            .room
            .certificate
            .signed
            .knowledge_automation_required = true;
        fixture.room.certificate.signature = crypto::sign(
            &fixture.authority,
            "idobata.room.v1",
            &fixture.room.certificate.signed,
        )
        .unwrap();
        let mut packet = prepare_record(
            &fixture.author,
            &fixture.room,
            fixture.input("How are fork witnesses identified?"),
            false,
            fixture.at,
        )
        .unwrap();
        let answer = solve_test_challenge(
            automation::create_challenge(
                &fixture.reviewer,
                &fixture.room,
                &packet.record.signed.author_peer_id,
                &packet.record.signed.id,
                "publish",
                fixture.at,
            )
            .unwrap(),
        );
        let receipt =
            automation::certify_answer(&fixture.reviewer, &fixture.room, &answer, fixture.at)
                .unwrap();
        packet.admission = Some(AutomationProof { answer, receipt });
        let mut first = prepare_review(
            &fixture.reviewer,
            &fixture.room,
            &packet,
            ReviewInput {
                verdict: "useful".into(),
                evidence: "The documented result was reproduced.".into(),
                references: vec![],
            },
            1,
            fixture.at,
        )
        .unwrap();
        let mut second = prepare_review(
            &fixture.reviewer,
            &fixture.room,
            &packet,
            ReviewInput {
                verdict: "incorrect".into(),
                evidence: "The documented result was different.".into(),
                references: vec![],
            },
            1,
            fixture.at,
        )
        .unwrap();
        let attach = |review: &mut ReviewPacket| {
            let answer = solve_test_challenge(
                automation::create_challenge(
                    &fixture.author,
                    &fixture.room,
                    &review.review.signed.reviewer_peer_id,
                    &review_digest(&review.review.signed).unwrap(),
                    "evaluate",
                    fixture.at,
                )
                .unwrap(),
            );
            let receipt =
                automation::certify_answer(&fixture.author, &fixture.room, &answer, fixture.at)
                    .unwrap();
            review.admission = Some(AutomationProof { answer, receipt });
        };
        attach(&mut first);
        attach(&mut second);
        let proof = ReviewConflict { first, second };
        validate_conflicts(
            &packet,
            std::slice::from_ref(&proof),
            &fixture.room,
            fixture.at,
        )
        .unwrap();
        let mut alternate = proof.clone();
        attach(&mut alternate.first);
        attach(&mut alternate.second);
        validate_conflicts(
            &packet,
            std::slice::from_ref(&alternate),
            &fixture.room,
            fixture.at,
        )
        .unwrap();
        assert_ne!(
            util::canonical(&proof).unwrap(),
            util::canonical(&alternate).unwrap()
        );
        assert_eq!(
            conflict_digest(&proof).unwrap(),
            conflict_digest(&alternate).unwrap()
        );
        let left = canonical_review_state(
            &packet,
            &fixture.room,
            vec![],
            vec![proof.clone(), alternate.clone()],
        )
        .unwrap();
        let right = canonical_review_state(
            &packet,
            &fixture.room,
            vec![],
            vec![alternate.clone(), proof],
        )
        .unwrap();
        assert_eq!(
            util::canonical(&left).unwrap(),
            util::canonical(&right).unwrap()
        );
        alternate.first.admission = None;
        assert!(validate_conflicts(&packet, &[alternate], &fixture.room, fixture.at).is_err());
    }

    #[test]
    #[ignore = "explicit optimized stress check; maximum operator quota corpus must not starve real-time IPC fixtures"]
    fn two_adversarial_operator_quota_search_and_atomic_admission_stress() {
        use std::time::{Duration, Instant};
        let fixture = Fixture::new();
        let keys = (0..6)
            .map(|_| identity::Keypair::generate_ed25519())
            .collect::<Vec<_>>();
        let room = operator_room(
            &fixture.authority,
            &keys.iter().collect::<Vec<_>>(),
            fixture.at,
            1,
        );
        let mut store = Store::open(&fixture.home).unwrap();
        store.set_rooms([room.clone()]);
        let policy = store.policy_limits();
        let mut used = BTreeMap::<OperatorGroup, u64>::new();
        for n in 0..MAX_OBJECTS / 2 {
            let mut pair = KnowledgeState::default();
            for author in 0..2 {
                let packet = create_record(
                    &keys[author],
                    &room,
                    fixture.input(&format!("Routine searchable procedure {n} actor {author}")),
                    false,
                    fixture.at,
                )
                .unwrap();
                let review = create_review(
                    &keys[1 - author],
                    &room,
                    &packet,
                    ReviewInput {
                        verdict: "useful".into(),
                        evidence: "The other operator's routine was reproduced.".into(),
                        references: vec![],
                    },
                    n as u64 + 1,
                    fixture.at,
                )
                .unwrap();
                pair.records.push(StoredKnowledge {
                    packet,
                    reviews: vec![review],
                    review_conflicts: vec![],
                    stored_at: fixture.at,
                    staging: true,
                });
            }
            let classes = store.assessments(&pair);
            let mut proposed = used.clone();
            for charge in store
                .storage_charges(&pair, &classes)
                .unwrap()
                .into_iter()
                .filter(|c| c.unconfirmed)
            {
                *proposed.entry(charge.group).or_default() += charge.bytes;
            }
            if proposed
                .values()
                .any(|bytes| *bytes > policy.operator_unconfirmed_bytes)
            {
                break;
            }
            used = proposed;
            store.state.records.extend(pair.records);
        }
        assert_eq!(used.len(), 2);
        assert!(
            used.values()
                .all(|bytes| *bytes > policy.operator_unconfirmed_bytes * 99 / 100)
        );
        let useful = create_record(
            &keys[2],
            &room,
            fixture.input("A useful low-frequency matching procedure"),
            false,
            fixture.at,
        )
        .unwrap();
        let reviews = keys[3..]
            .iter()
            .enumerate()
            .map(|(n, key)| {
                create_review(
                    key,
                    &room,
                    &useful,
                    ReviewInput {
                        verdict: "useful".into(),
                        evidence: "Independent reproduction succeeded.".into(),
                        references: vec![],
                    },
                    n as u64 + 1,
                    fixture.at,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let id = useful.record.signed.id.clone();
        store.state.records.push(StoredKnowledge {
            packet: useful,
            reviews,
            review_conflicts: vec![],
            stored_at: fixture.at,
            staging: true,
        });
        store.save().unwrap();
        let before = std::fs::read(fixture.home.join("knowledge.enc")).unwrap();
        let start = Instant::now();
        let normal = store.search_mode(
            &room.certificate.signed.room_id,
            "procedure",
            20,
            fixture.at,
            SearchMode::Normal,
        );
        let normal_elapsed = start.elapsed();
        assert_eq!(normal.len(), 1);
        assert_eq!(normal[0].packet.record.signed.id, id);
        assert!(normal_elapsed < Duration::from_secs(7));
        let start = Instant::now();
        let explore = store.search_mode(
            &room.certificate.signed.room_id,
            "procedure",
            20,
            fixture.at,
            SearchMode::Explore,
        );
        let explore_elapsed = start.elapsed();
        assert_eq!(explore.len(), 3);
        assert_eq!(explore[0].packet.record.signed.id, id);
        assert!(explore_elapsed < Duration::from_secs(7));
        let mut large = fixture.input("A new spam contribution cannot displace accepted staging.");
        large.solution = "Use the documented procedure. ".repeat(200);
        let packet = create_record(&keys[0], &room, large, false, fixture.at).unwrap();
        let start = Instant::now();
        assert_eq!(store.insert(packet, true, fixture.at).unwrap_err().code, 30);
        let admission_elapsed = start.elapsed();
        assert!(admission_elapsed < Duration::from_secs(7));
        assert_eq!(
            before,
            std::fs::read(fixture.home.join("knowledge.enc")).unwrap()
        );
        assert!(store.state.records.iter().all(|row| row.staging));
        assert!(store.get(&room.certificate.signed.room_id, &id).is_some());
        eprintln!(
            "quota_stress records={} operator_bytes={:?} normal={normal_elapsed:?} explore={explore_elapsed:?} rejected_admission={admission_elapsed:?}",
            store.state.records.len(),
            used.values().collect::<Vec<_>>()
        );
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
