//! Bounded, currently authorized knowledge replication and distributed retrieval.
//! Signed storage receipts are peer claims, not proofs of future availability.
use crate::{
    automation::{self, AutomationAnswer, AutomationProof, AutomationReceipt, ChallengePacket},
    config, crypto,
    error::{Error, INVALID, Result, STORAGE},
    ipc,
    knowledge::{self, KnowledgeHit, RecordPacket, ReviewPacket, Store},
    knowledge_rating::{self, Evidence},
    network,
    scanner::Scanner,
    types::{Config, Reply, Request, Signed, TrustedRoom},
    util,
};
use libp2p::{
    PeerId, Swarm, identity,
    request_response::{self, Message, OutboundRequestId},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

const MAX_WIRE: usize = network::MAX_KNOWLEDGE_WIRE;
const RESPONSE_BYTES: usize = 3 * 1024 * 1024;
const IPC_BYTES: usize = 58000;
const LEASE_SECONDS: u64 = 3600;
const QUERY_BYTES: usize = 4 * 1024 * 1024;
const QUERY_HITS: usize = 32;
const MAX_QUERIES: usize = 16;
const CACHE_BYTES: usize = 4 * 1024 * 1024;
const CACHE_ENTRIES: usize = 16;
const POLL_BATCH: usize = 2;
const ROUTES: usize = knowledge::MAX_OBJECTS * knowledge::REPLICAS;
const RECEIPT_DOMAIN: &str = "idobata.knowledge.storage.v1";

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum WireRequest {
    Challenge {
        room_id: String,
        action_digest: String,
        purpose: String,
    },
    Certify {
        answer: Box<AutomationAnswer>,
    },
    Store {
        room_id: String,
        packet: Box<RecordPacket>,
        reviews: Vec<ReviewPacket>,
    },
    Search {
        room_id: String,
        query: String,
        limit: usize,
    },
    Get {
        room_id: String,
        id: String,
    },
    Inventory {
        room_id: String,
        after: Option<String>,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StorageReceipt {
    pub room_id: String,
    pub id: String,
    pub digest: String,
    pub keeper_peer_id: String,
    pub epoch: u64,
    pub stored_at: u64,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum WireReply {
    Challenge {
        challenge: ChallengePacket,
    },
    Certified {
        receipt: Signed<AutomationReceipt>,
    },
    Stored {
        receipt: Signed<StorageReceipt>,
    },
    Hits {
        hits: Vec<KnowledgeHit>,
        truncated: bool,
    },
    Inventory {
        ids: Vec<String>,
        next: Option<String>,
    },
    Rejected {
        code: i32,
    },
}
struct Cached {
    hit: KnowledgeHit,
    until: Instant,
    bytes: usize,
}
struct Query {
    response: tokio::sync::oneshot::Sender<Reply>,
    room: TrustedRoom,
    query: String,
    id: Option<String>,
    peers_mode: bool,
    hits: BTreeMap<String, KnowledgeHit>,
    providers: BTreeMap<String, BTreeSet<String>>,
    conflicts: BTreeMap<(String, String), u64>,
    queue: VecDeque<PeerId>,
    planned: BTreeSet<String>,
    inflight: usize,
    responded: usize,
    failed: usize,
    truncated: bool,
    exhausted: bool,
    limit: usize,
    deadline: Instant,
}
enum Work {
    GateChallenge(u64, PeerId),
    GateCertify(u64, PeerId),
    Query(u64, PeerId),
    Store {
        peer: PeerId,
        room: String,
        id: String,
        digest: String,
        epoch: u64,
        sent_at: u64,
    },
    Inventory {
        peer: PeerId,
        room: String,
        after: Option<String>,
    },
    Repair {
        peer: PeerId,
        room: String,
        id: String,
    },
}
#[derive(Serialize)]
enum GateAction {
    Publish(RecordPacket),
    Evaluate {
        record: Box<RecordPacket>,
        previous: Vec<ReviewPacket>,
        review: ReviewPacket,
    },
}
struct GatePending {
    response: tokio::sync::oneshot::Sender<Reply>,
    room: TrustedRoom,
    digest: String,
    purpose: String,
    action: Option<GateAction>,
    answer: Option<AutomationAnswer>,
    issuer: PeerId,
    candidates: VecDeque<PeerId>,
    attempt_until: Instant,
    deadline: Instant,
}
struct GateIntent {
    room: TrustedRoom,
    digest: String,
    purpose: String,
    action: GateAction,
    answer: Option<AutomationAnswer>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Nonce {
    id: String,
    digest: String,
    expires_at: u64,
    spent: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NonceState {
    version: u32,
    entries: Vec<Nonce>,
}
struct Nonces {
    path: PathBuf,
    state: NonceState,
}
impl Nonces {
    fn open(home: &Path) -> Result<Self> {
        let path = home.join("automation-nonces.json");
        let state = if path.exists() {
            util::protected(&path)?;
            let state: NonceState =
                serde_json::from_slice(&util::read_bounded(&path, 131072)?).map_err(|_| STORAGE)?;
            let unique = state
                .entries
                .iter()
                .map(|entry| &entry.id)
                .collect::<BTreeSet<_>>();
            if state.version != 1
                || state.entries.len() > 256
                || unique.len() != state.entries.len()
                || state.entries.iter().any(|entry| {
                    !util::valid_id(&entry.id)
                        || !util::valid_id(&entry.digest)
                        || entry.expires_at > 9_007_199_254_740_991
                })
            {
                return Err(STORAGE);
            }
            state
        } else {
            NonceState {
                version: 1,
                entries: vec![],
            }
        };
        Ok(Self { path, state })
    }
    fn issue(&mut self, challenge: &ChallengePacket) -> Result<()> {
        let mut state = self.state.clone();
        state.entries.retain(|entry| entry.expires_at > util::now());
        if state.entries.len() >= 256 {
            return Err(Error::new(30, "automation_challenge_capacity"));
        }
        let value = &challenge.challenge.signed;
        if state.entries.iter().any(|entry| entry.id == value.id) {
            return Err(INVALID);
        }
        state.entries.push(Nonce {
            id: value.id.clone(),
            digest: util::hash(&util::canonical(challenge)?),
            expires_at: value.expires_at,
            spent: false,
        });
        util::atomic_write(&self.path, &util::canonical(&state)?)?;
        self.state = state;
        Ok(())
    }
    fn spend(&mut self, challenge: &ChallengePacket) -> Result<()> {
        let digest = util::hash(&util::canonical(challenge)?);
        let mut state = self.state.clone();
        let entry = state
            .entries
            .iter_mut()
            .find(|entry| {
                entry.id == challenge.challenge.signed.id
                    && entry.digest == digest
                    && !entry.spent
                    && entry.expires_at > util::now()
            })
            .ok_or(INVALID)?;
        entry.spent = true;
        util::atomic_write(&self.path, &util::canonical(&state)?)?;
        self.state = state;
        Ok(())
    }
}
struct Rate {
    tokens: f64,
    updated: Instant,
}
struct ReceiptExpectation<'a> {
    room_id: &'a str,
    id: &'a str,
    digest: &'a str,
    epoch: u64,
    sent_at: u64,
}
impl Rate {
    fn take(&mut self, burst: f64, per_second: f64, now: Instant) -> bool {
        self.tokens =
            (self.tokens + now.duration_since(self.updated).as_secs_f64() * per_second).min(burst);
        self.updated = now;
        if self.tokens < 1.0 {
            false
        } else {
            self.tokens -= 1.0;
            true
        }
    }
}
pub struct Runtime {
    home: PathBuf,
    key: identity::Keypair,
    own: String,
    pub store: Store,
    #[cfg(test)]
    poll_record_validations: usize,
    nonces: Nonces,
    gates: BTreeMap<u64, GatePending>,
    next_gate: u64,
    pending: BTreeMap<OutboundRequestId, Work>,
    queries: BTreeMap<u64, Query>,
    next_query: u64,
    acks: BTreeMap<(String, String), (String, u64, u64)>,
    retry: BTreeMap<(String, String), Instant>,
    cache: BTreeMap<String, Cached>,
    remote_rates: BTreeMap<PeerId, Rate>,
    mutation_rates: BTreeMap<String, Rate>,
    cursor: usize,
    last_inventory: Instant,
    last_prune: Instant,
    inventory_cursor: usize,
    inventory_pages: VecDeque<(PeerId, String, Option<String>)>,
    repairs: VecDeque<(PeerId, String, String)>,
}
fn transfer_digest(packet: &RecordPacket, reviews: &[ReviewPacket]) -> Result<String> {
    let mut ids = reviews
        .iter()
        .map(|r| r.review.signed.id.as_str())
        .collect::<Vec<_>>();
    ids.sort();
    Ok(util::hash(&util::canonical(&(
        packet.record.signed.id.as_str(),
        ids,
    ))?))
}
fn scan_query(query: &str) -> Result<()> {
    if query.len() > 2048 {
        return Err(INVALID);
    }
    if query.is_empty() {
        return Ok(());
    }
    let draft = crate::types::Draft {
        kind: "question".into(),
        title: "Knowledge query".into(),
        body: query.into(),
        references: vec![],
    };
    crypto::validate_draft(&draft)?;
    let report = Scanner::new()?.scan(&draft, false)?;
    if report.code != 0 {
        return Err(Error::new(report.code, "knowledge_query_rejected"));
    }
    Ok(())
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
fn hit_bytes(hit: &KnowledgeHit) -> usize {
    serde_json::to_vec(hit).map_or(usize::MAX, |v| v.len())
}
fn query_bytes(q: &Query) -> usize {
    serde_json::to_vec(&(&q.hits, &q.providers))
        .map_or(usize::MAX, |v| v.len())
        .saturating_add(q.query.len())
        .saturating_add(util::canonical(&q.room).map_or(usize::MAX, |v| v.len()))
        .saturating_add(q.conflicts.len().saturating_mul(256))
        .saturating_add(q.planned.iter().map(String::len).sum::<usize>())
}
fn evidence_for<'a>(hits: impl Iterator<Item = &'a KnowledgeHit>) -> Vec<Evidence> {
    hits.flat_map(|hit| {
        hit.reviews.iter().map(|r| {
            let review = &r.review.signed;
            Evidence {
                record_id: review.record_id.clone(),
                author: hit.packet.record.signed.author_peer_id.clone(),
                reviewer: review.reviewer_peer_id.clone(),
                useful: review.verdict == "useful",
                sequence: review.sequence,
                created_at: review.created_at,
            }
        })
    })
    .collect()
}
fn truncate_utf8(text: &str, max: usize) -> String {
    let mut end = text.len().min(max);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}

impl Runtime {
    pub fn open(home: &Path, key: identity::Keypair) -> Result<Self> {
        let own = key.public().to_peer_id().to_string();
        Ok(Self {
            home: home.into(),
            key,
            own,
            store: Store::open(home)?,
            #[cfg(test)]
            poll_record_validations: 0,
            nonces: Nonces::open(home)?,
            gates: BTreeMap::new(),
            next_gate: 0,
            pending: BTreeMap::new(),
            queries: BTreeMap::new(),
            next_query: 0,
            acks: BTreeMap::new(),
            retry: BTreeMap::new(),
            cache: BTreeMap::new(),
            remote_rates: BTreeMap::new(),
            mutation_rates: BTreeMap::new(),
            cursor: 0,
            last_inventory: Instant::now() - Duration::from_secs(60),
            last_prune: Instant::now() - Duration::from_secs(60),
            inventory_cursor: 0,
            inventory_pages: VecDeque::new(),
            repairs: VecDeque::new(),
        })
    }
    pub fn handles(request: &Request) -> bool {
        matches!(
            request,
            Request::KnowledgePublish { .. }
                | Request::KnowledgeSearch { .. }
                | Request::KnowledgeGet { .. }
                | Request::KnowledgeEvaluate { .. }
                | Request::KnowledgePeers { .. }
                | Request::KnowledgeStatus { .. }
        )
    }
    fn room(&self, config: &Config, alias: &str) -> Result<TrustedRoom> {
        let room = config.rooms.get(alias).ok_or(INVALID)?;
        self.current_room(config, &room.certificate.signed.room_id)
    }
    fn current_room(&self, config: &Config, id: &str) -> Result<TrustedRoom> {
        network::room_for(config, id, &self.own)
            .cloned()
            .ok_or(INVALID)
    }
    fn authorized(&self, config: &Config, id: &str, peer: &PeerId) -> Result<TrustedRoom> {
        let room = self.current_room(config, id)?;
        if !room
            .certificate
            .signed
            .members
            .iter()
            .any(|m| m.peer_id == peer.to_string())
        {
            return Err(INVALID);
        }
        Ok(room)
    }
    fn allow_remote(&mut self, peer: PeerId) -> bool {
        if !self.remote_rates.contains_key(&peer) && self.remote_rates.len() >= 1024 {
            return false;
        }
        self.remote_rates
            .entry(peer)
            .or_insert(Rate {
                tokens: 16.0,
                updated: Instant::now(),
            })
            .take(16.0, 4.0, Instant::now())
    }
    fn allow_mutation(&mut self, owner: &str) -> bool {
        if !self.mutation_rates.contains_key(owner) && self.mutation_rates.len() >= 64 {
            return false;
        }
        self.mutation_rates
            .entry(owner.into())
            .or_insert(Rate {
                tokens: 2.0,
                updated: Instant::now(),
            })
            .take(2.0, 1.0 / 6.0, Instant::now())
    }
    fn validate_hit(&self, hit: &KnowledgeHit, room: &TrustedRoom) -> Result<()> {
        if hit.reviews.len() > knowledge::MAX_REVIEWERS {
            return Err(INVALID);
        }
        knowledge::validate_record(&hit.packet, room, util::now())?;
        for review in &hit.reviews {
            knowledge::validate_review_for_verified_record(review, &hit.packet, room, util::now())?;
        }
        Ok(())
    }
    fn known_hit_current(&self, hit: &KnowledgeHit, room: &TrustedRoom) -> bool {
        // Load, admission and cache insertion already verified these immutable
        // bytes. Re-pin the original proof to the current profile and authority.
        hit.reviews.len() <= knowledge::MAX_REVIEWERS
            && same_pin(&hit.packet.certificate, room)
            && hit.packet.record.signed.policy_id == Scanner::policy_id()
            && (!room.certificate.signed.knowledge_automation_required
                || (hit.packet.admission.is_some()
                    && hit.reviews.iter().all(|review| review.admission.is_some())))
            && hit
                .reviews
                .iter()
                .all(|review| same_pin(&review.certificate, room))
    }
    fn local_hit(&self, room: &str, id: &str) -> Option<KnowledgeHit> {
        self.store.get(room, id).map(|stored| KnowledgeHit {
            packet: stored.packet.clone(),
            reviews: stored.reviews.clone(),
            quality: knowledge_rating::quality(
                id,
                &stored.packet.record.signed.author_peer_id,
                &[],
            ),
            score: 0.0,
        })
    }
    fn cached_hit(&self, room: &str, id: &str) -> Option<KnowledgeHit> {
        self.local_hit(room, id).or_else(|| {
            self.cache
                .get(id)
                .filter(|c| c.until > Instant::now() && c.hit.packet.record.signed.room_id == room)
                .map(|c| c.hit.clone())
        })
    }
    fn remember(&mut self, hit: KnowledgeHit) {
        let id = hit.packet.record.signed.id.clone();
        let bytes = hit_bytes(&hit).saturating_add(id.len());
        if bytes > CACHE_BYTES {
            return;
        }
        self.cache.remove(&id);
        while self.cache.len() >= CACHE_ENTRIES
            || self
                .cache
                .values()
                .map(|v| v.bytes)
                .sum::<usize>()
                .saturating_add(bytes)
                > CACHE_BYTES
        {
            let Some(old) = self
                .cache
                .iter()
                .min_by_key(|(_, c)| c.until)
                .map(|(id, _)| id.clone())
            else {
                break;
            };
            self.cache.remove(&old);
        }
        self.cache.insert(
            id,
            Cached {
                hit,
                until: Instant::now() + Duration::from_secs(300),
                bytes,
            },
        );
    }
    pub fn metrics(&self) -> Value {
        json!({"storage": self.store.metrics(), "pending_replications": self.pending.values().filter(|v| matches!(v, Work::Store { .. })).count(), "pending_repairs": self.repairs.len() + self.pending.values().filter(|work| matches!(work, Work::Repair { .. })).count(), "pending_inventory_pages": self.inventory_pages.len() + self.pending.values().filter(|work| matches!(work, Work::Inventory { .. })).count(), "staging_records": self.store.state.records.iter().filter(|s| s.staging).count(), "active_queries": self.queries.len(), "pending_automation": self.gates.len(), "query_bytes": self.queries.values().map(query_bytes).sum::<usize>(), "cache_bytes": self.cache.values().map(|c| c.bytes).sum::<usize>(), "replication_factor": knowledge::REPLICAS, "receipt_claims_are_availability_proofs": false})
    }
    /// This is only this keeper's recent public subset, never a whole-room feed.
    pub fn public_entries(&self, room: &TrustedRoom) -> Vec<crate::publication::PublicEntry> {
        let at = util::now();
        if !room.certificate.signed.public
            || crypto::validate_room(room, &Scanner::policy_id(), at).is_err()
        {
            return vec![];
        }
        let mut records = self
            .store
            .state
            .records
            .iter()
            .filter(|s| {
                let record = &s.packet.record.signed;
                record.room_id == room.certificate.signed.room_id
                    && record.public
                    && record.created_at <= at.saturating_add(300)
                    && record.created_at.saturating_add(30 * 86400) >= at
            })
            .collect::<Vec<_>>();
        records.sort_by(|a, b| {
            b.packet
                .record
                .signed
                .created_at
                .cmp(&a.packet.record.signed.created_at)
                .then_with(|| a.packet.record.signed.id.cmp(&b.packet.record.signed.id))
        });
        let Ok(scanner) = Scanner::new() else {
            return vec![];
        };
        records
            .into_iter()
            .take(50)
            .filter_map(|stored| {
                knowledge::validate_record(&stored.packet, room, at).ok()?;
                let record = &stored.packet.record.signed;
                let draft = crate::types::Draft {
                    kind: "answer".into(),
                    title: truncate_utf8(&record.problem, 256),
                    body: truncate_utf8(
                        &format!(
                            "{}{}{}",
                            record.solution,
                            if record.context.is_empty() {
                                ""
                            } else {
                                "\n\n"
                            },
                            record.context
                        ),
                        8192,
                    ),
                    references: record.references.clone(),
                };
                crypto::validate_draft(&draft).ok()?;
                if scanner.scan(&draft, false).ok()?.code != 0 {
                    return None;
                }
                Some(crate::publication::PublicEntry {
                    content: draft,
                    published_at: record.created_at,
                    origin: crate::publication::Origin {
                        message_id: record.id.clone(),
                        author: format!(
                            "agent-{}",
                            &util::hash(record.author_peer_id.as_bytes())[..8]
                        ),
                        reply_to: None,
                        resolution: None,
                    },
                })
            })
            .collect()
    }
    fn replica_state(
        &self,
        room: &TrustedRoom,
        stored: &knowledge::StoredKnowledge,
    ) -> Result<(Vec<String>, Vec<String>, bool)> {
        let record = &stored.packet.record.signed;
        let keepers =
            knowledge::replica_peers(&room.certificate.signed, &record.id, knowledge::REPLICAS);
        let digest = transfer_digest(&stored.packet, &stored.reviews)?;
        let acks = keepers
            .iter()
            .filter(|peer| {
                *peer == &self.own
                    || self
                        .acks
                        .get(&(record.id.clone(), (*peer).clone()))
                        .is_some_and(|(d, epoch, at)| {
                            d == &digest
                                && *epoch == room.certificate.signed.epoch
                                && at.saturating_add(LEASE_SECONDS) > util::now()
                        })
            })
            .cloned()
            .collect::<Vec<_>>();
        let complete = keepers.len() >= knowledge::REPLICAS && acks.len() == keepers.len();
        Ok((keepers, acks, complete))
    }
    fn status(&self, config: &Config, alias: Option<&str>) -> Result<Value> {
        let filter = alias.map(|a| self.room(config, a)).transpose()?;
        let mut rows = vec![];
        let mut count = 0;
        let mut degraded = false;
        for stored in &self.store.state.records {
            let record = &stored.packet.record.signed;
            if filter
                .as_ref()
                .is_some_and(|r| r.certificate.signed.room_id != record.room_id)
            {
                continue;
            }
            let Ok(room) = self.current_room(config, &record.room_id) else {
                continue;
            };
            count += 1;
            if rows.len() >= 50 {
                continue;
            }
            let (keepers, acks, complete) = self.replica_state(&room, stored)?;
            degraded |= keepers.len() < knowledge::REPLICAS;
            rows.push(json!({"id": record.id, "room_id": record.room_id, "assigned_keepers": keepers, "replica_acks": acks, "local_role": if keepers.contains(&self.own) { "keeper" } else { "staging" }, "staging": stored.staging, "replication_complete": complete, "degraded": keepers.len() < knowledge::REPLICAS, "reviews": stored.reviews.len()}));
        }
        if let Some(room) = filter {
            degraded |= room.certificate.signed.members.len() < knowledge::REPLICAS;
        }
        let metrics = self.store.metrics();
        Ok(
            json!({"status": if degraded { "degraded" } else { "ready" }, "objects": metrics.objects, "bytes": metrics.bytes, "quota_bytes": metrics.quota_bytes, "replication_factor": knowledge::REPLICAS, "records": rows, "matching_records": count, "records_truncated": count > 50, "storage_receipts_are_claims": true, "untrusted": false}),
        )
    }
    pub fn command(&mut self, command: ipc::Command, swarm: &mut Swarm<network::Behaviour>) {
        let ipc::Command {
            owner,
            request,
            response,
        } = command;
        if let Err((error, response)) = self.start_command(&owner, request, response, swarm) {
            let _ = response.send(Reply::new(
                error.code,
                json!({"status": "failed", "error": error.error, "enqueued": false}),
            ));
        }
    }
    fn start_command(
        &mut self,
        owner: &str,
        request: Request,
        response: tokio::sync::oneshot::Sender<Reply>,
        swarm: &mut Swarm<network::Behaviour>,
    ) -> std::result::Result<(), (Error, tokio::sync::oneshot::Sender<Reply>)> {
        let config = match config::load(&self.home) {
            Ok(config) => config,
            Err(error) => return Err((error, response)),
        };
        if matches!(
            request,
            Request::KnowledgePublish { .. } | Request::KnowledgeEvaluate { .. }
        ) && !self.allow_mutation(owner)
        {
            return Err((Error::new(30, "knowledge_mutation_rate_limited"), response));
        }
        let gate: Result<Option<GateIntent>> = (|| match &request {
            Request::KnowledgePublish {
                room,
                input,
                public,
                proof,
            } => {
                let room = self.room(&config, room)?;
                if !room.certificate.signed.knowledge_automation_required && proof.is_none() {
                    return Ok(None);
                }
                let packet = knowledge::prepare_record(
                    &self.key,
                    &room,
                    input.clone(),
                    *public,
                    util::now(),
                )?;
                Ok(Some(GateIntent {
                    digest: packet.record.signed.id.clone(),
                    room,
                    purpose: "publish".into(),
                    action: GateAction::Publish(packet),
                    answer: proof.clone(),
                }))
            }
            Request::KnowledgeEvaluate {
                room,
                id,
                input,
                proof,
            } => {
                let room = self.room(&config, room)?;
                if !room.certificate.signed.knowledge_automation_required && proof.is_none() {
                    return Ok(None);
                }
                let hit = self
                    .cached_hit(&room.certificate.signed.room_id, id)
                    .ok_or(INVALID)?;
                if !self.known_hit_current(&hit, &room) {
                    return Err(INVALID);
                }
                let sequence = hit
                    .reviews
                    .iter()
                    .filter(|review| review.review.signed.reviewer_peer_id == self.own)
                    .map(|review| review.review.signed.sequence)
                    .max()
                    .unwrap_or(0)
                    .checked_add(1)
                    .ok_or(INVALID)?;
                let review = knowledge::prepare_review(
                    &self.key,
                    &room,
                    &hit.packet,
                    input.clone(),
                    sequence,
                    util::now(),
                )?;
                let digest = knowledge::review_action_digest(
                    &room.certificate.signed.room_id,
                    id,
                    &self.own,
                    input,
                )?;
                Ok(Some(GateIntent {
                    room,
                    digest,
                    purpose: "evaluate".into(),
                    action: GateAction::Evaluate {
                        record: Box::new(hit.packet),
                        previous: hit.reviews,
                        review,
                    },
                    answer: proof.clone(),
                }))
            }
            _ => Ok(None),
        })();
        match gate {
            Err(error) => return Err((error, response)),
            Ok(Some(intent)) => return self.begin_gate(intent, response, swarm),
            Ok(None) => {}
        }
        let outcome: Result<Value> = (|| match &request {
            Request::KnowledgePublish {
                room,
                input,
                public,
                ..
            } => {
                let room = self.room(&config, room)?;
                let packet = knowledge::create_record(
                    &self.key,
                    &room,
                    input.clone(),
                    *public,
                    util::now(),
                )?;
                let id = packet.record.signed.id.clone();
                let keepers =
                    knowledge::replica_peers(&room.certificate.signed, &id, knowledge::REPLICAS);
                if !self.store.insert(packet, true, util::now())? {
                    return Err(STORAGE);
                }
                Ok(
                    json!({"status": "accepted", "id": id, "stored": true, "assigned_keepers": keepers, "replication_factor": knowledge::REPLICAS, "replication_complete": false, "degraded": keepers.len() < knowledge::REPLICAS, "untrusted": false}),
                )
            }
            Request::KnowledgeEvaluate {
                room, id, input, ..
            } => {
                let room = self.room(&config, room)?;
                let hit = self
                    .cached_hit(&room.certificate.signed.room_id, id)
                    .ok_or(INVALID)?;
                if !self.known_hit_current(&hit, &room) {
                    return Err(INVALID);
                }
                let sequence = hit
                    .reviews
                    .iter()
                    .filter(|r| r.review.signed.reviewer_peer_id == self.own)
                    .map(|r| r.review.signed.sequence)
                    .max()
                    .unwrap_or(0)
                    .checked_add(1)
                    .ok_or(INVALID)?;
                let review = knowledge::create_review(
                    &self.key,
                    &room,
                    &hit.packet,
                    input.clone(),
                    sequence,
                    util::now(),
                )?;
                if !self.store.insert(hit.packet.clone(), true, util::now())? {
                    return Err(STORAGE);
                }
                for old in hit.reviews {
                    let offered = old.clone();
                    let _ = self.store.evaluate(old, util::now())?;
                    if !self.review_retained(&room, &hit.packet.record.signed.id, &offered) {
                        return Err(STORAGE);
                    }
                }
                let offered = review.clone();
                let _ = self.store.evaluate(review, util::now())?;
                if !self.review_retained(&room, &hit.packet.record.signed.id, &offered) {
                    return Err(STORAGE);
                }
                Ok(
                    json!({"status": "accepted", "id": id, "evaluation_applied": true, "replication_complete": false, "untrusted": false}),
                )
            }
            Request::KnowledgeStatus { room } => self.status(&config, room.as_deref()),
            Request::KnowledgeSearch { room, query, limit }
            | Request::KnowledgePeers { room, query, limit } => {
                self.room(&config, room)?;
                scan_query(query)?;
                if *limit == 0 || *limit > 20 {
                    return Err(INVALID);
                }
                Ok(Value::Null)
            }
            Request::KnowledgeGet { room, id } => {
                self.room(&config, room)?;
                if !util::valid_id(id) {
                    return Err(INVALID);
                }
                Ok(Value::Null)
            }
            _ => Err(INVALID),
        })();
        let outcome = match outcome {
            Ok(outcome) => outcome,
            Err(error) => return Err((error, response)),
        };
        if !outcome.is_null() {
            let _ = response.send(Reply::new(0, outcome));
            self.poll(swarm);
            return Ok(());
        }
        let (alias, query, id, limit, peers_mode) = match request {
            Request::KnowledgeSearch { room, query, limit } => (room, query, None, limit, false),
            Request::KnowledgePeers { room, query, limit } => (room, query, None, limit, true),
            Request::KnowledgeGet { room, id } => (room, String::new(), Some(id), 1, false),
            _ => unreachable!(),
        };
        let room = match self.room(&config, &alias) {
            Ok(room) => room,
            Err(error) => return Err((error, response)),
        };
        if self.queries.len() >= MAX_QUERIES {
            return Err((INVALID, response));
        }
        let local = if let Some(id) = &id {
            self.cached_hit(&room.certificate.signed.room_id, id)
                .into_iter()
                .collect()
        } else {
            self.store
                .search(&room.certificate.signed.room_id, &query, 20, util::now())
        };
        let queue: VecDeque<PeerId> = room
            .certificate
            .signed
            .members
            .iter()
            .filter(|m| m.peer_id != self.own)
            .filter_map(|m| m.peer_id.parse().ok())
            .collect();
        let planned = queue.iter().map(ToString::to_string).collect();
        let mut pending = Query {
            response,
            room,
            query,
            id,
            peers_mode,
            hits: BTreeMap::new(),
            providers: BTreeMap::new(),
            conflicts: BTreeMap::new(),
            queue,
            planned,
            inflight: 0,
            responded: 0,
            failed: 0,
            truncated: false,
            exhausted: false,
            limit,
            deadline: Instant::now() + Duration::from_secs(7),
        };
        for hit in local {
            if self.known_hit_current(&hit, &pending.room) {
                Self::merge_hit(&mut pending, hit, &self.own);
            } else {
                pending.truncated = true;
            }
        }
        self.next_query = self.next_query.wrapping_add(1);
        self.queries.insert(self.next_query, pending);
        self.poll(swarm);
        Ok(())
    }
    fn begin_gate(
        &mut self,
        mut intent: GateIntent,
        response: tokio::sync::oneshot::Sender<Reply>,
        swarm: &mut Swarm<network::Behaviour>,
    ) -> std::result::Result<(), (Error, tokio::sync::oneshot::Sender<Reply>)> {
        let checked: Result<(PeerId, WireRequest, VecDeque<PeerId>)> = (|| {
            if self.gates.len() >= MAX_QUERIES
                || self.pending.len() >= 8
                || serde_json::to_vec(&intent.action)
                    .map_err(|_| INVALID)?
                    .len()
                    > QUERY_BYTES
            {
                return Err(Error::new(30, "automation_work_capacity"));
            }
            let config = config::load(&self.home)?;
            let current = self.current_room(&config, &intent.room.certificate.signed.room_id)?;
            if !same_pin(&intent.room, &current) {
                return Err(INVALID);
            }
            intent.room = current;
            match &intent.answer {
                Some(answer) => {
                    if answer.answers.len() != automation::CASE_COUNT {
                        return Err(INVALID);
                    }
                    automation::verify_challenge(
                        &answer.challenge,
                        &intent.room,
                        &self.own,
                        &intent.digest,
                        &intent.purpose,
                        util::now(),
                        true,
                    )?;
                    let issuer =
                        crypto::public_key(&answer.challenge.challenge.public_key)?.to_peer_id();
                    self.authorized(&config, &intent.room.certificate.signed.room_id, &issuer)?;
                    Ok((
                        issuer,
                        WireRequest::Certify {
                            answer: Box::new(answer.clone()),
                        },
                        VecDeque::new(),
                    ))
                }
                None => {
                    let mut candidates = intent
                        .room
                        .certificate
                        .signed
                        .members
                        .iter()
                        .filter(|member| member.peer_id != self.own)
                        .filter_map(|member| member.peer_id.parse().ok())
                        .collect::<Vec<PeerId>>();
                    candidates.sort_by_key(|peer| !swarm.is_connected(peer));
                    let mut candidates: VecDeque<_> = candidates.into();
                    let issuer = candidates
                        .pop_front()
                        .ok_or(Error::new(40, "automation_issuer_unavailable"))?;
                    // One finite cold-connection retry after other candidates.
                    // A simultaneous Noise dial must not make a two-peer room
                    // depend on the caller manually resubmitting its action.
                    candidates.push_back(issuer);
                    Ok((
                        issuer,
                        WireRequest::Challenge {
                            room_id: intent.room.certificate.signed.room_id.clone(),
                            action_digest: intent.digest.clone(),
                            purpose: intent.purpose.clone(),
                        },
                        candidates,
                    ))
                }
            }
        })();
        let (issuer, request, candidates) = match checked {
            Ok(value) => value,
            Err(error) => return Err((error, response)),
        };
        self.next_gate = self.next_gate.wrapping_add(1);
        let work = if intent.answer.is_some() {
            Work::GateCertify(self.next_gate, issuer)
        } else {
            Work::GateChallenge(self.next_gate, issuer)
        };
        if !self.send(swarm, issuer, &request, work) {
            return Err((Error::new(40, "automation_issuer_unavailable"), response));
        }
        self.gates.insert(
            self.next_gate,
            GatePending {
                response,
                room: intent.room,
                digest: intent.digest,
                purpose: intent.purpose,
                action: intent.answer.as_ref().map(|_| intent.action),
                answer: intent.answer,
                issuer,
                candidates,
                attempt_until: Instant::now() + Duration::from_secs(2),
                deadline: Instant::now() + Duration::from_secs(7),
            },
        );
        Ok(())
    }
    fn review_retained(&self, room: &TrustedRoom, id: &str, offered: &ReviewPacket) -> bool {
        self.store
            .get(&room.certificate.signed.room_id, id)
            .is_some_and(|stored| {
                stored.reviews.iter().any(|retained| {
                    let a = &retained.review.signed;
                    let b = &offered.review.signed;
                    a.reviewer_peer_id == b.reviewer_peer_id
                        && (a.sequence > b.sequence || (a.sequence == b.sequence && a.id == b.id))
                        && same_pin(&retained.certificate, room)
                        && (!room.certificate.signed.knowledge_automation_required
                            || retained.admission.is_some())
                })
            })
    }
    fn incoming(&mut self, peer: PeerId, request: WireRequest) -> Result<WireReply> {
        let config = config::load(&self.home)?;
        let id = match &request {
            WireRequest::Challenge { room_id, .. } => room_id,
            WireRequest::Certify { answer } => &answer.challenge.challenge.signed.room_id,
            WireRequest::Store { room_id, .. }
            | WireRequest::Search { room_id, .. }
            | WireRequest::Get { room_id, .. }
            | WireRequest::Inventory { room_id, .. } => room_id,
        };
        let room = self.authorized(&config, id, &peer)?;
        if !self.allow_remote(peer) {
            return Err(Error::new(30, "knowledge_peer_rate_limited"));
        }
        match request {
            WireRequest::Challenge {
                action_digest,
                purpose,
                ..
            } => {
                if !util::valid_id(&action_digest)
                    || !["publish", "evaluate"].contains(&purpose.as_str())
                {
                    return Err(INVALID);
                }
                let challenge = automation::create_challenge(
                    &self.key,
                    &room,
                    &peer.to_string(),
                    &action_digest,
                    &purpose,
                    util::now(),
                )?;
                self.nonces.issue(&challenge)?;
                Ok(WireReply::Challenge { challenge })
            }
            WireRequest::Certify { answer } => {
                if answer.challenge.challenge.signed.subject_peer_id != peer.to_string()
                    || answer.challenge.challenge.public_key != crypto::public(&self.key)
                {
                    return Err(INVALID);
                }
                let receipt = automation::certify_answer(&self.key, &room, &answer, util::now())?;
                self.nonces.spend(&answer.challenge)?;
                Ok(WireReply::Certified { receipt })
            }
            WireRequest::Store {
                packet, reviews, ..
            } => {
                let hit = KnowledgeHit {
                    quality: knowledge_rating::quality(
                        &packet.record.signed.id,
                        &packet.record.signed.author_peer_id,
                        &[],
                    ),
                    packet: *packet,
                    reviews,
                    score: 0.0,
                };
                if hit.reviews.len() > knowledge::MAX_REVIEWERS {
                    return Err(INVALID);
                }
                knowledge::validate_record(&hit.packet, &room, util::now())?;
                if hit.reviews.iter().any(|review| {
                    !same_pin(&review.certificate, &room)
                        || (room.certificate.signed.knowledge_automation_required
                            && review.admission.is_none())
                }) {
                    return Err(INVALID);
                }
                let id = hit.packet.record.signed.id.clone();
                if !knowledge::replica_peers(&room.certificate.signed, &id, knowledge::REPLICAS)
                    .contains(&self.own)
                {
                    return Err(INVALID);
                }
                let staging = self
                    .store
                    .get(&room.certificate.signed.room_id, &id)
                    .is_some_and(|s| s.staging);
                if !self
                    .store
                    .insert(hit.packet.clone(), staging, util::now())?
                {
                    return Err(STORAGE);
                }
                for review in &hit.reviews {
                    let exact = self
                        .store
                        .get(&room.certificate.signed.room_id, &id)
                        .is_some_and(|stored| {
                            stored.reviews.iter().any(|old| {
                                util::canonical(old).ok() == util::canonical(review).ok()
                            })
                        });
                    if !exact {
                        let _ = self.store.evaluate(review.clone(), util::now())?;
                    }
                }
                let stored = self
                    .store
                    .get(&room.certificate.signed.room_id, &id)
                    .ok_or(STORAGE)?;
                knowledge::validate_record(&stored.packet, &room, util::now())?;
                for review in &hit.reviews {
                    if !self.review_retained(&room, &id, review) {
                        return Err(STORAGE);
                    }
                }
                let digest = transfer_digest(&hit.packet, &hit.reviews)?;
                let receipt = StorageReceipt {
                    room_id: room.certificate.signed.room_id.clone(),
                    id,
                    digest,
                    keeper_peer_id: self.own.clone(),
                    epoch: room.certificate.signed.epoch,
                    stored_at: util::now(),
                };
                Ok(WireReply::Stored {
                    receipt: Signed {
                        signature: crypto::sign(&self.key, RECEIPT_DOMAIN, &receipt)?,
                        public_key: crypto::public(&self.key),
                        signed: receipt,
                    },
                })
            }
            WireRequest::Search { query, limit, .. } => {
                scan_query(&query)?;
                if limit == 0 || limit > 20 {
                    return Err(INVALID);
                }
                let mut invalid = false;
                let hits = self
                    .store
                    .search(&room.certificate.signed.room_id, &query, limit, util::now())
                    .into_iter()
                    .filter(|hit| {
                        let valid = self.known_hit_current(hit, &room);
                        invalid |= !valid;
                        valid
                    })
                    .collect();
                let mut reply = Self::bounded_hits(hits);
                if let WireReply::Hits { truncated, .. } = &mut reply {
                    *truncated |= invalid;
                }
                Ok(reply)
            }
            WireRequest::Get { id, .. } => {
                if !util::valid_id(&id) {
                    return Err(INVALID);
                }
                let hit = self.local_hit(&room.certificate.signed.room_id, &id);
                if hit
                    .as_ref()
                    .is_some_and(|hit| !self.known_hit_current(hit, &room))
                {
                    return Err(INVALID);
                }
                Ok(Self::bounded_hits(hit.into_iter().collect()))
            }
            WireRequest::Inventory { after, .. } => {
                if after.as_ref().is_some_and(|id| !util::valid_id(id)) {
                    return Err(INVALID);
                }
                let mut ids = BTreeSet::new();
                for stored in &self.store.state.records {
                    let record = &stored.packet.record.signed;
                    if record.room_id == room.certificate.signed.room_id
                        && same_pin(&stored.packet.certificate, &room)
                        && after.as_ref().is_none_or(|after| &record.id > after)
                    {
                        ids.insert(record.id.clone());
                        if ids.len() > 65 {
                            ids.pop_last();
                        }
                    }
                }
                let mut ids = ids.into_iter().collect::<Vec<_>>();
                let next = (ids.len() > 64).then(|| ids[63].clone());
                ids.truncate(64);
                Ok(WireReply::Inventory { ids, next })
            }
        }
    }
    fn bounded_hits(mut hits: Vec<KnowledgeHit>) -> WireReply {
        let mut truncated = hits.len() > 20;
        hits.truncate(20);
        loop {
            let reply = WireReply::Hits { hits, truncated };
            if serde_json::to_vec(&reply).is_ok_and(|v| v.len() <= RESPONSE_BYTES) {
                return reply;
            }
            let WireReply::Hits {
                hits: mut remaining,
                ..
            } = reply
            else {
                unreachable!()
            };
            if remaining.pop().is_none() {
                return WireReply::Hits {
                    hits: vec![],
                    truncated: true,
                };
            }
            truncated = true;
            hits = remaining;
        }
    }
    pub fn event(
        &mut self,
        event: request_response::Event<Vec<u8>, Vec<u8>>,
        swarm: &mut Swarm<network::Behaviour>,
    ) {
        match event {
            request_response::Event::Message {
                peer,
                message:
                    Message::Request {
                        request, channel, ..
                    },
                ..
            } => {
                let reply = if request.len() <= MAX_WIRE {
                    serde_json::from_slice(&request)
                        .map_err(|_| INVALID)
                        .and_then(|r| self.incoming(peer, r))
                } else {
                    Err(INVALID)
                };
                let reply = reply.unwrap_or_else(|error| WireReply::Rejected { code: error.code });
                if let Ok(bytes) = serde_json::to_vec(&reply) {
                    let _ = swarm
                        .behaviour_mut()
                        .knowledge
                        .send_response(channel, bytes);
                }
            }
            request_response::Event::Message {
                peer,
                message:
                    Message::Response {
                        request_id,
                        response,
                    },
                ..
            } => {
                if let Some(work) = self.pending.remove(&request_id) {
                    let reply = (response.len() <= MAX_WIRE)
                        .then(|| serde_json::from_slice::<WireReply>(&response).ok())
                        .flatten();
                    self.completed(work, peer, reply);
                }
            }
            request_response::Event::OutboundFailure { request_id, .. } => {
                if let Some(work) = self.pending.remove(&request_id) {
                    let peer = match &work {
                        Work::Query(_, peer)
                        | Work::GateChallenge(_, peer)
                        | Work::GateCertify(_, peer)
                        | Work::Store { peer, .. }
                        | Work::Inventory { peer, .. }
                        | Work::Repair { peer, .. } => *peer,
                    };
                    self.completed(work, peer, None);
                }
            }
            _ => {}
        }
    }
    fn verify_receipt(
        &self,
        config: &Config,
        peer: PeerId,
        expected: ReceiptExpectation<'_>,
        receipt: &Signed<StorageReceipt>,
    ) -> Result<()> {
        let ReceiptExpectation {
            room_id,
            id,
            digest,
            epoch,
            sent_at,
        } = expected;
        let room = self.authorized(config, room_id, &peer)?;
        let value = &receipt.signed;
        let now = util::now();
        let member = room
            .certificate
            .signed
            .members
            .iter()
            .find(|m| m.peer_id == peer.to_string())
            .ok_or(INVALID)?;
        if room.certificate.signed.epoch != epoch
            || value.room_id != room_id
            || value.id != id
            || value.digest != digest
            || value.epoch != epoch
            || value.keeper_peer_id != peer.to_string()
            || value.stored_at > now.saturating_add(300)
            || value.stored_at.saturating_add(LEASE_SECONDS) <= now
            || value.stored_at.saturating_add(300) < sent_at
            || receipt.public_key != member.public_key
            || !knowledge::replica_peers(&room.certificate.signed, id, knowledge::REPLICAS)
                .contains(&peer.to_string())
        {
            return Err(INVALID);
        }
        let stored = self.store.get(room_id, id).ok_or(INVALID)?;
        if !same_pin(&stored.packet.certificate, &room)
            || transfer_digest(&stored.packet, &stored.reviews)? != digest
        {
            return Err(INVALID);
        }
        crypto::verify(
            &crypto::public_key(&member.public_key)?,
            RECEIPT_DOMAIN,
            value,
            &receipt.signature,
        )
    }
    fn merge_hit(query: &mut Query, mut incoming: KnowledgeHit, provider: &str) {
        if query.exhausted {
            query.truncated = true;
            return;
        }
        let id = incoming.packet.record.signed.id.clone();
        if query.id.as_ref().is_some_and(|wanted| wanted != &id) {
            query.truncated = true;
            return;
        }
        if query.id.is_none()
            && !query.query.trim().is_empty()
            && knowledge_rating::lexical_relevance(
                &incoming.packet.record.signed.problem,
                &incoming.packet.record.signed.solution,
                &incoming.packet.record.signed.context,
                &query.query,
            ) <= 0.0
        {
            return;
        }
        let previous = query.hits.get(&id).cloned();
        if previous.is_none() && query.hits.len() >= QUERY_HITS {
            query.truncated = true;
            return;
        }
        if let Some(old) = &previous {
            incoming.packet = old.packet.clone();
        }
        let mut reviews = BTreeMap::<String, ReviewPacket>::new();
        for packet in previous
            .iter()
            .flat_map(|h| h.reviews.iter())
            .chain(incoming.reviews.iter())
        {
            let value = &packet.review.signed;
            let key = (id.clone(), value.reviewer_peer_id.clone());
            if let Some(sequence) = query.conflicts.get(&key).copied() {
                if value.sequence <= sequence {
                    continue;
                }
                query.conflicts.remove(&key);
            }
            if let Some(old) = reviews.get(&value.reviewer_peer_id) {
                let old = &old.review.signed;
                if value.sequence == old.sequence && value.id != old.id {
                    reviews.remove(&value.reviewer_peer_id);
                    query.conflicts.insert(key, value.sequence);
                    query.truncated = true;
                    continue;
                }
                if value.sequence <= old.sequence {
                    continue;
                }
            }
            reviews.insert(value.reviewer_peer_id.clone(), packet.clone());
        }
        incoming.reviews = reviews.into_values().collect();
        incoming.reviews.sort_by(|a, b| {
            b.review
                .signed
                .created_at
                .cmp(&a.review.signed.created_at)
                .then_with(|| {
                    a.review
                        .signed
                        .reviewer_peer_id
                        .cmp(&b.review.signed.reviewer_peer_id)
                })
        });
        if incoming.reviews.len() > knowledge::MAX_REVIEWERS {
            incoming.reviews.truncate(knowledge::MAX_REVIEWERS);
            query.truncated = true;
        }
        query.hits.insert(id.clone(), incoming);
        query
            .providers
            .entry(id.clone())
            .or_default()
            .insert(provider.into());
        if query_bytes(query) > QUERY_BYTES
            || query.conflicts.len() > QUERY_HITS * knowledge::MAX_REVIEWERS
        {
            // Stop explicitly rather than keep an arbitrarily large partial
            // evidence set or restore a positive vote excluded by a fork.
            query.truncated = true;
            query.hits.clear();
            query.providers.clear();
            query.conflicts.clear();
            query.deadline = Instant::now();
            query.exhausted = true;
        }
    }
    fn completed(&mut self, work: Work, peer: PeerId, reply: Option<WireReply>) {
        let Ok(config) = config::load(&self.home) else {
            return;
        };
        match work {
            Work::GateChallenge(id, expected) => self.complete_gate(
                id,
                peer,
                if peer == expected { reply } else { None },
                false,
                &config,
            ),
            Work::GateCertify(id, expected) => self.complete_gate(
                id,
                peer,
                if peer == expected { reply } else { None },
                true,
                &config,
            ),
            Work::Store {
                peer: expected,
                room,
                id,
                digest,
                epoch,
                sent_at,
            } => {
                if peer == expected
                    && let Some(WireReply::Stored { receipt }) = reply
                    && self
                        .verify_receipt(
                            &config,
                            peer,
                            ReceiptExpectation {
                                room_id: &room,
                                id: &id,
                                digest: &digest,
                                epoch,
                                sent_at,
                            },
                            &receipt,
                        )
                        .is_ok()
                {
                    if self.acks.len() >= ROUTES {
                        self.acks.pop_first();
                    }
                    self.acks.insert(
                        (id, peer.to_string()),
                        (digest, epoch, receipt.signed.stored_at),
                    );
                }
            }
            Work::Query(query_id, expected) => {
                let Some(query) = self.queries.get(&query_id) else {
                    return;
                };
                if query.deadline <= Instant::now() {
                    let query = self.queries.get_mut(&query_id).unwrap();
                    query.inflight = query.inflight.saturating_sub(1);
                    query.failed += 1;
                    query.truncated = true;
                    return;
                }
                let authorization = self
                    .authorized(&config, &query.room.certificate.signed.room_id, &peer)
                    .and_then(|room| {
                        if same_pin(&query.room, &room) {
                            Ok(room)
                        } else {
                            Err(INVALID)
                        }
                    });
                let Some(query) = self.queries.get_mut(&query_id) else {
                    return;
                };
                query.inflight = query.inflight.saturating_sub(1);
                let Ok(room) = authorization else {
                    query.failed += 1;
                    query.truncated = true;
                    return;
                };
                if peer != expected {
                    query.failed += 1;
                    return;
                }
                let Some(WireReply::Hits { hits, truncated }) = reply else {
                    query.failed += 1;
                    return;
                };
                if hits.len() > 20 {
                    query.failed += 1;
                    query.truncated = true;
                    return;
                }
                let mut valid = vec![];
                let mut invalid = false;
                for hit in hits {
                    if self.validate_hit(&hit, &room).is_ok() {
                        valid.push(hit);
                    } else {
                        invalid = true;
                    }
                }
                let Some(query) = self.queries.get_mut(&query_id) else {
                    return;
                };
                query.responded += 1;
                query.truncated |= truncated || invalid;
                for hit in valid {
                    Self::merge_hit(query, hit, &peer.to_string());
                }
            }
            Work::Inventory {
                peer: expected,
                room,
                after,
            } => {
                if expected != peer {
                    return;
                }
                let Ok(current) = self.authorized(&config, &room, &peer) else {
                    return;
                };
                if let Some(WireReply::Inventory { ids, next }) = reply {
                    if ids.len() > 64 {
                        return;
                    }
                    for id in ids {
                        if util::valid_id(&id)
                            && knowledge::replica_peers(
                                &current.certificate.signed,
                                &id,
                                knowledge::REPLICAS,
                            )
                            .contains(&self.own)
                            && self.store.get(&room, &id).is_none()
                            && self.repairs.len() < 256
                            && !self.repairs.iter().any(|(_, r, i)| r == &room && i == &id)
                        {
                            self.repairs.push_back((peer, room.clone(), id));
                        }
                    }
                    if let Some(next) = next
                        && util::valid_id(&next)
                        && after.as_ref().is_none_or(|after| &next > after)
                        && self.inventory_pages.len() < 32
                    {
                        self.inventory_pages.push_back((peer, room, Some(next)));
                    }
                }
            }
            Work::Repair {
                peer: expected,
                room,
                id,
            } => {
                if peer != expected {
                    return;
                }
                let Ok(current) = self.authorized(&config, &room, &peer) else {
                    return;
                };
                if !knowledge::replica_peers(&current.certificate.signed, &id, knowledge::REPLICAS)
                    .contains(&self.own)
                {
                    return;
                }
                if let Some(WireReply::Hits {
                    hits,
                    truncated: false,
                }) = reply
                {
                    if hits.len() > 1 {
                        return;
                    }
                    for hit in hits {
                        if hit.packet.record.signed.id != id
                            || self.validate_hit(&hit, &current).is_err()
                        {
                            continue;
                        }
                        let staging = self
                            .store
                            .get(&room, &id)
                            .is_some_and(|stored| stored.staging);
                        if self
                            .store
                            .insert(hit.packet, staging, util::now())
                            .unwrap_or(false)
                        {
                            for review in hit.reviews {
                                let _ = self.store.evaluate(review, util::now());
                            }
                        }
                    }
                }
            }
        }
    }
    fn complete_gate(
        &mut self,
        id: u64,
        peer: PeerId,
        reply: Option<WireReply>,
        certify: bool,
        config: &Config,
    ) {
        if !certify
            && !matches!(&reply, Some(WireReply::Challenge { .. }))
            && let Some(pending) = self.gates.get_mut(&id)
            && pending.issuer == peer
            && !pending.candidates.is_empty()
            && pending.deadline > Instant::now()
        {
            pending.attempt_until = Instant::now();
            return;
        }
        let Some(mut pending) = self.gates.remove(&id) else {
            return;
        };
        let action_id = pending.action.as_ref().map(|action| match action {
            GateAction::Publish(packet) => packet.record.signed.id.clone(),
            GateAction::Evaluate { review, .. } => review.review.signed.record_id.clone(),
        });
        let outcome: Result<(i32, Value)> = (|| {
            if peer != pending.issuer || pending.deadline <= Instant::now() {
                return Err(Error::new(40, "automation_issuer_unavailable"));
            }
            let room = self.authorized(config, &pending.room.certificate.signed.room_id, &peer)?;
            if !same_pin(&pending.room, &room) {
                return Err(INVALID);
            }
            if !certify {
                let Some(WireReply::Challenge { challenge }) = reply else {
                    return Err(Error::new(40, "automation_issuer_unavailable"));
                };
                automation::verify_challenge(
                    &challenge,
                    &room,
                    &self.own,
                    &pending.digest,
                    &pending.purpose,
                    util::now(),
                    true,
                )?;
                if crypto::public_key(&challenge.challenge.public_key)?.to_peer_id() != peer {
                    return Err(INVALID);
                }
                let tasks = automation::tasks(&challenge.challenge.signed);
                return Ok((
                    31,
                    json!({"status": "automation_challenge_required", "challenge": challenge, "tasks": tasks, "task_spec": automation::task_spec(), "enqueued": false, "stored": false, "untrusted": true}),
                ));
            }
            let Some(WireReply::Certified { receipt }) = reply else {
                return Err(Error::new(40, "automation_issuer_unavailable"));
            };
            let proof = AutomationProof {
                answer: pending.answer.take().ok_or(INVALID)?,
                receipt,
            };
            let action = pending.action.take().ok_or(INVALID)?;
            let at = match &action {
                GateAction::Publish(packet) => packet.record.signed.created_at,
                GateAction::Evaluate { review, .. } => review.review.signed.created_at,
            };
            automation::verify_proof(
                &proof,
                &room,
                &self.own,
                &pending.digest,
                &pending.purpose,
                at,
                util::now(),
            )?;
            let result = match action {
                GateAction::Publish(mut packet) => {
                    packet.admission = Some(proof);
                    knowledge::validate_record(&packet, &room, util::now())?;
                    let id = packet.record.signed.id.clone();
                    let keepers = knowledge::replica_peers(
                        &room.certificate.signed,
                        &id,
                        knowledge::REPLICAS,
                    );
                    if !self.store.insert(packet, true, util::now())? {
                        return Err(STORAGE);
                    }
                    json!({"status": "accepted", "id": id, "stored": true, "replication_factor": knowledge::REPLICAS, "assigned_keepers": keepers, "degraded": keepers.len() < knowledge::REPLICAS, "replication_complete": false, "assurance": "automation_tested", "untrusted": false})
                }
                GateAction::Evaluate {
                    record,
                    previous,
                    mut review,
                } => {
                    review.admission = Some(proof);
                    knowledge::validate_review(&review, &record, &room, util::now())?;
                    let id = record.record.signed.id.clone();
                    if !self.store.insert(*record, true, util::now())? {
                        return Err(STORAGE);
                    }
                    for old in previous {
                        let offered = old.clone();
                        let _ = self.store.evaluate(old, util::now())?;
                        if !self.review_retained(&room, &id, &offered) {
                            return Err(STORAGE);
                        }
                    }
                    let offered = review.clone();
                    let _ = self.store.evaluate(review, util::now())?;
                    if !self.review_retained(&room, &id, &offered) {
                        return Err(STORAGE);
                    }
                    json!({"status": "accepted", "id": id, "evaluation_applied": true, "replication_complete": false, "assurance": "automation_tested", "untrusted": false})
                }
            };
            Ok((0, result))
        })();
        let reply = match outcome {
            Ok((code, result)) => Reply::new(code, result),
            Err(error) => Reply::new(
                error.code,
                json!({"status": "failed", "error": error.error, "enqueued": false, "stored": action_id.as_ref().is_some_and(|id| self.store.get(&pending.room.certificate.signed.room_id, id).is_some()), "partial_state_possible": action_id.is_some()}),
            ),
        };
        let _ = pending.response.send(reply);
    }
    fn retry_gates(&mut self, config: &Config, swarm: &mut Swarm<network::Behaviour>) {
        let due = self
            .gates
            .iter()
            .filter(|(_, pending)| {
                pending.answer.is_none()
                    && pending.attempt_until <= Instant::now()
                    && pending.deadline > Instant::now()
            })
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        for id in due {
            self.pending
                .retain(|_, work| !matches!(work, Work::GateChallenge(gate, _) if *gate == id));
            if self.pending.len() >= 8 {
                continue;
            }
            let Some(mut pending) = self.gates.remove(&id) else {
                continue;
            };
            let mut sent = false;
            while let Some(peer) = pending.candidates.pop_front() {
                let Ok(room) =
                    self.authorized(config, &pending.room.certificate.signed.room_id, &peer)
                else {
                    continue;
                };
                if !same_pin(&pending.room, &room) {
                    continue;
                }
                let request = WireRequest::Challenge {
                    room_id: room.certificate.signed.room_id.clone(),
                    action_digest: pending.digest.clone(),
                    purpose: pending.purpose.clone(),
                };
                pending.issuer = peer;
                pending.room = room;
                pending.attempt_until = Instant::now() + Duration::from_secs(2);
                if self.send(swarm, peer, &request, Work::GateChallenge(id, peer)) {
                    sent = true;
                    break;
                }
            }
            if sent {
                self.gates.insert(id, pending);
            } else {
                let _ = pending.response.send(Reply::new(40, json!({"status": "failed", "error": "automation_issuer_unavailable", "enqueued": false, "stored": false})));
            }
        }
    }
    fn send(
        &mut self,
        swarm: &mut Swarm<network::Behaviour>,
        peer: PeerId,
        request: &WireRequest,
        work: Work,
    ) -> bool {
        let Ok(bytes) = serde_json::to_vec(request) else {
            return false;
        };
        if bytes.len() > MAX_WIRE {
            return false;
        }
        let id = swarm.behaviour_mut().knowledge.send_request(&peer, bytes);
        self.pending.insert(id, work);
        true
    }
    fn prune_metadata(&mut self, config: &Config) {
        self.cache.retain(|_, cached| cached.until > Instant::now());
        if self.last_prune.elapsed() < Duration::from_secs(5) {
            return;
        }
        let mut rooms = BTreeMap::new();
        for room in config.rooms.values() {
            if network::room_for(config, &room.certificate.signed.room_id, &self.own).is_some() {
                rooms.insert(room.certificate.signed.room_id.clone(), room);
            }
        }
        let mut routes = BTreeMap::new();
        for stored in &self.store.state.records {
            let record = &stored.packet.record.signed;
            if let Some(room) = rooms.get(&record.room_id) {
                for peer in knowledge::replica_peers(
                    &room.certificate.signed,
                    &record.id,
                    knowledge::REPLICAS,
                ) {
                    if peer != self.own {
                        routes.insert((record.id.clone(), peer), room.certificate.signed.epoch);
                    }
                }
            }
        }
        self.acks.retain(|route, (_, epoch, at)| {
            routes.get(route) == Some(epoch) && at.saturating_add(LEASE_SECONDS) > util::now()
        });
        self.retry.retain(|route, _| routes.contains_key(route));
        let peers = rooms
            .values()
            .flat_map(|room| {
                room.certificate
                    .signed
                    .members
                    .iter()
                    .filter_map(|m| m.peer_id.parse().ok())
            })
            .collect::<BTreeSet<PeerId>>();
        self.remote_rates.retain(|peer, _| peers.contains(peer));
        self.mutation_rates
            .retain(|_, rate| rate.updated.elapsed() < Duration::from_secs(3600));
        self.last_prune = Instant::now();
    }
    fn poll_records(&mut self, config: &Config, swarm: &mut Swarm<network::Behaviour>) {
        let count = self.store.state.records.len();
        if count == 0 {
            self.cursor = 0;
            return;
        }
        self.cursor %= count;
        let mut handoff = vec![];
        let mut clear = vec![];
        let records = (0..POLL_BATCH.min(count))
            .map(|offset| self.store.state.records[(self.cursor + offset) % count].clone())
            .collect::<Vec<_>>();
        self.cursor = (self.cursor + records.len()) % count;
        for stored in records {
            let record = &stored.packet.record.signed;
            let Ok(room) = self.current_room(config, &record.room_id) else {
                continue;
            };
            if !same_pin(&stored.packet.certificate, &room) {
                continue;
            }
            let Ok((keepers, _, complete)) = self.replica_state(&room, &stored) else {
                continue;
            };
            if complete {
                if !keepers.contains(&self.own) {
                    handoff.push(record.id.clone());
                } else if stored.staging {
                    clear.push(record.id.clone());
                }
                continue;
            }
            if (!keepers.contains(&self.own) || keepers.len() < knowledge::REPLICAS)
                && !stored.staging
                && self
                    .store
                    .protect_staging(std::slice::from_ref(&record.id))
                    .is_err()
            {
                continue;
            }
            let Ok(digest) = transfer_digest(&stored.packet, &stored.reviews) else {
                continue;
            };
            let due = keepers.into_iter().filter(|other| {
                if other == &self.own { return false; }
                let route = (record.id.clone(), other.clone());
                !self.acks.get(&route).is_some_and(|(d, epoch, at)| d == &digest && *epoch == room.certificate.signed.epoch && at.saturating_add(LEASE_SECONDS) > util::now())
                    && self.retry.get(&route).is_none_or(|due| *due <= Instant::now())
                    && !self.pending.values().any(|work| matches!(work, Work::Store { id, peer, .. } if id == &record.id && peer.to_string() == *other))
            }).take(8usize.saturating_sub(self.pending.len())).collect::<Vec<_>>();
            // A degraded roster still retains staging, but fresh receipts, a
            // retry delay or occupied transport slots do not require rescanning
            // an immutable body when no transfer can run in this poll.
            if due.is_empty() {
                continue;
            }
            #[cfg(test)]
            {
                self.poll_record_validations += 1;
            }
            if knowledge::validate_record(&stored.packet, &room, util::now()).is_err()
                || stored.reviews.iter().any(|review| {
                    !same_pin(&review.certificate, &room)
                        || (room.certificate.signed.knowledge_automation_required
                            && review.admission.is_none())
                })
            {
                continue;
            }
            for other in due {
                if self.pending.len() >= 8 {
                    break;
                }
                let route = (record.id.clone(), other.clone());
                let Ok(peer) = other.parse() else {
                    continue;
                };
                let request = WireRequest::Store {
                    room_id: record.room_id.clone(),
                    packet: Box::new(stored.packet.clone()),
                    reviews: stored.reviews.clone(),
                };
                if self.retry.len() >= ROUTES {
                    self.retry.pop_first();
                }
                self.retry
                    .insert(route, Instant::now() + Duration::from_secs(10));
                self.send(
                    swarm,
                    peer,
                    &request,
                    Work::Store {
                        peer,
                        room: record.room_id.clone(),
                        id: record.id.clone(),
                        digest: digest.clone(),
                        epoch: room.certificate.signed.epoch,
                        sent_at: util::now(),
                    },
                );
            }
        }
        if !handoff.is_empty() || !clear.is_empty() {
            let _ = self.store.transition_roles(&handoff, &clear);
        }
    }
    pub fn poll(&mut self, swarm: &mut Swarm<network::Behaviour>) {
        let expired = self
            .gates
            .iter()
            .filter(|(_, pending)| pending.deadline <= Instant::now())
            .map(|(id, _)| *id)
            .collect::<BTreeSet<_>>();
        for id in &expired {
            if let Some(pending) = self.gates.remove(id) {
                let _ = pending.response.send(Reply::new(40, json!({"status": "failed", "error": "automation_challenge_timeout", "enqueued": false, "stored": false})));
            }
        }
        self.pending.retain(|_, work| !matches!(work, Work::GateChallenge(id, _) | Work::GateCertify(id, _) if expired.contains(id)));
        let config = match config::load(&self.home) {
            Ok(config) => config,
            Err(_) => {
                for (_, query) in std::mem::take(&mut self.queries) {
                    let _ = query.response.send(Reply::new(30, json!({"status": "failed", "error": "current_authorization_unavailable", "partial": true, "untrusted": true})));
                }
                for (_, pending) in std::mem::take(&mut self.gates) {
                    let _ = pending.response.send(Reply::new(30, json!({"status": "failed", "error": "current_authorization_unavailable", "enqueued": false, "stored": false})));
                }
                self.pending.retain(|_, work| {
                    !matches!(
                        work,
                        Work::Query(..) | Work::GateChallenge(..) | Work::GateCertify(..)
                    )
                });
                return;
            }
        };
        self.prune_metadata(&config);
        self.retry_gates(&config, swarm);
        let finished = self
            .queries
            .iter()
            .filter(|(_, query)| {
                query.deadline <= Instant::now() || (query.queue.is_empty() && query.inflight == 0)
            })
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        for id in finished {
            if let Some(query) = self.queries.remove(&id) {
                self.finish_query(query, &config);
            }
            self.pending
                .retain(|_, work| !matches!(work, Work::Query(q, _) if *q == id));
        }
        let ids = self.queries.keys().copied().collect::<Vec<_>>();
        for id in ids {
            while self.pending.len() < 8 {
                let Some(query) = self.queries.get(&id) else {
                    break;
                };
                let room_id = query.room.certificate.signed.room_id.clone();
                let previous = query.room.clone();
                let Some(query) = self.queries.get_mut(&id) else {
                    break;
                };
                let Some(peer) = query.queue.pop_front() else {
                    break;
                };
                let Ok(current) = self.authorized(&config, &room_id, &peer).and_then(|room| {
                    if same_pin(&previous, &room) {
                        Ok(room)
                    } else {
                        Err(INVALID)
                    }
                }) else {
                    let query = self.queries.get_mut(&id).unwrap();
                    query.failed += 1;
                    query.truncated = true;
                    continue;
                };
                let query = self.queries.get_mut(&id).unwrap();
                let request = if let Some(id) = &query.id {
                    WireRequest::Get {
                        room_id: room_id.clone(),
                        id: id.clone(),
                    }
                } else {
                    WireRequest::Search {
                        room_id: room_id.clone(),
                        query: query.query.clone(),
                        limit: 20,
                    }
                };
                query.room = current;
                query.inflight += 1;
                if !self.send(swarm, peer, &request, Work::Query(id, peer)) {
                    let query = self.queries.get_mut(&id).unwrap();
                    query.inflight = query.inflight.saturating_sub(1);
                    query.failed += 1;
                }
            }
        }
        self.poll_records(&config, swarm);
        if self.last_inventory.elapsed() >= Duration::from_secs(30) {
            let pairs = config
                .rooms
                .values()
                .filter(|room| {
                    network::room_for(&config, &room.certificate.signed.room_id, &self.own)
                        .is_some()
                })
                .flat_map(|room| {
                    room.certificate
                        .signed
                        .members
                        .iter()
                        .filter(|m| m.peer_id != self.own)
                        .filter_map(|m| m.peer_id.parse().ok())
                        .map(|peer| (peer, room.certificate.signed.room_id.clone()))
                })
                .collect::<Vec<_>>();
            if !pairs.is_empty() && self.inventory_pages.len() < 32 {
                let (peer, room) = pairs[self.inventory_cursor % pairs.len()].clone();
                self.inventory_cursor = self.inventory_cursor.wrapping_add(1);
                self.inventory_pages.push_back((peer, room, None));
            }
            self.last_inventory = Instant::now();
        }
        while self.pending.len() < 8 {
            if let Some((peer, room, id)) = self.repairs.pop_front() {
                let Ok(current) = self.authorized(&config, &room, &peer) else {
                    continue;
                };
                if !knowledge::replica_peers(&current.certificate.signed, &id, knowledge::REPLICAS)
                    .contains(&self.own)
                {
                    continue;
                }
                self.send(
                    swarm,
                    peer,
                    &WireRequest::Get {
                        room_id: room.clone(),
                        id: id.clone(),
                    },
                    Work::Repair { peer, room, id },
                );
            } else if let Some((peer, room, after)) = self.inventory_pages.pop_front() {
                if self.authorized(&config, &room, &peer).is_err() {
                    continue;
                }
                self.send(
                    swarm,
                    peer,
                    &WireRequest::Inventory {
                        room_id: room.clone(),
                        after: after.clone(),
                    },
                    Work::Inventory { peer, room, after },
                );
            } else {
                break;
            }
        }
    }
    fn finish_query(&mut self, mut query: Query, config: &Config) {
        let current = self
            .current_room(config, &query.room.certificate.signed.room_id)
            .and_then(|room| {
                if same_pin(&query.room, &room) {
                    Ok(room)
                } else {
                    Err(INVALID)
                }
            });
        let Ok(room) = current else {
            let _ = query.response.send(Reply::new(30, json!({"status": "failed", "error": "current_authorization_unavailable", "partial": true, "untrusted": true})));
            return;
        };
        let before = query.hits.len();
        let before_providers: usize = query.providers.values().map(BTreeSet::len).sum();
        query.providers.values_mut().for_each(|providers| {
            providers.retain(|peer| {
                peer == &self.own
                    || peer.parse().ok().is_some_and(|peer| {
                        self.authorized(config, &room.certificate.signed.room_id, &peer)
                            .is_ok()
                    })
            })
        });
        query.hits.retain(|id, hit| {
            same_pin(&hit.packet.certificate, &room)
                && query
                    .providers
                    .get(id)
                    .is_some_and(|providers| !providers.is_empty())
        });
        let current_peers = room
            .certificate
            .signed
            .members
            .iter()
            .filter(|member| member.peer_id != self.own)
            .map(|member| &member.peer_id);
        query.truncated |= before != query.hits.len()
            || before_providers != query.providers.values().map(BTreeSet::len).sum::<usize>()
            || current_peers
                .into_iter()
                .any(|peer| !query.planned.contains(peer));
        let partial =
            query.failed > 0 || query.inflight > 0 || !query.queue.is_empty() || query.truncated;
        let mut all = evidence_for(query.hits.values());
        // Historical storage was verified at insertion/load. Re-pin it to this
        // current room before using its observations as a bounded author prior.
        for stored in &self.store.state.records {
            if stored.packet.record.signed.room_id != room.certificate.signed.room_id
                || !same_pin(&stored.packet.certificate, &room)
            {
                continue;
            }
            let author = &stored.packet.record.signed.author_peer_id;
            for review in &stored.reviews {
                let value = &review.review.signed;
                all.push(Evidence {
                    record_id: value.record_id.clone(),
                    author: author.clone(),
                    reviewer: value.reviewer_peer_id.clone(),
                    useful: value.verdict == "useful",
                    sequence: value.sequence,
                    created_at: value.created_at,
                });
            }
        }
        all.retain(|vote| {
            query
                .conflicts
                .get(&(vote.record_id.clone(), vote.reviewer.clone()))
                .is_none_or(|sequence| vote.sequence > *sequence)
        });
        let mut hits = query.hits.into_values().collect::<Vec<_>>();
        for hit in &mut hits {
            let record = &hit.packet.record.signed;
            hit.quality = knowledge_rating::quality(&record.id, &record.author_peer_id, &all);
            hit.score = knowledge_rating::search_score(
                knowledge_rating::lexical_relevance(
                    &record.problem,
                    &record.solution,
                    &record.context,
                    &query.query,
                ),
                &hit.quality,
            );
        }
        hits.retain(|hit| {
            query.id.is_some()
                || query.query.trim().is_empty()
                || knowledge_rating::lexical_relevance(
                    &hit.packet.record.signed.problem,
                    &hit.packet.record.signed.solution,
                    &hit.packet.record.signed.context,
                    &query.query,
                ) > 0.0
        });
        hits.sort_by(|a, b| {
            b.score
                .total_cmp(&a.score)
                .then_with(|| a.packet.record.signed.id.cmp(&b.packet.record.signed.id))
        });
        let mut result = if let Some(id) = query.id {
            if let Some(hit) = hits
                .into_iter()
                .find(|hit| hit.packet.record.signed.id == id)
            {
                self.remember(hit.clone());
                let reviews = hit.reviews.iter().map(|review| json!({"reviewer_peer_id": review.review.signed.reviewer_peer_id, "sequence": review.review.signed.sequence, "verdict": review.review.signed.verdict, "evidence": review.review.signed.evidence, "references": review.review.signed.references, "verified": true, "untrusted": true})).collect::<Vec<_>>();
                json!({"status": "found", "found": true, "record": hit.packet.record.signed, "signature": hit.packet.record.signature, "public_key": hit.packet.record.public_key, "quality": hit.quality, "total_reviews": reviews.len(), "reviews": reviews, "reviews_truncated": false, "untrusted": true})
            } else {
                json!({"status": if partial { "incomplete" } else { "not_found" }, "found": false, "untrusted": true})
            }
        } else if query.peers_mode {
            let mut groups = BTreeMap::<String, (f64, usize, Vec<String>)>::new();
            for hit in &hits {
                let record = &hit.packet.record.signed;
                let row = groups.entry(record.author_peer_id.clone()).or_default();
                row.0 += hit.score;
                row.1 += 1;
                row.2.push(record.id.clone());
            }
            let mut peers = groups.into_iter().map(|(peer, (sum, count, ids))| json!({"peer_id": peer, "score": sum / count as f64, "matching_records": count, "record_ids": ids, "untrusted": true})).collect::<Vec<_>>();
            peers.sort_by(|a, b| {
                b["score"]
                    .as_f64()
                    .unwrap_or(0.0)
                    .total_cmp(&a["score"].as_f64().unwrap_or(0.0))
            });
            peers.truncate(query.limit);
            json!({"status": "ok", "peers": peers, "untrusted": true})
        } else {
            hits.truncate(query.limit);
            let mut rows = vec![];
            for hit in hits {
                let record = &hit.packet.record.signed;
                rows.push(json!({"id": record.id, "problem": record.problem, "kind": record.kind, "author_peer_id": record.author_peer_id, "created_at": record.created_at, "quality": hit.quality, "score": hit.score, "providers": query.providers.get(&record.id).cloned().unwrap_or_default(), "verified": true, "untrusted": true}));
                self.remember(hit);
            }
            json!({"status": "ok", "hits": rows, "untrusted": true})
        };
        result["partial"] = partial.into();
        result["responded_peers"] = query.responded.into();
        result["failed_peers"] = (query.failed + query.inflight + query.queue.len()).into();
        while serde_json::to_vec(&result).is_ok_and(|bytes| bytes.len() > IPC_BYTES) {
            if let Some(rows) = result.get_mut("reviews").and_then(Value::as_array_mut)
                && rows.pop().is_some()
            {
                result["reviews_truncated"] = true.into();
                result["partial"] = true.into();
                continue;
            }
            if let Some(rows) = result.get_mut("hits").and_then(Value::as_array_mut)
                && rows.pop().is_some()
            {
                result["partial"] = true.into();
                continue;
            }
            if let Some(rows) = result.get_mut("peers").and_then(Value::as_array_mut)
                && rows.pop().is_some()
            {
                result["partial"] = true.into();
                continue;
            }
            result = json!({"status": "incomplete", "partial": true, "error": "knowledge_response_limit", "untrusted": true});
            break;
        }
        let _ = query.response.send(Reply::new(0, result));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::knowledge::{KnowledgeInput, ReviewInput};
    use crate::types::{Member, Room};

    struct Fixture {
        _temp: tempfile::TempDir,
        home: PathBuf,
        keys: Vec<identity::Keypair>,
        authority: identity::Keypair,
        room: TrustedRoom,
    }
    impl Fixture {
        fn new(size: usize) -> Self {
            let temp = tempfile::tempdir().unwrap();
            let home = temp.path().join("node");
            config::init(&home, vec!["/ip4/127.0.0.1/tcp/0".into()]).unwrap();
            let mut keys = vec![crypto::load_key(&home).unwrap()];
            keys.extend((1..size).map(|_| identity::Keypair::generate_ed25519()));
            let authority = identity::Keypair::generate_ed25519();
            let room = Self::certificate(
                &authority,
                &keys.iter().collect::<Vec<_>>(),
                1,
                false,
                util::now(),
            );
            let fixture = Self {
                _temp: temp,
                home,
                keys,
                authority,
                room,
            };
            fixture.install(&fixture.room);
            fixture
        }
        fn certificate(
            authority: &identity::Keypair,
            keys: &[&identity::Keypair],
            epoch: u64,
            public: bool,
            at: u64,
        ) -> TrustedRoom {
            let room = Room {
                version: if public { 2 } else { 1 },
                room_id: util::hash(b"runtime test room"),
                epoch,
                issued_at: at.saturating_sub(10),
                expires_at: at + 86400,
                policy_id: Scanner::policy_id(),
                members: keys
                    .iter()
                    .map(|key| Member {
                        peer_id: key.public().to_peer_id().to_string(),
                        public_key: crypto::public(key),
                        addresses: vec![],
                    })
                    .collect(),
                public,
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
        fn install(&self, room: &TrustedRoom) {
            let mut config = config::load(&self.home).unwrap();
            config.rooms.insert("room".into(), room.clone());
            config::save(&self.home, &config).unwrap();
        }
        fn runtime(&self) -> Runtime {
            Runtime::open(&self.home, self.keys[0].clone()).unwrap()
        }
        fn record(&self, problem: &str) -> RecordPacket {
            knowledge::create_record(
                &self.keys[1.min(self.keys.len() - 1)],
                &self.room,
                KnowledgeInput {
                    problem: problem.into(),
                    solution: "Run the documented procedure and check the output.".into(),
                    context: "A normal development setup.".into(),
                    references: vec![],
                    kind: "answer".into(),
                },
                false,
                util::now(),
            )
            .unwrap()
        }
        fn review(&self, packet: &RecordPacket, sequence: u64, verdict: &str) -> ReviewPacket {
            knowledge::create_review(
                &self.keys[0],
                &self.room,
                packet,
                ReviewInput {
                    verdict: verdict.into(),
                    evidence: "I ran the steps and checked the documented outcome.".into(),
                    references: vec![],
                },
                sequence,
                util::now(),
            )
            .unwrap()
        }
        fn hit(&self, packet: RecordPacket, reviews: Vec<ReviewPacket>) -> KnowledgeHit {
            KnowledgeHit {
                quality: knowledge_rating::quality(
                    &packet.record.signed.id,
                    &packet.record.signed.author_peer_id,
                    &[],
                ),
                packet,
                reviews,
                score: 0.0,
            }
        }
        fn query(&self, query: &str) -> (Query, tokio::sync::oneshot::Receiver<Reply>) {
            let (response, receiver) = tokio::sync::oneshot::channel();
            (
                Query {
                    response,
                    room: self.room.clone(),
                    query: query.into(),
                    id: None,
                    peers_mode: false,
                    hits: BTreeMap::new(),
                    providers: BTreeMap::new(),
                    conflicts: BTreeMap::new(),
                    queue: VecDeque::new(),
                    planned: self
                        .keys
                        .iter()
                        .skip(1)
                        .map(|key| key.public().to_peer_id().to_string())
                        .collect(),
                    inflight: 0,
                    responded: 0,
                    failed: 0,
                    truncated: false,
                    exhausted: false,
                    limit: 20,
                    deadline: Instant::now() + Duration::from_secs(7),
                },
                receiver,
            )
        }
        fn receipt(
            &self,
            signer: usize,
            packet: &RecordPacket,
            reviews: &[ReviewPacket],
        ) -> Signed<StorageReceipt> {
            let value = StorageReceipt {
                room_id: self.room.certificate.signed.room_id.clone(),
                id: packet.record.signed.id.clone(),
                digest: transfer_digest(packet, reviews).unwrap(),
                keeper_peer_id: self.keys[signer].public().to_peer_id().to_string(),
                epoch: self.room.certificate.signed.epoch,
                stored_at: util::now(),
            };
            Signed {
                signature: crypto::sign(&self.keys[signer], RECEIPT_DOMAIN, &value).unwrap(),
                public_key: crypto::public(&self.keys[signer]),
                signed: value,
            }
        }
    }

    #[test]
    fn receipt_binds_current_keeper_key_content_epoch_and_freshness() {
        let fixture = Fixture::new(3);
        let mut runtime = fixture.runtime();
        let packet = fixture.record("How do I verify a receipt?");
        runtime
            .store
            .insert(packet.clone(), true, util::now())
            .unwrap();
        let receipt = fixture.receipt(2, &packet, &[]);
        let peer = fixture.keys[2].public().to_peer_id();
        let config = config::load(&fixture.home).unwrap();
        let check = |proof: &Signed<StorageReceipt>| {
            runtime.verify_receipt(
                &config,
                peer,
                ReceiptExpectation {
                    room_id: &fixture.room.certificate.signed.room_id,
                    id: &packet.record.signed.id,
                    digest: &receipt.signed.digest,
                    epoch: 1,
                    sent_at: util::now(),
                },
                proof,
            )
        };
        check(&receipt).unwrap();
        let mut wrong = receipt.clone();
        wrong.signed.digest = util::hash(b"other");
        assert!(check(&wrong).is_err());
        let mut wrong = receipt.clone();
        wrong.signed.id = util::hash(b"other");
        assert!(check(&wrong).is_err());
        let mut wrong = receipt.clone();
        wrong.signed.room_id = util::hash(b"other");
        assert!(check(&wrong).is_err());
        let mut wrong = receipt.clone();
        wrong.signed.epoch += 1;
        assert!(check(&wrong).is_err());
        let mut wrong = receipt.clone();
        wrong.signed.stored_at = util::now() - LEASE_SECONDS - 1;
        wrong.signature = crypto::sign(&fixture.keys[2], RECEIPT_DOMAIN, &wrong.signed).unwrap();
        assert!(check(&wrong).is_err());
        let mut wrong = receipt.clone();
        wrong.public_key = crypto::public(&fixture.keys[1]);
        wrong.signature = crypto::sign(&fixture.keys[1], RECEIPT_DOMAIN, &wrong.signed).unwrap();
        assert!(check(&wrong).is_err());
        let renewed = Fixture::certificate(
            &fixture.authority,
            &[&fixture.keys[0], &fixture.keys[1]],
            2,
            false,
            util::now(),
        );
        fixture.install(&renewed);
        runtime.completed(
            Work::Store {
                peer,
                room: receipt.signed.room_id.clone(),
                id: receipt.signed.id.clone(),
                digest: receipt.signed.digest.clone(),
                epoch: 1,
                sent_at: util::now(),
            },
            peer,
            Some(WireReply::Stored { receipt }),
        );
        assert!(runtime.acks.is_empty());
    }

    #[test]
    fn quota_rejection_cannot_issue_false_review_receipt_and_replay_can_ack() {
        let fixture = Fixture::new(3);
        let mut runtime = fixture.runtime();
        let packet = fixture.record("How can a review fit?");
        let review = fixture.review(&packet, 1, "useful");
        runtime
            .store
            .insert(packet.clone(), true, util::now())
            .unwrap();
        let original = std::fs::read(fixture.home.join("knowledge.enc")).unwrap();
        runtime.store = Store::with_quota(&fixture.home, original.len() + 32).unwrap();
        let sender = fixture.keys[1].public().to_peer_id();
        let request = || WireRequest::Store {
            room_id: fixture.room.certificate.signed.room_id.clone(),
            packet: Box::new(packet.clone()),
            reviews: vec![review.clone()],
        };
        assert!(runtime.incoming(sender, request()).is_err());
        assert!(runtime.store.state.records[0].staging);
        assert!(runtime.store.state.records[0].reviews.is_empty());
        assert_eq!(
            std::fs::read(fixture.home.join("knowledge.enc")).unwrap(),
            original
        );
        runtime.store = Store::open(&fixture.home).unwrap();
        assert!(matches!(
            runtime.incoming(sender, request()).unwrap(),
            WireReply::Stored { .. }
        ));
        assert!(matches!(
            runtime.incoming(sender, request()).unwrap(),
            WireReply::Stored { .. }
        ));
        assert_eq!(runtime.store.state.records[0].reviews.len(), 1);
    }

    #[test]
    fn small_roster_is_degraded_and_never_completes_replication() {
        let fixture = Fixture::new(2);
        let mut runtime = fixture.runtime();
        let packet = fixture.record("How is underreplication reported?");
        runtime
            .store
            .insert(packet.clone(), true, util::now())
            .unwrap();
        let peer = fixture.keys[1].public().to_peer_id().to_string();
        runtime.acks.insert(
            (packet.record.signed.id.clone(), peer),
            (transfer_digest(&packet, &[]).unwrap(), 1, util::now()),
        );
        let (_, _, complete) = runtime
            .replica_state(&fixture.room, &runtime.store.state.records[0])
            .unwrap();
        assert!(!complete);
        let status = runtime
            .status(&config::load(&fixture.home).unwrap(), Some("room"))
            .unwrap();
        assert_eq!(status["status"], "degraded");
        assert_eq!(status["records"][0]["replication_complete"], false);
        assert!(runtime.store.state.records[0].staging);
    }

    #[test]
    fn revoked_query_peer_and_invalid_hits_are_partial_and_do_not_enter_cache() {
        let fixture = Fixture::new(3);
        let mut runtime = fixture.runtime();
        let packet = fixture.record("How is a query authorized?");
        let hit = fixture.hit(packet.clone(), vec![]);
        let peer = fixture.keys[2].public().to_peer_id();
        let (mut query, mut response) = fixture.query("query");
        query.inflight = 1;
        runtime.queries.insert(1, query);
        let renewed = Fixture::certificate(
            &fixture.authority,
            &[&fixture.keys[0], &fixture.keys[1]],
            2,
            false,
            util::now(),
        );
        fixture.install(&renewed);
        runtime.completed(
            Work::Query(1, peer),
            peer,
            Some(WireReply::Hits {
                hits: vec![hit.clone()],
                truncated: false,
            }),
        );
        let query = runtime.queries.remove(&1).unwrap();
        assert_eq!(query.failed, 1);
        assert!(query.hits.is_empty());
        runtime.finish_query(query, &config::load(&fixture.home).unwrap());
        assert_eq!(response.try_recv().unwrap().result["partial"], true);
        assert!(runtime.cache.is_empty());
        fixture.install(&fixture.room);
        let (mut query, mut response) = fixture.query("query");
        query.inflight = 1;
        runtime.queries.insert(2, query);
        let mut invalid = hit;
        invalid.packet.record.signature = "invalid".into();
        runtime.completed(
            Work::Query(2, peer),
            peer,
            Some(WireReply::Hits {
                hits: vec![invalid],
                truncated: false,
            }),
        );
        let query = runtime.queries.remove(&2).unwrap();
        assert!(query.truncated);
        runtime.finish_query(query, &config::load(&fixture.home).unwrap());
        assert_eq!(response.try_recv().unwrap().result["partial"], true);
        assert!(runtime.cache.is_empty());
    }

    #[test]
    fn repair_rechecks_current_assignment_after_roster_change() {
        let fixture = Fixture::new(5);
        let old = Fixture::certificate(
            &fixture.authority,
            &[&fixture.keys[0], &fixture.keys[1], &fixture.keys[2]],
            1,
            false,
            util::now(),
        );
        let current = Fixture::certificate(
            &fixture.authority,
            &fixture.keys.iter().collect::<Vec<_>>(),
            2,
            false,
            util::now(),
        );
        let own = fixture.keys[0].public().to_peer_id().to_string();
        let packet = (0..128)
            .find_map(|index| {
                let packet = knowledge::create_record(
                    &fixture.keys[1],
                    &old,
                    KnowledgeInput {
                        problem: format!("How should ownership change {index}?"),
                        solution: "Verify the current assigned keepers before saving.".into(),
                        context: String::new(),
                        references: vec![],
                        kind: "answer".into(),
                    },
                    false,
                    util::now(),
                )
                .unwrap();
                (!knowledge::replica_peers(
                    &current.certificate.signed,
                    &packet.record.signed.id,
                    knowledge::REPLICAS,
                )
                .contains(&own))
                .then_some(packet)
            })
            .unwrap();
        assert!(
            knowledge::replica_peers(
                &old.certificate.signed,
                &packet.record.signed.id,
                knowledge::REPLICAS
            )
            .contains(&own)
        );
        assert!(
            current
                .certificate
                .signed
                .members
                .iter()
                .any(|member| member.peer_id == own)
        );
        fixture.install(&current);
        let mut runtime = fixture.runtime();
        let peer = fixture.keys[1].public().to_peer_id();
        runtime.completed(
            Work::Repair {
                peer,
                room: current.certificate.signed.room_id.clone(),
                id: packet.record.signed.id.clone(),
            },
            peer,
            Some(WireReply::Hits {
                hits: vec![fixture.hit(packet, vec![])],
                truncated: false,
            }),
        );
        assert!(runtime.store.state.records.is_empty());
    }

    #[test]
    fn query_budgets_latest_reviews_and_conflicts_ignore_supplied_scores() {
        let fixture = Fixture::new(3);
        let mut runtime = fixture.runtime();
        let packet = fixture.record("How does useful search work?");
        let useful = fixture.review(&packet, 1, "useful");
        let incorrect = fixture.review(&packet, 1, "incorrect");
        let (mut query, mut response) = fixture.query("useful search");
        let mut hit = fixture.hit(packet.clone(), vec![useful.clone()]);
        hit.score = 1e200;
        hit.quality.value = 1e200;
        Runtime::merge_hit(&mut query, hit, &runtime.own);
        Runtime::merge_hit(
            &mut query,
            fixture.hit(packet.clone(), vec![incorrect]),
            &runtime.own,
        );
        assert!(query.hits[&packet.record.signed.id].reviews.is_empty());
        assert!(query.truncated);
        runtime
            .store
            .insert(packet.clone(), false, util::now())
            .unwrap();
        runtime.store.evaluate(useful, util::now()).unwrap();
        runtime.finish_query(query, &config::load(&fixture.home).unwrap());
        let result = response.try_recv().unwrap().result;
        assert_eq!(result["partial"], true);
        assert_eq!(result["hits"][0]["quality"]["useful_votes"], 0);
        assert!(result["hits"][0]["score"].as_f64().unwrap() < 1e100);
        assert_eq!(result["hits"][0]["untrusted"], true);
        let (mut query, _) = fixture.query("");
        for index in 0..QUERY_HITS + 2 {
            let mut hit = fixture.hit(packet.clone(), vec![]);
            hit.packet.record.signed.id = util::hash(index.to_string().as_bytes());
            Runtime::merge_hit(&mut query, hit, &runtime.own);
        }
        assert_eq!(query.hits.len(), QUERY_HITS);
        assert!(query.truncated);
        assert!(query_bytes(&query) <= QUERY_BYTES);
        let (mut query, _) = fixture.query("");
        for index in 0..2 {
            let mut hit = fixture.hit(packet.clone(), vec![]);
            hit.packet.record.signed.id = util::hash(index.to_string().as_bytes());
            hit.packet.record.signed.solution = "a".repeat(QUERY_BYTES * 2 / 3);
            Runtime::merge_hit(&mut query, hit, &runtime.own);
        }
        assert!(query.truncated);
        assert!(query_bytes(&query) <= QUERY_BYTES);
    }

    #[test]
    fn cache_and_route_metadata_are_bounded_and_eviction_is_pruned() {
        let fixture = Fixture::new(3);
        let mut runtime = fixture.runtime();
        let packet = fixture.record("How is cache bounded?");
        for index in 0..32 {
            let mut hit = fixture.hit(packet.clone(), vec![]);
            hit.packet.record.signed.id = util::hash(index.to_string().as_bytes());
            hit.packet.record.signed.solution = "a".repeat(CACHE_BYTES / 8);
            runtime.remember(hit);
        }
        assert!(runtime.cache.len() <= CACHE_ENTRIES);
        assert!(runtime.cache.values().map(|c| c.bytes).sum::<usize>() <= CACHE_BYTES);
        runtime.acks.insert(
            (
                packet.record.signed.id.clone(),
                fixture.keys[1].public().to_peer_id().to_string(),
            ),
            (transfer_digest(&packet, &[]).unwrap(), 1, util::now()),
        );
        runtime.retry.insert(
            (
                packet.record.signed.id,
                fixture.keys[1].public().to_peer_id().to_string(),
            ),
            Instant::now(),
        );
        runtime.prune_metadata(&config::load(&fixture.home).unwrap());
        assert!(runtime.acks.is_empty());
        assert!(runtime.retry.is_empty());
    }

    #[test]
    fn rate_limits_bound_bursts_refill_and_separate_authenticated_owners() {
        let now = Instant::now();
        let mut remote = Rate {
            tokens: 16.0,
            updated: now,
        };
        for _ in 0..16 {
            assert!(remote.take(16.0, 4.0, now));
        }
        assert!(!remote.take(16.0, 4.0, now));
        assert!(remote.take(16.0, 4.0, now + Duration::from_millis(250)));
        let fixture = Fixture::new(2);
        let mut runtime = fixture.runtime();
        assert!(runtime.allow_mutation("uid:1"));
        assert!(runtime.allow_mutation("uid:1"));
        assert!(!runtime.allow_mutation("uid:1"));
        assert!(runtime.allow_mutation("uid:2"));
        let rate = runtime.mutation_rates.get_mut("uid:1").unwrap();
        rate.updated -= Duration::from_secs(6);
        assert!(runtime.allow_mutation("uid:1"));
    }

    #[tokio::test]
    async fn poll_work_is_a_small_cursor_batch_and_revoked_queued_queries_do_not_send() {
        let fixture = Fixture::new(3);
        let mut runtime = fixture.runtime();
        for index in 0..6 {
            runtime
                .store
                .insert(
                    fixture.record(&format!("How do I verify procedure {index}?")),
                    true,
                    util::now(),
                )
                .unwrap();
        }
        let mut swarm = network::build(
            fixture.keys[0].clone(),
            &config::load(&fixture.home).unwrap(),
        )
        .await
        .unwrap();
        runtime.poll_records(&config::load(&fixture.home).unwrap(), &mut swarm);
        let ids = runtime
            .pending
            .values()
            .filter_map(|work| match work {
                Work::Store { id, .. } => Some(id),
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(ids.len(), POLL_BATCH);
        let peer = fixture.keys[2].public().to_peer_id();
        let (mut query, mut response) = fixture.query("private query");
        query.queue.push_back(peer);
        runtime.queries.insert(1, query);
        let renewed = Fixture::certificate(
            &fixture.authority,
            &[&fixture.keys[0], &fixture.keys[1]],
            2,
            false,
            util::now(),
        );
        fixture.install(&renewed);
        runtime.poll(&mut swarm);
        runtime.poll(&mut swarm);
        assert!(
            !runtime
                .pending
                .values()
                .any(|work| matches!(work, Work::Query(_, p) if p == &peer))
        );
        assert_eq!(response.try_recv().unwrap().result["partial"], true);
    }

    #[tokio::test]
    async fn nonowner_handoff_pins_until_all_three_receipts_and_survives_restart() {
        let fixture = Fixture::new(4);
        let mut runtime = fixture.runtime();
        let packet = (0..128)
            .find_map(|index| {
                let packet = fixture.record(&format!("How is source handoff {index} protected?"));
                (!knowledge::replica_peers(
                    &fixture.room.certificate.signed,
                    &packet.record.signed.id,
                    knowledge::REPLICAS,
                )
                .contains(&runtime.own))
                .then_some(packet)
            })
            .unwrap();
        let id = packet.record.signed.id.clone();
        runtime
            .store
            .insert(packet.clone(), false, util::now())
            .unwrap();
        let mut swarm = network::build(
            fixture.keys[0].clone(),
            &config::load(&fixture.home).unwrap(),
        )
        .await
        .unwrap();
        runtime.poll_records(&config::load(&fixture.home).unwrap(), &mut swarm);
        assert!(runtime.store.state.records[0].staging);
        let keepers =
            knowledge::replica_peers(&fixture.room.certificate.signed, &id, knowledge::REPLICAS);
        for keeper in keepers.iter().take(2) {
            let index = fixture
                .keys
                .iter()
                .position(|key| key.public().to_peer_id().to_string() == *keeper)
                .unwrap();
            let receipt = fixture.receipt(index, &packet, &[]);
            let peer = fixture.keys[index].public().to_peer_id();
            runtime.completed(
                Work::Store {
                    peer,
                    room: receipt.signed.room_id.clone(),
                    id: id.clone(),
                    digest: receipt.signed.digest.clone(),
                    epoch: 1,
                    sent_at: util::now(),
                },
                peer,
                Some(WireReply::Stored { receipt }),
            );
        }
        runtime.poll_records(&config::load(&fixture.home).unwrap(), &mut swarm);
        assert!(
            runtime
                .store
                .get(&fixture.room.certificate.signed.room_id, &id)
                .unwrap()
                .staging
        );
        let mut restarted = fixture.runtime();
        assert!(restarted.acks.is_empty());
        assert!(
            restarted
                .store
                .get(&fixture.room.certificate.signed.room_id, &id)
                .unwrap()
                .staging
        );
        for keeper in &keepers {
            let index = fixture
                .keys
                .iter()
                .position(|key| key.public().to_peer_id().to_string() == *keeper)
                .unwrap();
            let receipt = fixture.receipt(index, &packet, &[]);
            let peer = fixture.keys[index].public().to_peer_id();
            restarted.completed(
                Work::Store {
                    peer,
                    room: receipt.signed.room_id.clone(),
                    id: id.clone(),
                    digest: receipt.signed.digest.clone(),
                    epoch: 1,
                    sent_at: util::now(),
                },
                peer,
                Some(WireReply::Stored { receipt }),
            );
        }
        restarted.poll_records(&config::load(&fixture.home).unwrap(), &mut swarm);
        assert!(
            restarted
                .store
                .get(&fixture.room.certificate.signed.room_id, &id)
                .is_none()
        );
        assert!(Store::open(&fixture.home).unwrap().state.records.is_empty());
    }

    #[test]
    #[ignore = "explicit optimized stress check; interpreter cost in debug can starve deadline-sensitive IPC fixtures"]
    fn large_valid_review_aggregate_fits_transport_without_dropping_review_tails() {
        let fixture = Fixture::new(32);
        let mut room = fixture.room.clone();
        for member in &mut room.certificate.signed.members {
            member.addresses = (1..=4)
                .map(|port| {
                    format!(
                        "/ip6/ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255/tcp/{}/ws",
                        65530 + port
                    )
                })
                .collect();
        }
        room.certificate.signature = crypto::sign(
            &fixture.authority,
            "idobata.room.v1",
            &room.certificate.signed,
        )
        .unwrap();
        let packet = knowledge::create_record(
            &fixture.keys[1],
            &room,
            KnowledgeInput {
                problem: "How do large signed review sets move?".into(),
                solution: "Keep the complete validated object in a bounded transfer. ".repeat(120),
                context: String::new(),
                references: vec![],
                kind: "answer".into(),
            },
            false,
            util::now(),
        )
        .unwrap();
        let template = knowledge::create_review(
            &fixture.keys[0],
            &room,
            &packet,
            ReviewInput {
                verdict: "useful".into(),
                evidence: "The documented procedure worked under the stated conditions. "
                    .repeat(16),
                references: vec![
                    format!("https://example.org/{}", "a".repeat(1000)),
                    format!("https://example.org/{}", "b".repeat(1000)),
                ],
            },
            1,
            util::now(),
        )
        .unwrap();
        let mut reviews = vec![];
        for (index, key) in fixture.keys.iter().enumerate() {
            if index == 1 {
                continue;
            }
            let mut review = template.clone();
            review.review.signed.reviewer_peer_id = key.public().to_peer_id().to_string();
            let mut value = serde_json::to_value(&review.review.signed).unwrap();
            value.as_object_mut().unwrap().remove("id");
            review.review.signed.id = util::hash(&util::canonical(&value).unwrap());
            review.review.public_key = crypto::public(key);
            review.review.signature =
                crypto::sign(key, "idobata.knowledge.review.v1", &review.review.signed).unwrap();
            reviews.push(review);
        }
        let request = WireRequest::Store {
            room_id: room.certificate.signed.room_id.clone(),
            packet: Box::new(packet.clone()),
            reviews: reviews.clone(),
        };
        assert!(serde_json::to_vec(&request).unwrap().len() > 512 * 1024);
        assert!(serde_json::to_vec(&request).unwrap().len() < MAX_WIRE);
        fixture.install(&room);
        let keeper = knowledge::replica_peers(
            &room.certificate.signed,
            &packet.record.signed.id,
            knowledge::REPLICAS,
        )[0]
        .clone();
        let keeper_index = fixture
            .keys
            .iter()
            .position(|key| key.public().to_peer_id().to_string() == keeper)
            .unwrap();
        let mut receiver =
            Runtime::open(&fixture.home, fixture.keys[keeper_index].clone()).unwrap();
        let started = Instant::now();
        assert!(matches!(
            receiver
                .incoming(
                    fixture.keys[(keeper_index + 1) % fixture.keys.len()]
                        .public()
                        .to_peer_id(),
                    request
                )
                .unwrap(),
            WireReply::Stored { .. }
        ));
        eprintln!(
            "large signed Store admission seconds: {:.3}",
            started.elapsed().as_secs_f64()
        );
        assert_eq!(receiver.store.state.records[0].reviews.len(), 31);
        let reply = Runtime::bounded_hits(vec![fixture.hit(packet, reviews)]);
        let WireReply::Hits { hits, truncated } = &reply else {
            panic!("wrong reply");
        };
        assert!(!truncated);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].reviews.len(), 31);
        assert!(serde_json::to_vec(&reply).unwrap().len() <= RESPONSE_BYTES);
    }

    #[test]
    fn public_subset_filters_old_content_and_keeps_utf8_titles_within_feed_limits() {
        let fixture = Fixture::new(3);
        let public = Fixture::certificate(
            &fixture.authority,
            &fixture.keys.iter().collect::<Vec<_>>(),
            2,
            true,
            util::now(),
        );
        fixture.install(&public);
        let mut runtime = fixture.runtime();
        let packet = knowledge::create_record(
            &fixture.keys[1],
            &public,
            KnowledgeInput {
                problem: "開発環境の確認について説明します。".repeat(20),
                solution: "手順を実行して結果を確認します。".into(),
                context: "通常の開発環境です。".into(),
                references: vec![],
                kind: "answer".into(),
            },
            true,
            util::now(),
        )
        .unwrap();
        runtime.store.insert(packet, false, util::now()).unwrap();
        let entries = runtime.public_entries(&public);
        assert_eq!(entries.len(), 1);
        assert!(entries[0].content.title.len() <= 256);
        crypto::validate_draft(&entries[0].content).unwrap();
        assert_eq!(
            Scanner::new()
                .unwrap()
                .scan(&entries[0].content, false)
                .unwrap()
                .code,
            0
        );
    }

    fn solve_public_test_tasks(challenge: ChallengePacket) -> AutomationAnswer {
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
        AutomationAnswer { challenge, answers }
    }
    fn required_fixture() -> Fixture {
        let mut fixture = Fixture::new(3);
        fixture.room.certificate.signed.version = 3;
        fixture.room.certificate.signed.epoch = 2;
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
        fixture.install(&fixture.room);
        fixture
    }
    fn gate_input() -> KnowledgeInput {
        KnowledgeInput {
            problem: "How is a capability-tested contribution admitted?".into(),
            solution: "Submit the exact inspected action with a valid independent peer receipt."
                .into(),
            context: "This tests automation capability without claiming AI identity.".into(),
            references: vec![],
            kind: "answer".into(),
        }
    }

    #[test]
    fn automation_gate_stores_nothing_before_certification_and_spent_nonce_survives_restart() {
        let fixture = required_fixture();
        let mut caller = fixture.runtime();
        let peer_home = fixture._temp.path().join("issuer");
        config::init(&peer_home, vec!["/ip4/127.0.0.1/tcp/0".into()]).unwrap();
        util::atomic_write(
            &peer_home.join("identity.key"),
            &fixture.keys[1].to_protobuf_encoding().unwrap(),
        )
        .unwrap();
        let mut config = config::load(&peer_home).unwrap();
        config.rooms.insert("room".into(), fixture.room.clone());
        config::save(&peer_home, &config).unwrap();
        let mut issuer = Runtime::open(&peer_home, fixture.keys[1].clone()).unwrap();
        let subject = fixture.keys[0].public().to_peer_id();
        let issuer_peer = fixture.keys[1].public().to_peer_id();
        let packet = knowledge::prepare_record(
            &fixture.keys[0],
            &fixture.room,
            gate_input(),
            false,
            util::now(),
        )
        .unwrap();
        let digest = packet.record.signed.id.clone();
        let reply = issuer
            .incoming(
                subject,
                WireRequest::Challenge {
                    room_id: fixture.room.certificate.signed.room_id.clone(),
                    action_digest: digest.clone(),
                    purpose: "publish".into(),
                },
            )
            .unwrap();
        let WireReply::Challenge { challenge } = reply else {
            panic!("challenge required");
        };
        let (response, mut receiver) = tokio::sync::oneshot::channel();
        caller.gates.insert(
            1,
            GatePending {
                response,
                room: fixture.room.clone(),
                digest: digest.clone(),
                purpose: "publish".into(),
                action: None,
                answer: None,
                issuer: issuer_peer,
                candidates: VecDeque::new(),
                attempt_until: Instant::now() + Duration::from_secs(2),
                deadline: Instant::now() + Duration::from_secs(7),
            },
        );
        caller.completed(
            Work::GateChallenge(1, issuer_peer),
            issuer_peer,
            Some(WireReply::Challenge {
                challenge: challenge.clone(),
            }),
        );
        let pending = receiver.try_recv().unwrap();
        assert_eq!(pending.code, 31);
        assert_eq!(pending.result["stored"], false);
        assert_eq!(pending.result["enqueued"], false);
        assert_eq!(
            pending.result["tasks"].as_array().unwrap().len(),
            automation::CASE_COUNT
        );
        assert!(caller.store.state.records.is_empty());
        assert!(issuer.store.state.records.is_empty());
        let answer = solve_public_test_tasks(challenge.clone());
        let mut invalid = answer.clone();
        invalid.answers[0] ^= 1;
        assert!(
            issuer
                .incoming(
                    subject,
                    WireRequest::Certify {
                        answer: Box::new(invalid)
                    }
                )
                .is_err()
        );
        assert!(!issuer.nonces.state.entries[0].spent);
        let reply = issuer
            .incoming(
                subject,
                WireRequest::Certify {
                    answer: Box::new(answer.clone()),
                },
            )
            .unwrap();
        assert!(issuer.nonces.state.entries[0].spent);
        assert!(
            Runtime::open(&peer_home, fixture.keys[1].clone())
                .unwrap()
                .nonces
                .state
                .entries[0]
                .spent
        );
        assert!(
            issuer
                .incoming(
                    subject,
                    WireRequest::Certify {
                        answer: Box::new(answer.clone())
                    }
                )
                .is_err()
        );
        let nonce_text = std::fs::read_to_string(peer_home.join("automation-nonces.json")).unwrap();
        assert!(!nonce_text.contains(&packet.record.signed.problem));
        assert!(!nonce_text.contains(&packet.record.signed.solution));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(peer_home.join("automation-nonces.json"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let (response, mut receiver) = tokio::sync::oneshot::channel();
        caller.gates.insert(
            2,
            GatePending {
                response,
                room: fixture.room.clone(),
                digest: digest.clone(),
                purpose: "publish".into(),
                action: Some(GateAction::Publish(packet)),
                answer: Some(answer),
                issuer: issuer_peer,
                candidates: VecDeque::new(),
                attempt_until: Instant::now() + Duration::from_secs(2),
                deadline: Instant::now() + Duration::from_secs(7),
            },
        );
        caller.completed(Work::GateCertify(2, issuer_peer), issuer_peer, Some(reply));
        let accepted = receiver.try_recv().unwrap();
        assert_eq!(accepted.code, 0);
        assert_eq!(accepted.result["assurance"], "automation_tested");
        let stored = &caller.store.state.records[0];
        assert_eq!(stored.packet.record.signed.id, digest);
        assert!(stored.packet.admission.is_some());
        knowledge::validate_record(
            &stored.packet,
            &fixture.room,
            util::now() + automation::CHALLENGE_TTL_SECONDS + 1,
        )
        .unwrap();
        assert!(issuer.store.state.records.is_empty());
    }

    #[test]
    fn nonce_capacity_and_failed_consumption_never_allow_false_receipts() {
        let fixture = required_fixture();
        let mut nonces = Nonces::open(&fixture.home).unwrap();
        let challenge = automation::create_challenge(
            &fixture.keys[1],
            &fixture.room,
            &fixture.keys[0].public().to_peer_id().to_string(),
            &util::hash(b"bounded action"),
            "publish",
            util::now(),
        )
        .unwrap();
        nonces.issue(&challenge).unwrap();
        std::fs::remove_file(&nonces.path).unwrap();
        std::fs::create_dir(&nonces.path).unwrap();
        assert!(nonces.spend(&challenge).is_err());
        assert!(!nonces.state.entries[0].spent);
        std::fs::remove_dir(&nonces.path).unwrap();
        nonces.state.entries = (0..256)
            .map(|index| Nonce {
                id: util::hash(index.to_string().as_bytes()),
                digest: util::hash(b"public digest"),
                expires_at: util::now() + 120,
                spent: false,
            })
            .collect();
        util::atomic_write(&nonces.path, &util::canonical(&nonces.state).unwrap()).unwrap();
        assert!(nonces.issue(&challenge).is_err());
        assert_eq!(
            Nonces::open(&fixture.home).unwrap().state.entries.len(),
            256
        );
    }

    #[tokio::test]
    async fn challenge_falls_back_from_offline_first_peer_and_pending_input_expires() {
        let fixture = required_fixture();
        let mut runtime = fixture.runtime();
        let mut swarm = network::build(
            fixture.keys[0].clone(),
            &config::load(&fixture.home).unwrap(),
        )
        .await
        .unwrap();
        let packet = knowledge::prepare_record(
            &fixture.keys[0],
            &fixture.room,
            gate_input(),
            false,
            util::now(),
        )
        .unwrap();
        let first = fixture.keys[1].public().to_peer_id();
        let second = fixture.keys[2].public().to_peer_id();
        let (response, mut receiver) = tokio::sync::oneshot::channel();
        runtime.gates.insert(
            7,
            GatePending {
                response,
                room: fixture.room.clone(),
                digest: packet.record.signed.id.clone(),
                purpose: "publish".into(),
                action: Some(GateAction::Publish(packet)),
                answer: None,
                issuer: first,
                candidates: VecDeque::from([second]),
                attempt_until: Instant::now() - Duration::from_secs(1),
                deadline: Instant::now() + Duration::from_secs(7),
            },
        );
        runtime.retry_gates(&config::load(&fixture.home).unwrap(), &mut swarm);
        assert_eq!(runtime.gates[&7].issuer, second);
        assert!(
            runtime
                .pending
                .values()
                .any(|work| matches!(work, Work::GateChallenge(7, peer) if peer == &second))
        );
        runtime.gates.get_mut(&7).unwrap().deadline = Instant::now() - Duration::from_secs(1);
        runtime.poll(&mut swarm);
        assert!(runtime.gates.is_empty());
        assert!(runtime.store.state.records.is_empty());
        assert!(!fixture.home.join("knowledge.enc").exists());
        assert_eq!(receiver.try_recv().unwrap().code, 40);
    }

    #[tokio::test]
    async fn two_peer_cold_challenge_retries_issuer_only_once() {
        let mut fixture = Fixture::new(2);
        fixture.room.certificate.signed.version = 3;
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
        fixture.install(&fixture.room);
        let mut runtime = fixture.runtime();
        let mut swarm = network::build(
            fixture.keys[0].clone(),
            &config::load(&fixture.home).unwrap(),
        )
        .await
        .unwrap();
        let packet = knowledge::prepare_record(
            &fixture.keys[0],
            &fixture.room,
            gate_input(),
            false,
            util::now(),
        )
        .unwrap();
        let (response, mut receiver) = tokio::sync::oneshot::channel();
        assert!(
            runtime
                .begin_gate(
                    GateIntent {
                        room: fixture.room.clone(),
                        digest: packet.record.signed.id.clone(),
                        purpose: "publish".into(),
                        action: GateAction::Publish(packet),
                        answer: None
                    },
                    response,
                    &mut swarm
                )
                .is_ok()
        );
        let id = runtime.next_gate;
        let issuer = fixture.keys[1].public().to_peer_id();
        assert_eq!(runtime.gates[&id].candidates, VecDeque::from([issuer]));
        runtime.completed(Work::GateChallenge(id, issuer), issuer, None);
        assert!(runtime.gates.contains_key(&id));
        runtime.retry_gates(&config::load(&fixture.home).unwrap(), &mut swarm);
        assert!(runtime.gates[&id].candidates.is_empty());
        assert_eq!(runtime.gates[&id].issuer, issuer);
        assert!(runtime.pending.values().any(
            |work| matches!(work, Work::GateChallenge(gate, peer) if *gate == id && *peer == issuer)
        ));
        runtime.completed(Work::GateChallenge(id, issuer), issuer, None);
        assert!(!runtime.gates.contains_key(&id));
        let failed = receiver.try_recv().unwrap();
        assert_eq!(failed.code, 40);
        assert_eq!(failed.result["stored"], false);
        assert!(runtime.store.state.records.is_empty());
    }

    #[tokio::test]
    async fn degraded_fresh_receipts_skip_poll_validation_but_due_transfers_reject_tampering() {
        let fixture = Fixture::new(2);
        let mut runtime = fixture.runtime();
        let packet = fixture.record("How do fresh acknowledgments avoid unnecessary scans?");
        let id = packet.record.signed.id.clone();
        runtime
            .store
            .insert(packet.clone(), false, util::now())
            .unwrap();
        let other = fixture.keys[1].public().to_peer_id().to_string();
        runtime.acks.insert(
            (id.clone(), other.clone()),
            (transfer_digest(&packet, &[]).unwrap(), 1, util::now()),
        );
        let config = config::load(&fixture.home).unwrap();
        let mut swarm = network::build(fixture.keys[0].clone(), &config)
            .await
            .unwrap();
        for _ in 0..4 {
            runtime.poll_records(&config, &mut swarm);
        }
        assert_eq!(runtime.poll_record_validations, 0);
        assert!(runtime.pending.is_empty());
        assert!(runtime.store.state.records[0].staging);
        assert_eq!(
            runtime.status(&config, Some("room")).unwrap()["records"][0]["replication_complete"],
            false
        );
        runtime.acks.clear();
        runtime.retry.insert(
            (id.clone(), other),
            Instant::now() + Duration::from_secs(10),
        );
        runtime.poll_records(&config, &mut swarm);
        assert_eq!(runtime.poll_record_validations, 0);
        runtime.retry.clear();
        runtime.store.state.records[0].packet.record.signature = "invalid".into();
        runtime.poll_records(&config, &mut swarm);
        assert_eq!(runtime.poll_record_validations, 1);
        assert!(runtime.pending.is_empty());
        assert!(runtime.store.state.records[0].staging);
    }
}
