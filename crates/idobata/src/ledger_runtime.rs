//! Explicitly configured private experiment: bounded Noise RPC, durable reward
//! application replay, and consensus driving. No automatic genesis or issuance.
use crate::{
    config, crypto,
    error::{Error, INVALID, Result, STORAGE},
    knowledge::{self, RecordPacket},
    knowledge_runtime,
    ledger::{self, Machine, Operation, SignedTransaction, Verdict},
    ledger_consensus::{
        self as consensus, CommitCertificate, Node, Proposal, TimeoutCertificate, TimeoutVote, Vote,
    },
    network,
    scanner::Scanner,
    types::{Signed, TrustedRoom},
    util,
};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use libp2p::{
    PeerId, Swarm, identity,
    request_response::{self, Message, OutboundRequestId},
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const MAX_POOL: usize = 64;
const PEER_POOL: usize = 4;
const OPERATOR_POOL: usize = 8;
const MAX_QUEUE: usize = 64;
const MAX_QUEUE_BYTES: usize = 8 * 1024 * 1024;
const MAX_PROOF_BYTES: usize = 4 * 1024 * 1024;
const MAX_PROOFS: usize = 128;
const OPERATOR_PROOF_REFS: usize = 8;
const OPERATOR_PROOF_BYTES: usize = 512 * 1024;
const PENDING_PROOF_REFS: usize = 64;
const PENDING_PROOF_BYTES: usize = 2 * 1024 * 1024;
const PHASE_PROOF_REFS: usize = 64;
const PHASE_PROOF_BYTES: usize = 2 * 1024 * 1024;
const BLOCK_PROOF_REFS: usize = 32;
const BLOCK_PROOF_BYTES: usize = network::MAX_LEDGER_WIRE - 128 * 1024;
// Core checkpoint16MiB + proofs4MiB + pending <=4MiB (64 x64KiB)
// + bounded tracking <=4MiB + QC/index/encryption overhead; reserve32MiB.
const MAX_DISK: usize = 32 * 1024 * 1024;
const SNAPSHOT_CHUNK: usize = 64 * 1024;
const MAGIC: &[u8] = b"idobata.ledger.runtime.v1\0";
const HOLD: Error = Error::new(10, "ledger_runtime_hold");

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    pub version: u32,
    pub room_alias: String,
    pub authority_peer_id: String,
    pub application: ledger::SignedGenesis,
    pub consensus: Signed<consensus::Genesis>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum WireRequest {
    Submit {
        transaction: Box<SignedTransaction>,
        records: Vec<RecordPacket>,
    },
    Proposal {
        proposal: Box<Proposal>,
        records: Vec<RecordPacket>,
    },
    Vote {
        vote: Vote,
    },
    Timeout {
        timeout: TimeoutVote,
    },
    TimeoutCertificate {
        certificate: TimeoutCertificate,
    },
    Commit {
        certificate: Box<CommitCertificate>,
    },
    Status,
    Sync {
        after_height: u64,
    },
    Snapshot {
        offset: usize,
        block_id: Option<String>,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum WireReply {
    Ack {
        height: u64,
        round: u64,
    },
    Head {
        height: u64,
        block_id: Option<String>,
        round: u64,
        round_certificate: Option<TimeoutCertificate>,
    },
    Blocks {
        certificates: Vec<CommitCertificate>,
        snapshot_required: bool,
    },
    Snapshot {
        certificate: Box<CommitCertificate>,
        digest: String,
        total: usize,
        offset: usize,
        bytes: Vec<u8>,
    },
    Rejected {
        code: i32,
    },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Disk {
    version: u32,
    checkpoint: ledger::Checkpoint,
    certificate: Option<CommitCertificate>,
    pending: Vec<SignedTransaction>,
    proofs: BTreeMap<String, RecordPacket>,
    history: BTreeMap<String, tracking::Tracked>,
    pruned_ids: BTreeSet<String>,
    history_pruned: bool,
}

struct Pending {
    peer: PeerId,
    request: WireRequest,
    started: Instant,
}
struct Bucket {
    tokens: f64,
    at: Instant,
}
struct SnapshotDownload {
    peer: PeerId,
    certificate: CommitCertificate,
    digest: String,
    total: usize,
    bytes: Vec<u8>,
    started: Instant,
}
struct Active {
    settings: Settings,
    node: Node,
    machine: Machine,
    key: identity::Keypair,
    storage_key: Zeroizing<Vec<u8>>,
    home: PathBuf,
    pool: Vec<SignedTransaction>,
    history: BTreeMap<String, tracking::Tracked>,
    pruned_ids: BTreeSet<String>,
    history_pruned: bool,
    proofs: BTreeMap<String, RecordPacket>,
    queue: VecDeque<(PeerId, WireRequest)>,
    pending: BTreeMap<OutboundRequestId, Pending>,
    published: BTreeSet<String>,
    last_rebroadcast: Instant,
    last_block: Instant,
    last_proposal_send: Option<(u64, u64, Instant)>,
    last_status: Instant,
    status_cursor: usize,
    pool_cursor: usize,
    buckets: BTreeMap<String, Bucket>,
    peer_buckets: BTreeMap<String, Bucket>,
    backoff: BTreeMap<PeerId, Instant>,
    send_due: BTreeMap<PeerId, Instant>,
    download: Option<SnapshotDownload>,
    snapshot_cache: Option<(Instant, Vec<u8>, CommitCertificate)>,
    needs_snapshot: bool,
    fault: Option<&'static str>,
    timings: timing::Timings,
    validation_cache: timing::ValidationCache,
}
pub struct Runtime {
    active: Option<Active>,
    fault: Option<&'static str>,
}

fn storage_failure(error: &Error) -> bool {
    error.code == STORAGE.code && error.error == STORAGE.error
}

/// Service-owner management only. No IPC request can create or replace genesis.
pub fn configure(home: &Path, settings: &Settings) -> Result<()> {
    util::protected(home)?;
    if settings.version != 1 || !util::valid_alias(&settings.room_alias) {
        return Err(INVALID);
    }
    consensus::validate_genesis(&settings.consensus.signed)?;
    let application =
        ledger::verify_genesis(settings.application.clone(), &settings.authority_peer_id)?;
    if application.chain_id() != settings.consensus.signed.chain_id
        || application.genesis_hash() != settings.consensus.signed.application_genesis_hash
        || settings.application.public_key != settings.consensus.public_key
    {
        return Err(INVALID);
    }
    let public = crypto::public_key(&settings.consensus.public_key)?;
    if public.to_peer_id().to_string() != settings.authority_peer_id {
        return Err(INVALID);
    }
    crypto::verify(
        &public,
        "idobata.ledger.genesis.v1",
        &settings.consensus.signed,
        &settings.consensus.signature,
    )?;
    let machine = Machine::new(application)?;
    if machine.state_root()? != settings.consensus.signed.initial_application_hash {
        return Err(INVALID);
    }
    for validator in &settings.consensus.signed.validators {
        let participant = settings
            .application
            .signed
            .participants
            .get(&validator.peer_id)
            .ok_or(INVALID)?;
        if participant.public_key != validator.public_key
            || participant.operator != validator.operator
        {
            return Err(INVALID);
        }
    }
    settings_room(
        home,
        settings,
        &crypto::load_key(home)?.public().to_peer_id().to_string(),
    )?;
    let path = home.join("ledger-settings.json");
    if path.exists() {
        util::protected(&path)?;
        let old: Settings =
            serde_json::from_slice(&util::read_bounded(&path, 256 * 1024)?).map_err(|_| STORAGE)?;
        if util::canonical(&old)? != util::canonical(settings)? {
            return Err(Error::new(30, "ledger_genesis_reconfiguration_unsupported"));
        }
        return Ok(());
    }
    util::atomic_write(&path, &serde_json::to_vec(settings).map_err(|_| STORAGE)?)
}

impl Runtime {
    pub fn open(home: &Path, key: identity::Keypair) -> Result<Self> {
        match Self::try_open(home, key) {
            Ok(runtime) => Ok(runtime),
            Err(error) => Ok(Self {
                active: None,
                fault: Some(error.error),
            }),
        }
    }
    fn try_open(home: &Path, key: identity::Keypair) -> Result<Self> {
        let path = home.join("ledger-settings.json");
        if !path.exists() {
            return Ok(Self {
                active: None,
                fault: None,
            });
        }
        util::protected(&path)?;
        let settings: Settings =
            serde_json::from_slice(&util::read_bounded(&path, 256 * 1024)?).map_err(|_| STORAGE)?;
        configure(home, &settings)?;
        let key_path = home.join("storage.key");
        util::protected(&key_path)?;
        let storage_key = util::read_bounded(&key_path, 32)?;
        if storage_key.len() != 32 {
            return Err(STORAGE);
        }
        let disk: Option<Disk> = read_disk(
            home,
            &storage_key,
            &settings.consensus.signed.application_genesis_hash,
        )?;
        let node = Node::open(
            home,
            key.clone(),
            settings.consensus.clone(),
            &settings.authority_peer_id,
        );
        let mut node = match node {
            Ok(node) => node,
            Err(error) => {
                let Some(disk) = &disk else { return Err(error) };
                let Some(cert) = &disk.certificate else {
                    return Err(error);
                };
                Node::open_from_checkpoint(
                    home,
                    key.clone(),
                    settings.consensus.clone(),
                    &settings.authority_peer_id,
                    cert.clone(),
                    disk.checkpoint.height,
                    &disk.checkpoint.state_root,
                )?
            }
        };
        let genesis =
            ledger::verify_genesis(settings.application.clone(), &settings.authority_peer_id)?;
        let (machine, pool, proofs, history, pruned_ids, history_pruned) = if let Some(disk) = disk
        {
            if disk.version != 1
                || disk.pending.len() > MAX_POOL
                || disk.proofs.len() > MAX_PROOFS
                || serde_json::to_vec(&disk.proofs).map_err(|_| STORAGE)?.len() > MAX_PROOF_BYTES
            {
                return Err(STORAGE);
            }
            let machine =
                Machine::restore_checkpoint(genesis, disk.checkpoint, |height, id, root| {
                    verify_snapshot(&node, disk.certificate.as_ref(), height, id, root)
                })?;
            if machine.state().height >= node.height() {
                node.import_checkpoint(
                    disk.certificate.ok_or(STORAGE)?,
                    machine.state().height,
                    &machine.state_root()?,
                )?;
            }
            (
                machine,
                disk.pending,
                disk.proofs,
                disk.history,
                disk.pruned_ids,
                disk.history_pruned,
            )
        } else {
            (
                Machine::new(genesis)?,
                vec![],
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeSet::new(),
                false,
            )
        };
        let mut active = Active {
            settings,
            node,
            machine,
            key,
            storage_key,
            home: home.into(),
            pool,
            proofs,
            history,
            pruned_ids,
            history_pruned,
            queue: VecDeque::new(),
            pending: BTreeMap::new(),
            published: BTreeSet::new(),
            last_rebroadcast: Instant::now(),
            last_block: Instant::now(),
            last_proposal_send: None,
            last_status: Instant::now() - Duration::from_secs(5),
            status_cursor: 0,
            pool_cursor: 0,
            buckets: BTreeMap::new(),
            peer_buckets: BTreeMap::new(),
            backoff: BTreeMap::new(),
            send_due: BTreeMap::new(),
            download: None,
            snapshot_cache: None,
            needs_snapshot: false,
            fault: None,
            timings: timing::Timings::default(),
            validation_cache: Default::default(),
        };
        active.validate_history()?;
        match active.replay() {
            Ok(()) => active.save()?,
            Err(error) if error.code == HOLD.code => active.needs_snapshot = true,
            Err(error) => return Err(error),
        }
        Ok(Self {
            active: Some(active),
            fault: None,
        })
    }
    pub fn status(&self) -> Value {
        match &self.active {
            None => {
                json!({"status":if self.fault.is_some(){"fault"}else{"hold"},"reason":self.fault.unwrap_or("ledger_not_configured"),"experiment_only":true})
            }
            Some(a) => {
                let reason = a
                    .fault
                    .or_else(|| a.room().err().map(|_| "ledger_room_authorization_changed"))
                    .or_else(|| {
                        a.needs_snapshot
                            .then_some("application_checkpoint_required")
                    })
                    .or_else(|| (!a.node.ready()).then_some("insufficient_independent_operators"));
                let own = a.key.public().to_peer_id().to_string();
                let pending=a.pool.iter().filter(|tx|tx.signed.signer_peer_id==own).map(|tx|json!({"transaction_id":ledger::transaction_id(tx).ok(),"nonce":tx.signed.nonce})).collect::<Vec<_>>();
                let mut recent = a
                    .history
                    .iter()
                    .filter(|(_, h)| h.signer == own)
                    .collect::<Vec<_>>();
                recent.sort_by(|(ia, a), (ib, b)| b.nonce.cmp(&a.nonce).then_with(|| ia.cmp(ib)));
                recent.truncate(32);
                let recent=recent.into_iter().map(|(id,h)|json!({"transaction_id":id,"nonce":h.nonce,"operation":h.summary,"outcome":h.outcome})).collect::<Vec<_>>();
                let next_submission = a
                    .pool
                    .iter()
                    .filter(|tx| tx.signed.signer_peer_id == own)
                    .map(|tx| tx.signed.nonce)
                    .max()
                    .unwrap_or(a.machine.next_nonce(&own).unwrap_or(1).saturating_sub(1))
                    .checked_add(1)
                    .filter(|nonce| *nonce <= ledger::MAX_INTEGER);
                json!({"consensus":a.node.status(),"performance":a.timings.json(),"status":if a.fault.is_some(){"fault"}else if reason.is_some(){"hold"}else{"ready"},"reason":reason,"chain_id":a.machine.genesis().chain_id(),"peer_id":a.key.public().to_peer_id().to_string(),"role":if a.node.is_validator(){"validator"}else{"wallet"},"application_height":a.machine.state().height,"state_root":a.machine.state_root().ok(),"balance":a.machine.balance(&a.key.public().to_peer_id().to_string()),"next_nonce":a.machine.next_nonce(&a.key.public().to_peer_id().to_string()).ok(),"active_questions":a.machine.state().questions.len(),"closed_questions":a.machine.state().closed_questions.len(),"total_minted":a.machine.state().total_minted,"pending_transactions":a.pool.len(),"pending":pending,"recent_submissions":recent,"next_submission_nonce":next_submission,"queued_requests":a.queue.len(),"seconds_since_commit":a.last_block.elapsed().as_secs(),"pending_requests":a.pending.len(),"experiment_only":true})
            }
        }
    }
    pub fn question(&self, id: &str) -> Result<Value> {
        let a = self.active.as_ref().ok_or(HOLD)?;
        a.room()?;
        if !util::valid_id(id) {
            return Err(INVALID);
        }
        if let Some(q) = a.machine.state().questions.get(id) {
            let answers=q.answers.iter().map(|(id,answer)|json!({"id":id,"original_author":answer.beneficiary_peer_id,"submitted_by":answer.submitted_by_peer_id,"submission_order":answer.submission_order,"votes":answer.votes.iter().map(|(operator,vote)|json!({"operator":operator,"peer_id":vote.signed.voter_peer_id,"verdict":vote.signed.verdict,"sequence":vote.signed.sequence})).collect::<Vec<_>>()})).collect::<Vec<_>>();
            return Ok(
                json!({"status":"open","question":{"id":q.id,"source_record_id":q.terms.source_record_id,"criteria_record_id":q.terms.criteria_record_id,"asker_peer_id":q.asker_peer_id,"deadline_height":q.terms.deadline_height,"bounty":q.terms.bounty,"escrow":q.escrow,"system_reward":q.system_reward,"answers":answers},"untrusted":true}),
            );
        }
        if let Some(q) = a.machine.state().closed_questions.get(id) {
            return Ok(json!({"status":"closed","question":q,"untrusted":true}));
        }
        Ok(json!({"status":"not_found","untrusted":true}))
    }
    pub fn room_alias(&self) -> Option<&str> {
        self.active.as_ref().map(|a| a.settings.room_alias.as_str())
    }
    pub fn required_records(&self, operation: &Operation) -> Result<Vec<String>> {
        let a = self.active.as_ref().ok_or(HOLD)?;
        a.ensure_live()?;
        let ids = a.references(operation).into_iter().collect::<BTreeSet<_>>();
        if ids.len() > 3 || ids.iter().any(|id| !util::valid_id(id)) {
            return Err(INVALID);
        }
        Ok(ids.into_iter().collect())
    }
    pub fn required_vote_records(&self, question: &str, answer: &str) -> Result<Vec<String>> {
        let a = self.active.as_ref().ok_or(HOLD)?;
        a.ensure_live()?;
        if !util::valid_id(question)
            || !util::valid_id(answer)
            || a.machine.state().closed_questions.contains_key(question)
        {
            return Err(INVALID);
        }
        let q = a.machine.state().questions.get(question).ok_or(HOLD)?;
        if !q.answers.contains_key(answer) {
            return Err(HOLD);
        }
        Ok(BTreeSet::from([
            q.terms.source_record_id.clone(),
            q.terms.criteria_record_id.clone(),
            answer.to_owned(),
        ])
        .into_iter()
        .collect())
    }
    pub fn submit_from_knowledge(
        &mut self,
        operation: Operation,
        knowledge: &knowledge_runtime::Runtime,
    ) -> Result<Value> {
        let a = self.active.as_ref().ok_or(HOLD)?;
        let records = a
            .references(&operation)
            .into_iter()
            .map(|id| {
                knowledge
                    .ledger_record(&a.settings.application.signed.room_id, &id)
                    .ok_or(HOLD)
            })
            .collect::<Result<Vec<_>>>()?;
        self.submit(operation, records)
    }
    pub fn cast_vote_from_knowledge(
        &mut self,
        question: &str,
        answer: &str,
        verdict: Verdict,
        knowledge: &knowledge_runtime::Runtime,
    ) -> Result<Value> {
        let ids = self.required_vote_records(question, answer)?;
        let a = self.active.as_ref().ok_or(HOLD)?;
        let records = ids
            .into_iter()
            .map(|id| {
                knowledge
                    .ledger_record(&a.settings.application.signed.room_id, &id)
                    .ok_or(HOLD)
            })
            .collect::<Result<Vec<_>>>()?;
        self.cast_vote(question, answer, verdict, records)
    }
    pub fn submit(&mut self, operation: Operation, records: Vec<RecordPacket>) -> Result<Value> {
        let a = self.active.as_mut().ok_or(HOLD)?;
        a.ensure_live()?;
        let own = a.key.public().to_peer_id().to_string();
        let nonce = a
            .pool
            .iter()
            .filter(|tx| tx.signed.signer_peer_id == own)
            .map(|tx| tx.signed.nonce)
            .max()
            .unwrap_or(a.machine.next_nonce(&own)?.saturating_sub(1))
            .checked_add(1)
            .ok_or(INVALID)?;
        let tx =
            ledger::sign_transaction(&a.key, a.machine.genesis().chain_id(), nonce, operation)?;
        let id = ledger::transaction_id(&tx)?;
        let question_id = match &tx.signed.operation {
            Operation::RegisterQuestion { question } => Some(ledger::question_id(
                a.machine.genesis().chain_id(),
                &question.source_record_id,
            )?),
            Operation::SubmitAnswer { answer } => Some(answer.question_id.clone()),
            Operation::CastAcceptanceVote { vote } => Some(vote.signed.question_id.clone()),
            _ => None,
        };
        if let Err(error) = a.admit(tx.clone(), records.clone()) {
            if storage_failure(&error) {
                a.fault = Some("ledger_storage_or_replay_failed")
            }
            return Err(error);
        }
        a.broadcast(WireRequest::Submit {
            transaction: Box::new(tx),
            records,
        });
        Ok(
            json!({"status":"pending","transaction_id":id,"question_id":question_id,"finalized":false,"experiment_only":true}),
        )
    }
    pub fn cast_vote(
        &mut self,
        question: &str,
        answer: &str,
        verdict: Verdict,
        records: Vec<RecordPacket>,
    ) -> Result<Value> {
        self.required_vote_records(question, answer)?;
        let a = self.active.as_ref().ok_or(HOLD)?;
        a.ensure_live()?;
        let own = a.key.public().to_peer_id().to_string();
        let sequence = a
            .pool
            .iter()
            .filter(|tx| tx.signed.signer_peer_id == own)
            .map(|tx| tx.signed.nonce)
            .max()
            .unwrap_or(a.machine.next_nonce(&own)?.saturating_sub(1))
            .checked_add(1)
            .ok_or(INVALID)?;
        let body = a
            .machine
            .acceptance_vote(question, answer, &own, sequence, verdict)?;
        let vote = ledger::sign_acceptance_vote(&a.key, body)?;
        self.submit(
            Operation::CastAcceptanceVote {
                vote: Box::new(vote),
            },
            records,
        )
    }
    pub fn needed_records(&self) -> Vec<String> {
        let Some(a) = self.active.as_ref() else {
            return vec![];
        };
        a.required_proof_ids()
            .into_iter()
            .filter(|id| !a.proofs.contains_key(id))
            .take(MAX_PROOFS)
            .collect()
    }
    pub fn poll(
        &mut self,
        swarm: &mut Swarm<network::Behaviour>,
        knowledge: &knowledge_runtime::Runtime,
    ) {
        let Some(a) = self.active.as_mut() else {
            return;
        };
        let needed = a.required_proof_ids();
        for id in needed.into_iter().take(MAX_PROOFS) {
            if !a.proofs.contains_key(&id)
                && let Some(record) =
                    knowledge.ledger_record(&a.settings.application.signed.room_id, &id)
            {
                let _ = a.remember(vec![record]);
            }
        }
        let started = Instant::now();
        let result = a.drive(swarm);
        a.timings.drive.observe(started);
        if let Err(error) = result
            && storage_failure(&error)
        {
            a.fault = Some("ledger_storage_or_replay_failed");
        }
    }
    pub fn event(
        &mut self,
        event: request_response::Event<Vec<u8>, Vec<u8>>,
        swarm: &mut Swarm<network::Behaviour>,
    ) {
        let Some(a) = self.active.as_mut() else {
            return;
        };
        match event {
            request_response::Event::Message {
                peer,
                message:
                    Message::Request {
                        request, channel, ..
                    },
                ..
            } => {
                let reply = a.receive(peer, &request);
                if let Ok(bytes) = serde_json::to_vec(&reply)
                    && bytes.len() <= network::MAX_LEDGER_WIRE
                {
                    let _ = swarm.behaviour_mut().ledger.send_response(channel, bytes);
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
                if let Some(pending) = a.pending.remove(&request_id) {
                    a.timings.response.observe(pending.started);
                    if peer != pending.peer || a.authorize(&peer).is_err() {
                        return;
                    }
                    if let Ok(reply) = serde_json::from_slice::<WireReply>(&response)
                        && let Err(e) = a.completed(peer, pending.request, reply)
                        && storage_failure(&e)
                    {
                        a.fault = Some("ledger_storage_or_replay_failed")
                    }
                }
            }
            request_response::Event::OutboundFailure { request_id, .. } => {
                if let Some(p) = a.pending.remove(&request_id) {
                    a.backoff
                        .insert(p.peer, Instant::now() + Duration::from_secs(5));
                }
            }
            _ => {}
        }
    }
}

fn verify_snapshot(
    node: &Node,
    certificate: Option<&CommitCertificate>,
    height: u64,
    id: Option<&str>,
    root: &str,
) -> Result<()> {
    if height == 0 {
        return if certificate.is_none() {
            Ok(())
        } else {
            Err(INVALID)
        };
    }
    let cert = certificate.ok_or(INVALID)?;
    node.verify_commit(cert)?;
    if cert.block.height != height
        || id != Some(cert.block.id()?.as_str())
        || root != cert.block.next_application_hash
    {
        return Err(INVALID);
    }
    Ok(())
}

fn settings_room(home: &Path, settings: &Settings, own: &str) -> Result<TrustedRoom> {
    let config = config::load(home)?;
    let room = config.rooms.get(&settings.room_alias).ok_or(HOLD)?;
    crypto::validate_room(room, &Scanner::policy_id(), util::now())?;
    if room.certificate.signed.public
        || room.certificate.signed.room_id != settings.application.signed.room_id
        || room.certificate.signed.members.len() != settings.application.signed.participants.len()
        || room.authority_peer_id != settings.authority_peer_id
        || !room
            .certificate
            .signed
            .members
            .iter()
            .any(|m| m.peer_id == own)
    {
        return Err(HOLD);
    }
    let claims = room
        .certificate
        .signed
        .knowledge_operators
        .as_ref()
        .ok_or(HOLD)?;
    for (peer, participant) in &settings.application.signed.participants {
        let member = room
            .certificate
            .signed
            .members
            .iter()
            .find(|m| &m.peer_id == peer)
            .ok_or(HOLD)?;
        {
            if member.public_key != participant.public_key
                || claims.bindings.get(peer) != Some(&participant.operator)
                || claims.credits.get(&participant.operator) != Some(&participant.credit)
            {
                return Err(HOLD);
            }
        }
    }
    for v in &settings.consensus.signed.validators {
        if !room
            .certificate
            .signed
            .members
            .iter()
            .any(|m| m.peer_id == v.peer_id && m.public_key == v.public_key)
        {
            return Err(HOLD);
        }
    }
    Ok(room.clone())
}

impl Active {
    fn room(&self) -> Result<TrustedRoom> {
        settings_room(
            &self.home,
            &self.settings,
            &self.key.public().to_peer_id().to_string(),
        )
    }
    fn authorize(&self, peer: &PeerId) -> Result<()> {
        let room = self.room()?;
        if !room
            .certificate
            .signed
            .members
            .iter()
            .any(|m| m.peer_id == peer.to_string())
            || !self
                .settings
                .application
                .signed
                .participants
                .contains_key(&peer.to_string())
        {
            return Err(INVALID);
        }
        Ok(())
    }
    fn ensure_live(&self) -> Result<()> {
        if self.fault.is_some()
            || self.needs_snapshot
            || self.download.is_some()
            || !self.node.ready()
        {
            return Err(HOLD);
        }
        self.room()?;
        if !self.node.validate_core(&self.machine)? {
            return Err(HOLD);
        }
        Ok(())
    }
    fn charge(&mut self, peer: &PeerId) -> Result<()> {
        let operator = self
            .settings
            .application
            .signed
            .participants
            .get(&peer.to_string())
            .ok_or(INVALID)?
            .operator
            .clone();
        let now = Instant::now();
        for bucket in [
            self.buckets.entry(operator).or_insert(Bucket {
                tokens: 32.0,
                at: now,
            }),
            self.peer_buckets.entry(peer.to_string()).or_insert(Bucket {
                tokens: 32.0,
                at: now,
            }),
        ] {
            bucket.tokens = (bucket.tokens + bucket.at.elapsed().as_secs_f64() * 4.0).min(32.0);
            bucket.at = now;
            if bucket.tokens < 1.0 {
                return Err(HOLD);
            }
            bucket.tokens -= 1.0;
        }
        Ok(())
    }
    fn references(&self, operation: &Operation) -> Vec<String> {
        match operation {
            Operation::RegisterQuestion { question } => vec![
                question.source_record_id.clone(),
                question.criteria_record_id.clone(),
            ],
            Operation::SubmitAnswer { answer } => vec![answer.source_record_id.clone()],
            Operation::CastAcceptanceVote { vote } => {
                let mut ids = vec![
                    vote.signed.criteria_record_id.clone(),
                    vote.signed.answer_id.clone(),
                ];
                if let Some(q) = self.machine.state().questions.get(&vote.signed.question_id) {
                    ids.push(q.terms.source_record_id.clone())
                }
                ids
            }
            _ => vec![],
        }
    }
    fn required_proof_ids(&self) -> BTreeSet<String> {
        let mut ids = self
            .pool
            .iter()
            .flat_map(|tx| self.references(&tx.signed.operation))
            .collect::<BTreeSet<_>>();
        for block in self.node.preferred_block().into_iter().chain(
            self.node
                .current_proposal()
                .map(|proposal| proposal.signed.block),
        ) {
            for tx in block.transactions {
                ids.extend(self.references(&tx.signed.operation));
            }
        }
        ids
    }
    fn proof_requests(
        &self,
        transactions: &[SignedTransaction],
    ) -> Result<BTreeMap<String, BTreeSet<String>>> {
        let mut requests = BTreeMap::<String, BTreeSet<String>>::new();
        for transaction in transactions {
            let operator = self
                .settings
                .application
                .signed
                .participants
                .get(&transaction.signed.signer_peer_id)
                .ok_or(INVALID)?
                .operator
                .clone();
            requests
                .entry(operator)
                .or_default()
                .extend(self.references(&transaction.signed.operation));
        }
        Ok(requests)
    }
    fn check_proof_budget(
        &self,
        requests: &BTreeMap<String, BTreeSet<String>>,
        proofs: &BTreeMap<String, RecordPacket>,
        max_refs: usize,
        max_bytes: usize,
    ) -> Result<()> {
        for ids in requests.values() {
            if ids.len() > max_refs {
                return Err(HOLD);
            }
            let bytes = ids.iter().try_fold(0usize, |total, id| {
                let bytes = if let Some(record) = proofs.get(id) {
                    serde_json::to_vec(record).map_err(|_| INVALID)?.len()
                } else {
                    knowledge::MAX_PACKET_BYTES
                };
                Ok::<usize, Error>(total.saturating_add(bytes))
            })?;
            if bytes > max_bytes {
                return Err(HOLD);
            }
        }
        Ok(())
    }
    fn check_total_proof_budget(
        &self,
        requests: &BTreeMap<String, BTreeSet<String>>,
        proofs: &BTreeMap<String, RecordPacket>,
        max_refs: usize,
        max_bytes: usize,
    ) -> Result<()> {
        let ids = requests
            .values()
            .flat_map(|ids| ids.iter())
            .collect::<BTreeSet<_>>();
        if ids.len() > max_refs {
            return Err(HOLD);
        }
        let bytes = ids.into_iter().try_fold(2usize, |total, id| {
            let value = proofs
                .get(id)
                .map(|record| {
                    serde_json::to_vec(record)
                        .map(|b| b.len())
                        .map_err(|_| INVALID)
                })
                .unwrap_or(Ok(knowledge::MAX_PACKET_BYTES))?;
            Ok::<usize, Error>(total.saturating_add(value + id.len() + 4))
        })?;
        if bytes > max_bytes {
            return Err(HOLD);
        }
        Ok(())
    }
    fn stage_proofs(
        &self,
        records: Vec<RecordPacket>,
        required: &BTreeSet<String>,
        extra_transactions: &[SignedTransaction],
        proposal: bool,
    ) -> Result<BTreeMap<String, RecordPacket>> {
        if records.len() > MAX_PROOFS {
            return Err(INVALID);
        }
        let room = self.room()?;
        let mut next = self.proofs.clone();
        for record in records {
            if !required.contains(&record.record.signed.id) {
                return Err(INVALID);
            }
            self.validate_record_cached(&record, &room)?;
            if record.record.signed.public {
                return Err(INVALID);
            }
            next.insert(record.record.signed.id.clone(), record);
        }
        let mut blocks = self
            .node
            .preferred_block()
            .into_iter()
            .map(|b| b.transactions)
            .collect::<Vec<_>>();
        if proposal {
            blocks.push(extra_transactions.to_vec());
        } else if let Some(current) = self.node.current_proposal() {
            blocks.push(current.signed.block.transactions);
        }
        let mut phase = BTreeMap::<String, BTreeSet<String>>::new();
        let mut consumed = BTreeMap::<String, u64>::new();
        for transactions in &blocks {
            let requests = self.proof_requests(transactions)?;
            self.check_total_proof_budget(&requests, &next, BLOCK_PROOF_REFS, BLOCK_PROOF_BYTES)?;
            self.check_proof_budget(&requests, &next, OPERATOR_PROOF_REFS, OPERATOR_PROOF_BYTES)?;
            for (op, ids) in requests {
                phase.entry(op).or_default().extend(ids);
            }
            for transaction in transactions {
                let value = consumed
                    .entry(transaction.signed.signer_peer_id.clone())
                    .or_default();
                *value = (*value).max(transaction.signed.nonce);
            }
        }
        // A locked/valid block and its justified successor may coexist. Reserve
        // two block proof sets independently from the pending-wallet allowance.
        self.check_total_proof_budget(&phase, &next, PHASE_PROOF_REFS, PHASE_PROOF_BYTES)?;
        self.check_proof_budget(
            &phase,
            &next,
            2 * OPERATOR_PROOF_REFS,
            2 * OPERATOR_PROOF_BYTES,
        )?;
        let mut pending = self
            .pool
            .iter()
            .filter(|tx| {
                consumed
                    .get(&tx.signed.signer_peer_id)
                    .is_none_or(|nonce| tx.signed.nonce > *nonce)
            })
            .cloned()
            .collect::<Vec<_>>();
        if !proposal {
            pending.extend_from_slice(extra_transactions);
        }
        let pending_requests = self.proof_requests(&pending)?;
        self.check_total_proof_budget(
            &pending_requests,
            &next,
            PENDING_PROOF_REFS,
            PENDING_PROOF_BYTES,
        )?;
        self.check_proof_budget(
            &pending_requests,
            &next,
            OPERATOR_PROOF_REFS,
            OPERATOR_PROOF_BYTES,
        )?;
        let mut pinned = required.clone();
        for ids in phase.values().chain(pending_requests.values()) {
            pinned.extend(ids.iter().cloned());
        }
        while next.len() > MAX_PROOFS
            || serde_json::to_vec(&next).map_err(|_| INVALID)?.len() > MAX_PROOF_BYTES
        {
            let id = next
                .keys()
                .find(|id| !pinned.contains(*id))
                .cloned()
                .ok_or(HOLD)?;
            next.remove(&id);
        }
        Ok(next)
    }
    fn remember(&mut self, records: Vec<RecordPacket>) -> Result<()> {
        let required = records.iter().map(|r| r.record.signed.id.clone()).collect();
        let next = self.stage_proofs(records, &required, &[], false)?;
        self.proofs = next;
        Ok(())
    }
    fn validate_references(&self, tx: &SignedTransaction) -> Result<()> {
        self.validate_references_with(tx, &self.proofs)
    }
    fn validate_references_with(
        &self,
        tx: &SignedTransaction,
        proofs: &BTreeMap<String, RecordPacket>,
    ) -> Result<()> {
        let room = self.room()?;
        if !room
            .certificate
            .signed
            .members
            .iter()
            .any(|m| m.peer_id == tx.signed.signer_peer_id && m.public_key == tx.public_key)
        {
            return Err(INVALID);
        }
        for id in self.references(&tx.signed.operation) {
            let record = proofs.get(&id).ok_or(HOLD)?;
            self.validate_record_cached(record, &room)?;
        }
        match &tx.signed.operation {
            Operation::RegisterQuestion { question } => {
                for id in [&question.source_record_id, &question.criteria_record_id] {
                    if proofs.get(id).ok_or(HOLD)?.record.signed.author_peer_id
                        != tx.signed.signer_peer_id
                    {
                        return Err(INVALID);
                    }
                }
            }
            Operation::SubmitAnswer { answer }
                if proofs
                    .get(&answer.source_record_id)
                    .ok_or(HOLD)?
                    .record
                    .signed
                    .author_peer_id
                    != answer.beneficiary_peer_id =>
            {
                return Err(INVALID);
            }
            _ => {}
        }
        Ok(())
    }
    fn proof_bundle(&self, transactions: &[SignedTransaction]) -> Result<Vec<RecordPacket>> {
        let mut ids = BTreeSet::new();
        for tx in transactions {
            self.validate_references(tx)?;
            ids.extend(self.references(&tx.signed.operation));
        }
        ids.into_iter()
            .map(|id| self.proofs.get(&id).cloned().ok_or(HOLD))
            .collect()
    }
    fn admit(&mut self, tx: SignedTransaction, records: Vec<RecordPacket>) -> Result<()> {
        self.ensure_live()?;
        let id = ledger::transaction_id(&tx)?;
        if self
            .pool
            .iter()
            .any(|old| ledger::transaction_id(old).ok().as_ref() == Some(&id))
        {
            return Ok(());
        }
        if self.pool.len() >= MAX_POOL {
            return Err(HOLD);
        }
        let operator = &self
            .settings
            .application
            .signed
            .participants
            .get(&tx.signed.signer_peer_id)
            .ok_or(INVALID)?
            .operator;
        if self
            .pool
            .iter()
            .filter(|old| old.signed.signer_peer_id == tx.signed.signer_peer_id)
            .count()
            >= PEER_POOL
            || self
                .pool
                .iter()
                .filter(|old| {
                    self.settings
                        .application
                        .signed
                        .participants
                        .get(&old.signed.signer_peer_id)
                        .is_some_and(|p| &p.operator == operator)
                })
                .count()
                >= OPERATOR_POOL
        {
            return Err(HOLD);
        }
        let mut next = self.pool.clone();
        next.push(tx.clone());
        // Authenticate and preview the transaction before retaining any attached
        // packet. Extra, unreferenced packets cannot occupy the proof quota.
        self.machine
            .validate_batch(self.node.height(), &self.machine.state_root()?, &next)?;
        let required = self.references(&tx.signed.operation).into_iter().collect();
        let proofs = self.stage_proofs(records, &required, std::slice::from_ref(&tx), false)?;
        self.validate_references_with(&tx, &proofs)?;
        let old_pool = std::mem::replace(&mut self.pool, next);
        let old_proofs = std::mem::replace(&mut self.proofs, proofs);
        let old_history = self.history.clone();
        let old_pruned = self.pruned_ids.clone();
        let old_flag = self.history_pruned;
        let result = self
            .track(&tx, tracking::Outcome::Pending)
            .and_then(|()| self.save());
        if let Err(error) = result {
            self.pool = old_pool;
            self.proofs = old_proofs;
            self.history = old_history;
            self.pruned_ids = old_pruned;
            self.history_pruned = old_flag;
            return Err(error);
        }
        Ok(())
    }
    fn broadcast(&mut self, request: WireRequest) {
        let peers = self
            .settings
            .consensus
            .signed
            .validators
            .iter()
            .filter(|v| v.peer_id != self.key.public().to_peer_id().to_string())
            .filter_map(|v| v.peer_id.parse().ok())
            .collect::<Vec<_>>();
        for peer in peers {
            self.enqueue(peer, request.clone());
        }
    }
    fn gossip(&mut self, request: WireRequest) -> Result<()> {
        let bytes = serde_json::to_vec(&request).map_err(|_| INVALID)?;
        if bytes.len() > network::MAX_LEDGER_WIRE {
            return Err(HOLD);
        }
        let id = util::hash(&bytes);
        if self.published.len() >= 2048 {
            return Err(HOLD);
        }
        if self.published.insert(id) {
            self.broadcast(request)
        }
        Ok(())
    }
    fn save(&self) -> Result<()> {
        let checkpoint = self.machine.export_checkpoint()?;
        let certificate = self
            .node
            .commits()
            .iter()
            .chain(self.node.checkpoint())
            .find(|c| c.block.height == checkpoint.height)
            .cloned();
        if checkpoint.height > 0 && certificate.is_none() {
            return Err(STORAGE);
        }
        write_disk(
            &self.home,
            &self.storage_key,
            self.machine.genesis().genesis_hash(),
            &Disk {
                version: 1,
                checkpoint,
                certificate,
                pending: self.pool.clone(),
                proofs: self.proofs.clone(),
                history: self.history.clone(),
                pruned_ids: self.pruned_ids.clone(),
                history_pruned: self.history_pruned,
            },
        )
    }
    fn replay(&mut self) -> Result<()> {
        while !self.node.validate_core(&self.machine)? {
            let page = self.node.sync_page(self.machine.state().height, 8);
            if page.is_empty() {
                return Err(STORAGE);
            }
            for cert in page {
                self.node.verify_commit(&cert)?;
                self.track_commit(&cert)?;
                self.machine.apply_committed(
                    cert.block.height,
                    &cert.block.id()?,
                    &cert.block.previous_application_hash,
                    &cert.block.transactions,
                )?;
                if self.machine.state_root()? != cert.block.next_application_hash {
                    return Err(STORAGE);
                }
            }
        }
        self.resolve_consumed(false);
        self.pool.retain(|tx| {
            self.machine
                .state()
                .nonces
                .get(&tx.signed.signer_peer_id)
                .is_some_and(|n| tx.signed.nonce > *n)
        });
        let old = std::mem::take(&mut self.pool);
        for transaction in old {
            let mut trial = self.pool.clone();
            trial.push(transaction);
            if self
                .machine
                .validate_batch(self.node.height(), &self.machine.state_root()?, &trial)
                .is_ok()
            {
                self.pool = trial;
            } else {
                if let Some(tx) = trial.last() {
                    let id = ledger::transaction_id(tx)?;
                    if let Some(tracked) = self.history.get_mut(&id)
                        && matches!(tracked.outcome, tracking::Outcome::Pending)
                    {
                        tracked.outcome = tracking::Outcome::ExpiredOrReplaced {
                            height: self.machine.state().height,
                        };
                    }
                }
            }
        }
        Ok(())
    }
    fn committed(&mut self) -> Result<()> {
        self.replay()?;
        // Admission, recovery and GC share the complete reference set. In
        // particular a pending acceptance vote needs the original question
        // source as well as its criteria and answer. Persist the pruned set
        // together with the pending pool before compacting consensus history.
        let required = self.required_proof_ids();
        self.proofs.retain(|id, _| required.contains(id));
        self.save()?;
        if self.node.commits().len() >= 128 {
            let root = self.machine.state_root()?;
            self.node
                .compact_at_head(self.machine.state().height, &root)?;
        }
        self.needs_snapshot = false;
        self.last_block = Instant::now();
        self.published.clear();
        Ok(())
    }
    fn on_vote(&mut self, vote: Vote) -> Result<()> {
        if let Some(cert) = self.node.observe_vote(vote)? {
            self.committed()?;
            self.gossip(WireRequest::Commit {
                certificate: Box::new(cert),
            })?;
        }
        Ok(())
    }
    fn on_proposal(&mut self, proposal: Proposal, records: Vec<RecordPacket>) -> Result<()> {
        self.ensure_live()?;
        if self.node.current_proposal().is_some_and(|old| {
            old.signature == proposal.signature && old.signed.block == proposal.signed.block
        }) && self
            .node
            .local_votes()
            .iter()
            .any(|v| v.signed.phase == consensus::Phase::Prevote)
        {
            return Ok(());
        }
        if !self.node.is_validator() {
            return Err(HOLD);
        }
        self.node.check_proposal(&proposal, &self.machine)?;
        let required = proposal
            .signed
            .block
            .transactions
            .iter()
            .flat_map(|tx| self.references(&tx.signed.operation))
            .collect();
        let proofs = self.stage_proofs(
            records,
            &required,
            &proposal.signed.block.transactions,
            true,
        )?;
        for tx in &proposal.signed.block.transactions {
            self.validate_references_with(tx, &proofs)?;
        }
        let old_proofs = std::mem::replace(&mut self.proofs, proofs);
        if let Err(error) = self.save() {
            self.proofs = old_proofs;
            return Err(error);
        }
        let vote = match self.node.prevote(&proposal, &self.machine) {
            Ok(vote) => vote,
            Err(error) => {
                if !storage_failure(&error) {
                    self.proofs = old_proofs;
                    self.save()?;
                }
                return Err(error);
            }
        };
        self.on_vote(vote.clone())?;
        self.gossip(WireRequest::Vote { vote })
    }
    fn receive(&mut self, peer: PeerId, bytes: &[u8]) -> WireReply {
        let result = (|| {
            self.authorize(&peer)?;
            self.charge(&peer)?;
            if bytes.len() > network::MAX_LEDGER_WIRE {
                return Err(INVALID);
            }
            let request = serde_json::from_slice::<WireRequest>(bytes).map_err(|_| INVALID)?;
            let started = Instant::now();
            let result = self.incoming(peer, request);
            self.timings.incoming.observe(started);
            result
        })();
        match result {
            Ok(reply) => reply,
            Err(error) => {
                if storage_failure(&error) {
                    self.fault = Some("ledger_storage_or_replay_failed");
                }
                WireReply::Rejected { code: error.code }
            }
        }
    }
    fn incoming(&mut self, peer: PeerId, request: WireRequest) -> Result<WireReply> {
        match request {
            WireRequest::Status => {
                return Ok(WireReply::Head {
                    height: self.machine.state().height,
                    block_id: self.machine.committed_block_id().map(str::to_owned),
                    round: self.node.round(),
                    round_certificate: self.node.round_certificate().cloned(),
                });
            }
            WireRequest::Sync { after_height } => {
                let first = self
                    .node
                    .commits()
                    .first()
                    .map(|c| c.block.height)
                    .unwrap_or(self.node.height());
                let mut certificates = self.node.sync_page(after_height, 2);
                while !certificates.is_empty()
                    && serde_json::to_vec(&certificates)
                        .map_err(|_| INVALID)?
                        .len()
                        > network::MAX_LEDGER_WIRE / 2
                {
                    certificates.pop();
                }
                return Ok(WireReply::Blocks {
                    certificates,
                    snapshot_required: after_height.saturating_add(1) < first,
                });
            }
            WireRequest::Snapshot { offset, block_id } => {
                return self.snapshot(offset, block_id.as_deref());
            }
            WireRequest::Submit {
                transaction,
                records,
            } => {
                self.admit(*transaction, records)?;
            }
            WireRequest::Proposal { proposal, records } => self.on_proposal(*proposal, records)?,
            WireRequest::Vote { vote } => {
                self.ensure_live()?;
                self.on_vote(vote)?
            }
            WireRequest::Timeout { timeout } => {
                self.ensure_live()?;
                if self.node.observe_timeout(timeout)? {
                    self.published.clear();
                    if let Some(certificate) = self.node.round_certificate().cloned() {
                        self.gossip(WireRequest::TimeoutCertificate { certificate })?;
                    }
                }
            }
            WireRequest::TimeoutCertificate { certificate } => {
                self.ensure_live()?;
                if self.node.observe_timeout_certificate(certificate)? {
                    self.published.clear();
                }
            }
            WireRequest::Commit { certificate } => {
                self.ensure_live()?;
                if certificate.block.height == self.node.height() {
                    self.node.import_commit(*certificate, &self.machine)?;
                    self.committed()?;
                } else if certificate.block.height > self.node.height() {
                    self.enqueue(
                        peer,
                        WireRequest::Sync {
                            after_height: self.machine.state().height,
                        },
                    );
                }
            }
        }
        Ok(WireReply::Ack {
            height: self.machine.state().height,
            round: self.node.round(),
        })
    }
    fn enqueue(&mut self, peer: PeerId, request: WireRequest) {
        let Ok(encoded) = serde_json::to_vec(&request) else {
            return;
        };
        if self
            .queue
            .iter()
            .any(|(p, r)| *p == peer && serde_json::to_vec(r).is_ok_and(|b| b == encoded))
            || self.pending.values().any(|p| {
                p.peer == peer && serde_json::to_vec(&p.request).is_ok_and(|b| b == encoded)
            })
        {
            return;
        }
        let bytes = serde_json::to_vec(&request)
            .map(|b| b.len())
            .unwrap_or(usize::MAX);
        let queued = self
            .queue
            .iter()
            .map(|(_, r)| {
                serde_json::to_vec(r)
                    .map(|b| b.len())
                    .unwrap_or(MAX_QUEUE_BYTES)
            })
            .sum::<usize>();
        let pending = self
            .pending
            .values()
            .map(|p| {
                serde_json::to_vec(&p.request)
                    .map(|b| b.len())
                    .unwrap_or(MAX_QUEUE_BYTES)
            })
            .sum::<usize>();
        let submission = matches!(request, WireRequest::Submit { .. });
        let queue_cap = if submission { MAX_QUEUE / 2 } else { MAX_QUEUE };
        let byte_cap = if submission {
            MAX_QUEUE_BYTES / 2
        } else {
            MAX_QUEUE_BYTES
        };
        if self.queue.len() < queue_cap
            && bytes <= network::MAX_LEDGER_WIRE
            && queued.saturating_add(pending).saturating_add(bytes) <= byte_cap
        {
            let control = matches!(
                request,
                WireRequest::Proposal { .. }
                    | WireRequest::Vote { .. }
                    | WireRequest::Timeout { .. }
                    | WireRequest::TimeoutCertificate { .. }
                    | WireRequest::Commit { .. }
            );
            if control {
                let at = self
                    .queue
                    .iter()
                    .position(|(_, r)| {
                        !matches!(
                            r,
                            WireRequest::Proposal { .. }
                                | WireRequest::Vote { .. }
                                | WireRequest::Timeout { .. }
                                | WireRequest::TimeoutCertificate { .. }
                                | WireRequest::Commit { .. }
                        )
                    })
                    .unwrap_or(self.queue.len());
                self.queue.insert(at, (peer, request));
            } else {
                self.queue.push_back((peer, request));
            }
        }
    }
    fn try_propose(&mut self) -> Result<()> {
        if self.last_proposal_send.as_ref().is_some_and(|(h, r, at)| {
            *h == self.node.height()
                && *r == self.node.round()
                && at.elapsed() < Duration::from_secs(3)
        }) {
            return Ok(());
        }
        if self.node.proposer(self.node.round()) == self.key.public().to_peer_id().to_string()
            && self.last_block.elapsed() > Duration::from_millis(300)
        {
            let preferred = self
                .node
                .current_proposal()
                .map(|proposal| proposal.signed.block)
                .or_else(|| self.node.preferred_block());
            let mut transactions = preferred
                .as_ref()
                .map(|b| b.transactions.clone())
                .unwrap_or_else(|| self.pool.clone());
            loop {
                let records = self.proof_bundle(&transactions);
                let preview = self.machine.validate_batch(
                    self.node.height(),
                    &self.machine.state_root()?,
                    &transactions,
                );
                if let (Ok(records), Ok(preview)) = (records, preview) {
                    let body_bytes = serde_json::to_vec(&(&transactions, &records))
                        .map_err(|_| INVALID)?
                        .len();
                    // Reserve the bounded proposer/signature/PoLC envelope before
                    // asking the persistent signer to freeze this proposal.
                    let requests = self.proof_requests(&transactions)?;
                    if body_bytes + 128 * 1024 > network::MAX_LEDGER_WIRE
                        || self
                            .check_total_proof_budget(
                                &requests,
                                &self.proofs,
                                BLOCK_PROOF_REFS,
                                BLOCK_PROOF_BYTES,
                            )
                            .is_err()
                    {
                        if preferred.is_some() {
                            return Err(HOLD);
                        }
                        if transactions.pop().is_none() {
                            break;
                        }
                        continue;
                    }
                    if self.node.current_proposal().is_none() {
                        self.save()?;
                    }
                    let proposal = self.node.propose(
                        transactions.clone(),
                        preview.state_root,
                        &self.machine,
                    )?;
                    let records = self.proof_bundle(&proposal.signed.block.transactions)?;
                    let request = WireRequest::Proposal {
                        proposal: Box::new(proposal.clone()),
                        records: records.clone(),
                    };
                    if serde_json::to_vec(&request).map_err(|_| INVALID)?.len()
                        <= network::MAX_LEDGER_WIRE
                    {
                        self.gossip(request)?;
                        if !self
                            .node
                            .local_votes()
                            .iter()
                            .any(|v| v.signed.phase == consensus::Phase::Prevote)
                        {
                            self.on_proposal(proposal, records)?;
                        }
                        self.last_proposal_send =
                            Some((self.node.height(), self.node.round(), Instant::now()));
                        break;
                    }
                }
                if preferred.is_some() {
                    return Err(HOLD);
                }
                if transactions.pop().is_none() {
                    break;
                }
            }
        }
        Ok(())
    }
    fn try_precommit(&mut self) -> Result<()> {
        if !self.node.precommit_ready() {
            return Ok(());
        }
        let proof_ready = self
            .node
            .preferred_block()
            .is_none_or(|block| self.proof_bundle(&block.transactions).is_ok());
        let already_precommitted = self
            .node
            .local_votes()
            .iter()
            .any(|v| v.signed.phase == consensus::Phase::Precommit);
        match if proof_ready && !already_precommitted {
            self.node.precommit()
        } else {
            Err(HOLD)
        } {
            Ok(vote) => {
                self.on_vote(vote.clone())?;
                self.gossip(WireRequest::Vote { vote })?;
            }
            Err(e) if storage_failure(&e) => return Err(e),
            Err(_) => {}
        }

        Ok(())
    }
    fn try_timeout(&mut self) -> Result<()> {
        match self.node.timeout() {
            Ok(timeout) => {
                if self.node.observe_timeout(timeout.clone())? {
                    self.published.clear();
                    if let Some(certificate) = self.node.round_certificate().cloned() {
                        self.gossip(WireRequest::TimeoutCertificate { certificate })?;
                    }
                }
                self.gossip(WireRequest::Timeout { timeout })?;
            }
            Err(e) if storage_failure(&e) => return Err(e),
            Err(_) => {}
        }

        Ok(())
    }
    fn drive(&mut self, swarm: &mut Swarm<network::Behaviour>) -> Result<()> {
        self.room()?;
        if self
            .download
            .as_ref()
            .is_some_and(|d| d.started.elapsed() > Duration::from_secs(300))
        {
            self.download = None;
        }
        if self.fault.is_some() {
            return Err(HOLD);
        }
        match self.replay() {
            Ok(()) => self.needs_snapshot = false,
            Err(error) if error.code == HOLD.code => self.needs_snapshot = true,
            Err(error) => return Err(error),
        }
        let height = self.node.height();
        let round = self.node.round();
        let nonces = &self.machine.state().nonces;
        self.queue.retain(|(_, request)| match request {
            WireRequest::Proposal { proposal, .. } => {
                proposal.signed.block.height == height && proposal.signed.round == round
            }
            WireRequest::Vote { vote } => {
                vote.signed.height == height
                    && vote.signed.round >= round.saturating_sub(1)
                    && vote.signed.round <= round
            }
            WireRequest::Timeout { timeout } => {
                timeout.signed.height == height && timeout.signed.round == round
            }
            WireRequest::TimeoutCertificate { certificate } => {
                certificate.height == height && certificate.round >= round.saturating_sub(1)
            }
            WireRequest::Commit { certificate } => {
                certificate.block.height.saturating_add(1) >= height
            }
            WireRequest::Submit { transaction, .. } => nonces
                .get(&transaction.signed.signer_peer_id)
                .is_some_and(|n| transaction.signed.nonce > *n),
            _ => true,
        });
        self.pending
            .retain(|_, p| p.started.elapsed() < Duration::from_secs(15));
        self.backoff.retain(|_, until| *until > Instant::now());
        if self.last_rebroadcast.elapsed() > Duration::from_secs(3) {
            self.published.clear();
            self.last_rebroadcast = Instant::now();
            // A durable certificate remains useful after its individual votes
            // become stale and after restart. Reuse its existing signatures so
            // delayed peers can join the current round without a Status cycle.
            if let Some(certificate) = self.node.round_certificate().cloned() {
                self.gossip(WireRequest::TimeoutCertificate { certificate })?;
            }
            // Accepted signed transactions survive wallet/validator restarts and
            // continue toward a future proposer; the durable pool is bounded.
            let transactions = if self.pool.is_empty() {
                vec![]
            } else {
                self.pool
                    .iter()
                    .cycle()
                    .skip(self.pool_cursor % self.pool.len())
                    .take(self.pool.len().min(2))
                    .cloned()
                    .collect::<Vec<_>>()
            };
            self.pool_cursor = self.pool_cursor.wrapping_add(2);
            for transaction in transactions {
                if let Ok(records) = self.proof_bundle(std::slice::from_ref(&transaction)) {
                    self.gossip(WireRequest::Submit {
                        transaction: Box::new(transaction),
                        records,
                    })?;
                }
            }
        }
        if self.last_status.elapsed() > Duration::from_secs(2) {
            let peers = self
                .settings
                .consensus
                .signed
                .validators
                .iter()
                .filter(|v| v.peer_id != self.key.public().to_peer_id().to_string())
                .collect::<Vec<_>>();
            if !peers.is_empty() {
                let peer = peers[self.status_cursor % peers.len()]
                    .peer_id
                    .parse()
                    .map_err(|_| INVALID)?;
                self.status_cursor = self.status_cursor.wrapping_add(1);
                self.enqueue(peer, WireRequest::Status);
            }
            self.last_status = Instant::now();
        }
        if let Some(download) = &self.download
            && !self.pending.values().any(|p| {
                p.peer == download.peer && matches!(p.request, WireRequest::Snapshot { .. })
            })
            && !self
                .queue
                .iter()
                .any(|(p, r)| *p == download.peer && matches!(r, WireRequest::Snapshot { .. }))
        {
            let peer = download.peer;
            let offset = download.bytes.len();
            let block_id = Some(download.certificate.block.id()?);
            self.enqueue(peer, WireRequest::Snapshot { offset, block_id });
        }
        if self.node.ready()
            && self.node.is_validator()
            && !self.needs_snapshot
            && self.download.is_none()
        {
            self.ensure_live()?;
            for (index, action) in [
                Self::try_propose as fn(&mut Self) -> Result<()>,
                Self::try_precommit,
                Self::try_timeout,
            ]
            .into_iter()
            .enumerate()
            {
                let started = Instant::now();
                let result = action(self);
                self.timings.actions[index].observe(started);
                if let Err(error) = result
                    && storage_failure(&error)
                {
                    return Err(error);
                }
            }
            for vote in self.node.local_votes() {
                let _ = self.gossip(WireRequest::Vote { vote });
            }
        }
        let attempts = self.queue.len();
        for _ in 0..attempts {
            if self.pending.len() >= 4 {
                break;
            }
            let Some((peer, request)) = self.queue.pop_front() else {
                break;
            };
            if self.authorize(&peer).is_err() {
                continue;
            }
            if self.pending.values().any(|pending| pending.peer == peer)
                || self.backoff.contains_key(&peer)
                || self
                    .send_due
                    .get(&peer)
                    .is_some_and(|due| *due > Instant::now())
            {
                self.queue.push_back((peer, request));
                continue;
            }
            let bytes = serde_json::to_vec(&request).map_err(|_| INVALID)?;
            if bytes.len() > network::MAX_LEDGER_WIRE {
                continue;
            }
            let id = swarm.behaviour_mut().ledger.send_request(&peer, bytes);
            self.send_due
                .insert(peer, Instant::now() + Duration::from_millis(250));
            self.pending.insert(
                id,
                Pending {
                    peer,
                    request,
                    started: Instant::now(),
                },
            );
        }
        Ok(())
    }
    fn completed(&mut self, peer: PeerId, request: WireRequest, reply: WireReply) -> Result<()> {
        let matches = matches!(
            (&request, &reply),
            (WireRequest::Status, WireReply::Head { .. })
                | (WireRequest::Sync { .. }, WireReply::Blocks { .. })
                | (WireRequest::Snapshot { .. }, WireReply::Snapshot { .. })
                | (_, WireReply::Rejected { .. })
        );
        if !matches && !matches!(reply, WireReply::Ack { .. }) {
            return Err(INVALID);
        }
        if let (
            WireRequest::Snapshot { offset, block_id },
            WireReply::Snapshot {
                offset: received,
                certificate,
                ..
            },
        ) = (&request, &reply)
            && (offset != received
                || block_id
                    .as_ref()
                    .is_some_and(|id| certificate.block.id().ok().as_ref() != Some(id)))
        {
            return Err(INVALID);
        }
        match reply {
            WireReply::Head {
                height,
                round_certificate,
                ..
            } => {
                if height > self.machine.state().height {
                    self.enqueue(
                        peer,
                        WireRequest::Sync {
                            after_height: self.machine.state().height,
                        },
                    );
                } else if height == self.machine.state().height
                    && let Some(cert) = round_certificate
                    && cert.height == self.node.height()
                    && cert.round >= self.node.round()
                {
                    self.node.observe_timeout_certificate(cert)?;
                    self.published.clear();
                }
            }
            WireReply::Blocks {
                certificates,
                snapshot_required,
            } => {
                if certificates.len() > 2 {
                    return Err(INVALID);
                }
                if snapshot_required {
                    self.enqueue(
                        peer,
                        WireRequest::Snapshot {
                            offset: 0,
                            block_id: None,
                        },
                    );
                    return Ok(());
                }
                let mut progressed = false;
                for cert in certificates {
                    if cert.block.height == self.node.height() {
                        self.node.import_commit(cert, &self.machine)?;
                        self.committed()?;
                        progressed = true;
                    }
                }
                if !progressed {
                    return Ok(());
                }
                self.enqueue(
                    peer,
                    WireRequest::Sync {
                        after_height: self.machine.state().height,
                    },
                );
            }
            WireReply::Snapshot {
                certificate,
                digest,
                total,
                offset,
                bytes,
            } => self.snapshot_received(peer, *certificate, digest, total, offset, bytes)?,
            // Stale votes, already-signed phases, and capacity Hold are protocol
            // responses, not transport failures. Backing off the whole peer here
            // can synchronize a quorum into a permanent round-change storm.
            WireReply::Rejected { .. } => {}
            WireReply::Ack { .. } => {
                let _ = request;
            }
        }
        Ok(())
    }
    fn snapshot(&mut self, offset: usize, block_id: Option<&str>) -> Result<WireReply> {
        if !offset.is_multiple_of(SNAPSHOT_CHUNK) {
            return Err(INVALID);
        }
        if self
            .snapshot_cache
            .as_ref()
            .is_none_or(|(at, _, _)| at.elapsed() > Duration::from_secs(300))
        {
            let checkpoint = self.machine.export_checkpoint()?;
            let cert = self.node.commits().last().cloned().ok_or(HOLD)?;
            let bytes = serde_json::to_vec(&checkpoint).map_err(|_| STORAGE)?;
            if bytes.len() > ledger::MAX_CHECKPOINT_BYTES {
                return Err(STORAGE);
            }
            self.snapshot_cache = Some((Instant::now(), bytes, cert));
        }
        let (_, bytes, cert) = self.snapshot_cache.as_ref().ok_or(HOLD)?;
        if offset > bytes.len()
            || block_id.is_some_and(|id| cert.block.id().ok().as_deref() != Some(id))
        {
            return Err(HOLD);
        }
        Ok(WireReply::Snapshot {
            certificate: Box::new(cert.clone()),
            digest: util::hash(bytes),
            total: bytes.len(),
            offset,
            bytes: bytes[offset..bytes.len().min(offset + SNAPSHOT_CHUNK)].to_vec(),
        })
    }
    fn snapshot_received(
        &mut self,
        peer: PeerId,
        cert: CommitCertificate,
        digest: String,
        total: usize,
        offset: usize,
        bytes: Vec<u8>,
    ) -> Result<()> {
        self.node.verify_commit(&cert)?;
        if !util::valid_id(&digest)
            || total == 0
            || total > ledger::MAX_CHECKPOINT_BYTES
            || offset >= total
            || !offset.is_multiple_of(SNAPSHOT_CHUNK)
            || bytes.len() != SNAPSHOT_CHUNK.min(total - offset)
        {
            return Err(INVALID);
        }
        if offset == 0 {
            if cert.block.height >= self.node.height() {
                self.node.checkpoint_admissible(&cert)?;
            } else {
                self.node.reconcile_application(
                    cert.block.height,
                    Some(&cert.block.id()?),
                    &cert.block.next_application_hash,
                )?;
            }
            if self.download.as_ref().is_some_and(|d| d.peer != peer) {
                return Err(HOLD);
            }
            self.download = Some(SnapshotDownload {
                peer,
                certificate: cert.clone(),
                digest: digest.clone(),
                total,
                bytes: vec![],
                started: Instant::now(),
            });
        }
        let download = self.download.as_mut().ok_or(INVALID)?;
        if download.peer != peer
            || download.total != total
            || download.digest != digest
            || download.certificate.block.id()? != cert.block.id()?
            || download.bytes.len() != offset
            || offset + bytes.len() > total
        {
            return Err(INVALID);
        }
        download.bytes.extend(bytes);
        if download.bytes.len() < total {
            let offset = download.bytes.len();
            let block_id = Some(cert.block.id()?);
            self.enqueue(peer, WireRequest::Snapshot { offset, block_id });
            return Ok(());
        }
        let download = self.download.take().ok_or(INVALID)?;
        if util::hash(&download.bytes) != digest {
            return Err(INVALID);
        }
        let checkpoint: ledger::Checkpoint =
            serde_json::from_slice(&download.bytes).map_err(|_| INVALID)?;
        let genesis = ledger::verify_genesis(
            self.settings.application.clone(),
            &self.settings.authority_peer_id,
        )?;
        let machine = Machine::restore_checkpoint(genesis, checkpoint, |h, id, root| {
            verify_snapshot(&self.node, Some(&cert), h, id, root)
        })?;
        if cert.block.height >= self.node.height() {
            self.node.checkpoint_admissible(&cert)?;
        } else {
            self.node.reconcile_application(
                machine.state().height,
                machine.committed_block_id(),
                &machine.state_root()?,
            )?;
        }
        self.track_snapshot(&machine, &cert)?;
        // Snapshot durable first, then minimum anchor and consensus history import.
        write_disk(
            &self.home,
            &self.storage_key,
            machine.genesis().genesis_hash(),
            &Disk {
                version: 1,
                checkpoint: machine.export_checkpoint()?,
                certificate: Some(cert.clone()),
                pending: self.pool.clone(),
                proofs: self.proofs.clone(),
                history: self.history.clone(),
                pruned_ids: self.pruned_ids.clone(),
                history_pruned: self.history_pruned,
            },
        )?;
        if cert.block.height >= self.node.height() {
            self.node.checkpoint_admissible(&cert)?;
        } else {
            self.node.reconcile_application(
                machine.state().height,
                machine.committed_block_id(),
                &machine.state_root()?,
            )?;
        }
        if cert.block.height >= self.node.height() {
            self.node
                .import_checkpoint(cert, machine.state().height, &machine.state_root()?)?;
        }
        self.machine = machine;
        let certificates = self.node.commits().to_vec();
        for certificate in certificates {
            self.track_commit(&certificate)?;
        }
        self.resolve_consumed(true);
        self.committed()?;
        self.enqueue(
            peer,
            WireRequest::Sync {
                after_height: self.machine.state().height,
            },
        );
        Ok(())
    }
}

fn read_disk(home: &Path, key: &[u8], genesis: &str) -> Result<Option<Disk>> {
    let path = home.join("ledger-application.enc");
    if !path.exists() {
        return Ok(None);
    }
    util::protected(&path)?;
    let bytes = util::read_bounded(&path, MAX_DISK as u64)?;
    if !bytes.starts_with(MAGIC) || bytes.len() < MAGIC.len() + 40 {
        return Err(STORAGE);
    }
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| STORAGE)?;
    let plain = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&bytes[MAGIC.len()..MAGIC.len() + 24]),
                Payload {
                    msg: &bytes[MAGIC.len() + 24..],
                    aad: genesis.as_bytes(),
                },
            )
            .map_err(|_| STORAGE)?,
    );
    Ok(Some(serde_json::from_slice(&plain).map_err(|_| STORAGE)?))
}
fn write_disk(home: &Path, key: &[u8], genesis: &str, disk: &Disk) -> Result<()> {
    let plain = Zeroizing::new(serde_json::to_vec(disk).map_err(|_| STORAGE)?);
    if plain.len() > MAX_DISK - MAGIC.len() - 40 {
        return Err(STORAGE);
    }
    let mut nonce = [0; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| STORAGE)?;
    let encrypted = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plain,
                aad: genesis.as_bytes(),
            },
        )
        .map_err(|_| STORAGE)?;
    let mut bytes = MAGIC.to_vec();
    bytes.extend(nonce);
    bytes.extend(encrypted);
    util::atomic_write(&home.join("ledger-application.enc"), &bytes)
}

#[path = "ledger_runtime_timing.rs"]
mod timing;

#[path = "ledger_runtime_tracking.rs"]
mod tracking;

#[cfg(test)]
#[path = "ledger_runtime_tests.rs"]
mod tests;
