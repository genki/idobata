//! Closed-experiment, fixed-validator consensus; activation is explicit.
//!
//! Two voting phases and persistent locks follow the Tendermint lock/valid-value
//! rules; round changes additionally require a quorum of signed timeouts. This
//! conservative pacemaker holds on a minority partition. Liveness requires an
//! eventually synchronous quorum, an honest round proposer, and message replay.
//! Operator independence is an explicit genesis authority attestation, not inferred
//! from hosts, keys, addresses, or agent competence. No dynamic validator changes,
//! validator reconfiguration, production minting, or rollback-proof hardware signer.
//! Certified application checkpoints compact history while preserving signing locks.
use crate::{
    crypto,
    error::{Error, INVALID, Result, STORAGE},
    types::Signed,
    util,
};
use chacha20poly1305::{
    KeyInit, XChaCha20Poly1305, XNonce,
    aead::{Aead, Payload},
};
use fs2::FileExt;
use libp2p::identity;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeSet,
    fs::{File, OpenOptions},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const GENESIS_DOMAIN: &str = "idobata.ledger.genesis.v1";
const PROPOSAL_DOMAIN: &str = "idobata.ledger.proposal.v1";
const VOTE_DOMAIN: &str = "idobata.ledger.vote.v1";
const TIMEOUT_DOMAIN: &str = "idobata.ledger.timeout.v1";
const MAGIC: &[u8] = b"idobata.ledger.consensus.v1\0";
pub const MAX_PAYLOAD_BYTES: usize = 256 * 1024;
pub const MAX_VALIDATORS: usize = 31;
pub const MAX_BLOCKS: usize = 4096;
pub const SYNC_TAIL_BLOCKS: usize = 64;
pub const MAX_ROUNDS: u64 = 9_007_199_254_740_991;
pub const MAX_HEIGHT: u64 = 9_007_199_254_740_991;
const MAX_STORE_BYTES: usize = 64 * 1024 * 1024;
const HOLD: Error = Error::new(10, "ledger_consensus_hold");

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Validator {
    pub peer_id: String,
    pub public_key: String,
    /// Identifier authenticated by the pinned genesis authority.
    pub operator: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Genesis {
    pub version: u32,
    pub chain_id: String,
    pub application_genesis_hash: String,
    pub initial_application_hash: String,
    pub validators: Vec<Validator>,
    pub fault_bound: usize,
    pub quorum: usize,
    pub timeout_ms: u64,
    pub experiment_only: bool,
}

pub fn sign_genesis(authority: &identity::Keypair, genesis: Genesis) -> Result<Signed<Genesis>> {
    validate_genesis(&genesis)?;
    Ok(Signed {
        signature: crypto::sign(authority, GENESIS_DOMAIN, &genesis)?,
        public_key: crypto::public(authority),
        signed: genesis,
    })
}

pub fn validate_genesis(g: &Genesis) -> Result<()> {
    if g.version != 1
        || !g.experiment_only
        || !util::valid_id(&g.chain_id)
        || !util::valid_id(&g.application_genesis_hash)
        || !util::valid_id(&g.initial_application_hash)
        || g.fault_bound == 0
        || g.fault_bound > 10
        || g.validators.len() > MAX_VALIDATORS
        || g.validators.len() != 3 * g.fault_bound + 1
        || g.quorum != 2 * g.fault_bound + 1
        || !(100..=60_000).contains(&g.timeout_ms)
    {
        return Err(INVALID);
    }
    let mut peers = BTreeSet::new();
    for v in &g.validators {
        let k = crypto::public_key(&v.public_key)?;
        if k.key_type() != identity::KeyType::Ed25519
            || k.to_peer_id().to_string() != v.peer_id
            || !peers.insert(&v.peer_id)
            || v.operator.is_empty()
            || v.operator.len() > 64
            || !v
                .operator
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
        {
            return Err(INVALID);
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Block {
    pub height: u64,
    pub parent: String,
    pub previous_application_hash: String,
    pub next_application_hash: String,
    /// Typed reward transactions are decoded and checked by the application.
    /// Consensus does not admit arbitrary free text as a valid reward transaction.
    pub transactions: Vec<crate::ledger::SignedTransaction>,
}
impl Block {
    pub fn id(&self) -> Result<String> {
        Ok(util::hash(&util::canonical(self)?))
    }
}

/// Must validate the typed transaction schema, signatures, deterministic transition,
/// and resulting application root. Validation has no externally visible effects.
pub trait Application {
    fn validate(&self, block: &Block) -> Result<()>;
}

impl Application for crate::ledger::Machine {
    fn validate(&self, block: &Block) -> Result<()> {
        let transition = self.validate_batch(
            block.height,
            &block.previous_application_hash,
            &block.transactions,
        )?;
        if transition.state_root != block.next_application_hash {
            return Err(INVALID);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Prevote,
    Precommit,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct VoteBody {
    pub genesis_hash: String,
    pub height: u64,
    pub round: u64,
    pub phase: Phase,
    pub validator: String,
    pub block_id: Option<String>,
}
pub type Vote = Signed<VoteBody>;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProposalBody {
    pub genesis_hash: String,
    pub round: u64,
    pub proposer: String,
    pub block: Block,
    pub valid_round: Option<u64>,
    pub valid_votes: Vec<Vote>,
}
pub type Proposal = Signed<ProposalBody>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TimeoutBody {
    pub genesis_hash: String,
    pub height: u64,
    pub round: u64,
    pub validator: String,
}
pub type TimeoutVote = Signed<TimeoutBody>;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeoutCertificate {
    pub genesis_hash: String,
    pub height: u64,
    pub round: u64,
    pub timeouts: Vec<TimeoutVote>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitCertificate {
    pub genesis_hash: String,
    pub round: u64,
    pub block: Block,
    pub precommits: Vec<Vote>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DoubleVoteEvidence {
    pub first: Vote,
    pub second: Vote,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Lock {
    round: u64,
    block: Block,
    prevotes: Vec<Vote>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u32,
    genesis_hash: String,
    height: u64,
    round: u64,
    checkpoint: Option<CommitCertificate>,
    commits: Vec<CommitCertificate>,
    proposals: Vec<Proposal>,
    votes: Vec<Vote>,
    timeouts: Vec<TimeoutVote>,
    round_certificate: Option<TimeoutCertificate>,
    lock: Option<Lock>,
    valid: Option<Lock>,
    evidence: Vec<DoubleVoteEvidence>,
}

/// A single encrypted, fsynced snapshot is the write-ahead signing journal and
/// finality log. The exclusive process lock prevents two live local signers.
/// Restoring old storage/key backups or cloning the key bypasses this guarantee.
pub struct Node {
    genesis: Signed<Genesis>,
    genesis_hash: String,
    own: String,
    key: identity::Keypair,
    storage_key: Zeroizing<Vec<u8>>,
    path: PathBuf,
    _file_lock: File,
    state: State,
    round_started: Instant,
    storage_blocked: bool,
}

impl Node {
    pub fn open(
        home: &Path,
        key: identity::Keypair,
        genesis: Signed<Genesis>,
        authority_peer: &str,
    ) -> Result<Self> {
        Self::open_internal(home, key, genesis, authority_peer, None)
    }
    /// Retry a checkpoint import interrupted after the minimum anchor fsync.
    /// The application snapshot must already be verified and durable.
    pub fn open_from_checkpoint(
        home: &Path,
        key: identity::Keypair,
        genesis: Signed<Genesis>,
        authority_peer: &str,
        certificate: CommitCertificate,
        core_height: u64,
        core_root: &str,
    ) -> Result<Self> {
        Self::open_internal(
            home,
            key,
            genesis,
            authority_peer,
            Some((certificate, core_height, core_root.to_owned())),
        )
    }
    fn open_internal(
        home: &Path,
        key: identity::Keypair,
        genesis: Signed<Genesis>,
        authority_peer: &str,
        recovery: Option<(CommitCertificate, u64, String)>,
    ) -> Result<Self> {
        validate_genesis(&genesis.signed)?;
        let authority = crypto::public_key(&genesis.public_key)?;
        if authority.key_type() != identity::KeyType::Ed25519
            || authority.to_peer_id().to_string() != authority_peer
        {
            return Err(INVALID);
        }
        crypto::verify(
            &authority,
            GENESIS_DOMAIN,
            &genesis.signed,
            &genesis.signature,
        )?;
        let genesis_hash = util::hash(&util::canonical(&genesis)?);
        util::protected(home)?;
        let key_path = home.join("storage.key");
        util::protected(&key_path)?;
        let storage_key = util::read_bounded(&key_path, 32)?;
        if storage_key.len() != 32 {
            return Err(STORAGE);
        }
        let lock_path = home.join("ledger-consensus.lock");
        if lock_path.exists() {
            util::protected(&lock_path)?;
        }
        let mut opts = OpenOptions::new();
        opts.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let file_lock = opts.open(lock_path).map_err(|_| STORAGE)?;
        file_lock
            .try_lock_exclusive()
            .map_err(|_| Error::new(30, "ledger_signer_already_running"))?;
        let path = home.join("ledger-consensus.enc");
        let initialized = home.join("ledger-consensus.initialized");
        // A missing signing journal is not a fresh signer when any initialized
        // ledger artifact remains. A head-H Core QC cannot recover lost H+1 votes.
        if !path.exists()
            && (initialized.exists()
                || home.join("ledger-application.enc").exists()
                || home.join("ledger-minimum.enc").exists())
        {
            return Err(STORAGE);
        }
        if initialized.exists() {
            util::protected(&initialized)?;
            let marker: (String, String) =
                serde_json::from_slice(&util::read_bounded(&initialized, 512)?)
                    .map_err(|_| STORAGE)?;
            if marker != (genesis_hash.clone(), crypto::public(&key)) {
                return Err(STORAGE);
            }
        }
        let state = if path.exists() {
            util::protected(&path)?;
            let bytes = util::read_bounded(&path, MAX_STORE_BYTES as u64)?;
            if bytes.len() < MAGIC.len() + 40 || !bytes.starts_with(MAGIC) {
                return Err(STORAGE);
            }
            let cipher = XChaCha20Poly1305::new_from_slice(&storage_key).map_err(|_| STORAGE)?;
            let plain = Zeroizing::new(
                cipher
                    .decrypt(
                        XNonce::from_slice(&bytes[MAGIC.len()..MAGIC.len() + 24]),
                        Payload {
                            msg: &bytes[MAGIC.len() + 24..],
                            aad: genesis_hash.as_bytes(),
                        },
                    )
                    .map_err(|_| STORAGE)?,
            );
            serde_json::from_slice::<State>(&plain).map_err(|_| STORAGE)?
        } else {
            State {
                version: 1,
                genesis_hash: genesis_hash.clone(),
                height: 1,
                round: 0,
                checkpoint: None,
                commits: vec![],
                proposals: vec![],
                votes: vec![],
                timeouts: vec![],
                round_certificate: None,
                lock: None,
                valid: None,
                evidence: vec![],
            }
        };
        let own = key.public().to_peer_id().to_string();
        if key.public().key_type() != identity::KeyType::Ed25519 {
            return Err(INVALID);
        }
        let node = Self {
            genesis,
            genesis_hash,
            own,
            key,
            storage_key,
            path,
            _file_lock: file_lock,
            state,
            round_started: Instant::now(),
            storage_blocked: false,
        };
        let mut node = node;
        node.validate_state()?;
        if let Some((certificate, height, root)) = recovery {
            node.import_checkpoint(certificate, height, &root)?;
        } else {
            node.verify_minimum()?;
        }
        // Persist the exact pinned genesis before any signing is possible.
        node.persist(&node.state)?;
        if !initialized.exists() {
            util::atomic_write(
                &initialized,
                &util::canonical(&(node.genesis_hash.clone(), crypto::public(&node.key)))?,
            )?;
        }
        Ok(node)
    }
    pub fn genesis_hash(&self) -> &str {
        &self.genesis_hash
    }
    pub fn genesis(&self) -> &Signed<Genesis> {
        &self.genesis
    }
    /// Bind consensus authority, operator authentication and chain to the strict
    /// reward application; return whether its durable prefix is at the log head.
    pub fn validate_core(&self, machine: &crate::ledger::Machine) -> Result<bool> {
        let app = machine.genesis();
        let g = &self.genesis.signed;
        if g.chain_id != app.chain_id()
            || g.application_genesis_hash != app.genesis_hash()
            || self.genesis.public_key != app.document().public_key
        {
            return Err(INVALID);
        }
        for validator in &g.validators {
            let participant = app
                .document()
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
        self.reconcile_application(
            machine.state().height,
            machine.committed_block_id(),
            &machine.state_root()?,
        )
    }
    pub fn height(&self) -> u64 {
        self.state.height
    }
    pub fn round(&self) -> u64 {
        self.state.round
    }
    pub fn commits(&self) -> &[CommitCertificate] {
        &self.state.commits
    }
    /// Check the complete application checkpoint before replay/signing. False
    /// means a verified prefix needs replay from this log. Missing pruned state,
    /// an ahead application, or an unequal root/block fails closed.
    pub fn reconcile_application(
        &self,
        core_height: u64,
        core_block_id: Option<&str>,
        core_root: &str,
    ) -> Result<bool> {
        if core_height >= self.height() {
            return Err(INVALID);
        }
        if core_height == 0 {
            if core_block_id.is_some() || core_root != self.genesis.signed.initial_application_hash
            {
                return Err(INVALID);
            }
        } else {
            let cert = self
                .state
                .commits
                .iter()
                .chain(self.state.checkpoint.iter())
                .find(|c| c.block.height == core_height)
                .ok_or(HOLD)?;
            if core_block_id != Some(cert.block.id()?.as_str())
                || core_root != cert.block.next_application_hash
            {
                return Err(INVALID);
            }
        }
        if core_height + 1 < self.height()
            && self
                .state
                .commits
                .first()
                .is_none_or(|c| c.block.height > core_height + 1)
        {
            return Err(HOLD);
        }
        Ok(core_height + 1 == self.height())
    }
    pub fn evidence(&self) -> &[DoubleVoteEvidence] {
        &self.state.evidence
    }
    pub fn independent_operators(&self) -> usize {
        self.genesis
            .signed
            .validators
            .iter()
            .map(|v| &v.operator)
            .collect::<BTreeSet<_>>()
            .len()
    }
    pub fn is_validator(&self) -> bool {
        self.genesis
            .signed
            .validators
            .iter()
            .any(|v| v.peer_id == self.own && v.public_key == crypto::public(&self.key))
    }
    fn ensure_signer(&self) -> Result<()> {
        self.ensure_ready()?;
        if !self.is_validator() {
            return Err(HOLD);
        }
        Ok(())
    }
    pub fn ready(&self) -> bool {
        self.independent_operators() == self.genesis.signed.validators.len()
    }
    pub fn proposer(&self, round: u64) -> &str {
        let n = self.genesis.signed.validators.len() as u64;
        let index = ((self.height().saturating_sub(1) % n) + (round % n)) % n;
        &self.genesis.signed.validators[index as usize].peer_id
    }
    pub fn status(&self) -> Value {
        serde_json::json!({"experiment_only":true,"height":self.height(),"round":self.round(),"status":if self.ready(){"awaiting_quorum"}else{"hold_independent_operators"},"independent_operators":self.independent_operators(),"quorum":self.genesis.signed.quorum,"committed_blocks":self.state.commits.len(),"double_vote_evidence":self.state.evidence.len(),"locked":self.state.lock.is_some(),"lock_round":self.state.lock.as_ref().map(|l|l.round),"valid_round":self.state.valid.as_ref().map(|l|l.round),"prevotes":self.state.votes.iter().filter(|v|v.signed.round==self.round()&&v.signed.phase==Phase::Prevote).count(),"precommits":self.state.votes.iter().filter(|v|v.signed.round==self.round()&&v.signed.phase==Phase::Precommit).count()})
    }
    fn ensure_ready(&self) -> Result<()> {
        if !self.ready() || self.storage_blocked || self.state.commits.len() >= MAX_BLOCKS {
            Err(HOLD)
        } else {
            Ok(())
        }
    }
    fn validator(&self, peer: &str, public: &str) -> Result<&Validator> {
        self.genesis
            .signed
            .validators
            .iter()
            .find(|v| v.peer_id == peer && v.public_key == public)
            .ok_or(INVALID)
    }
    fn previous(&self) -> Result<(String, String)> {
        Ok(match self.state.commits.last() {
            Some(c) => (c.block.id()?, c.block.next_application_hash.clone()),
            None => match &self.state.checkpoint {
                Some(c) => (c.block.id()?, c.block.next_application_hash.clone()),
                None => (
                    self.genesis_hash.clone(),
                    self.genesis.signed.initial_application_hash.clone(),
                ),
            },
        })
    }
    fn check_block(&self, block: &Block) -> Result<()> {
        let (parent, app) = self.previous()?;
        if block.height != self.height()
            || block.height >= MAX_HEIGHT
            || block.parent != parent
            || block.previous_application_hash != app
            || !util::valid_id(&block.next_application_hash)
            || util::canonical(&block.transactions)?.len() > MAX_PAYLOAD_BYTES
        {
            return Err(INVALID);
        }
        Ok(())
    }
    fn verify_vote(&self, v: &Vote) -> Result<()> {
        self.validator(&v.signed.validator, &v.public_key)?;
        if v.signed.genesis_hash != self.genesis_hash
            || v.signed.height == 0
            || v.signed.height > MAX_HEIGHT
            || v.signed.round >= MAX_ROUNDS
            || v.signed
                .block_id
                .as_ref()
                .is_some_and(|id| !util::valid_id(id))
        {
            return Err(INVALID);
        }
        crypto::verify(
            &crypto::public_key(&v.public_key)?,
            VOTE_DOMAIN,
            &v.signed,
            &v.signature,
        )
    }
    fn quorum(
        &self,
        votes: &[Vote],
        height: u64,
        round: u64,
        phase: Phase,
        id: &Option<String>,
    ) -> Result<()> {
        if votes.len() > self.genesis.signed.validators.len() {
            return Err(INVALID);
        }
        let mut operators = BTreeSet::new();
        let mut peers = BTreeSet::new();
        for v in votes {
            self.verify_vote(v)?;
            let b = &v.signed;
            if b.height != height
                || b.round != round
                || b.phase != phase
                || &b.block_id != id
                || !peers.insert(&b.validator)
                || !operators.insert(&self.validator(&b.validator, &v.public_key)?.operator)
            {
                return Err(INVALID);
            }
        }
        if peers.len() < self.genesis.signed.quorum {
            return Err(HOLD);
        }
        Ok(())
    }
    fn matching(&self, phase: Phase, id: &Option<String>) -> Vec<Vote> {
        self.state
            .votes
            .iter()
            .filter(|v| {
                v.signed.round == self.round()
                    && v.signed.phase == phase
                    && &v.signed.block_id == id
            })
            .cloned()
            .collect()
    }
    pub fn check_proposal(&self, p: &Proposal, app: &impl Application) -> Result<()> {
        let b = &p.signed;
        self.validator(&b.proposer, &p.public_key)?;
        if b.genesis_hash != self.genesis_hash
            || b.round != self.round()
            || b.proposer != self.proposer(b.round)
        {
            return Err(INVALID);
        }
        crypto::verify(
            &crypto::public_key(&p.public_key)?,
            PROPOSAL_DOMAIN,
            b,
            &p.signature,
        )?;
        self.check_block(&b.block)?;
        app.validate(&b.block)?;
        match b.valid_round {
            Some(r) if r < b.round => self.quorum(
                &b.valid_votes,
                b.block.height,
                r,
                Phase::Prevote,
                &Some(b.block.id()?),
            ),
            None if b.valid_votes.is_empty() => Ok(()),
            _ => Err(INVALID),
        }
    }
    pub fn propose(
        &mut self,
        transactions: Vec<crate::ledger::SignedTransaction>,
        next_application_hash: String,
        app: &impl Application,
    ) -> Result<Proposal> {
        self.ensure_signer()?;
        if self.proposer(self.round()) != self.own {
            return Err(HOLD);
        }
        if let Some(old) = self
            .state
            .proposals
            .iter()
            .find(|p| p.signed.round == self.round() && p.signed.proposer == self.own)
        {
            return Ok(old.clone());
        }
        if self
            .state
            .votes
            .iter()
            .any(|v| v.signed.round == self.round() && v.signed.validator == self.own)
            || self
                .state
                .timeouts
                .iter()
                .any(|t| t.signed.round == self.round() && t.signed.validator == self.own)
        {
            return Err(HOLD);
        }
        let (parent, previous_application_hash) = self.previous()?;
        let (block, valid_round, valid_votes) = match &self.state.valid {
            Some(v) => (v.block.clone(), Some(v.round), v.prevotes.clone()),
            None => (
                Block {
                    height: self.height(),
                    parent,
                    previous_application_hash,
                    next_application_hash,
                    transactions,
                },
                None,
                vec![],
            ),
        };
        let body = ProposalBody {
            genesis_hash: self.genesis_hash.clone(),
            round: self.round(),
            proposer: self.own.clone(),
            block,
            valid_round,
            valid_votes,
        };
        let p = Signed {
            signature: crypto::sign(&self.key, PROPOSAL_DOMAIN, &body)?,
            public_key: crypto::public(&self.key),
            signed: body,
        };
        self.check_proposal(&p, app)?;
        let mut state = self.state.clone();
        state.proposals.push(p.clone());
        self.install(state)?;
        Ok(p)
    }
    pub fn prevote(&mut self, proposal: &Proposal, app: &impl Application) -> Result<Vote> {
        self.ensure_signer()?;
        self.check_proposal(proposal, app)?;
        let id = proposal.signed.block.id()?;
        let allowed = match &self.state.lock {
            None => true,
            Some(lock) => {
                lock.block.id()? == id
                    || proposal.signed.valid_round.is_some_and(|r| r >= lock.round)
            }
        };
        let mut state = self.state.clone();
        if !state.proposals.iter().any(|p| {
            p.signed.round == proposal.signed.round && p.signed.block == proposal.signed.block
        }) {
            state.proposals.push(proposal.clone());
        }
        self.sign_vote(state, Phase::Prevote, allowed.then_some(id))
    }
    fn sign_vote(
        &mut self,
        mut state: State,
        phase: Phase,
        block_id: Option<String>,
    ) -> Result<Vote> {
        self.ensure_signer()?;
        if let Some(old) = self.state.votes.iter().find(|v| {
            v.signed.validator == self.own
                && v.signed.round == self.round()
                && v.signed.phase == phase
        }) {
            if old.signed.block_id != block_id {
                return Err(HOLD);
            }
            return Ok(old.clone());
        }
        if phase == Phase::Prevote
            && self.state.votes.iter().any(|v| {
                v.signed.validator == self.own
                    && v.signed.round == self.round()
                    && v.signed.phase == Phase::Precommit
            })
        {
            return Err(HOLD);
        }
        // A local timeout irrevocably closes signing in this round.
        if self
            .state
            .timeouts
            .iter()
            .any(|t| t.signed.round == self.round() && t.signed.validator == self.own)
        {
            return Err(HOLD);
        }
        let body = VoteBody {
            genesis_hash: self.genesis_hash.clone(),
            height: self.height(),
            round: self.round(),
            phase,
            validator: self.own.clone(),
            block_id,
        };
        let v = Signed {
            signature: crypto::sign(&self.key, VOTE_DOMAIN, &body)?,
            public_key: crypto::public(&self.key),
            signed: body,
        };
        state.votes.push(v.clone());
        self.install(state)?;
        Ok(v)
    }
    pub fn precommit(&mut self) -> Result<Vote> {
        self.ensure_signer()?;
        if !self.state.votes.iter().any(|v| {
            v.signed.validator == self.own
                && v.signed.round == self.round()
                && v.signed.phase == Phase::Prevote
        }) {
            return Err(HOLD);
        }
        for p in &self.state.proposals {
            if p.signed.round != self.round() {
                continue;
            }
            let id = Some(p.signed.block.id()?);
            let votes = self.matching(Phase::Prevote, &id);
            if self
                .quorum(&votes, self.height(), self.round(), Phase::Prevote, &id)
                .is_ok()
            {
                let lock = Lock {
                    round: self.round(),
                    block: p.signed.block.clone(),
                    prevotes: votes,
                };
                let mut state = self.state.clone();
                state.lock = Some(lock.clone());
                state.valid = Some(lock);
                return self.sign_vote(state, Phase::Precommit, id);
            }
        }
        let votes = self.matching(Phase::Prevote, &None);
        self.quorum(&votes, self.height(), self.round(), Phase::Prevote, &None)?;
        self.sign_vote(self.state.clone(), Phase::Precommit, None)
    }
    /// Cheap readiness over already authenticated vote slots; signing still
    /// performs the complete quorum/lock validation in precommit().
    pub fn precommit_ready(&self) -> bool {
        if !self.is_validator()
            || self
                .state
                .timeouts
                .iter()
                .any(|t| t.signed.round == self.round() && t.signed.validator == self.own)
            || !self.state.votes.iter().any(|v| {
                v.signed.validator == self.own
                    && v.signed.round == self.round()
                    && v.signed.phase == Phase::Prevote
            })
            || self.state.votes.iter().any(|v| {
                v.signed.validator == self.own
                    && v.signed.round == self.round()
                    && v.signed.phase == Phase::Precommit
            })
        {
            return false;
        }
        let quorum = self.genesis.signed.quorum;
        if self
            .state
            .votes
            .iter()
            .filter(|v| {
                v.signed.round == self.round()
                    && v.signed.phase == Phase::Prevote
                    && v.signed.block_id.is_none()
            })
            .count()
            >= quorum
        {
            return true;
        }
        self.state
            .proposals
            .iter()
            .filter(|p| p.signed.round == self.round())
            .any(|p| {
                p.signed.block.id().ok().is_some_and(|id| {
                    self.state
                        .votes
                        .iter()
                        .filter(|v| {
                            v.signed.round == self.round()
                                && v.signed.phase == Phase::Prevote
                                && v.signed.block_id.as_deref() == Some(&id)
                        })
                        .count()
                        >= quorum
                })
            })
    }
    pub fn observe_vote(&mut self, vote: Vote) -> Result<Option<CommitCertificate>> {
        self.ensure_ready()?;
        self.verify_vote(&vote)?;
        if vote.signed.height != self.height()
            || vote.signed.round > self.round()
            || vote.signed.round < self.round().saturating_sub(1)
        {
            return Err(INVALID);
        }
        if let Some(old) = self.state.votes.iter().find(|v| {
            v.signed.validator == vote.signed.validator
                && v.signed.round == vote.signed.round
                && v.signed.phase == vote.signed.phase
        }) {
            if old.signed.block_id != vote.signed.block_id {
                let mut state = self.state.clone();
                // At most one evidence pair per validator across the chain; never erase
                // evidence by submitting a later phase/round or restarting.
                if !state
                    .evidence
                    .iter()
                    .any(|e| e.first.signed.validator == vote.signed.validator)
                {
                    state.evidence.push(DoubleVoteEvidence {
                        first: old.clone(),
                        second: vote,
                    });
                    self.install(state)?;
                }
                return Err(Error::new(30, "ledger_double_vote"));
            }
        } else {
            let mut state = self.state.clone();
            state.votes.push(vote);
            self.install(state)?;
        }
        // Save validValue even if a timeout was already signed: next proposer must
        // carry forward the highest locally observed proof of lock.
        let mut state = self.state.clone();
        for p in &state.proposals.clone() {
            let round = p.signed.round;
            let id = Some(p.signed.block.id()?);
            let votes = state
                .votes
                .iter()
                .filter(|v| {
                    v.signed.round == round
                        && v.signed.phase == Phase::Prevote
                        && v.signed.block_id == id
                })
                .cloned()
                .collect::<Vec<_>>();
            if self
                .quorum(&votes, self.height(), round, Phase::Prevote, &id)
                .is_ok()
                && state.valid.as_ref().is_none_or(|l| l.round < round)
            {
                state.valid = Some(Lock {
                    round,
                    block: p.signed.block.clone(),
                    prevotes: votes,
                });
            }
        }
        self.install(state)?;
        for p in &self.state.proposals {
            let id = Some(p.signed.block.id()?);
            let round = p.signed.round;
            let votes = self
                .state
                .votes
                .iter()
                .filter(|v| {
                    v.signed.round == round
                        && v.signed.phase == Phase::Precommit
                        && v.signed.block_id == id
                })
                .cloned()
                .collect::<Vec<_>>();
            if self
                .quorum(&votes, self.height(), round, Phase::Precommit, &id)
                .is_ok()
            {
                let cert = CommitCertificate {
                    genesis_hash: self.genesis_hash.clone(),
                    round,
                    block: p.signed.block.clone(),
                    precommits: votes,
                };
                self.finalize(cert.clone())?;
                return Ok(Some(cert));
            }
        }
        Ok(None)
    }
    pub fn timeout_duration(&self) -> Duration {
        Duration::from_millis(
            self.genesis
                .signed
                .timeout_ms
                .saturating_mul(self.round() + 1)
                .min(60_000),
        )
    }
    pub fn timeout(&mut self) -> Result<TimeoutVote> {
        self.ensure_signer()?;
        if self.round_started.elapsed() < self.timeout_duration() {
            return Err(HOLD);
        }
        if let Some(t) = self
            .state
            .timeouts
            .iter()
            .find(|t| t.signed.round == self.round() && t.signed.validator == self.own)
        {
            return Ok(t.clone());
        }
        let body = TimeoutBody {
            genesis_hash: self.genesis_hash.clone(),
            height: self.height(),
            round: self.round(),
            validator: self.own.clone(),
        };
        let t = Signed {
            signature: crypto::sign(&self.key, TIMEOUT_DOMAIN, &body)?,
            public_key: crypto::public(&self.key),
            signed: body,
        };
        let mut state = self.state.clone();
        state.timeouts.push(t.clone());
        self.install(state)?;
        Ok(t)
    }
    fn verify_timeout(&self, t: &TimeoutVote) -> Result<()> {
        self.validator(&t.signed.validator, &t.public_key)?;
        if t.signed.genesis_hash != self.genesis_hash
            || t.signed.height == 0
            || t.signed.height > MAX_HEIGHT
            || t.signed.round >= MAX_ROUNDS
        {
            return Err(INVALID);
        }
        crypto::verify(
            &crypto::public_key(&t.public_key)?,
            TIMEOUT_DOMAIN,
            &t.signed,
            &t.signature,
        )
    }
    pub fn observe_timeout(&mut self, timeout: TimeoutVote) -> Result<bool> {
        self.ensure_ready()?;
        self.verify_timeout(&timeout)?;
        if timeout.signed.height != self.height() || timeout.signed.round != self.round() {
            return Err(INVALID);
        }
        let duplicate = self.state.timeouts.iter().any(|old| {
            old.signed.round == timeout.signed.round
                && old.signed.validator == timeout.signed.validator
        });
        // timeout() persists the local signed vote before returning it. That
        // already-present vote can be the final quorum member, including after
        // a crash between durable signing and certificate construction.
        if duplicate
            && self
                .state
                .timeouts
                .iter()
                .filter(|vote| vote.signed.round == self.round())
                .count()
                < self.genesis.signed.quorum
        {
            return Ok(false);
        }
        let mut state = self.state.clone();
        if !state.timeouts.iter().any(|t| {
            t.signed.round == timeout.signed.round && t.signed.validator == timeout.signed.validator
        }) {
            state.timeouts.push(timeout)
        }
        let timeouts = state
            .timeouts
            .iter()
            .filter(|t| t.signed.round == state.round)
            .cloned()
            .collect::<Vec<_>>();
        let advanced = timeouts.len() >= self.genesis.signed.quorum;
        if advanced {
            let cert = TimeoutCertificate {
                genesis_hash: self.genesis_hash.clone(),
                height: self.height(),
                round: self.round(),
                timeouts,
            };
            self.verify_timeout_certificate(&cert)?;
            self.advance_with_certificate(&mut state, cert)?;
        }
        self.install(state)?;
        if advanced {
            self.round_started = Instant::now();
        }
        Ok(advanced)
    }
    pub fn round_certificate(&self) -> Option<&TimeoutCertificate> {
        self.state.round_certificate.as_ref()
    }
    pub fn local_votes(&self) -> Vec<Vote> {
        self.state
            .votes
            .iter()
            .filter(|v| v.signed.validator == self.own && v.signed.round == self.round())
            .cloned()
            .collect()
    }
    pub fn local_timeout(&self) -> Option<TimeoutVote> {
        self.state
            .timeouts
            .iter()
            .find(|t| t.signed.validator == self.own && t.signed.round == self.round())
            .cloned()
    }
    pub fn current_proposal(&self) -> Option<Proposal> {
        self.state
            .proposals
            .iter()
            .find(|p| p.signed.round == self.round())
            .cloned()
    }
    pub fn preferred_block(&self) -> Option<Block> {
        self.state.valid.as_ref().map(|v| v.block.clone())
    }
    pub fn verify_timeout_certificate(&self, cert: &TimeoutCertificate) -> Result<()> {
        if !self.ready()
            || cert.genesis_hash != self.genesis_hash
            || cert.height == 0
            || cert.height > MAX_HEIGHT
            || cert.round >= MAX_ROUNDS - 1
            || cert.timeouts.len() > self.genesis.signed.validators.len()
        {
            return Err(INVALID);
        }
        let mut peers = BTreeSet::new();
        let mut operators = BTreeSet::new();
        for timeout in &cert.timeouts {
            self.verify_timeout(timeout)?;
            let t = &timeout.signed;
            if t.height != cert.height
                || t.round != cert.round
                || !peers.insert(&t.validator)
                || !operators.insert(&self.validator(&t.validator, &timeout.public_key)?.operator)
            {
                return Err(INVALID);
            }
        }
        if peers.len() < self.genesis.signed.quorum {
            return Err(HOLD);
        }
        Ok(())
    }
    fn advance_with_certificate(&self, state: &mut State, cert: TimeoutCertificate) -> Result<()> {
        let next = cert
            .round
            .checked_add(1)
            .filter(|r| *r < MAX_ROUNDS)
            .ok_or(HOLD)?;
        state.round = next;
        let cutoff = next.saturating_sub(1);
        state.proposals.retain(|p| p.signed.round >= cutoff);
        state.votes.retain(|v| v.signed.round >= cutoff);
        state.timeouts = cert.timeouts.clone();
        state.round_certificate = Some(cert);
        // Self-contained lock and validValue PoLCs survive GC and future-round jumps.
        Ok(())
    }
    pub fn observe_timeout_certificate(&mut self, cert: TimeoutCertificate) -> Result<bool> {
        self.ensure_ready()?;
        self.verify_timeout_certificate(&cert)?;
        if cert.height != self.height() {
            return Err(INVALID);
        }
        if cert.round < self.round() {
            return Ok(false);
        }
        let mut state = self.state.clone();
        self.advance_with_certificate(&mut state, cert)?;
        self.install(state)?;
        self.round_started = Instant::now();
        Ok(true)
    }
    pub fn verify_commit(&self, cert: &CommitCertificate) -> Result<()> {
        if !self.ready() {
            return Err(HOLD);
        }
        if cert.genesis_hash != self.genesis_hash
            || cert.round >= MAX_ROUNDS
            || cert.block.height == 0
            || cert.block.height >= MAX_HEIGHT
            || !util::valid_id(&cert.block.parent)
            || !util::valid_id(&cert.block.previous_application_hash)
            || !util::valid_id(&cert.block.next_application_hash)
            || util::canonical(&cert.block.transactions)?.len() > MAX_PAYLOAD_BYTES
        {
            return Err(INVALID);
        }
        self.quorum(
            &cert.precommits,
            cert.block.height,
            cert.round,
            Phase::Precommit,
            &Some(cert.block.id()?),
        )
    }
    pub fn import_commit(&mut self, cert: CommitCertificate, app: &impl Application) -> Result<()> {
        self.ensure_ready()?;
        self.verify_commit(&cert)?;
        self.check_block(&cert.block)?;
        app.validate(&cert.block)?;
        self.finalize(cert)
    }
    fn finalize(&mut self, cert: CommitCertificate) -> Result<()> {
        self.verify_commit(&cert)?;
        self.check_block(&cert.block)?;
        let mut state = self.state.clone();
        state.commits.push(cert);
        state.height = state.height.checked_add(1).ok_or(HOLD)?;
        state.round = 0;
        state.proposals.clear();
        state.votes.clear();
        state.timeouts.clear();
        state.round_certificate = None;
        state.lock = None;
        state.valid = None;
        self.install(state)?;
        self.round_started = Instant::now();
        Ok(())
    }
    /// Bounded, sequential sync. Call import_commit with application validation
    /// and advance the application after each certificate. No trusted state jump.
    pub fn sync_page(&self, after_height: u64, limit: usize) -> Vec<CommitCertificate> {
        self.state
            .commits
            .iter()
            .filter(|c| c.block.height > after_height)
            .take(limit.min(8))
            .cloned()
            .collect()
    }
    pub fn verify_evidence(&self, e: &DoubleVoteEvidence) -> Result<()> {
        self.verify_vote(&e.first)?;
        self.verify_vote(&e.second)?;
        let (a, b) = (&e.first.signed, &e.second.signed);
        if a.validator != b.validator
            || a.height != b.height
            || a.round != b.round
            || a.phase != b.phase
            || a.block_id == b.block_id
        {
            return Err(INVALID);
        }
        Ok(())
    }
    pub fn observe_evidence(&mut self, e: DoubleVoteEvidence) -> Result<bool> {
        self.verify_evidence(&e)?;
        if e.first.signed.height > self.height() {
            return Err(INVALID);
        }
        if self
            .state
            .evidence
            .iter()
            .any(|old| old.first.signed.validator == e.first.signed.validator)
        {
            return Ok(false);
        }
        if self.state.evidence.len() >= self.genesis.signed.validators.len() {
            return Err(HOLD);
        }
        let mut state = self.state.clone();
        state.evidence.push(e);
        self.install(state)?;
        Ok(true)
    }
    fn validate_state(&self) -> Result<()> {
        let s = &self.state;
        if s.version != 1
            || s.genesis_hash != self.genesis_hash
            || s.height
                != s.commits
                    .last()
                    .map(|c| c.block.height)
                    .or_else(|| s.checkpoint.as_ref().map(|c| c.block.height))
                    .unwrap_or(0)
                    .checked_add(1)
                    .ok_or(STORAGE)?
            || s.commits.len() > MAX_BLOCKS
            || s.round >= MAX_ROUNDS
            || s.height > MAX_HEIGHT
            || s.proposals.len() > 2 * self.genesis.signed.validators.len()
            || s.votes.len() > 4 * self.genesis.signed.validators.len()
            || s.timeouts.len() > 2 * self.genesis.signed.validators.len()
            || s.evidence.len() > self.genesis.signed.validators.len()
        {
            return Err(STORAGE);
        }
        let mut parent = self.genesis_hash.clone();
        let mut app = self.genesis.signed.initial_application_hash.clone();
        let mut first_height = 1;
        if let Some(checkpoint) = &s.checkpoint {
            self.verify_commit(checkpoint).map_err(|_| STORAGE)?;
            if checkpoint.block.height >= s.height {
                return Err(STORAGE);
            }
            let Some(first) = s.commits.first() else {
                return Err(STORAGE);
            };
            if first.block.height > checkpoint.block.height + 1 {
                return Err(STORAGE);
            }
            first_height = first.block.height;
            if first_height == checkpoint.block.height + 1 {
                parent = checkpoint.block.id()?;
                app = checkpoint.block.next_application_hash.clone();
            } else {
                parent = first.block.parent.clone();
                app = first.block.previous_application_hash.clone();
            }
            if first_height <= checkpoint.block.height
                && !s.commits.iter().any(|c| {
                    c.block.height == checkpoint.block.height
                        && c.block.id().ok() == checkpoint.block.id().ok()
                })
            {
                return Err(STORAGE);
            }
        }
        for (i, c) in s.commits.iter().enumerate() {
            // Full-store boundary must not make an existing valid journal unreadable.
            if c.genesis_hash != self.genesis_hash
                || c.block.height != first_height + i as u64
                || c.block.parent != parent
                || c.block.previous_application_hash != app
            {
                return Err(STORAGE);
            }
            self.verify_commit(c).map_err(|_| STORAGE)?;
            parent = c.block.id()?;
            app = c.block.next_application_hash.clone();
        }
        let mut slots = BTreeSet::new();
        for v in &s.votes {
            self.verify_vote(v).map_err(|_| STORAGE)?;
            if v.signed.height != s.height
                || v.signed.round > s.round
                || !slots.insert((
                    v.signed.validator.clone(),
                    v.signed.round,
                    match v.signed.phase {
                        Phase::Prevote => 0,
                        Phase::Precommit => 1,
                    },
                ))
            {
                return Err(STORAGE);
            }
        }
        for t in &s.timeouts {
            self.verify_timeout(t).map_err(|_| STORAGE)?;
            if t.signed.height != s.height || t.signed.round > s.round {
                return Err(STORAGE);
            }
        }
        for lock in [&s.lock, &s.valid].into_iter().flatten() {
            self.check_block(&lock.block).map_err(|_| STORAGE)?;
            if lock.round > s.round {
                return Err(STORAGE);
            }
            self.quorum(
                &lock.prevotes,
                s.height,
                lock.round,
                Phase::Prevote,
                &Some(lock.block.id()?),
            )
            .map_err(|_| STORAGE)?;
        }
        if s.round > 0 {
            let cert = s.round_certificate.as_ref().ok_or(STORAGE)?;
            self.verify_timeout_certificate(cert).map_err(|_| STORAGE)?;
            if cert.height != s.height || cert.round.checked_add(1) != Some(s.round) {
                return Err(STORAGE);
            }
        } else if s.round_certificate.is_some() {
            return Err(STORAGE);
        }
        for e in &s.evidence {
            self.verify_evidence(e).map_err(|_| STORAGE)?;
        }
        Ok(())
    }
    fn install(&mut self, state: State) -> Result<()> {
        self.persist(&state)?;
        self.state = state;
        Ok(())
    }
    fn persist(&self, state: &State) -> Result<()> {
        let plain = Zeroizing::new(serde_json::to_vec(state).map_err(|_| STORAGE)?);
        if plain.len() > MAX_STORE_BYTES - MAGIC.len() - 40 {
            return Err(STORAGE);
        }
        let mut nonce = [0; 24];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        let cipher = XChaCha20Poly1305::new_from_slice(&self.storage_key).map_err(|_| STORAGE)?;
        let encrypted = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plain,
                    aad: self.genesis_hash.as_bytes(),
                },
            )
            .map_err(|_| STORAGE)?;
        let mut bytes = MAGIC.to_vec();
        bytes.extend(nonce);
        bytes.extend(encrypted);
        util::atomic_write(&self.path, &bytes)
    }
}

#[path = "ledger_consensus_checkpoint.rs"]
mod checkpoint;

#[cfg(test)]
#[path = "ledger_consensus_tests.rs"]
mod tests;
