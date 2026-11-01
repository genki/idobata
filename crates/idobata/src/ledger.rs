//! Deterministic application for an explicitly initialized private experiment.
//!
//! Consensus is a separate layer: only a validated committed block may advance
//! this machine. Signatures identify claims, not semantic truth. Runtime must
//! resolve question/criteria/answer IDs to inspected, signed knowledge in this
//! exact private room before proposing or voting on transactions. This module
//! never reads environment/secret values or starts a production currency.

use crate::{
    crypto,
    error::{Error, INVALID, Result},
    util,
};
use libp2p::identity;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_INTEGER: u64 = 9_007_199_254_740_991;
pub const MAX_TRANSACTION_BYTES: usize = 64 * 1024;
pub const MAX_BATCH_BYTES: usize = 256 * 1024;
pub const MAX_CHECKPOINT_BYTES: usize = 16 * 1024 * 1024;
const GENESIS_DOMAIN: &str = "idobata.ledger.application-genesis.v1";
const TX_DOMAIN: &str = "idobata.ledger.transaction.v1";
const ACCEPTANCE_DOMAIN: &str = "idobata.ledger.acceptance-vote.v1";
const HOLD: Error = Error::new(10, "ledger_acceptance_hold");

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Participant {
    pub public_key: String,
    pub operator: String,
    pub credit: u16,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Parameters {
    pub blocks_per_epoch: u64,
    pub epoch_mint_cap: u64,
    pub minimum_system_reward: u64,
    pub question_fee: u64,
    pub attempts_per_operator_epoch: u32,
    pub active_questions_per_operator: u32,
    pub minimum_deadline_blocks: u64,
    pub maximum_deadline_blocks: u64,
    pub maximum_active_questions: usize,
    pub operator_state_bytes: u64,
    pub answers_per_question: usize,
    pub answers_per_operator_question: usize,
    pub maximum_batch_transactions: usize,
}

impl Default for Parameters {
    fn default() -> Self {
        Self {
            blocks_per_epoch: 100,
            epoch_mint_cap: 32,
            minimum_system_reward: 1,
            question_fee: 0,
            attempts_per_operator_epoch: 8,
            active_questions_per_operator: 4,
            minimum_deadline_blocks: 5,
            maximum_deadline_blocks: 50,
            maximum_active_questions: 128,
            operator_state_bytes: 256 * 1024,
            answers_per_question: 8,
            answers_per_operator_question: 2,
            maximum_batch_transactions: 64,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Genesis {
    pub version: u32,
    pub experiment_only: bool,
    pub room_id: String,
    pub network_salt: String,
    pub authority_peer_id: String,
    pub operator_epoch: u64,
    pub participants: BTreeMap<String, Participant>,
    pub parameters: Parameters,
    /// Explicit test bootstrap only. Default is empty; at most 100 per operator.
    pub bootstrap_balances: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedGenesis {
    pub signed: Genesis,
    pub public_key: String,
    pub signature: String,
}

pub struct VerifiedGenesis {
    document: SignedGenesis,
    hash: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct QuestionTerms {
    pub source_record_id: String,
    pub criteria_record_id: String,
    pub deadline_height: u64,
    pub bounty: u64,
    pub conflict_operators: BTreeSet<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AnswerSubmission {
    pub question_id: String,
    pub source_record_id: String,
    /// No finder fee: runtime fixes this to the inspected source record's original author.
    pub beneficiary_peer_id: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Satisfied,
    Unsatisfied,
    Abstain,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceVote {
    pub version: u32,
    pub chain_id: String,
    pub question_id: String,
    pub question_snapshot: String,
    pub criteria_record_id: String,
    pub answer_id: String,
    pub beneficiary_peer_id: String,
    pub submitted_by_peer_id: String,
    pub voter_peer_id: String,
    pub sequence: u64,
    pub operator_epoch: u64,
    pub reservation_epoch: u64,
    pub round: u64,
    pub bounty: u64,
    pub system_reward: u64,
    pub verdict: Verdict,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedAcceptanceVote {
    pub signed: AcceptanceVote,
    pub public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceCertificate {
    pub version: u32,
    pub chain_id: String,
    pub question_id: String,
    pub question_snapshot: String,
    pub criteria_record_id: String,
    pub answer_id: String,
    pub beneficiary_peer_id: String,
    pub submitted_by_peer_id: String,
    pub operator_epoch: u64,
    pub reservation_epoch: u64,
    pub bounty: u64,
    pub system_reward: u64,
    pub votes: Vec<SignedAcceptanceVote>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    RegisterQuestion {
        question: QuestionTerms,
    },
    SubmitAnswer {
        answer: AnswerSubmission,
    },
    CastAcceptanceVote {
        vote: Box<SignedAcceptanceVote>,
    },
    SettleAnswer {
        certificate: Box<AcceptanceCertificate>,
    },
    Transfer {
        to_peer_id: String,
        amount: u64,
    },
    RefundExpired {
        question_id: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Transaction {
    pub version: u32,
    pub chain_id: String,
    pub signer_peer_id: String,
    pub nonce: u64,
    pub operation: Operation,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedTransaction {
    pub signed: Transaction,
    pub public_key: String,
    pub signature: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EpochSupply {
    pub minted: u64,
    pub reserved: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AnswerState {
    pub source_record_id: String,
    pub beneficiary_peer_id: String,
    pub submitted_by_peer_id: String,
    pub submission_transaction_id: String,
    pub submission_order: u64,
    pub votes: BTreeMap<String, SignedAcceptanceVote>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum QuestionOutcome {
    Open,
    Accepted {
        certificate: Box<AcceptanceCertificate>,
        transaction_id: String,
        settled_height: u64,
    },
    Expired {
        transaction_id: String,
        refunded_height: u64,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct QuestionState {
    pub id: String,
    pub snapshot: String,
    pub asker_peer_id: String,
    pub asker_operator: String,
    pub terms: QuestionTerms,
    pub registered_height: u64,
    pub reservation_epoch: u64,
    pub system_reward: u64,
    /// Reserve compact outcome/index overhead now, so another actor's final
    /// vote cannot make this author's already accepted reservation exceed quota.
    pub metadata_reservation: u64,
    pub escrow: u64,
    pub answers: BTreeMap<String, AnswerState>,
    pub outcome: QuestionOutcome,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClosedOutcome {
    Accepted {
        answer_id: String,
        beneficiary_peer_id: String,
        submitted_by_peer_id: String,
        certificate_digest: String,
        settlement_id: String,
        settled_height: u64,
    },
    Expired {
        refund_id: String,
        refunded_height: u64,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClosedQuestion {
    pub id: String,
    pub source_record_id: String,
    pub criteria_record_id: String,
    pub snapshot: String,
    pub asker_peer_id: String,
    pub asker_operator: String,
    pub registered_height: u64,
    pub deadline_height: u64,
    pub reservation_epoch: u64,
    pub system_reward: u64,
    pub bounty: u64,
    pub metadata_reservation: u64,
    pub outcome: ClosedOutcome,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct State {
    pub version: u32,
    pub genesis_hash: String,
    pub height: u64,
    pub balances: BTreeMap<String, u64>,
    pub nonces: BTreeMap<String, u64>,
    pub questions: BTreeMap<String, QuestionState>,
    pub closed_questions: BTreeMap<String, ClosedQuestion>,
    /// Never pruned, including after expiry. Another transaction ID or nonce
    /// cannot turn the same source record back into an unused mining question.
    pub used_question_sources: BTreeMap<String, String>,
    pub epoch_supply: BTreeMap<u64, EpochSupply>,
    pub operator_attempts: BTreeMap<u64, BTreeMap<String, u32>>,
    pub total_minted: u64,
    pub total_burned: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Event {
    QuestionRegistered {
        question_id: String,
        reservation_epoch: u64,
    },
    AnswerSubmitted {
        question_id: String,
        answer_id: String,
    },
    AcceptanceVoteRecorded {
        question_id: String,
        answer_id: String,
    },
    RewardSettled {
        question_id: String,
        answer_id: String,
        beneficiary: String,
        minted: u64,
        bounty: u64,
    },
    Transferred {
        from: String,
        to: String,
        amount: u64,
    },
    ExpiredRefunded {
        question_id: String,
        to: String,
        amount: u64,
    },
}

pub struct Transition {
    pub state_root: String,
    pub transaction_ids: Vec<String>,
    pub events: Vec<Event>,
    next: State,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Receipt {
    pub height: u64,
    pub block_id: String,
    pub previous_state_root: String,
    pub state_root: String,
    pub transaction_ids: Vec<String>,
    pub events: Vec<Event>,
}

/// The complete application state. Authentication comes from the separate
/// consensus commit certificate and its durable minimum anchor, not a hash
/// chain or an unauthenticated height in this document.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub version: u32,
    pub genesis_hash: String,
    pub height: u64,
    pub block_id: Option<String>,
    pub state_root: String,
    pub state: State,
}

pub struct Machine {
    genesis: VerifiedGenesis,
    state: State,
    committed_block_id: Option<String>,
}

fn id(value: &str) -> Result<()> {
    if util::valid_id(value) {
        Ok(())
    } else {
        Err(INVALID)
    }
}
fn add(a: u64, b: u64) -> Result<u64> {
    a.checked_add(b)
        .filter(|v| *v <= MAX_INTEGER)
        .ok_or(INVALID)
}
fn sub(a: u64, b: u64) -> Result<u64> {
    a.checked_sub(b).ok_or(INVALID)
}
fn operator_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}
fn canonical_key(public: &str, peer: &str) -> Result<identity::PublicKey> {
    let key = crypto::public_key(public)?;
    if key.key_type() != identity::KeyType::Ed25519
        || key.to_peer_id().to_string() != peer
        || crypto::encode(&key.encode_protobuf()) != public
    {
        return Err(INVALID);
    }
    Ok(key)
}
fn hash<T: Serialize>(domain: &str, value: &T) -> Result<String> {
    Ok(util::hash(&util::canonical(&(domain, value))?))
}

fn validate_genesis(g: &Genesis) -> Result<()> {
    id(&g.room_id)?;
    id(&g.network_salt)?;
    if g.version != 1
        || !g.experiment_only
        || g.operator_epoch != 1
        || g.participants.is_empty()
        || g.participants.len() > 32
    {
        return Err(INVALID);
    }
    let p = &g.parameters;
    if !(10..=100_000).contains(&p.blocks_per_epoch)
        || p.epoch_mint_cap == 0
        || p.minimum_system_reward == 0
        || p.minimum_system_reward > p.epoch_mint_cap
        || p.epoch_mint_cap > MAX_INTEGER
        || p.question_fee > MAX_INTEGER
        || !(1..=32).contains(&p.attempts_per_operator_epoch)
        || !(1..=16).contains(&p.active_questions_per_operator)
        || p.minimum_deadline_blocks == 0
        || p.maximum_deadline_blocks < p.minimum_deadline_blocks
        || p.maximum_deadline_blocks >= p.blocks_per_epoch
        || p.maximum_active_questions == 0
        || p.maximum_active_questions > 4096
        || !(8192..=256 * 1024).contains(&p.operator_state_bytes)
        || !(1..=8).contains(&p.answers_per_question)
        || p.answers_per_operator_question == 0
        || p.answers_per_operator_question > p.answers_per_question
        || !(1..=64).contains(&p.maximum_batch_transactions)
    {
        return Err(INVALID);
    }
    let mut credits = BTreeMap::new();
    for (peer, participant) in &g.participants {
        canonical_key(&participant.public_key, peer)?;
        if !operator_id(&participant.operator)
            || participant.credit > 1000
            || credits
                .insert(&participant.operator, participant.credit)
                .is_some_and(|v| v != participant.credit)
        {
            return Err(INVALID);
        }
    }
    let mut bootstrap = BTreeMap::<&str, u64>::new();
    let mut total = 0;
    for (peer, balance) in &g.bootstrap_balances {
        let owner = g.participants.get(peer).ok_or(INVALID)?;
        total = add(total, *balance)?;
        let current = bootstrap.entry(&owner.operator).or_default();
        *current = add(*current, *balance)?;
        if *current > 100 {
            return Err(INVALID);
        }
    }
    Ok(())
}

pub fn sign_genesis(authority: &identity::Keypair, genesis: Genesis) -> Result<SignedGenesis> {
    validate_genesis(&genesis)?;
    if authority.public().to_peer_id().to_string() != genesis.authority_peer_id {
        return Err(INVALID);
    }
    Ok(SignedGenesis {
        signature: crypto::sign(authority, GENESIS_DOMAIN, &genesis)?,
        public_key: crypto::public(authority),
        signed: genesis,
    })
}

pub fn verify_genesis(document: SignedGenesis, authority_peer: &str) -> Result<VerifiedGenesis> {
    validate_genesis(&document.signed)?;
    if document.signed.authority_peer_id != authority_peer {
        return Err(INVALID);
    }
    let key = canonical_key(&document.public_key, authority_peer)?;
    crypto::verify(&key, GENESIS_DOMAIN, &document.signed, &document.signature)?;
    let hash = hash(GENESIS_DOMAIN, &document.signed)?;
    Ok(VerifiedGenesis { document, hash })
}

impl VerifiedGenesis {
    pub fn chain_id(&self) -> &str {
        &self.hash
    }
    pub fn genesis_hash(&self) -> &str {
        &self.hash
    }
    pub fn document(&self) -> &SignedGenesis {
        &self.document
    }
}

pub fn sign_transaction(
    key: &identity::Keypair,
    chain_id: &str,
    nonce: u64,
    operation: Operation,
) -> Result<SignedTransaction> {
    id(chain_id)?;
    if nonce == 0 || nonce > MAX_INTEGER {
        return Err(INVALID);
    }
    let signed = Transaction {
        version: 1,
        chain_id: chain_id.to_owned(),
        signer_peer_id: key.public().to_peer_id().to_string(),
        nonce,
        operation,
    };
    let transaction = SignedTransaction {
        signature: crypto::sign(key, TX_DOMAIN, &signed)?,
        public_key: crypto::public(key),
        signed,
    };
    if util::canonical(&transaction)?.len() > MAX_TRANSACTION_BYTES {
        return Err(INVALID);
    }
    Ok(transaction)
}

pub fn transaction_id(transaction: &SignedTransaction) -> Result<String> {
    hash(TX_DOMAIN, &transaction.signed)
}

pub fn sign_acceptance_vote(
    key: &identity::Keypair,
    vote: AcceptanceVote,
) -> Result<SignedAcceptanceVote> {
    if key.public().to_peer_id().to_string() != vote.voter_peer_id {
        return Err(INVALID);
    }
    Ok(SignedAcceptanceVote {
        signature: crypto::sign(key, ACCEPTANCE_DOMAIN, &vote)?,
        public_key: crypto::public(key),
        signed: vote,
    })
}

pub fn question_id(chain_id: &str, source_record_id: &str) -> Result<String> {
    id(chain_id)?;
    id(source_record_id)?;
    hash("idobata.ledger.question.v1", &(chain_id, source_record_id))
}

struct QuestionOrigin<'a> {
    id: &'a str,
    source: &'a str,
    asker: &'a str,
    operator: &'a str,
    registered: u64,
    epoch: u64,
}

impl Machine {
    pub fn new(genesis: VerifiedGenesis) -> Result<Self> {
        let g = &genesis.document.signed;
        let balances = g
            .participants
            .keys()
            .map(|p| (p.clone(), *g.bootstrap_balances.get(p).unwrap_or(&0)))
            .collect();
        let nonces = g.participants.keys().map(|p| (p.clone(), 0)).collect();
        let state = State {
            version: 1,
            genesis_hash: genesis.hash.clone(),
            height: 0,
            balances,
            nonces,
            questions: BTreeMap::new(),
            closed_questions: BTreeMap::new(),
            used_question_sources: BTreeMap::new(),
            epoch_supply: BTreeMap::new(),
            operator_attempts: BTreeMap::new(),
            total_minted: 0,
            total_burned: 0,
        };
        let machine = Self {
            genesis,
            state,
            committed_block_id: None,
        };
        machine.validate_state(&machine.state)?;
        Ok(machine)
    }
    pub fn genesis(&self) -> &VerifiedGenesis {
        &self.genesis
    }
    pub fn state(&self) -> &State {
        &self.state
    }
    pub fn state_root(&self) -> Result<String> {
        hash("idobata.ledger.state.v1", &self.state)
    }
    pub fn committed_block_id(&self) -> Option<&str> {
        self.committed_block_id.as_deref()
    }
    pub fn next_nonce(&self, peer: &str) -> Result<u64> {
        add(*self.state.nonces.get(peer).ok_or(INVALID)?, 1)
    }
    pub fn balance(&self, peer: &str) -> u64 {
        *self.state.balances.get(peer).unwrap_or(&0)
    }

    pub fn validate_batch(
        &self,
        height: u64,
        parent_root: &str,
        txs: &[SignedTransaction],
    ) -> Result<Transition> {
        if height != add(self.state.height, 1)?
            || self.state_root()? != parent_root
            || txs.len()
                > self
                    .genesis
                    .document
                    .signed
                    .parameters
                    .maximum_batch_transactions
            || util::canonical(&txs)?.len() > MAX_BATCH_BYTES
        {
            return Err(INVALID);
        }
        let mut next = self.state.clone();
        next.height = height;
        let mut transaction_ids = vec![];
        let mut events = vec![];
        self.expire_questions(&mut next, &mut events)?;
        for transaction in txs {
            self.verify_transaction(transaction)?;
            let signer = &transaction.signed.signer_peer_id;
            if transaction.signed.nonce != add(*next.nonces.get(signer).ok_or(INVALID)?, 1)? {
                return Err(Error::new(30, "ledger_nonce_replay_or_gap"));
            }
            let tx_id = transaction_id(transaction)?;
            let event = self.apply_operation(&mut next, transaction, &tx_id)?;
            next.nonces.insert(signer.clone(), transaction.signed.nonce);
            transaction_ids.push(tx_id);
            events.push(event);
        }
        self.settle_satisfied_answers(&mut next, &mut events)?;
        self.validate_state(&next)?;
        if util::canonical(&next)?.len() > MAX_CHECKPOINT_BYTES - 64 * 1024 {
            return Err(Error::new(30, "ledger_state_capacity"));
        }
        Ok(Transition {
            state_root: hash("idobata.ledger.state.v1", &next)?,
            transaction_ids,
            events,
            next,
        })
    }

    /// Caller must first verify the separate consensus commit certificate. This
    /// application method is not itself a quorum, finality or fork-choice rule.
    pub fn apply_committed(
        &mut self,
        height: u64,
        block_id: &str,
        parent_root: &str,
        txs: &[SignedTransaction],
    ) -> Result<Receipt> {
        id(block_id)?;
        let transition = self.validate_batch(height, parent_root, txs)?;
        let receipt = Receipt {
            height,
            block_id: block_id.to_owned(),
            previous_state_root: parent_root.to_owned(),
            state_root: transition.state_root,
            transaction_ids: transition.transaction_ids,
            events: transition.events,
        };
        self.state = transition.next;
        self.committed_block_id = Some(block_id.to_owned());
        Ok(receipt)
    }

    fn verify_transaction(&self, tx: &SignedTransaction) -> Result<()> {
        let body = &tx.signed;
        let owner = self
            .genesis
            .document
            .signed
            .participants
            .get(&body.signer_peer_id)
            .ok_or(INVALID)?;
        if body.version != 1
            || body.chain_id != self.genesis.hash
            || body.nonce == 0
            || body.nonce > MAX_INTEGER
            || tx.public_key != owner.public_key
            || util::canonical(tx)?.len() > MAX_TRANSACTION_BYTES
        {
            return Err(INVALID);
        }
        crypto::verify(
            &canonical_key(&tx.public_key, &body.signer_peer_id)?,
            TX_DOMAIN,
            body,
            &tx.signature,
        )
    }

    fn epoch(&self, height: u64) -> Result<u64> {
        Ok(sub(height, 1)? / self.genesis.document.signed.parameters.blocks_per_epoch)
    }
    fn debit(state: &mut State, peer: &str, amount: u64) -> Result<()> {
        let balance = state.balances.get_mut(peer).ok_or(INVALID)?;
        *balance = balance
            .checked_sub(amount)
            .ok_or(Error::new(30, "ledger_insufficient_balance"))?;
        Ok(())
    }
    fn credit(state: &mut State, peer: &str, amount: u64) -> Result<()> {
        let balance = state.balances.get_mut(peer).ok_or(INVALID)?;
        *balance = add(*balance, amount)?;
        Ok(())
    }
    fn snapshot_for(&self, q: &QuestionState) -> Result<String> {
        hash(
            "idobata.ledger.question-snapshot.v1",
            &(
                &self.genesis.hash,
                &q.id,
                &q.asker_peer_id,
                &q.terms,
                q.registered_height,
                q.reservation_epoch,
                q.system_reward,
            ),
        )
    }
    fn open_question<'a>(&self, state: &'a State, question: &str) -> Result<&'a QuestionState> {
        id(question)?;
        let q = state.questions.get(question).ok_or(INVALID)?;
        if q.outcome != QuestionOutcome::Open
            || state.height >= q.terms.deadline_height
            || self.epoch(state.height)? != q.reservation_epoch
        {
            return Err(Error::new(30, "ledger_question_closed_or_expired"));
        }
        Ok(q)
    }
    fn apply_operation(
        &self,
        state: &mut State,
        tx: &SignedTransaction,
        tx_id: &str,
    ) -> Result<Event> {
        let g = &self.genesis.document.signed;
        let p = &g.parameters;
        let signer = &tx.signed.signer_peer_id;
        let participant = g.participants.get(signer).ok_or(INVALID)?;
        match &tx.signed.operation {
            Operation::RegisterQuestion { question } => {
                id(&question.source_record_id)?;
                id(&question.criteria_record_id)?;
                let epoch = self.epoch(state.height)?;
                if question.bounty > MAX_INTEGER
                    || question.deadline_height > MAX_INTEGER
                    || question.deadline_height < add(state.height, p.minimum_deadline_blocks)?
                    || question.deadline_height > add(state.height, p.maximum_deadline_blocks)?
                    || self.epoch(sub(question.deadline_height, 1)?)? != epoch
                    || question.conflict_operators.len() > 32
                    || question
                        .conflict_operators
                        .iter()
                        .any(|op| !g.participants.values().any(|v| &v.operator == op))
                {
                    return Err(INVALID);
                }
                if state
                    .used_question_sources
                    .contains_key(&question.source_record_id)
                {
                    return Err(Error::new(30, "ledger_question_source_already_used"));
                }
                if state.questions.len() >= p.maximum_active_questions {
                    return Err(Error::new(30, "ledger_question_capacity"));
                }
                let active = state
                    .questions
                    .values()
                    .filter(|q| {
                        q.asker_operator == participant.operator
                            && q.outcome == QuestionOutcome::Open
                    })
                    .count();
                let attempts = state
                    .operator_attempts
                    .get(&epoch)
                    .and_then(|m| m.get(&participant.operator))
                    .copied()
                    .unwrap_or(0);
                if active >= p.active_questions_per_operator as usize
                    || attempts >= p.attempts_per_operator_epoch
                {
                    return Err(Error::new(30, "ledger_operator_question_limit"));
                }
                let budget = state.epoch_supply.get(&epoch).cloned().unwrap_or_default();
                if add(
                    add(budget.minted, budget.reserved)?,
                    p.minimum_system_reward,
                )? > p.epoch_mint_cap
                {
                    return Err(Error::new(10, "ledger_epoch_reward_capacity_hold"));
                }
                let initial = g
                    .bootstrap_balances
                    .values()
                    .try_fold(0, |sum, n| add(sum, *n))?;
                let reserved = state
                    .epoch_supply
                    .values()
                    .try_fold(0, |sum, e| add(sum, e.reserved))?;
                add(
                    add(add(initial, state.total_minted)?, reserved)?,
                    p.minimum_system_reward,
                )?;
                Self::debit(state, signer, add(question.bounty, p.question_fee)?)?;
                state.total_burned = add(state.total_burned, p.question_fee)?;
                let qid = question_id(&self.genesis.hash, &question.source_record_id)?;
                let mut q = QuestionState {
                    id: qid.clone(),
                    snapshot: String::new(),
                    asker_peer_id: signer.clone(),
                    asker_operator: participant.operator.clone(),
                    terms: question.clone(),
                    registered_height: state.height,
                    reservation_epoch: epoch,
                    system_reward: p.minimum_system_reward,
                    metadata_reservation: 2048,
                    escrow: question.bounty,
                    answers: BTreeMap::new(),
                    outcome: QuestionOutcome::Open,
                };
                q.snapshot = self.snapshot_for(&q)?;
                q.metadata_reservation = self.question_charge(&q)?;
                state.questions.insert(qid.clone(), q);
                state
                    .used_question_sources
                    .insert(question.source_record_id.clone(), qid.clone());
                state.epoch_supply.entry(epoch).or_default().reserved =
                    add(budget.reserved, p.minimum_system_reward)?;
                state.operator_attempts.entry(epoch).or_default().insert(
                    participant.operator.clone(),
                    attempts.checked_add(1).ok_or(INVALID)?,
                );
                Ok(Event::QuestionRegistered {
                    question_id: qid,
                    reservation_epoch: epoch,
                })
            }
            Operation::SubmitAnswer { answer } => {
                id(&answer.source_record_id)?;
                let q = self.open_question(state, &answer.question_id)?;
                if !g.participants.contains_key(&answer.beneficiary_peer_id) {
                    return Err(Error::new(30, "ledger_unknown_original_author"));
                }
                if q.answers.contains_key(&answer.source_record_id) {
                    return Err(Error::new(30, "ledger_answer_already_submitted"));
                }
                let own = q
                    .answers
                    .values()
                    .filter(|a| {
                        g.participants[&a.submitted_by_peer_id].operator == participant.operator
                    })
                    .count();
                if q.answers.len() >= p.answers_per_question
                    || own >= p.answers_per_operator_question
                {
                    return Err(Error::new(30, "ledger_answer_capacity"));
                }
                let submission_order = q.answers.len() as u64;
                state
                    .questions
                    .get_mut(&answer.question_id)
                    .unwrap()
                    .answers
                    .insert(
                        answer.source_record_id.clone(),
                        AnswerState {
                            source_record_id: answer.source_record_id.clone(),
                            beneficiary_peer_id: answer.beneficiary_peer_id.clone(),
                            submitted_by_peer_id: signer.clone(),
                            submission_transaction_id: tx_id.to_owned(),
                            submission_order,
                            votes: BTreeMap::new(),
                        },
                    );
                Ok(Event::AnswerSubmitted {
                    question_id: answer.question_id.clone(),
                    answer_id: answer.source_record_id.clone(),
                })
            }
            Operation::CastAcceptanceVote { vote } => {
                let v = &vote.signed;
                let q = self.open_question(state, &v.question_id)?;
                let answer = q.answers.get(&v.answer_id).ok_or(INVALID)?;
                if v.voter_peer_id != *signer || v.sequence != tx.signed.nonce {
                    return Err(INVALID);
                }
                self.verify_acceptance_vote(
                    q,
                    &answer.source_record_id,
                    &answer.beneficiary_peer_id,
                    &answer.submitted_by_peer_id,
                    vote,
                )?;
                state
                    .questions
                    .get_mut(&v.question_id)
                    .unwrap()
                    .answers
                    .get_mut(&v.answer_id)
                    .unwrap()
                    .votes
                    .insert(participant.operator.clone(), *vote.clone());
                Ok(Event::AcceptanceVoteRecorded {
                    question_id: v.question_id.clone(),
                    answer_id: v.answer_id.clone(),
                })
            }
            Operation::SettleAnswer { certificate } => self.settle(state, certificate, tx_id),
            Operation::Transfer { to_peer_id, amount } => {
                if *amount == 0 || *amount > MAX_INTEGER || !g.participants.contains_key(to_peer_id)
                {
                    return Err(INVALID);
                }
                Self::debit(state, signer, *amount)?;
                Self::credit(state, to_peer_id, *amount)?;
                Ok(Event::Transferred {
                    from: signer.clone(),
                    to: to_peer_id.clone(),
                    amount: *amount,
                })
            }
            Operation::RefundExpired { question_id } => {
                id(question_id)?;
                let closed = state
                    .closed_questions
                    .get(question_id)
                    .ok_or(Error::new(30, "ledger_refund_not_due"))?;
                if !matches!(closed.outcome, ClosedOutcome::Expired { .. }) {
                    return Err(Error::new(30, "ledger_refund_not_due"));
                }
                Ok(Event::ExpiredRefunded {
                    question_id: question_id.clone(),
                    to: closed.asker_peer_id.clone(),
                    amount: 0,
                })
            }
        }
    }

    fn settle(
        &self,
        state: &mut State,
        certificate: &AcceptanceCertificate,
        settlement_id: &str,
    ) -> Result<Event> {
        let q = self.open_question(state, &certificate.question_id)?.clone();
        if *certificate != self.certificate_for(state, &q.id, &certificate.answer_id)? {
            return Err(Error::new(30, "ledger_acceptance_snapshot_mismatch"));
        }
        self.verify_certificate(&q, certificate)?;
        Self::credit(
            state,
            &certificate.beneficiary_peer_id,
            add(q.escrow, q.system_reward)?,
        )?;
        state.total_minted = add(state.total_minted, q.system_reward)?;
        let budget = state
            .epoch_supply
            .get_mut(&q.reservation_epoch)
            .ok_or(INVALID)?;
        budget.reserved = sub(budget.reserved, q.system_reward)?;
        budget.minted = add(budget.minted, q.system_reward)?;
        if add(budget.minted, budget.reserved)?
            > self.genesis.document.signed.parameters.epoch_mint_cap
        {
            return Err(INVALID);
        }
        let outcome = ClosedOutcome::Accepted {
            answer_id: certificate.answer_id.clone(),
            beneficiary_peer_id: certificate.beneficiary_peer_id.clone(),
            submitted_by_peer_id: certificate.submitted_by_peer_id.clone(),
            certificate_digest: hash(ACCEPTANCE_DOMAIN, certificate)?,
            settlement_id: settlement_id.to_owned(),
            settled_height: state.height,
        };
        self.close_question(state, &q, outcome)?;
        Ok(Event::RewardSettled {
            question_id: q.id,
            answer_id: certificate.answer_id.clone(),
            beneficiary: certificate.beneficiary_peer_id.clone(),
            minted: q.system_reward,
            bounty: q.escrow,
        })
    }

    fn expire_questions(&self, state: &mut State, events: &mut Vec<Event>) -> Result<()> {
        let expired = state
            .questions
            .values()
            .filter(|q| {
                q.outcome == QuestionOutcome::Open && q.terms.deadline_height <= state.height
            })
            .map(|q| q.id.clone())
            .collect::<Vec<_>>();
        for question_id in expired {
            let q = state.questions[&question_id].clone();
            Self::credit(state, &q.asker_peer_id, q.escrow)?;
            let budget = state
                .epoch_supply
                .get_mut(&q.reservation_epoch)
                .ok_or(INVALID)?;
            budget.reserved = sub(budget.reserved, q.system_reward)?;
            let effect = hash(
                "idobata.ledger.automatic-refund.v1",
                &(&self.genesis.hash, state.height, &question_id),
            )?;
            self.close_question(
                state,
                &q,
                ClosedOutcome::Expired {
                    refund_id: effect,
                    refunded_height: state.height,
                },
            )?;
            events.push(Event::ExpiredRefunded {
                question_id,
                to: q.asker_peer_id,
                amount: q.escrow,
            });
        }
        Ok(())
    }

    fn settle_satisfied_answers(&self, state: &mut State, events: &mut Vec<Event>) -> Result<()> {
        let open = state
            .questions
            .values()
            .filter(|q| q.outcome == QuestionOutcome::Open)
            .map(|q| q.id.clone())
            .collect::<Vec<_>>();
        for question_id in open {
            let mut candidates = state.questions[&question_id]
                .answers
                .values()
                .map(|a| (a.submission_order, a.source_record_id.clone()))
                .collect::<Vec<_>>();
            candidates.sort();
            for (_, answer) in candidates {
                let certificate = self.certificate_for(state, &question_id, &answer)?;
                match self.verify_certificate(&state.questions[&question_id], &certificate) {
                    Ok(()) => {
                        let effect = hash(
                            "idobata.ledger.automatic-settlement.v1",
                            &(&self.genesis.hash, state.height, &question_id, &certificate),
                        )?;
                        events.push(self.settle(state, &certificate, &effect)?);
                        break;
                    }
                    Err(error) if error.code == HOLD.code => {}
                    Err(error) => return Err(error),
                }
            }
        }
        Ok(())
    }

    pub fn export_checkpoint(&self) -> Result<Checkpoint> {
        self.validate_state(&self.state)?;
        Ok(Checkpoint {
            version: 1,
            genesis_hash: self.genesis.hash.clone(),
            height: self.state.height,
            block_id: self.committed_block_id.clone(),
            state_root: self.state_root()?,
            state: self.state.clone(),
        })
    }

    /// Runtime must authenticate this exact height/block/root with the pinned
    /// consensus CommitQC AND its durable minimum anchor before returning Ok.
    /// Runtime encrypts/fsyncs the complete checkpoint before consensus pruning.
    pub fn restore_checkpoint<F>(
        genesis: VerifiedGenesis,
        checkpoint: Checkpoint,
        verify: F,
    ) -> Result<Self>
    where
        F: Fn(u64, Option<&str>, &str) -> Result<()>,
    {
        if checkpoint.version != 1
            || checkpoint.genesis_hash != genesis.hash
            || checkpoint.height != checkpoint.state.height
            || (checkpoint.height == 0) != checkpoint.block_id.is_none()
            || checkpoint.height > MAX_INTEGER
            || util::canonical(&checkpoint)?.len() > MAX_CHECKPOINT_BYTES
        {
            return Err(INVALID);
        }
        if let Some(block) = &checkpoint.block_id {
            id(block)?;
        }
        let machine = Self {
            genesis,
            state: checkpoint.state,
            committed_block_id: checkpoint.block_id,
        };
        machine.validate_state(&machine.state)?;
        if machine.state_root()? != checkpoint.state_root {
            return Err(INVALID);
        }
        verify(
            checkpoint.height,
            machine.committed_block_id(),
            &checkpoint.state_root,
        )?;
        Ok(machine)
    }

    pub fn acceptance_vote(
        &self,
        question: &str,
        answer: &str,
        voter: &str,
        sequence: u64,
        verdict: Verdict,
    ) -> Result<AcceptanceVote> {
        let q = self.state.questions.get(question).ok_or(INVALID)?;
        let a = q.answers.get(answer).ok_or(INVALID)?;
        Ok(AcceptanceVote {
            version: 1,
            chain_id: self.genesis.hash.clone(),
            question_id: q.id.clone(),
            question_snapshot: q.snapshot.clone(),
            criteria_record_id: q.terms.criteria_record_id.clone(),
            answer_id: a.source_record_id.clone(),
            beneficiary_peer_id: a.beneficiary_peer_id.clone(),
            submitted_by_peer_id: a.submitted_by_peer_id.clone(),
            voter_peer_id: voter.to_owned(),
            sequence,
            operator_epoch: self.genesis.document.signed.operator_epoch,
            reservation_epoch: q.reservation_epoch,
            round: 0,
            bounty: q.terms.bounty,
            system_reward: q.system_reward,
            verdict,
        })
    }
    pub fn acceptance_certificate(
        &self,
        question: &str,
        answer: &str,
    ) -> Result<AcceptanceCertificate> {
        self.certificate_for(&self.state, question, answer)
    }
    fn certificate_for(
        &self,
        state: &State,
        question: &str,
        answer: &str,
    ) -> Result<AcceptanceCertificate> {
        let q = state.questions.get(question).ok_or(INVALID)?;
        let a = q.answers.get(answer).ok_or(INVALID)?;
        Ok(AcceptanceCertificate {
            version: 1,
            chain_id: self.genesis.hash.clone(),
            question_id: q.id.clone(),
            question_snapshot: q.snapshot.clone(),
            criteria_record_id: q.terms.criteria_record_id.clone(),
            answer_id: a.source_record_id.clone(),
            beneficiary_peer_id: a.beneficiary_peer_id.clone(),
            submitted_by_peer_id: a.submitted_by_peer_id.clone(),
            operator_epoch: self.genesis.document.signed.operator_epoch,
            reservation_epoch: q.reservation_epoch,
            bounty: q.terms.bounty,
            system_reward: q.system_reward,
            votes: a.votes.values().cloned().collect(),
        })
    }
    fn verify_acceptance_vote(
        &self,
        q: &QuestionState,
        answer: &str,
        beneficiary: &str,
        submitted_by: &str,
        vote: &SignedAcceptanceVote,
    ) -> Result<()> {
        let v = &vote.signed;
        let g = &self.genesis.document.signed;
        let voter = g.participants.get(&v.voter_peer_id).ok_or(INVALID)?;
        let recipient = g.participants.get(beneficiary).ok_or(INVALID)?;
        let finder = g.participants.get(submitted_by).ok_or(INVALID)?;
        if v.version != 1
            || v.chain_id != self.genesis.hash
            || v.question_id != q.id
            || v.question_snapshot != q.snapshot
            || v.criteria_record_id != q.terms.criteria_record_id
            || v.answer_id != answer
            || v.beneficiary_peer_id != beneficiary
            || v.submitted_by_peer_id != submitted_by
            || v.operator_epoch != g.operator_epoch
            || v.reservation_epoch != q.reservation_epoch
            || v.round != 0
            || v.bounty != q.terms.bounty
            || v.system_reward != q.system_reward
            || v.sequence == 0
            || v.sequence > MAX_INTEGER
            || vote.public_key != voter.public_key
        {
            return Err(INVALID);
        }
        if voter.operator == q.asker_operator
            || voter.operator == recipient.operator
            || voter.operator == finder.operator
            || q.terms.conflict_operators.contains(&voter.operator)
        {
            return Err(Error::new(30, "ledger_conflicted_acceptance_voter"));
        }
        if voter.credit == 0 {
            return Err(HOLD);
        }
        crypto::verify(
            &canonical_key(&vote.public_key, &v.voter_peer_id)?,
            ACCEPTANCE_DOMAIN,
            v,
            &vote.signature,
        )
    }
    fn verify_certificate(
        &self,
        q: &QuestionState,
        certificate: &AcceptanceCertificate,
    ) -> Result<()> {
        let c = certificate;
        let g = &self.genesis.document.signed;
        id(&c.answer_id)?;
        if c.version != 1
            || c.chain_id != self.genesis.hash
            || c.question_id != q.id
            || c.question_snapshot != q.snapshot
            || c.criteria_record_id != q.terms.criteria_record_id
            || c.operator_epoch != g.operator_epoch
            || c.reservation_epoch != q.reservation_epoch
            || c.bounty != q.terms.bounty
            || c.system_reward != q.system_reward
            || c.votes.len() > 32
            || !g.participants.contains_key(&c.beneficiary_peer_id)
            || !g.participants.contains_key(&c.submitted_by_peer_id)
        {
            return Err(INVALID);
        }
        let mut seen = BTreeSet::new();
        let mut groups = BTreeMap::<&str, (bool, u16)>::new();
        let mut previous = None;
        for vote in &c.votes {
            let peer = &vote.signed.voter_peer_id;
            self.verify_acceptance_vote(
                q,
                &c.answer_id,
                &c.beneficiary_peer_id,
                &c.submitted_by_peer_id,
                vote,
            )?;
            let participant = &g.participants[peer];
            let operator = &participant.operator;
            if !seen.insert(operator) || previous.is_some_and(|old| old >= operator) {
                return Err(INVALID);
            }
            previous = Some(operator);
            match vote.signed.verdict {
                Verdict::Abstain => {}
                Verdict::Satisfied => {
                    groups.insert(operator.as_str(), (true, participant.credit));
                }
                Verdict::Unsatisfied => {
                    groups.insert(operator.as_str(), (false, participant.credit));
                }
            }
        }
        let positive_groups = groups.values().filter(|(positive, _)| *positive).count();
        let positive = groups
            .values()
            .filter(|(positive, _)| *positive)
            .map(|(_, credit)| u32::from(*credit))
            .sum::<u32>();
        let negative = groups
            .values()
            .filter(|(positive, _)| !*positive)
            .map(|(_, credit)| u32::from(*credit))
            .sum::<u32>();
        if positive_groups < 3 || positive < 3000 || positive <= negative {
            return Err(HOLD);
        }
        Ok(())
    }

    fn validate_state(&self, state: &State) -> Result<()> {
        let g = &self.genesis.document.signed;
        let p = &g.parameters;
        let peers = g.participants.keys().collect::<BTreeSet<_>>();
        if state.version != 1
            || state.genesis_hash != self.genesis.hash
            || state.height > MAX_INTEGER
            || state.balances.keys().collect::<BTreeSet<_>>() != peers
            || state.nonces.keys().collect::<BTreeSet<_>>() != peers
            || state
                .balances
                .values()
                .chain(state.nonces.values())
                .any(|v| *v > MAX_INTEGER)
            || state.questions.len() > p.maximum_active_questions
            || state.used_question_sources.len()
                != state.questions.len() + state.closed_questions.len()
        {
            return Err(INVALID);
        }
        let mut epochs = BTreeMap::<u64, EpochSupply>::new();
        let mut attempts = BTreeMap::<u64, BTreeMap<String, u32>>::new();
        let mut active = BTreeMap::<&str, u32>::new();
        let mut minted = 0;
        let mut escrow = 0;
        for (key, q) in &state.questions {
            self.validate_question_origin(
                state,
                key,
                QuestionOrigin {
                    id: &q.id,
                    source: &q.terms.source_record_id,
                    asker: &q.asker_peer_id,
                    operator: &q.asker_operator,
                    registered: q.registered_height,
                    epoch: q.reservation_epoch,
                },
            )?;
            if q.outcome != QuestionOutcome::Open
                || q.escrow != q.terms.bounty
                || q.system_reward != p.minimum_system_reward
                || q.terms.bounty > MAX_INTEGER
                || q.terms.deadline_height > MAX_INTEGER
                || q.terms.deadline_height < add(q.registered_height, p.minimum_deadline_blocks)?
                || q.terms.deadline_height > add(q.registered_height, p.maximum_deadline_blocks)?
                || self.epoch(sub(q.terms.deadline_height, 1)?)? != q.reservation_epoch
                || state.height >= q.terms.deadline_height
                || q.snapshot != self.snapshot_for(q)?
                || q.terms.conflict_operators.len() > 32
                || q.terms
                    .conflict_operators
                    .iter()
                    .any(|op| !g.participants.values().any(|v| &v.operator == op))
                || q.metadata_reservation != self.question_charge(q)?
                || q.answers.len() > p.answers_per_question
            {
                return Err(INVALID);
            }
            id(&q.terms.criteria_record_id)?;
            let used = attempts
                .entry(q.reservation_epoch)
                .or_default()
                .entry(q.asker_operator.clone())
                .or_default();
            *used = used.checked_add(1).ok_or(INVALID)?;
            let count = active.entry(&q.asker_operator).or_default();
            *count = count.checked_add(1).ok_or(INVALID)?;
            if *count > p.active_questions_per_operator {
                return Err(INVALID);
            }
            escrow = add(escrow, q.escrow)?;
            let budget = epochs.entry(q.reservation_epoch).or_default();
            budget.reserved = add(budget.reserved, q.system_reward)?;
            let mut answers = BTreeMap::<&str, usize>::new();
            let mut orders = BTreeSet::new();
            for (answer_id, answer) in &q.answers {
                id(answer_id)?;
                id(&answer.submission_transaction_id)?;
                let author = g
                    .participants
                    .get(&answer.submitted_by_peer_id)
                    .ok_or(INVALID)?;
                if !g.participants.contains_key(&answer.beneficiary_peer_id) {
                    return Err(INVALID);
                }
                if answer.source_record_id != *answer_id
                    || answer.submission_order >= q.answers.len() as u64
                    || !orders.insert(answer.submission_order)
                    || answer.votes.len() > 32
                {
                    return Err(INVALID);
                }
                let own = answers.entry(&author.operator).or_default();
                *own += 1;
                if *own > p.answers_per_operator_question {
                    return Err(INVALID);
                }
                for (operator, vote) in &answer.votes {
                    let voter = g
                        .participants
                        .get(&vote.signed.voter_peer_id)
                        .ok_or(INVALID)?;
                    if operator != &voter.operator
                        || vote.signed.sequence
                            > *state
                                .nonces
                                .get(&vote.signed.voter_peer_id)
                                .ok_or(INVALID)?
                    {
                        return Err(INVALID);
                    }
                    self.verify_acceptance_vote(
                        q,
                        answer_id,
                        &answer.beneficiary_peer_id,
                        &answer.submitted_by_peer_id,
                        vote,
                    )?;
                }
                if self
                    .verify_certificate(q, &self.certificate_for(state, key, answer_id)?)
                    .is_ok()
                {
                    return Err(INVALID);
                }
            }
        }
        for (key, q) in &state.closed_questions {
            self.validate_question_origin(
                state,
                key,
                QuestionOrigin {
                    id: &q.id,
                    source: &q.source_record_id,
                    asker: &q.asker_peer_id,
                    operator: &q.asker_operator,
                    registered: q.registered_height,
                    epoch: q.reservation_epoch,
                },
            )?;
            id(&q.criteria_record_id)?;
            id(&q.snapshot)?;
            if state.questions.contains_key(key)
                || q.bounty > MAX_INTEGER
                || q.system_reward != p.minimum_system_reward
                || q.deadline_height < add(q.registered_height, p.minimum_deadline_blocks)?
                || q.deadline_height > add(q.registered_height, p.maximum_deadline_blocks)?
                || self.epoch(sub(q.deadline_height, 1)?)? != q.reservation_epoch
                || q.metadata_reservation < 2048
                || self.closed_charge(q)? > q.metadata_reservation
            {
                return Err(INVALID);
            }
            let used = attempts
                .entry(q.reservation_epoch)
                .or_default()
                .entry(q.asker_operator.clone())
                .or_default();
            *used = used.checked_add(1).ok_or(INVALID)?;
            let budget = epochs.entry(q.reservation_epoch).or_default();
            match &q.outcome {
                ClosedOutcome::Accepted {
                    answer_id,
                    beneficiary_peer_id,
                    submitted_by_peer_id,
                    certificate_digest,
                    settlement_id,
                    settled_height,
                } => {
                    id(answer_id)?;
                    id(certificate_digest)?;
                    id(settlement_id)?;
                    if !g.participants.contains_key(beneficiary_peer_id)
                        || !g.participants.contains_key(submitted_by_peer_id)
                        || *settled_height < q.registered_height
                        || *settled_height >= q.deadline_height
                        || *settled_height > state.height
                        || self.epoch(*settled_height)? != q.reservation_epoch
                    {
                        return Err(INVALID);
                    }
                    minted = add(minted, q.system_reward)?;
                    budget.minted = add(budget.minted, q.system_reward)?;
                }
                ClosedOutcome::Expired {
                    refund_id,
                    refunded_height,
                } => {
                    id(refund_id)?;
                    if *refunded_height < q.deadline_height || *refunded_height > state.height {
                        return Err(INVALID);
                    }
                }
            }
        }
        if attempts
            .values()
            .any(|m| m.values().any(|n| *n > p.attempts_per_operator_epoch))
            || epochs.values().any(|e| {
                e.minted
                    .checked_add(e.reserved)
                    .is_none_or(|n| n > p.epoch_mint_cap)
            })
        {
            return Err(INVALID);
        }
        let initial = g
            .bootstrap_balances
            .values()
            .try_fold(0, |s, n| add(s, *n))?;
        let count = (state.questions.len() + state.closed_questions.len()) as u64;
        let burn = count
            .checked_mul(p.question_fee)
            .filter(|v| *v <= MAX_INTEGER)
            .ok_or(INVALID)?;
        let balances = state.balances.values().try_fold(0, |s, n| add(s, *n))?;
        let reserved = epochs.values().try_fold(0, |s, e| add(s, e.reserved))?;
        add(add(initial, minted)?, reserved)?;
        if epochs != state.epoch_supply
            || attempts != state.operator_attempts
            || minted != state.total_minted
            || burn != state.total_burned
            || add(balances, escrow)? != sub(add(initial, minted)?, burn)?
        {
            return Err(INVALID);
        }
        if state.height == 0
            && (!state.questions.is_empty()
                || !state.closed_questions.is_empty()
                || state.nonces.values().any(|n| *n != 0)
                || state
                    .balances
                    .iter()
                    .any(|(peer, n)| *n != *g.bootstrap_balances.get(peer).unwrap_or(&0)))
        {
            return Err(INVALID);
        }
        self.enforce_quotas(state)
    }

    fn validate_question_origin(
        &self,
        state: &State,
        key: &str,
        origin: QuestionOrigin<'_>,
    ) -> Result<()> {
        let QuestionOrigin {
            id: qid,
            source,
            asker,
            operator,
            registered,
            epoch,
        } = origin;
        id(source)?;
        let author = self
            .genesis
            .document
            .signed
            .participants
            .get(asker)
            .ok_or(INVALID)?;
        if key != qid
            || qid != question_id(&self.genesis.hash, source)?
            || state.used_question_sources.get(source).map(String::as_str) != Some(qid)
            || author.operator != operator
            || registered == 0
            || registered > state.height
            || epoch != self.epoch(registered)?
        {
            return Err(INVALID);
        }
        Ok(())
    }

    fn question_charge(&self, q: &QuestionState) -> Result<u64> {
        let mut base = q.clone();
        base.answers.clear();
        base.metadata_reservation = 0;
        Ok((util::canonical(&base)?.len() as u64 + 512).max(2048))
    }
    fn closed_charge(&self, q: &ClosedQuestion) -> Result<u64> {
        Ok(util::canonical(q)?.len() as u64 + 512)
    }
    fn close_question(
        &self,
        state: &mut State,
        q: &QuestionState,
        outcome: ClosedOutcome,
    ) -> Result<()> {
        let closed = ClosedQuestion {
            id: q.id.clone(),
            source_record_id: q.terms.source_record_id.clone(),
            criteria_record_id: q.terms.criteria_record_id.clone(),
            snapshot: q.snapshot.clone(),
            asker_peer_id: q.asker_peer_id.clone(),
            asker_operator: q.asker_operator.clone(),
            registered_height: q.registered_height,
            deadline_height: q.terms.deadline_height,
            reservation_epoch: q.reservation_epoch,
            system_reward: q.system_reward,
            bounty: q.terms.bounty,
            metadata_reservation: q.metadata_reservation,
            outcome,
        };
        if self.closed_charge(&closed)? > q.metadata_reservation {
            return Err(INVALID);
        }
        state.questions.remove(&q.id);
        state.closed_questions.insert(q.id.clone(), closed);
        Ok(())
    }

    fn enforce_quotas(&self, state: &State) -> Result<()> {
        let g = &self.genesis.document.signed;
        let mut charges = BTreeMap::<&str, u64>::new();
        for q in state.questions.values() {
            *charges.entry(&q.asker_operator).or_default() = add(
                *charges.get(q.asker_operator.as_str()).unwrap_or(&0),
                q.metadata_reservation,
            )?;
            for answer in q.answers.values() {
                let operator = &g.participants[&answer.submitted_by_peer_id].operator;
                let mut body = answer.clone();
                body.votes.clear();
                let n = (util::canonical(&body)?.len() as u64 + 128).max(512);
                let entry = charges.entry(operator).or_default();
                *entry = add(*entry, n)?;
                for vote in answer.votes.values() {
                    let operator = &g.participants[&vote.signed.voter_peer_id].operator;
                    let entry = charges.entry(operator).or_default();
                    *entry = add(*entry, util::canonical(vote)?.len() as u64 + 256)?;
                }
            }
        }
        for q in state.closed_questions.values() {
            let entry = charges.entry(&q.asker_operator).or_default();
            *entry = add(*entry, q.metadata_reservation)?;
        }
        if charges
            .values()
            .any(|n| *n > g.parameters.operator_state_bytes)
        {
            return Err(Error::new(30, "ledger_operator_state_quota"));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "ledger_tests.rs"]
mod tests;
