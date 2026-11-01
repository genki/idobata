use super::*;

const HISTORY: usize = 4096;
const GROUP_HISTORY: usize = 128;
const PRUNED_IDS: usize = 2048;
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Outcome {
    Pending,
    Confirmed { height: u64, block_id: String },
    ExpiredOrReplaced { height: u64 },
    Pruned { height: u64 },
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Tracked {
    pub signer: String,
    pub nonce: u64,
    pub seen_height: u64,
    pub outcome: Outcome,
    pub summary: Summary,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Summary {
    RegisterQuestion {
        source_record_id: String,
    },
    SubmitAnswer {
        question_id: String,
        answer_id: String,
        beneficiary_peer_id: String,
    },
    CastAcceptanceVote {
        question_id: String,
        answer_id: String,
    },
    SettleAnswer {
        question_id: String,
        answer_id: String,
    },
    Transfer {
        to_peer_id: String,
        amount: u64,
    },
    RefundExpired {
        question_id: String,
    },
}
impl Summary {
    pub(super) fn from_tx(tx: &SignedTransaction) -> Self {
        match &tx.signed.operation {
            Operation::RegisterQuestion { question } => Self::RegisterQuestion {
                source_record_id: question.source_record_id.clone(),
            },
            Operation::SubmitAnswer { answer } => Self::SubmitAnswer {
                question_id: answer.question_id.clone(),
                answer_id: answer.source_record_id.clone(),
                beneficiary_peer_id: answer.beneficiary_peer_id.clone(),
            },
            Operation::CastAcceptanceVote { vote } => Self::CastAcceptanceVote {
                question_id: vote.signed.question_id.clone(),
                answer_id: vote.signed.answer_id.clone(),
            },
            Operation::SettleAnswer { certificate } => Self::SettleAnswer {
                question_id: certificate.question_id.clone(),
                answer_id: certificate.answer_id.clone(),
            },
            Operation::Transfer { to_peer_id, amount } => Self::Transfer {
                to_peer_id: to_peer_id.clone(),
                amount: *amount,
            },
            Operation::RefundExpired { question_id } => Self::RefundExpired {
                question_id: question_id.clone(),
            },
        }
    }
}

impl Active {
    pub(super) fn track_snapshot(
        &mut self,
        machine: &Machine,
        certificate: &CommitCertificate,
    ) -> Result<()> {
        let certificates = self
            .node
            .commits()
            .iter()
            .filter(|c| c.block.height <= machine.state().height)
            .cloned()
            .chain(std::iter::once(certificate.clone()))
            .collect::<Vec<_>>();
        for cert in certificates {
            self.track_commit(&cert)?;
        }
        for tracked in self.history.values_mut() {
            if matches!(tracked.outcome, Outcome::Pending)
                && machine
                    .state()
                    .nonces
                    .get(&tracked.signer)
                    .is_some_and(|nonce| *nonce >= tracked.nonce)
            {
                tracked.outcome = Outcome::Pruned {
                    height: machine.state().height,
                };
            }
        }
        Ok(())
    }
    pub(super) fn track(&mut self, tx: &SignedTransaction, outcome: Outcome) -> Result<()> {
        let id = ledger::transaction_id(tx)?;
        if let Some(old) = self.history.get_mut(&id) {
            if !matches!(old.outcome, Outcome::Confirmed { .. }) {
                old.outcome = outcome;
            }
            return Ok(());
        }
        let operator = &self
            .settings
            .application
            .signed
            .participants
            .get(&tx.signed.signer_peer_id)
            .ok_or(INVALID)?
            .operator;
        let own_count = self
            .history
            .values()
            .filter(|h| {
                self.settings
                    .application
                    .signed
                    .participants
                    .get(&h.signer)
                    .is_some_and(|p| &p.operator == operator)
            })
            .count();
        if own_count >= GROUP_HISTORY || self.history.len() >= HISTORY {
            let evicted = self
                .history
                .iter()
                .filter(|(_, h)| !matches!(h.outcome, Outcome::Pending))
                .filter(|(_, h)| {
                    own_count < GROUP_HISTORY
                        || self
                            .settings
                            .application
                            .signed
                            .participants
                            .get(&h.signer)
                            .is_some_and(|p| &p.operator == operator)
                })
                .min_by_key(|(id, h)| (h.seen_height, *id))
                .map(|(id, _)| id.clone());
            if let Some(id) = evicted {
                self.history.remove(&id);
                self.pruned_ids.insert(id);
                self.history_pruned = true;
                while self.pruned_ids.len() > PRUNED_IDS {
                    if let Some(id) = self.pruned_ids.first().cloned() {
                        self.pruned_ids.remove(&id);
                    }
                }
            } else {
                return Err(HOLD);
            }
        }
        self.history.insert(
            id,
            Tracked {
                signer: tx.signed.signer_peer_id.clone(),
                nonce: tx.signed.nonce,
                seen_height: self.machine.state().height,
                outcome,
                summary: Summary::from_tx(tx),
            },
        );
        Ok(())
    }
    pub(super) fn track_commit(&mut self, cert: &CommitCertificate) -> Result<()> {
        for tx in &cert.block.transactions {
            self.track(
                tx,
                Outcome::Confirmed {
                    height: cert.block.height,
                    block_id: cert.block.id()?,
                },
            )?;
        }
        Ok(())
    }
    pub(super) fn resolve_consumed(&mut self, snapshot_gap: bool) {
        let height = self.machine.state().height;
        for tracked in self.history.values_mut() {
            if matches!(tracked.outcome, Outcome::Pending)
                && self
                    .machine
                    .state()
                    .nonces
                    .get(&tracked.signer)
                    .is_some_and(|nonce| *nonce >= tracked.nonce)
            {
                tracked.outcome = if snapshot_gap {
                    Outcome::Pruned { height }
                } else {
                    Outcome::ExpiredOrReplaced { height }
                };
            }
        }
    }
    pub(super) fn validate_history(&self) -> Result<()> {
        if self.history.len() > HISTORY
            || self.pruned_ids.len() > PRUNED_IDS
            || self.pruned_ids.iter().any(|id| !util::valid_id(id))
        {
            return Err(STORAGE);
        }
        for (id, h) in &self.history {
            if !util::valid_id(id)
                || !self
                    .settings
                    .application
                    .signed
                    .participants
                    .contains_key(&h.signer)
                || h.nonce == 0
                || h.nonce > ledger::MAX_INTEGER
                || h.seen_height > ledger::MAX_INTEGER
            {
                return Err(STORAGE);
            }
        }
        Ok(())
    }
}

impl Runtime {
    pub fn balance(&self, peer: Option<&str>) -> Result<Value> {
        let a = self.active.as_ref().ok_or(HOLD)?;
        a.room()?;
        let own = a.key.public().to_peer_id().to_string();
        let peer = peer.unwrap_or(&own);
        if !a
            .settings
            .application
            .signed
            .participants
            .contains_key(peer)
        {
            return Err(INVALID);
        }
        Ok(
            json!({"status":"ok","peer_id":peer,"balance":a.machine.balance(peer),"committed_nonce":a.machine.state().nonces.get(peer),"application_height":a.machine.state().height,"state_root":a.machine.state_root()?,"experiment_only":true}),
        )
    }
    /// A nonce alone never establishes which transaction was finalized. Only a
    /// verified committed block or a durable prior observation yields confirmed.
    pub fn transaction(&self, id: &str) -> Result<Value> {
        let a = self.active.as_ref().ok_or(HOLD)?;
        a.room()?;
        if !util::valid_id(id) {
            return Err(INVALID);
        }
        for cert in a.node.commits() {
            for tx in &cert.block.transactions {
                if ledger::transaction_id(tx)? == id {
                    return Ok(
                        json!({"status":"confirmed","transaction_id":id,"height":cert.block.height,"block_id":cert.block.id()?,"commit_certificate_available":true,"experiment_only":true}),
                    );
                }
            }
        }
        if let Some(tracked) = a.history.get(id) {
            let mut value = serde_json::to_value(&tracked.outcome).map_err(|_| STORAGE)?;
            value["transaction_id"] = id.into();
            value["commit_certificate_available"] = false.into();
            value["experiment_only"] = true.into();
            return Ok(value);
        }
        Ok(
            json!({"status":if a.pruned_ids.contains(id){"pruned"}else{"unknown"},"transaction_id":id,"history_pruned":a.history_pruned,"scope":"retained_local_index_and_certified_block_tail","experiment_only":true}),
        )
    }
    pub fn questions(&self, limit: usize, cursor: Option<&str>) -> Result<Value> {
        let a = self.active.as_ref().ok_or(HOLD)?;
        a.room()?;
        if !(1..=20).contains(&limit) || cursor.is_some_and(|id| !util::valid_id(id)) {
            return Err(INVALID);
        }
        let mut ids = a
            .machine
            .state()
            .questions
            .keys()
            .chain(a.machine.state().closed_questions.keys())
            .filter(|id| cursor.is_none_or(|c| id.as_str() > c))
            .cloned()
            .collect::<Vec<_>>();
        ids.sort();
        let more = ids.len() > limit;
        ids.truncate(limit);
        let next = more.then(|| ids.last().cloned()).flatten();
        let mut questions = vec![];
        for id in ids {
            if let Some(q) = a.machine.state().questions.get(&id) {
                questions.push(json!({"id":id,"status":"open","source_record_id":q.terms.source_record_id,"criteria_record_id":q.terms.criteria_record_id,"asker_peer_id":q.asker_peer_id,"deadline_height":q.terms.deadline_height,"bounty":q.terms.bounty,"answers":q.answers.len()}));
            } else if let Some(q) = a.machine.state().closed_questions.get(&id) {
                questions.push(json!({"id":id,"status":"closed","outcome":q.outcome}));
            }
        }
        Ok(json!({"status":"ok","questions":questions,"next_cursor":next,"untrusted":true}))
    }
    pub fn blocks(&self, from: u64, limit: usize) -> Result<Value> {
        let a = self.active.as_ref().ok_or(HOLD)?;
        a.room()?;
        if from > ledger::MAX_INTEGER || !(1..=8).contains(&limit) {
            return Err(INVALID);
        }
        let rows=a.node.commits().iter().filter(|c|c.block.height>=from).take(limit).map(|c|Ok(json!({"height":c.block.height,"id":c.block.id()?,"parent":c.block.parent,"previous_state_root":c.block.previous_application_hash,"state_root":c.block.next_application_hash,"round":c.round,"commit_votes":c.precommits.len(),"transaction_ids":c.block.transactions.iter().map(ledger::transaction_id).collect::<Result<Vec<_>>>()?}))).collect::<Result<Vec<_>>>()?;
        Ok(
            json!({"status":"ok","blocks":rows,"pruned_before":a.node.commits().first().map(|c|c.block.height),"head_height":a.machine.state().height,"metadata_only":true,"experiment_only":true}),
        )
    }
    pub fn checkpoint(&self) -> Result<Value> {
        let a = self.active.as_ref().ok_or(HOLD)?;
        a.room()?;
        let checkpoint=a.node.checkpoint().map(|c|json!({"height":c.block.height,"block_id":c.block.id().ok(),"state_root":c.block.next_application_hash,"commit_votes":c.precommits.len()}));
        Ok(
            json!({"status":"ok","checkpoint":checkpoint,"application_height":a.machine.state().height,"application_block_id":a.machine.committed_block_id(),"application_state_root":a.machine.state_root()?,"consensus_height":a.node.height(),"consensus_round":a.node.round(),"retained_from":a.node.commits().first().map(|c|c.block.height),"history_capacity":HISTORY,"pruned_id_capacity":PRUNED_IDS,"experiment_only":true}),
        )
    }
}
