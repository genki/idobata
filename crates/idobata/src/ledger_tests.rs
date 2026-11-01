//! Application tests only. Fixture commit simulates an already authenticated
//! ordered commit; the separate consensus tests verify actual finality.
use super::*;

struct Fixture {
    authority: identity::Keypair,
    keys: Vec<identity::Keypair>,
    document: SignedGenesis,
    machine: Machine,
}
impl Fixture {
    fn with(edit: impl FnOnce(&mut Genesis, &[identity::Keypair])) -> Self {
        let authority = identity::Keypair::generate_ed25519();
        let keys = (0..7)
            .map(|_| identity::Keypair::generate_ed25519())
            .collect::<Vec<_>>();
        let participants = keys
            .iter()
            .enumerate()
            .map(|(i, k)| {
                (
                    k.public().to_peer_id().to_string(),
                    Participant {
                        public_key: crypto::public(k),
                        operator: format!("operator-{i}"),
                        credit: 1000,
                    },
                )
            })
            .collect();
        let mut genesis = Genesis {
            version: 1,
            experiment_only: true,
            room_id: util::hash(b"private experimental room"),
            network_salt: util::hash(b"explicit experiment"),
            authority_peer_id: authority.public().to_peer_id().to_string(),
            operator_epoch: 1,
            participants,
            parameters: Parameters::default(),
            bootstrap_balances: BTreeMap::new(),
        };
        edit(&mut genesis, &keys);
        let document = sign_genesis(&authority, genesis).unwrap();
        let verified = verify_genesis(
            document.clone(),
            &authority.public().to_peer_id().to_string(),
        )
        .unwrap();
        let machine = Machine::new(verified).unwrap();
        Self {
            authority,
            keys,
            document,
            machine,
        }
    }
    fn new() -> Self {
        Self::with(|_, _| {})
    }
    fn peer(&self, key: usize) -> String {
        self.keys[key].public().to_peer_id().to_string()
    }
    fn tx(&self, key: usize, op: Operation) -> SignedTransaction {
        sign_transaction(
            &self.keys[key],
            self.machine.genesis().chain_id(),
            self.machine.next_nonce(&self.peer(key)).unwrap(),
            op,
        )
        .unwrap()
    }
    fn commit(&mut self, txs: Vec<SignedTransaction>) -> Receipt {
        let height = self.machine.state.height + 1;
        let parent = self.machine.state_root().unwrap();
        let block = hash("fixture-ordered-commit", &(height, &parent, &txs)).unwrap();
        self.machine
            .apply_committed(height, &block, &parent, &txs)
            .unwrap()
    }
    fn reject(&self, tx: SignedTransaction) -> Error {
        let before = self.machine.state_root().unwrap();
        let error = self
            .machine
            .validate_batch(self.machine.state.height + 1, &before, &[tx])
            .err()
            .expect("must reject");
        assert_eq!(before, self.machine.state_root().unwrap());
        error
    }
    fn register(&mut self, key: usize, label: &str, bounty: u64, delta: u64) -> String {
        let source = util::hash(label.as_bytes());
        let qid = question_id(self.machine.genesis().chain_id(), &source).unwrap();
        let terms = QuestionTerms {
            source_record_id: source,
            criteria_record_id: util::hash(format!("criteria-{label}").as_bytes()),
            deadline_height: self.machine.state.height + 1 + delta,
            bounty,
            conflict_operators: BTreeSet::new(),
        };
        let tx = self.tx(key, Operation::RegisterQuestion { question: terms });
        self.commit(vec![tx]);
        qid
    }
    fn answer(&mut self, key: usize, question: &str, label: &str) -> String {
        let answer = util::hash(label.as_bytes());
        let tx = self.tx(
            key,
            Operation::SubmitAnswer {
                answer: AnswerSubmission {
                    question_id: question.into(),
                    source_record_id: answer.clone(),
                    beneficiary_peer_id: self.peer(key),
                },
            },
        );
        self.commit(vec![tx]);
        answer
    }
    fn vote_at(
        &self,
        key: usize,
        question: &str,
        answer: &str,
        nonce: u64,
        verdict: Verdict,
    ) -> SignedTransaction {
        let body = self
            .machine
            .acceptance_vote(question, answer, &self.peer(key), nonce, verdict)
            .unwrap();
        let vote = sign_acceptance_vote(&self.keys[key], body).unwrap();
        sign_transaction(
            &self.keys[key],
            self.machine.genesis().chain_id(),
            nonce,
            Operation::CastAcceptanceVote {
                vote: Box::new(vote),
            },
        )
        .unwrap()
    }
    fn vote(
        &self,
        key: usize,
        question: &str,
        answer: &str,
        verdict: Verdict,
    ) -> SignedTransaction {
        self.vote_at(
            key,
            question,
            answer,
            self.machine.next_nonce(&self.peer(key)).unwrap(),
            verdict,
        )
    }
    fn advance(&mut self, height: u64) {
        while self.machine.state.height < height {
            self.commit(vec![]);
        }
    }
    fn verified(&self) -> VerifiedGenesis {
        verify_genesis(
            self.document.clone(),
            &self.authority.public().to_peer_id().to_string(),
        )
        .unwrap()
    }
}

#[test]
fn zero_bootstrap_zero_bounty_reserves_then_expires_without_mint_or_losing_tombstone() {
    let mut f = Fixture::new();
    assert!(f.machine.state.balances.values().all(|n| *n == 0));
    let question = f.register(0, "zero-funded question", 0, 5);
    assert_eq!(
        f.machine.state.epoch_supply[&0],
        EpochSupply {
            minted: 0,
            reserved: 1
        }
    );
    f.advance(6);
    assert!(!f.machine.state.questions.contains_key(&question));
    assert!(matches!(
        f.machine.state.closed_questions[&question].outcome,
        ClosedOutcome::Expired { .. }
    ));
    assert_eq!(f.machine.state.total_minted, 0);
    assert_eq!(f.machine.state.epoch_supply[&0].reserved, 0);
    let terms = QuestionTerms {
        source_record_id: util::hash(b"zero-funded question"),
        criteria_record_id: util::hash(b"different criteria"),
        deadline_height: 20,
        bounty: 0,
        conflict_operators: BTreeSet::new(),
    };
    assert_eq!(
        f.reject(f.tx(1, Operation::RegisterQuestion { question: terms }))
            .error,
        "ledger_question_source_already_used"
    );
}

#[test]
fn third_independent_vote_automatically_mints_and_pays_escrow_in_same_commit() {
    let mut f = Fixture::with(|g, keys| {
        g.bootstrap_balances
            .insert(keys[0].public().to_peer_id().to_string(), 10);
    });
    let q = f.register(0, "funded question", 7, 30);
    let answer = f.answer(1, &q, "original signed answer");
    assert_eq!(f.machine.balance(&f.peer(0)), 3);
    let votes = (2..5)
        .map(|i| f.vote(i, &q, &answer, Verdict::Satisfied))
        .collect();
    let receipt = f.commit(votes);
    assert_eq!(f.machine.balance(&f.peer(1)), 8);
    assert_eq!(f.machine.state.total_minted, 1);
    assert_eq!(
        f.machine.state.epoch_supply[&0],
        EpochSupply {
            minted: 1,
            reserved: 0
        }
    );
    assert!(!f.machine.state.questions.contains_key(&q));
    assert!(matches!(
        f.machine.state.closed_questions[&q].outcome,
        ClosedOutcome::Accepted { .. }
    ));
    assert!(receipt.events.iter().any(|e| matches!(
        e,
        Event::RewardSettled {
            minted: 1,
            bounty: 7,
            ..
        }
    )));
    let transfer = f.tx(
        1,
        Operation::Transfer {
            to_peer_id: f.peer(6),
            amount: 2,
        },
    );
    f.commit(vec![transfer.clone()]);
    assert_eq!(f.machine.balance(&f.peer(1)), 6);
    assert_eq!(f.machine.balance(&f.peer(6)), 2);
    assert_eq!(f.reject(transfer).error, "ledger_nonce_replay_or_gap");
}

#[test]
fn one_operator_four_hosts_never_becomes_independent_support() {
    let mut f = Fixture::with(|g, _| {
        for participant in g.participants.values_mut() {
            participant.operator = "same-owner".into();
        }
    });
    let q = f.register(0, "one owner question", 0, 30);
    let a = f.answer(1, &q, "one owner answer");
    for key in 2..7 {
        assert_eq!(
            f.reject(f.vote(key, &q, &a, Verdict::Satisfied)).error,
            "ledger_conflicted_acceptance_voter"
        );
    }
    let proof = f.machine.acceptance_certificate(&q, &a).unwrap();
    assert_eq!(
        f.reject(f.tx(
            0,
            Operation::SettleAnswer {
                certificate: Box::new(proof)
            }
        ))
        .code,
        10
    );
    assert_eq!(f.machine.state.total_minted, 0);
}

#[test]
fn author_and_two_friends_or_three_weak_groups_cannot_mint() {
    for weak in [false, true] {
        let mut f = Fixture::with(|g, keys| {
            if weak {
                g.participants
                    .get_mut(&keys[4].public().to_peer_id().to_string())
                    .unwrap()
                    .credit = 100;
            }
        });
        let q = f.register(0, "bounded support", 0, 30);
        let a = f.answer(1, &q, "candidate");
        let range = if weak { 2..5 } else { 2..4 };
        let votes = range
            .map(|i| f.vote(i, &q, &a, Verdict::Satisfied))
            .collect();
        f.commit(votes);
        assert_eq!(f.machine.state.total_minted, 0);
        assert!(f.machine.state.questions.contains_key(&q));
    }
}

#[test]
fn two_negative_groups_do_not_veto_three_positive_groups() {
    let mut f = Fixture::new();
    let q = f.register(0, "not a minority veto", 0, 30);
    let a = f.answer(1, &q, "answer");
    let mut votes = (2..5)
        .map(|i| f.vote(i, &q, &a, Verdict::Satisfied))
        .collect::<Vec<_>>();
    votes.extend((5..7).map(|i| f.vote(i, &q, &a, Verdict::Unsatisfied)));
    f.commit(votes);
    assert_eq!(f.machine.state.total_minted, 1);
    assert_eq!(f.machine.balance(&f.peer(1)), 1);
}

#[test]
fn same_operator_latest_committed_vote_wins_not_largest_peer_nonce() {
    let mut f = Fixture::with(|g, keys| {
        g.participants
            .get_mut(&keys[3].public().to_peer_id().to_string())
            .unwrap()
            .operator = "operator-2".into();
        g.bootstrap_balances
            .insert(keys[2].public().to_peer_id().to_string(), 1);
    });
    let q = f.register(0, "canonical commit order", 0, 40);
    let a = f.answer(1, &q, "answer");
    let self_transfers = (1..=5)
        .map(|nonce| {
            sign_transaction(
                &f.keys[2],
                f.machine.genesis().chain_id(),
                nonce,
                Operation::Transfer {
                    to_peer_id: f.peer(2),
                    amount: 1,
                },
            )
            .unwrap()
        })
        .collect();
    f.commit(self_transfers);
    let first = f.vote(2, &q, &a, Verdict::Satisfied);
    assert_eq!(first.signed.nonce, 6);
    let later = f.vote(3, &q, &a, Verdict::Unsatisfied);
    assert_eq!(later.signed.nonce, 1);
    f.commit(vec![first.clone(), later]);
    let certificate = f.machine.acceptance_certificate(&q, &a).unwrap();
    assert_eq!(certificate.votes.len(), 1);
    assert_eq!(certificate.votes[0].signed.voter_peer_id, f.peer(3));
    assert_eq!(certificate.votes[0].signed.verdict, Verdict::Unsatisfied);
    assert_eq!(f.reject(first).error, "ledger_nonce_replay_or_gap");
    let newer = f.vote(2, &q, &a, Verdict::Satisfied);
    f.commit(vec![newer]);
    assert_eq!(
        f.machine.acceptance_certificate(&q, &a).unwrap().votes[0]
            .signed
            .voter_peer_id,
        f.peer(2)
    );
}

#[test]
fn original_author_and_all_declared_conflict_operators_are_excluded() {
    let mut f = Fixture::new();
    let source = util::hash(b"explicit conflicts");
    let q = question_id(f.machine.genesis().chain_id(), &source).unwrap();
    let tx = f.tx(
        0,
        Operation::RegisterQuestion {
            question: QuestionTerms {
                source_record_id: source,
                criteria_record_id: util::hash(b"criteria"),
                deadline_height: 40,
                bounty: 0,
                conflict_operators: BTreeSet::from(["operator-2".into()]),
            },
        },
    );
    f.commit(vec![tx]);
    let a = f.answer(1, &q, "original source");
    for i in 0..3 {
        assert_eq!(
            f.reject(f.vote(i, &q, &a, Verdict::Satisfied)).error,
            "ledger_conflicted_acceptance_voter"
        );
    }
    let copied = util::hash(b"existing author source");
    let finder = f.tx(
        3,
        Operation::SubmitAnswer {
            answer: AnswerSubmission {
                question_id: q.clone(),
                source_record_id: copied.clone(),
                beneficiary_peer_id: f.peer(1),
            },
        },
    );
    f.commit(vec![finder]);
    assert_eq!(
        f.machine.state.questions[&q].answers[&copied].submitted_by_peer_id,
        f.peer(3)
    );
    assert_eq!(
        f.reject(f.vote(3, &q, &copied, Verdict::Satisfied)).error,
        "ledger_conflicted_acceptance_voter"
    );
    let unknown = identity::Keypair::generate_ed25519()
        .public()
        .to_peer_id()
        .to_string();
    let invalid = f.tx(
        3,
        Operation::SubmitAnswer {
            answer: AnswerSubmission {
                question_id: q,
                source_record_id: util::hash(b"unknown author"),
                beneficiary_peer_id: unknown,
            },
        },
    );
    assert_eq!(f.reject(invalid).error, "ledger_unknown_original_author");
}

#[test]
fn signatures_chain_scope_and_useful_feedback_domain_are_not_interchangeable() {
    let mut f = Fixture::new();
    let q = f.register(0, "signed criterion", 0, 30);
    let a = f.answer(1, &q, "answer");
    let good = f.vote(2, &q, &a, Verdict::Satisfied);
    let mut wrong = good.clone();
    wrong.signed.chain_id = util::hash(b"other chain");
    assert_eq!(f.reject(wrong).code, 30);
    let mut wrong = good.clone();
    wrong.signature =
        crypto::sign(&f.keys[2], "idobata.knowledge.review.v1", &wrong.signed).unwrap();
    assert_eq!(f.reject(wrong).code, 30);
    let Operation::CastAcceptanceVote { vote } = good.signed.operation else {
        unreachable!()
    };
    let mut wrong = *vote;
    wrong.signed.bounty = 1;
    wrong.signature = crypto::sign(&f.keys[2], ACCEPTANCE_DOMAIN, &wrong.signed).unwrap();
    assert_eq!(
        f.reject(f.tx(
            2,
            Operation::CastAcceptanceVote {
                vote: Box::new(wrong)
            }
        ))
        .code,
        30
    );
    let mut wrong = f.vote(2, &q, &a, Verdict::Satisfied);
    if let Operation::CastAcceptanceVote { vote } = &mut wrong.signed.operation {
        vote.signature =
            crypto::sign(&f.keys[2], "idobata.knowledge.review.v1", &vote.signed).unwrap();
    }
    wrong.signature = crypto::sign(&f.keys[2], TX_DOMAIN, &wrong.signed).unwrap();
    assert_eq!(f.reject(wrong).code, 30);
}

#[test]
fn optional_fee_is_burned_not_refunded_and_bounty_refund_never_goes_to_trigger() {
    let mut f = Fixture::with(|g, keys| {
        g.parameters.question_fee = 2;
        g.bootstrap_balances
            .insert(keys[0].public().to_peer_id().to_string(), 10);
    });
    let q = f.register(0, "fee and refund", 5, 5);
    assert_eq!(f.machine.balance(&f.peer(0)), 3);
    f.advance(6);
    assert_eq!(f.machine.balance(&f.peer(0)), 8);
    assert_eq!(f.machine.state.total_burned, 2);
    let request = f.tx(1, Operation::RefundExpired { question_id: q });
    f.commit(vec![request.clone()]);
    assert_eq!(f.machine.balance(&f.peer(1)), 0);
    assert_eq!(f.machine.balance(&f.peer(0)), 8);
    assert_eq!(f.reject(request).error, "ledger_nonce_replay_or_gap");
}

#[test]
fn expired_reservation_releases_original_epoch_not_new_epoch() {
    let mut f = Fixture::new();
    f.advance(95);
    let q = f.register(0, "old epoch reservation", 0, 5);
    assert_eq!(f.machine.state.questions[&q].terms.deadline_height, 101);
    f.advance(100);
    assert_eq!(f.machine.state.epoch_supply[&0].reserved, 1);
    let source = util::hash(b"new epoch reservation");
    let tx = f.tx(
        1,
        Operation::RegisterQuestion {
            question: QuestionTerms {
                source_record_id: source,
                criteria_record_id: util::hash(b"criteria"),
                deadline_height: 120,
                bounty: 0,
                conflict_operators: BTreeSet::new(),
            },
        },
    );
    f.commit(vec![tx]);
    assert_eq!(f.machine.state.epoch_supply[&0].reserved, 0);
    assert_eq!(f.machine.state.epoch_supply[&1].reserved, 1);
    assert!(f.machine.state.closed_questions.contains_key(&q));
}

#[test]
fn hard_epoch_cap_is_reserved_before_acceptance_and_failed_batch_is_atomic() {
    let mut f = Fixture::with(|g, _| g.parameters.epoch_mint_cap = 1);
    f.register(0, "reserved budget", 0, 30);
    let q = QuestionTerms {
        source_record_id: util::hash(b"over budget"),
        criteria_record_id: util::hash(b"criteria"),
        deadline_height: 30,
        bounty: 0,
        conflict_operators: BTreeSet::new(),
    };
    assert_eq!(
        f.reject(f.tx(1, Operation::RegisterQuestion { question: q }))
            .error,
        "ledger_epoch_reward_capacity_hold"
    );
    let before = f.machine.export_checkpoint().unwrap();
    let invalid = f.tx(
        2,
        Operation::Transfer {
            to_peer_id: f.peer(3),
            amount: 1,
        },
    );
    let parent = f.machine.state_root().unwrap();
    assert!(f.machine.validate_batch(2, &parent, &[invalid]).is_err());
    assert_eq!(before, f.machine.export_checkpoint().unwrap());
}

#[test]
fn two_spammers_fill_only_own_metadata_while_honest_questions_and_transfers_continue() {
    let mut f = Fixture::with(|g, keys| {
        g.parameters.operator_state_bytes = 8192;
        g.bootstrap_balances
            .insert(keys[0].public().to_peer_id().to_string(), 10);
    });
    let mut txs = vec![];
    for key in 0..2 {
        for n in 0..4 {
            let terms = QuestionTerms {
                source_record_id: util::hash(format!("spam-{key}-{n}").as_bytes()),
                criteria_record_id: util::hash(b"criteria"),
                deadline_height: 6,
                bounty: 0,
                conflict_operators: BTreeSet::new(),
            };
            txs.push(
                sign_transaction(
                    &f.keys[key],
                    f.machine.genesis().chain_id(),
                    n + 1,
                    Operation::RegisterQuestion { question: terms },
                )
                .unwrap(),
            );
        }
    }
    f.commit(txs);
    f.advance(6);
    assert_eq!(f.machine.state.closed_questions.len(), 8);
    let honest = f.register(2, "honest still has dedicated capacity", 0, 30);
    let answer = f.answer(3, &honest, "honest answer");
    assert_eq!(
        f.reject(f.vote(0, &honest, &answer, Verdict::Unsatisfied))
            .error,
        "ledger_operator_state_quota"
    );
    let terms = QuestionTerms {
        source_record_id: util::hash(b"fresh spam"),
        criteria_record_id: util::hash(b"criteria"),
        deadline_height: 30,
        bounty: 0,
        conflict_operators: BTreeSet::new(),
    };
    assert_eq!(
        f.reject(f.tx(0, Operation::RegisterQuestion { question: terms }))
            .error,
        "ledger_operator_state_quota"
    );
    let transfer = f.tx(
        0,
        Operation::Transfer {
            to_peer_id: f.peer(4),
            amount: 1,
        },
    );
    f.commit(vec![transfer]);
    assert_eq!(f.machine.balance(&f.peer(0)), 9);
    assert_eq!(f.machine.balance(&f.peer(4)), 1);
    assert!(f.machine.state.questions.contains_key(&honest));
    assert_eq!(f.machine.state.closed_questions.len(), 8);
}

#[test]
fn authenticated_checkpoint_preserves_nonce_source_and_outcome_and_rejects_rewind() {
    let mut f = Fixture::new();
    let q = f.register(0, "persistent question", 0, 30);
    let a = f.answer(1, &q, "persistent answer");
    let before = f.machine.export_checkpoint().unwrap();
    let votes = (2..5)
        .map(|i| f.vote(i, &q, &a, Verdict::Satisfied))
        .collect();
    f.commit(votes);
    let checkpoint = f.machine.export_checkpoint().unwrap();
    let trusted = checkpoint.clone();
    let verify = |height, block: Option<&str>, root: &str| {
        if height == trusted.height
            && block == trusted.block_id.as_deref()
            && root == trusted.state_root
        {
            Ok(())
        } else {
            Err(INVALID)
        }
    };
    let bytes = util::canonical(&checkpoint).unwrap();
    let decoded: Checkpoint = serde_json::from_slice(&bytes).unwrap();
    let restored = Machine::restore_checkpoint(f.verified(), decoded, verify).unwrap();
    assert_eq!(restored.state(), f.machine.state());
    assert_eq!(restored.balance(&f.peer(1)), 1);
    assert!(Machine::restore_checkpoint(f.verified(), before, verify).is_err());
    let mut forged = checkpoint.clone();
    forged.state.nonces.insert(f.peer(0), 0);
    forged.state_root = hash("idobata.ledger.state.v1", &forged.state).unwrap();
    assert!(Machine::restore_checkpoint(f.verified(), forged, verify).is_err());
    let mut forged = checkpoint;
    forged.state.used_question_sources.clear();
    assert!(Machine::restore_checkpoint(f.verified(), forged, |_, _, _| Ok(())).is_err());
}

#[test]
fn deterministic_replicas_bootstrap_caps_and_integer_bounds_fail_closed() {
    let mut f = Fixture::new();
    let mut replica = Machine::new(f.verified()).unwrap();
    let terms = QuestionTerms {
        source_record_id: util::hash(b"determinism"),
        criteria_record_id: util::hash(b"criteria"),
        deadline_height: 30,
        bounty: 0,
        conflict_operators: BTreeSet::new(),
    };
    let tx = f.tx(0, Operation::RegisterQuestion { question: terms });
    let parent = f.machine.state_root().unwrap();
    let preview = replica
        .validate_batch(1, &parent, std::slice::from_ref(&tx))
        .unwrap();
    let receipt = f.commit(vec![tx.clone()]);
    assert_eq!(preview.state_root, receipt.state_root);
    replica
        .apply_committed(1, &receipt.block_id, &parent, &[tx])
        .unwrap();
    assert_eq!(replica.state(), f.machine.state());
    let tx = f.tx(
        0,
        Operation::Transfer {
            to_peer_id: f.peer(1),
            amount: MAX_INTEGER + 1,
        },
    );
    assert_eq!(f.reject(tx).code, 30);
    assert!(
        sign_transaction(
            &f.keys[0],
            f.machine.genesis().chain_id(),
            MAX_INTEGER + 1,
            Operation::RefundExpired {
                question_id: util::hash(b"x")
            }
        )
        .is_err()
    );
    let mut genesis = f.document.signed.clone();
    genesis.bootstrap_balances.insert(f.peer(0), 101);
    assert!(sign_genesis(&f.authority, genesis).is_err());
    let mut genesis = f.document.signed.clone();
    genesis.experiment_only = false;
    assert!(sign_genesis(&f.authority, genesis).is_err());
}

#[test]
fn finder_can_present_offline_authors_existing_answer_but_cannot_vote_or_take_reward() {
    let mut f = Fixture::new();
    let q = f.register(0, "finder reuse", 0, 30);
    let answer = util::hash(b"offline authors existing signed record");
    let submit = f.tx(
        2,
        Operation::SubmitAnswer {
            answer: AnswerSubmission {
                question_id: q.clone(),
                source_record_id: answer.clone(),
                beneficiary_peer_id: f.peer(1),
            },
        },
    );
    f.commit(vec![submit]);
    assert_eq!(f.machine.state.nonces[&f.peer(1)], 0); // Original author sends no ledger transaction.
    for voter in [0, 1, 2] {
        assert_eq!(
            f.reject(f.vote(voter, &q, &answer, Verdict::Satisfied))
                .error,
            "ledger_conflicted_acceptance_voter"
        );
    }
    let votes = (3..6)
        .map(|v| f.vote(v, &q, &answer, Verdict::Satisfied))
        .collect();
    f.commit(votes);
    assert_eq!(f.machine.balance(&f.peer(1)), 1);
    assert_eq!(f.machine.balance(&f.peer(2)), 0);
    assert!(
        matches!(&f.machine.state.closed_questions[&q].outcome,ClosedOutcome::Accepted{submitted_by_peer_id,beneficiary_peer_id,..} if submitted_by_peer_id==&f.peer(2) && beneficiary_peer_id==&f.peer(1))
    );
}

#[test]
#[ignore = "explicit optimized stress check; fills both default operator lifetime quotas through committed expiry"]
fn default_two_operator_quota_does_not_exhaust_honest_registration_or_transfers() {
    let mut f = Fixture::with(|g, keys| {
        g.bootstrap_balances
            .insert(keys[0].public().to_peer_id().to_string(), 10);
    });
    let started = std::time::Instant::now();
    for epoch in 0..16 {
        f.advance(epoch * 100);
        for batch in 0..2 {
            let height = f.machine.state.height + 1;
            let mut txs = vec![];
            for key in 0..2 {
                let base = f.machine.next_nonce(&f.peer(key)).unwrap();
                for item in 0..4 {
                    let label = format!("default-spam-{epoch}-{batch}-{key}-{item}");
                    let terms = QuestionTerms {
                        source_record_id: util::hash(label.as_bytes()),
                        criteria_record_id: util::hash(b"criteria"),
                        deadline_height: height + 5,
                        bounty: 0,
                        conflict_operators: BTreeSet::new(),
                    };
                    txs.push(
                        sign_transaction(
                            &f.keys[key],
                            f.machine.genesis().chain_id(),
                            base + item,
                            Operation::RegisterQuestion { question: terms },
                        )
                        .unwrap(),
                    );
                }
            }
            f.commit(txs);
            f.advance(height + 5);
        }
    }
    assert_eq!(f.machine.state.closed_questions.len(), 256);
    let metadata = f.machine.state.closed_questions.values().fold(
        BTreeMap::<String, u64>::new(),
        |mut map, q| {
            *map.entry(q.asker_operator.clone()).or_default() += q.metadata_reservation;
            map
        },
    );
    assert_eq!(metadata.len(), 2);
    assert!(metadata.values().all(|n| *n == 256 * 1024));
    // The last spam batch consumed epoch15's eighth registration attempt. Start
    // an unused epoch before the independent lifetime-quota probe, so neither
    // that limit nor an expired honest question can shadow the tested boundary.
    f.advance(16 * 100);
    assert!(!f.machine.state.operator_attempts.contains_key(&16));
    let honest = f.register(2, "honest under full attacker lifetime quota", 0, 30);
    assert!(!f.machine.state.operator_attempts[&16].contains_key("operator-0"));
    let terms = QuestionTerms {
        source_record_id: util::hash(b"default fresh spam rejected"),
        criteria_record_id: util::hash(b"criteria"),
        deadline_height: f.machine.state.height + 20,
        bounty: 0,
        conflict_operators: BTreeSet::new(),
    };
    assert_eq!(
        f.reject(f.tx(0, Operation::RegisterQuestion { question: terms }))
            .error,
        "ledger_operator_state_quota"
    );
    let transfer = f.tx(
        0,
        Operation::Transfer {
            to_peer_id: f.peer(4),
            amount: 1,
        },
    );
    let start = std::time::Instant::now();
    f.commit(vec![transfer]);
    let transfer_time = start.elapsed();
    assert_eq!(f.machine.balance(&f.peer(4)), 1);
    assert!(f.machine.state.questions.contains_key(&honest));
    let state_bytes = util::canonical(f.machine.state()).unwrap().len();
    eprintln!(
        "ledger_default_quota closed=256 operator_charge=262144x2 state_bytes={state_bytes} transfer_ms={:.3} setup_seconds={:.3}",
        transfer_time.as_secs_f64() * 1000.0,
        started.elapsed().as_secs_f64()
    );
    assert!(transfer_time < std::time::Duration::from_secs(7));
}
