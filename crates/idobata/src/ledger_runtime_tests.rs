use super::*;
use crate::{
    knowledge::{KnowledgeInput, RecordPacket},
    knowledge_abuse::OperatorClaims,
    types::Member,
};

struct Fixture {
    _temp: tempfile::TempDir,
    homes: Vec<PathBuf>,
    keys: Vec<identity::Keypair>,
    members: Vec<Member>,
    settings: Settings,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let homes = (0..5)
            .map(|i| temp.path().join(format!("peer-{i}")))
            .collect::<Vec<_>>();
        let members = homes
            .iter()
            .enumerate()
            .map(|(i, home)| {
                config::init(home, vec![format!("/ip4/127.0.0.1/tcp/{}", 41000 + i)]).unwrap()
            })
            .collect::<Vec<_>>();
        let keys = homes
            .iter()
            .map(|home| crypto::load_key(home).unwrap())
            .collect::<Vec<_>>();
        let claims = OperatorClaims {
            bindings: members
                .iter()
                .enumerate()
                .map(|(i, m)| (m.peer_id.clone(), format!("operator-{i}")))
                .collect(),
            credits: (0..5).map(|i| (format!("operator-{i}"), 1000)).collect(),
        };
        let room = config::create_room_with_operators(
            &homes[0],
            "ledger",
            members.clone(),
            1,
            false,
            false,
            Some(claims),
        )
        .unwrap();
        for home in &homes[1..] {
            config::join_room(home, "ledger", room.clone(), &members[0].peer_id).unwrap();
        }
        let application = ledger::sign_genesis(
            &keys[0],
            ledger::Genesis {
                version: 1,
                experiment_only: true,
                room_id: room.signed.room_id,
                network_salt: util::hash(b"private runtime test"),
                authority_peer_id: members[0].peer_id.clone(),
                operator_epoch: 1,
                participants: members
                    .iter()
                    .enumerate()
                    .map(|(i, m)| {
                        (
                            m.peer_id.clone(),
                            ledger::Participant {
                                public_key: m.public_key.clone(),
                                operator: format!("operator-{i}"),
                                credit: 1000,
                            },
                        )
                    })
                    .collect(),
                parameters: ledger::Parameters::default(),
                bootstrap_balances: members.iter().map(|m| (m.peer_id.clone(), 10)).collect(),
            },
        )
        .unwrap();
        let machine =
            Machine::new(ledger::verify_genesis(application.clone(), &members[0].peer_id).unwrap())
                .unwrap();
        let consensus = consensus::sign_genesis(
            &keys[0],
            consensus::Genesis {
                version: 1,
                chain_id: machine.genesis().chain_id().into(),
                application_genesis_hash: machine.genesis().genesis_hash().into(),
                initial_application_hash: machine.state_root().unwrap(),
                validators: members[..4]
                    .iter()
                    .enumerate()
                    .map(|(i, m)| consensus::Validator {
                        peer_id: m.peer_id.clone(),
                        public_key: m.public_key.clone(),
                        operator: format!("operator-{i}"),
                    })
                    .collect(),
                fault_bound: 1,
                quorum: 3,
                timeout_ms: 3000,
                experiment_only: true,
            },
        )
        .unwrap();
        let settings = Settings {
            version: 1,
            room_alias: "ledger".into(),
            authority_peer_id: members[0].peer_id.clone(),
            application,
            consensus,
        };
        Self {
            _temp: temp,
            homes,
            keys,
            members,
            settings,
        }
    }
    fn runtime(&self, i: usize) -> Runtime {
        configure(&self.homes[i], &self.settings).unwrap();
        let r = Runtime::open(&self.homes[i], self.keys[i].clone()).unwrap();
        assert!(r.active.is_some(), "{}", r.status());
        r
    }
    fn record(&self, i: usize, problem: &str) -> RecordPacket {
        let room = config::load(&self.homes[i]).unwrap().rooms["ledger"].clone();
        knowledge::create_record(
            &self.keys[i],
            &room,
            KnowledgeInput {
                problem: problem.into(),
                solution: "Use the documented procedure and verify its result.".into(),
                context: "A controlled test environment.".into(),
                references: vec![],
                kind: "answer".into(),
            },
            false,
            util::now(),
        )
        .unwrap()
    }
    fn certify(&self, a: &Active, transactions: Vec<SignedTransaction>) -> CommitCertificate {
        let previous_application_hash = a.machine.state_root().unwrap();
        let next = a
            .machine
            .validate_batch(a.node.height(), &previous_application_hash, &transactions)
            .unwrap();
        let parent = a
            .node
            .commits()
            .last()
            .map(|c| c.block.id().unwrap())
            .unwrap_or_else(|| a.node.genesis_hash().into());
        let block = consensus::Block {
            height: a.node.height(),
            parent,
            previous_application_hash,
            next_application_hash: next.state_root,
            transactions,
        };
        let precommits = (0..3)
            .map(|i| {
                let signed = consensus::VoteBody {
                    genesis_hash: a.node.genesis_hash().into(),
                    height: block.height,
                    round: 0,
                    phase: consensus::Phase::Precommit,
                    validator: self.members[i].peer_id.clone(),
                    block_id: Some(block.id().unwrap()),
                };
                Signed {
                    signature: crypto::sign(&self.keys[i], "idobata.ledger.vote.v1", &signed)
                        .unwrap(),
                    public_key: crypto::public(&self.keys[i]),
                    signed,
                }
            })
            .collect();
        CommitCertificate {
            genesis_hash: a.node.genesis_hash().into(),
            round: 0,
            block,
            precommits,
        }
    }
}

#[test]
fn ordinary_wallet_can_submit_but_cannot_sign_consensus_phases() {
    let f = Fixture::new();
    let mut r = f.runtime(4);
    assert!(!r.active.as_ref().unwrap().node.is_validator());
    let result = r
        .submit(
            Operation::Transfer {
                to_peer_id: f.members[0].peer_id.clone(),
                amount: 1,
            },
            vec![],
        )
        .unwrap();
    assert_eq!(result["finalized"], false);
    assert!(r.active.as_mut().unwrap().node.timeout().is_err());
    assert_eq!(r.active.as_ref().unwrap().pool[0].signed.nonce, 1);
}

#[test]
fn invalid_initial_root_is_rejected_before_immutable_settings_write() {
    let f = Fixture::new();
    let mut settings = f.settings.clone();
    let mut genesis = settings.consensus.signed;
    genesis.initial_application_hash = util::hash(b"wrong initial application root");
    settings.consensus = consensus::sign_genesis(&f.keys[0], genesis).unwrap();
    assert!(configure(&f.homes[0], &settings).is_err());
    assert!(!f.homes[0].join("ledger-settings.json").exists());
}

#[test]
fn unsynchronized_vote_inputs_hold_before_signing_or_consuming_a_nonce() {
    let f = Fixture::new();
    let mut runtime = f.runtime(4);
    let unknown_question = util::hash(b"not yet synchronized question");
    let unknown_answer = util::hash(b"not yet synchronized answer");
    assert_eq!(
        runtime
            .required_vote_records(&unknown_question, &unknown_answer)
            .unwrap_err()
            .code,
        HOLD.code
    );
    assert_eq!(
        runtime
            .cast_vote(
                &unknown_question,
                &unknown_answer,
                Verdict::Satisfied,
                vec![]
            )
            .unwrap_err()
            .code,
        HOLD.code
    );
    let a = runtime.active.as_mut().unwrap();
    let chain = a.machine.genesis().chain_id().to_owned();
    let source = f.record(0, "A committed question before its answer is synchronized.");
    let criteria = f.record(
        0,
        "The question has independently testable expected conditions.",
    );
    let question = ledger::question_id(&chain, &source.record.signed.id).unwrap();
    let transaction = ledger::sign_transaction(
        &f.keys[0],
        &chain,
        1,
        Operation::RegisterQuestion {
            question: ledger::QuestionTerms {
                source_record_id: source.record.signed.id,
                criteria_record_id: criteria.record.signed.id,
                deadline_height: 9,
                bounty: 0,
                conflict_operators: BTreeSet::new(),
            },
        },
    )
    .unwrap();
    let certificate = f.certify(a, vec![transaction]);
    a.node.import_commit(certificate, &a.machine).unwrap();
    a.committed().unwrap();
    assert_eq!(
        runtime
            .cast_vote(&question, &unknown_answer, Verdict::Satisfied, vec![])
            .unwrap_err()
            .code,
        HOLD.code
    );
    assert_eq!(
        runtime
            .required_vote_records(&question, "malformed")
            .unwrap_err()
            .code,
        INVALID.code
    );
    let a = runtime.active.as_ref().unwrap();
    assert!(a.pool.is_empty());
    assert!(
        a.history
            .values()
            .all(|tracked| tracked.signer != f.members[4].peer_id)
    );
    assert!(a.node.local_votes().is_empty());
    assert_eq!(a.machine.next_nonce(&f.members[4].peer_id).unwrap(), 1);
}

#[test]
fn authority_signed_invalid_consensus_structure_never_becomes_immutable_settings() {
    let f = Fixture::new();
    let mut settings = f.settings.clone();
    settings.consensus.signed.quorum = 2;
    settings.consensus.signature = crypto::sign(
        &f.keys[0],
        "idobata.ledger.genesis.v1",
        &settings.consensus.signed,
    )
    .unwrap();
    assert!(configure(&f.homes[0], &settings).is_err());
    assert!(!f.homes[0].join("ledger-settings.json").exists());
}

#[test]
fn corrupt_ledger_isolated_as_fault_without_destroying_knowledge_store() {
    let f = Fixture::new();
    configure(&f.homes[0], &f.settings).unwrap();
    util::atomic_write(
        &f.homes[0].join("ledger-application.enc"),
        b"corrupt private test fixture",
    )
    .unwrap();
    let runtime = Runtime::open(&f.homes[0], f.keys[0].clone()).unwrap();
    assert_eq!(runtime.status()["status"], "fault");
    assert!(knowledge::Store::open(&f.homes[0]).is_ok());
    assert_eq!(
        std::fs::read(f.homes[0].join("ledger-application.enc")).unwrap(),
        b"corrupt private test fixture"
    );
}

#[test]
fn pending_question_proofs_and_nonce_reservation_survive_restart() {
    let f = Fixture::new();
    let source = f.record(0, "How can the result be verified?");
    let criteria = f.record(0, "The command must complete and its result must match.");
    let mut r = f.runtime(0);
    r.submit(
        Operation::RegisterQuestion {
            question: ledger::QuestionTerms {
                source_record_id: source.record.signed.id.clone(),
                criteria_record_id: criteria.record.signed.id.clone(),
                deadline_height: 7,
                bounty: 0,
                conflict_operators: BTreeSet::new(),
            },
        },
        vec![source, criteria],
    )
    .unwrap();
    assert_eq!(r.active.as_ref().unwrap().pool.len(), 1);
    drop(r);
    let mut r = f.runtime(0);
    assert_eq!(r.active.as_ref().unwrap().proofs.len(), 2);
    r.submit(
        Operation::Transfer {
            to_peer_id: f.members[1].peer_id.clone(),
            amount: 1,
        },
        vec![],
    )
    .unwrap();
    assert_eq!(r.active.as_ref().unwrap().pool[1].signed.nonce, 2);
    let disk = std::fs::read(f.homes[0].join("ledger-application.enc")).unwrap();
    assert!(
        !disk
            .windows(b"How can the result be verified?".len())
            .any(|w| w == b"How can the result be verified?")
    );
}

#[test]
fn acceptance_vote_uses_outer_account_nonce_after_other_activity() {
    let f = Fixture::new();
    let mut r = f.runtime(2);
    let a = r.active.as_mut().unwrap();
    let question = f.record(0, "How should the procedure be verified?");
    let criteria = f.record(0, "The documented result must be reproduced.");
    let answer = f.record(1, "A procedure that reproduces the expected result.");
    let qid =
        ledger::question_id(a.machine.genesis().chain_id(), &question.record.signed.id).unwrap();
    let aid = answer.record.signed.id.clone();
    a.remember(vec![question.clone(), criteria.clone(), answer.clone()])
        .unwrap();
    let txs = vec![
        ledger::sign_transaction(
            &f.keys[0],
            a.machine.genesis().chain_id(),
            1,
            Operation::RegisterQuestion {
                question: ledger::QuestionTerms {
                    source_record_id: question.record.signed.id.clone(),
                    criteria_record_id: criteria.record.signed.id.clone(),
                    deadline_height: 9,
                    bounty: 0,
                    conflict_operators: BTreeSet::new(),
                },
            },
        )
        .unwrap(),
        ledger::sign_transaction(
            &f.keys[1],
            a.machine.genesis().chain_id(),
            1,
            Operation::SubmitAnswer {
                answer: ledger::AnswerSubmission {
                    question_id: qid.clone(),
                    source_record_id: aid.clone(),
                    beneficiary_peer_id: f.members[1].peer_id.clone(),
                },
            },
        )
        .unwrap(),
        ledger::sign_transaction(
            &f.keys[2],
            a.machine.genesis().chain_id(),
            1,
            Operation::Transfer {
                to_peer_id: f.members[3].peer_id.clone(),
                amount: 1,
            },
        )
        .unwrap(),
    ];
    let cert = f.certify(a, txs);
    a.node.import_commit(cert, &a.machine).unwrap();
    a.committed().unwrap();
    r.cast_vote(
        &qid,
        &aid,
        Verdict::Satisfied,
        vec![question, criteria, answer],
    )
    .unwrap();
    let tx = &r.active.as_ref().unwrap().pool[0];
    assert_eq!(tx.signed.nonce, 2);
    let Operation::CastAcceptanceVote { vote } = &tx.signed.operation else {
        panic!("expected typed vote")
    };
    assert_eq!(vote.signed.sequence, 2);
}

#[test]
fn removal_of_a_wallet_participant_holds_the_fixed_private_ledger() {
    let f = Fixture::new();
    let mut r = f.runtime(0);
    r.active.as_mut().unwrap().needs_snapshot = true;
    assert_eq!(r.status()["reason"], "application_checkpoint_required");
    let members = f.members[..4].to_vec();
    let policy = OperatorClaims {
        bindings: members
            .iter()
            .enumerate()
            .map(|(i, m)| (m.peer_id.clone(), format!("operator-{i}")))
            .collect(),
        credits: (0..4).map(|i| (format!("operator-{i}"), 1000)).collect(),
    };
    config::create_room_with_operators(
        &f.homes[0],
        "ledger",
        members,
        1,
        false,
        false,
        Some(policy),
    )
    .unwrap();
    assert!(r.active.as_ref().unwrap().room().is_err());
    assert_eq!(r.status()["status"], "hold");
    assert_eq!(r.status()["reason"], "ledger_room_authorization_changed");
    r.active.as_mut().unwrap().fault = Some("ledger_storage_or_replay_failed");
    assert_eq!(r.status()["status"], "fault");
    assert_eq!(r.status()["reason"], "ledger_storage_or_replay_failed");
}

#[test]
fn snapshot_hash_failure_is_atomic_and_valid_snapshot_advances_wallet() {
    let f = Fixture::new();
    let mut source = f.runtime(0);
    let a = source.active.as_mut().unwrap();
    let cert = f.certify(a, vec![]);
    a.node.import_commit(cert, &a.machine).unwrap();
    a.committed().unwrap();
    let WireReply::Snapshot {
        certificate,
        digest,
        total,
        offset,
        bytes,
    } = a.snapshot(0, None).unwrap()
    else {
        panic!("snapshot")
    };
    let mut target = f.runtime(4);
    let a = target.active.as_mut().unwrap();
    let before = a.machine.state_root().unwrap();
    let mut bad = bytes.clone();
    bad[0] ^= 1;
    assert!(
        a.snapshot_received(
            f.members[0].peer_id.parse().unwrap(),
            *certificate.clone(),
            digest.clone(),
            total,
            offset,
            bad
        )
        .is_err()
    );
    assert_eq!(a.machine.state_root().unwrap(), before);
    a.snapshot_received(
        f.members[0].peer_id.parse().unwrap(),
        *certificate,
        digest,
        total,
        offset,
        bytes,
    )
    .unwrap();
    assert_eq!(a.machine.state().height, 1);
    assert_eq!(a.node.height(), 2);
}

#[test]
fn same_head_core_snapshot_recovery_keeps_next_height_signing_journal() {
    let f = Fixture::new();
    let mut r = f.runtime(0);
    let a = r.active.as_mut().unwrap();
    let cert = f.certify(a, vec![]);
    a.node.import_commit(cert, &a.machine).unwrap();
    a.committed().unwrap();
    let WireReply::Snapshot {
        certificate,
        digest,
        total,
        offset,
        bytes,
    } = a.snapshot(0, None).unwrap()
    else {
        panic!("snapshot")
    };
    let next = f.certify(a, vec![]).block;
    let body = consensus::ProposalBody {
        genesis_hash: a.node.genesis_hash().into(),
        round: 0,
        proposer: f.members[1].peer_id.clone(),
        block: next,
        valid_round: None,
        valid_votes: vec![],
    };
    let proposal = Signed {
        signature: crypto::sign(&f.keys[1], "idobata.ledger.proposal.v1", &body).unwrap(),
        public_key: f.members[1].public_key.clone(),
        signed: body,
    };
    let vote = a.node.prevote(&proposal, &a.machine).unwrap();
    a.machine = Machine::new(
        ledger::verify_genesis(f.settings.application.clone(), &f.members[0].peer_id).unwrap(),
    )
    .unwrap();
    a.needs_snapshot = true;
    a.snapshot_received(
        f.members[1].peer_id.parse().unwrap(),
        *certificate,
        digest,
        total,
        offset,
        bytes,
    )
    .unwrap();
    assert_eq!(a.machine.state().height, 1);
    assert_eq!(a.node.local_votes()[0].signature, vote.signature);
    assert_eq!(a.node.height(), 2);
    assert!(!a.needs_snapshot);
}

#[test]
fn conflicting_same_nonce_transaction_is_removed_on_another_transactions_commit() {
    let f = Fixture::new();
    let mut left = f.runtime(0);
    let mut right = f.runtime(1);
    let chain = left
        .active
        .as_ref()
        .unwrap()
        .machine
        .genesis()
        .chain_id()
        .to_owned();
    let txa = ledger::sign_transaction(
        &f.keys[0],
        &chain,
        1,
        Operation::Transfer {
            to_peer_id: f.members[1].peer_id.clone(),
            amount: 1,
        },
    )
    .unwrap();
    let txb = ledger::sign_transaction(
        &f.keys[0],
        &chain,
        1,
        Operation::Transfer {
            to_peer_id: f.members[2].peer_id.clone(),
            amount: 2,
        },
    )
    .unwrap();
    let replaced_id = ledger::transaction_id(&txb).unwrap();
    let confirmed_id = ledger::transaction_id(&txa).unwrap();
    left.active
        .as_mut()
        .unwrap()
        .admit(txa.clone(), vec![])
        .unwrap();
    right.active.as_mut().unwrap().admit(txb, vec![]).unwrap();
    let cert = f.certify(left.active.as_ref().unwrap(), vec![txa]);
    for runtime in [&mut left, &mut right] {
        let a = runtime.active.as_mut().unwrap();
        a.node.import_commit(cert.clone(), &a.machine).unwrap();
        a.committed().unwrap();
        assert!(a.pool.is_empty());
    }
    assert_eq!(
        left.active.as_ref().unwrap().machine.state_root().unwrap(),
        right.active.as_ref().unwrap().machine.state_root().unwrap()
    );
    assert_eq!(
        right.transaction(&replaced_id).unwrap()["status"],
        "expired_or_replaced"
    );
    assert_eq!(
        right.transaction(&confirmed_id).unwrap()["status"],
        "confirmed"
    );
    let a = right.active.as_mut().unwrap();
    let next = a
        .machine
        .validate_batch(a.node.height(), &a.machine.state_root().unwrap(), &[])
        .unwrap();
    assert!(a.node.propose(vec![], next.state_root, &a.machine).is_ok());
}

#[test]
fn failed_or_unrelated_proof_admission_leaves_no_cache_history_or_disk_mutation() {
    let f = Fixture::new();
    let mut runtime = f.runtime(0);
    let packet = f.record(0, "A packet unrelated to this transfer.");
    let a = runtime.active.as_mut().unwrap();
    let before = std::fs::read(f.homes[0].join("ledger-application.enc")).unwrap();
    let mut invalid = ledger::sign_transaction(
        &f.keys[0],
        a.machine.genesis().chain_id(),
        1,
        Operation::Transfer {
            to_peer_id: f.members[1].peer_id.clone(),
            amount: 1,
        },
    )
    .unwrap();
    invalid.signature = crypto::encode(&[0; 64]);
    assert!(a.admit(invalid, vec![packet.clone()]).is_err());
    let valid = ledger::sign_transaction(
        &f.keys[0],
        a.machine.genesis().chain_id(),
        1,
        Operation::Transfer {
            to_peer_id: f.members[1].peer_id.clone(),
            amount: 1,
        },
    )
    .unwrap();
    assert!(a.admit(valid, vec![packet]).is_err());
    assert!(a.proofs.is_empty());
    assert!(a.history.is_empty());
    assert!(a.pool.is_empty());
    assert_eq!(
        std::fs::read(f.homes[0].join("ledger-application.enc")).unwrap(),
        before
    );
}

#[test]
fn finder_can_reuse_offline_authors_record_but_cannot_redirect_its_reward() {
    let f = Fixture::new();
    let mut runtime = f.runtime(2);
    let source = f.record(1, "A question whose answer already exists.");
    let criteria = f.record(
        1,
        "The original documented answer satisfies these conditions.",
    );
    let original = f.record(
        0,
        "An existing signed answer from an offline original author.",
    );
    let a = runtime.active.as_mut().unwrap();
    let qid =
        ledger::question_id(a.machine.genesis().chain_id(), &source.record.signed.id).unwrap();
    let register = ledger::sign_transaction(
        &f.keys[1],
        a.machine.genesis().chain_id(),
        1,
        Operation::RegisterQuestion {
            question: ledger::QuestionTerms {
                source_record_id: source.record.signed.id,
                criteria_record_id: criteria.record.signed.id,
                deadline_height: 9,
                bounty: 0,
                conflict_operators: BTreeSet::new(),
            },
        },
    )
    .unwrap();
    let cert = f.certify(a, vec![register]);
    a.node.import_commit(cert, &a.machine).unwrap();
    a.committed().unwrap();
    let forged = ledger::sign_transaction(
        &f.keys[2],
        a.machine.genesis().chain_id(),
        1,
        Operation::SubmitAnswer {
            answer: ledger::AnswerSubmission {
                question_id: qid.clone(),
                source_record_id: original.record.signed.id.clone(),
                beneficiary_peer_id: f.members[2].peer_id.clone(),
            },
        },
    )
    .unwrap();
    assert!(a.admit(forged, vec![original.clone()]).is_err());
    assert!(a.pool.is_empty());
    assert!(a.proofs.is_empty());
    let valid = ledger::sign_transaction(
        &f.keys[2],
        a.machine.genesis().chain_id(),
        1,
        Operation::SubmitAnswer {
            answer: ledger::AnswerSubmission {
                question_id: qid.clone(),
                source_record_id: original.record.signed.id.clone(),
                beneficiary_peer_id: f.members[0].peer_id.clone(),
            },
        },
    )
    .unwrap();
    a.admit(valid, vec![original]).unwrap();
    assert_eq!(a.pool.len(), 1);
}

#[test]
fn unpinned_proof_cache_turnover_does_not_permanently_hold_after_32_records() {
    let f = Fixture::new();
    let mut runtime = f.runtime(0);
    for i in 0..MAX_PROOFS + 2 {
        let record = f.record(0, &format!("A normal documented example number {i}."));
        let id = record.record.signed.id.clone();
        runtime
            .active
            .as_mut()
            .unwrap()
            .remember(vec![record])
            .unwrap();
        let a = runtime.active.as_ref().unwrap();
        assert!(a.proofs.len() <= MAX_PROOFS);
        assert!(a.proofs.contains_key(&id));
    }
    assert_eq!(runtime.active.as_ref().unwrap().proofs.len(), MAX_PROOFS);
}

#[test]
fn immutable_record_validation_measurement_and_current_certificate_scope() {
    let f = Fixture::new();
    let runtime = f.runtime(0);
    let a = runtime.active.as_ref().unwrap();
    let record = f.record(0, "A fixed immutable procedure for timing validation.");
    let room = a.room().unwrap();
    for _ in 0..12 {
        a.validate_record_cached(&record, &room).unwrap();
    }
    let mut renewed = room.clone();
    renewed.certificate.signed.epoch += 1;
    renewed.certificate.signature =
        crypto::sign(&f.keys[0], "idobata.room.v1", &renewed.certificate.signed).unwrap();
    a.validate_record_cached(&record, &renewed).unwrap();
    let mut changed = record.clone();
    changed
        .record
        .signed
        .solution
        .push_str(" A tampered addition.");
    assert!(a.validate_record_cached(&changed, &renewed).is_err());
    let before = a.timings.json();
    for (_, prior_check) in a.validation_cache.borrow_mut().values_mut() {
        *prior_check = util::now() + 60;
    }
    a.validate_record_cached(&record, &room).unwrap();
    assert_eq!(
        a.timings.json()["record_cache_hits"],
        before["record_cache_hits"]
    );
    // Simulate a packet cached before the wall clock moved backwards: its
    // creation was within the former +300s window but lies outside it now.
    let mut future = record;
    future.record.signed.created_at = util::now() + 301;
    future.record.signature = crypto::sign(
        &f.keys[0],
        "idobata.knowledge.record.v1",
        &future.record.signed,
    )
    .unwrap();
    let key = (
        util::hash(&util::canonical(&future).unwrap()),
        util::hash(&util::canonical(&room).unwrap()),
    );
    a.validation_cache.borrow_mut().insert(
        key,
        (Instant::now() + Duration::from_secs(30), util::now() + 1),
    );
    assert!(a.validate_record_cached(&future, &room).is_err());
    assert_eq!(
        a.timings.json()["record_cache_hits"],
        before["record_cache_hits"]
    );
    println!(
        "{}",
        json!({"case":"immutable_record_validation","cache_enabled":timing::CACHE_ENABLED,"measurements":a.timings.json()})
    );
}

#[test]
fn missing_initialized_wal_is_a_ledger_only_fault_and_is_not_recreated() {
    let f = Fixture::new();
    let runtime = f.runtime(0);
    drop(runtime);
    let wal = f.homes[0].join("ledger-consensus.enc");
    assert!(f.homes[0].join("ledger-consensus.initialized").exists());
    std::fs::remove_file(&wal).unwrap();
    let reopened = Runtime::open(&f.homes[0], f.keys[0].clone()).unwrap();
    assert_eq!(reopened.status()["status"], "fault");
    assert!(!wal.exists());
    assert!(knowledge::Store::open(&f.homes[0]).is_ok());
}

#[test]
fn failed_disk_admission_rolls_back_pending_history_and_faults_only_ledger() {
    let f = Fixture::new();
    let mut runtime = f.runtime(0);
    let path = f.homes[0].join("ledger-application.enc");
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(
        runtime
            .submit(
                Operation::Transfer {
                    to_peer_id: f.members[1].peer_id.clone(),
                    amount: 1
                },
                vec![]
            )
            .is_err()
    );
    let a = runtime.active.as_ref().unwrap();
    assert!(a.pool.is_empty());
    assert!(a.history.is_empty());
    assert_eq!(runtime.status()["status"], "fault");
}

#[test]
fn scanner_code22_is_rejected_without_fault_but_real_storage_failure_stops_the_ledger() {
    assert!(storage_failure(&STORAGE));
    assert!(!storage_failure(&crate::error::SCANNER));
    assert!(!storage_failure(&Error::new(
        22,
        "knowledge_content_rejected"
    )));
    assert!(!storage_failure(&Error::new(30, STORAGE.error)));
    let f = Fixture::new();
    let mut local = f.runtime(0);
    let mut blocked = f.record(0, "A valid record before adversarial content is attached.");
    blocked.record.signed.problem = "A forbidden directional control: \u{202e}".into();
    // The attacker has its own valid member key: make the content ID and author
    // signature correct, leaving actual scanner rejection as the only defect.
    let mut content = serde_json::to_value(&blocked.record.signed).unwrap();
    let fields = content.as_object_mut().unwrap();
    fields.remove("id");
    fields.remove("created_at");
    blocked.record.signed.id = util::hash(&util::canonical(&content).unwrap());
    blocked.record.signature = crypto::sign(
        &f.keys[0],
        "idobata.knowledge.record.v1",
        &blocked.record.signed,
    )
    .unwrap();
    let criteria = f.record(0, "The documented conditions for accepting an answer.");
    let operation = Operation::RegisterQuestion {
        question: ledger::QuestionTerms {
            source_record_id: blocked.record.signed.id.clone(),
            criteria_record_id: criteria.record.signed.id.clone(),
            deadline_height: 9,
            bounty: 0,
            conflict_operators: BTreeSet::new(),
        },
    };
    let records = vec![blocked, criteria];
    let local_disk = std::fs::read(f.homes[0].join("ledger-application.enc")).unwrap();
    let signing_wal = std::fs::read(f.homes[0].join("ledger-consensus.enc")).unwrap();
    let error = local
        .submit(operation.clone(), records.clone())
        .unwrap_err();
    assert_eq!(error.code, 22);
    assert_eq!(error.error, "knowledge_content_rejected");
    assert_eq!(local.status()["status"], "ready");
    let a = local.active.as_ref().unwrap();
    assert!(a.pool.is_empty() && a.history.is_empty() && a.proofs.is_empty());
    assert_eq!(a.machine.next_nonce(&f.members[0].peer_id).unwrap(), 1);
    assert_eq!(
        std::fs::read(f.homes[0].join("ledger-application.enc")).unwrap(),
        local_disk
    );
    assert_eq!(
        std::fs::read(f.homes[0].join("ledger-consensus.enc")).unwrap(),
        signing_wal
    );

    let mut remote = f.runtime(1);
    let peer = f.members[0].peer_id.parse().unwrap();
    let chain = remote
        .active
        .as_ref()
        .unwrap()
        .machine
        .genesis()
        .chain_id()
        .to_owned();
    let rejected = WireRequest::Submit {
        transaction: Box::new(ledger::sign_transaction(&f.keys[0], &chain, 1, operation).unwrap()),
        records,
    };
    let reply = remote
        .active
        .as_mut()
        .unwrap()
        .receive(peer, &serde_json::to_vec(&rejected).unwrap());
    assert!(matches!(reply, WireReply::Rejected { code: 22 }));
    assert_eq!(remote.status()["status"], "ready");
    let a = remote.active.as_ref().unwrap();
    assert!(a.pool.is_empty() && a.history.is_empty() && a.proofs.is_empty());
    assert!(a.node.local_votes().is_empty());

    let valid = WireRequest::Submit {
        transaction: Box::new(
            ledger::sign_transaction(
                &f.keys[0],
                &chain,
                1,
                Operation::Transfer {
                    to_peer_id: f.members[4].peer_id.clone(),
                    amount: 1,
                },
            )
            .unwrap(),
        ),
        records: vec![],
    };
    let bytes = serde_json::to_vec(&valid).unwrap();
    assert!(matches!(
        remote.active.as_mut().unwrap().receive(peer, &bytes),
        WireReply::Ack { .. }
    ));
    assert_eq!(remote.status()["status"], "ready");
    assert_eq!(remote.active.as_ref().unwrap().pool[0].signed.nonce, 1);
    local
        .submit(
            Operation::Transfer {
                to_peer_id: f.members[4].peer_id.clone(),
                amount: 1,
            },
            vec![],
        )
        .unwrap();
    assert_eq!(local.active.as_ref().unwrap().pool[0].signed.nonce, 1);

    let mut broken_disk = f.runtime(2);
    let path = f.homes[2].join("ledger-application.enc");
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(matches!(
        broken_disk.active.as_mut().unwrap().receive(peer, &bytes),
        WireReply::Rejected { code: 22 }
    ));
    assert_eq!(broken_disk.status()["status"], "fault");
    assert_eq!(
        broken_disk.status()["reason"],
        "ledger_storage_or_replay_failed"
    );
    let a = broken_disk.active.as_ref().unwrap();
    assert!(a.pool.is_empty() && a.history.is_empty() && a.proofs.is_empty());
}

#[tokio::test]
async fn timed_out_leader_hold_still_pumps_timeout_and_network_queue() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut f = Fixture::new();
    let mut genesis = f.settings.consensus.signed.clone();
    genesis.timeout_ms = 100;
    f.settings.consensus = consensus::sign_genesis(&f.keys[0], genesis).unwrap();
    let mut runtime = f.runtime(0);
    tokio::time::sleep(Duration::from_millis(110)).await;
    let a = runtime.active.as_mut().unwrap();
    a.node.timeout().unwrap();
    a.last_block = Instant::now() - Duration::from_secs(1);
    a.enqueue(f.members[1].peer_id.parse().unwrap(), WireRequest::Status);
    let mut config = config::load(&f.homes[0]).unwrap();
    config.listen = vec!["/ip4/127.0.0.1/tcp/0".into()];
    let mut swarm = network::build(f.keys[0].clone(), &config).await.unwrap();
    a.drive(&mut swarm).unwrap();
    assert!(!a.pending.is_empty());
    assert!(
        a.pending
            .values()
            .any(|p| matches!(p.request, WireRequest::Timeout { .. }))
    );
}

#[tokio::test]
async fn own_final_timeout_quorum_broadcasts_and_replays_its_durable_certificate() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut f = Fixture::new();
    let mut genesis = f.settings.consensus.signed.clone();
    genesis.timeout_ms = 100;
    f.settings.consensus = consensus::sign_genesis(&f.keys[0], genesis).unwrap();
    let mut runtime = f.runtime(0);
    let a = runtime.active.as_mut().unwrap();
    for signer in [1, 2] {
        let body = consensus::TimeoutBody {
            genesis_hash: a.node.genesis_hash().into(),
            height: a.node.height(),
            round: a.node.round(),
            validator: f.members[signer].peer_id.clone(),
        };
        let timeout = Signed {
            signature: crypto::sign(&f.keys[signer], "idobata.ledger.timeout.v1", &body).unwrap(),
            public_key: crypto::public(&f.keys[signer]),
            signed: body,
        };
        assert!(!a.node.observe_timeout(timeout).unwrap());
    }
    tokio::time::sleep(Duration::from_millis(110)).await;
    a.try_timeout().unwrap();
    assert_eq!(a.node.round(), 1);
    let certificate = a.node.round_certificate().unwrap().clone();
    assert_eq!(certificate.timeouts.len(), 3);
    assert!(a.queue.iter().any(|(_, request)| matches!(request,
        WireRequest::TimeoutCertificate { certificate: sent }
        if util::canonical(sent).unwrap() == util::canonical(&certificate).unwrap())));
    let encoded_certificate = util::canonical(&certificate).unwrap();
    drop(runtime);

    let mut runtime = Runtime::open(&f.homes[0], f.keys[0].clone()).unwrap();
    let a = runtime.active.as_mut().unwrap();
    assert_eq!(a.node.round(), 1);
    assert_eq!(
        util::canonical(a.node.round_certificate().unwrap()).unwrap(),
        encoded_certificate
    );
    a.last_rebroadcast = Instant::now() - Duration::from_secs(4);
    let mut config = config::load(&f.homes[0]).unwrap();
    config.listen = vec!["/ip4/127.0.0.1/tcp/0".into()];
    let mut swarm = network::build(f.keys[0].clone(), &config).await.unwrap();
    a.drive(&mut swarm).unwrap();
    assert!(
        a.queue
            .iter()
            .map(|(_, request)| request)
            .chain(a.pending.values().map(|pending| &pending.request))
            .any(
                |request| matches!(request, WireRequest::TimeoutCertificate { certificate: sent }
            if util::canonical(sent).unwrap() == encoded_certificate)
            )
    );
}

#[test]
fn immutable_proposal_retransmission_never_attaches_new_pending_refs() {
    let f = Fixture::new();
    let mut runtime = f.runtime(0);
    for i in 0..2 {
        let source = f.record(0, &format!("A distinct pending question {i}."));
        let criteria = f.record(
            0,
            &format!("The documented expected conditions for item {i}."),
        );
        runtime
            .submit(
                Operation::RegisterQuestion {
                    question: ledger::QuestionTerms {
                        source_record_id: source.record.signed.id.clone(),
                        criteria_record_id: criteria.record.signed.id.clone(),
                        deadline_height: 9,
                        bounty: 0,
                        conflict_operators: BTreeSet::new(),
                    },
                },
                vec![source.clone(), criteria.clone()],
            )
            .unwrap();
        if i == 0 {
            let a = runtime.active.as_mut().unwrap();
            a.last_block = Instant::now() - Duration::from_secs(1);
            a.try_propose().unwrap();
            assert_eq!(
                a.node
                    .current_proposal()
                    .unwrap()
                    .signed
                    .block
                    .transactions
                    .len(),
                1
            );
        }
    }
    let a = runtime.active.as_mut().unwrap();
    a.published.clear();
    a.queue.clear();
    a.last_proposal_send = None;
    a.try_propose().unwrap();
    let (_, WireRequest::Proposal { proposal, records }) = a
        .queue
        .iter()
        .find(|(_, r)| matches!(r, WireRequest::Proposal { .. }))
        .unwrap()
    else {
        panic!("proposal")
    };
    let expected = a
        .references(&proposal.signed.block.transactions[0].signed.operation)
        .into_iter()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        records
            .iter()
            .map(|r| r.record.signed.id.clone())
            .collect::<BTreeSet<_>>(),
        expected
    );
    assert_eq!(records.len(), 2);
}

#[test]
fn empty_commit_preserves_all_pending_acceptance_vote_references() {
    let f = Fixture::new();
    let mut runtime = f.runtime(0);
    let source = f.record(
        2,
        "A pending vote must retain the committed question source.",
    );
    let criteria = f.record(2, "The independently verified answer acceptance criteria.");
    let answer = f.record(3, "An answer submitted by its original author.");
    let a = runtime.active.as_mut().unwrap();
    let chain = a.machine.genesis().chain_id().to_owned();
    let question_id = ledger::question_id(&chain, &source.record.signed.id).unwrap();
    let register = ledger::sign_transaction(
        &f.keys[2],
        &chain,
        1,
        Operation::RegisterQuestion {
            question: ledger::QuestionTerms {
                source_record_id: source.record.signed.id.clone(),
                criteria_record_id: criteria.record.signed.id.clone(),
                deadline_height: 9,
                bounty: 0,
                conflict_operators: BTreeSet::new(),
            },
        },
    )
    .unwrap();
    let submit = ledger::sign_transaction(
        &f.keys[3],
        &chain,
        1,
        Operation::SubmitAnswer {
            answer: ledger::AnswerSubmission {
                question_id: question_id.clone(),
                source_record_id: answer.record.signed.id.clone(),
                beneficiary_peer_id: f.members[3].peer_id.clone(),
            },
        },
    )
    .unwrap();
    let certificate = f.certify(a, vec![register, submit]);
    a.node.import_commit(certificate, &a.machine).unwrap();
    a.committed().unwrap();
    runtime
        .cast_vote(
            &question_id,
            &answer.record.signed.id,
            Verdict::Satisfied,
            vec![source.clone(), criteria, answer.clone()],
        )
        .unwrap();
    let a = runtime.active.as_mut().unwrap();
    assert!(a.proof_bundle(&a.pool).is_ok());
    let certificate = f.certify(a, vec![]);
    a.node.import_commit(certificate, &a.machine).unwrap();
    a.committed().unwrap();
    assert_eq!(a.pool.len(), 1);
    assert!(
        a.machine
            .validate_batch(a.node.height(), &a.machine.state_root().unwrap(), &a.pool)
            .is_ok()
    );
    assert!(a.proofs.contains_key(&source.record.signed.id));
    assert!(a.proof_bundle(&a.pool).is_ok());
    drop(runtime);
    let runtime = Runtime::open(&f.homes[0], f.keys[0].clone()).unwrap();
    assert_eq!(runtime.status()["status"], "ready");
    let a = runtime.active.as_ref().unwrap();
    assert_eq!(a.pool.len(), 1);
    assert_eq!(a.proof_bundle(&a.pool).unwrap().len(), 3);
    assert!(a.proofs.contains_key(&source.record.signed.id));
}

#[test]
fn two_operators_with_reference_heavy_valid_votes_leave_room_for_honest_question() {
    let f = Fixture::new();
    let mut runtime = f.runtime(4);
    let mut records = vec![];
    let mut transactions = vec![];
    let mut questions = vec![];
    let chain = runtime
        .active
        .as_ref()
        .unwrap()
        .machine
        .genesis()
        .chain_id()
        .to_owned();
    for i in 0..4 {
        let source = f.record(
            2,
            &format!("A valid question for bounded vote proof item {i}."),
        );
        let criteria = f.record(
            2,
            &format!("The independently checked requirements for item {i}."),
        );
        let answer = f.record(
            3,
            &format!("The documented answer to bounded proof item {i}."),
        );
        let qid = ledger::question_id(&chain, &source.record.signed.id).unwrap();
        transactions.push(
            ledger::sign_transaction(
                &f.keys[2],
                &chain,
                i + 1,
                Operation::RegisterQuestion {
                    question: ledger::QuestionTerms {
                        source_record_id: source.record.signed.id.clone(),
                        criteria_record_id: criteria.record.signed.id.clone(),
                        deadline_height: 9,
                        bounty: 0,
                        conflict_operators: BTreeSet::new(),
                    },
                },
            )
            .unwrap(),
        );
        questions.push((qid, answer.record.signed.id.clone()));
        records.push(vec![source, criteria, answer]);
    }
    for (i, (qid, aid)) in questions.iter().enumerate() {
        transactions.push(
            ledger::sign_transaction(
                &f.keys[3],
                &chain,
                i as u64 + 1,
                Operation::SubmitAnswer {
                    answer: ledger::AnswerSubmission {
                        question_id: qid.clone(),
                        source_record_id: aid.clone(),
                        beneficiary_peer_id: f.members[3].peer_id.clone(),
                    },
                },
            )
            .unwrap(),
        );
    }
    let a = runtime.active.as_mut().unwrap();
    let cert = f.certify(a, transactions);
    a.node.import_commit(cert, &a.machine).unwrap();
    a.committed().unwrap();
    for signer in [0, 1] {
        for i in 0..2 {
            let body = a
                .machine
                .acceptance_vote(
                    &questions[i].0,
                    &questions[i].1,
                    &f.members[signer].peer_id,
                    i as u64 + 1,
                    Verdict::Satisfied,
                )
                .unwrap();
            let vote = ledger::sign_acceptance_vote(&f.keys[signer], body).unwrap();
            let tx = ledger::sign_transaction(
                &f.keys[signer],
                &chain,
                i as u64 + 1,
                Operation::CastAcceptanceVote {
                    vote: Box::new(vote),
                },
            )
            .unwrap();
            a.admit(tx, records[i].clone()).unwrap();
        }
        let body = a
            .machine
            .acceptance_vote(
                &questions[2].0,
                &questions[2].1,
                &f.members[signer].peer_id,
                3,
                Verdict::Satisfied,
            )
            .unwrap();
        let vote = ledger::sign_acceptance_vote(&f.keys[signer], body).unwrap();
        let tx = ledger::sign_transaction(
            &f.keys[signer],
            &chain,
            3,
            Operation::CastAcceptanceVote {
                vote: Box::new(vote),
            },
        )
        .unwrap();
        let mut preview = a.pool.clone();
        preview.push(tx.clone());
        assert!(
            a.machine
                .validate_batch(a.node.height(), &a.machine.state_root().unwrap(), &preview)
                .is_ok()
        );
        assert!(a.admit(tx, records[2].clone()).is_err());
    }
    let source = f.record(
        4,
        "An honest new question after two operators submitted votes.",
    );
    let criteria = f.record(
        4,
        "The honest new question has independently testable conditions.",
    );
    runtime
        .submit(
            Operation::RegisterQuestion {
                question: ledger::QuestionTerms {
                    source_record_id: source.record.signed.id.clone(),
                    criteria_record_id: criteria.record.signed.id.clone(),
                    deadline_height: 9,
                    bounty: 0,
                    conflict_operators: BTreeSet::new(),
                },
            },
            vec![source, criteria],
        )
        .unwrap();
    assert_eq!(runtime.active.as_ref().unwrap().pool.len(), 5);
}

#[test]
fn two_flooding_peers_leave_pending_capacity_for_another_operator() {
    let f = Fixture::new();
    let mut runtime = f.runtime(3);
    let a = runtime.active.as_mut().unwrap();
    let chain = a.machine.genesis().chain_id().to_owned();
    for signer in [0, 1] {
        for nonce in 1..=PEER_POOL as u64 {
            let tx = ledger::sign_transaction(
                &f.keys[signer],
                &chain,
                nonce,
                Operation::Transfer {
                    to_peer_id: f.members[4].peer_id.clone(),
                    amount: 1,
                },
            )
            .unwrap();
            a.admit(tx, vec![]).unwrap();
        }
        let blocked = ledger::sign_transaction(
            &f.keys[signer],
            &chain,
            PEER_POOL as u64 + 1,
            Operation::Transfer {
                to_peer_id: f.members[4].peer_id.clone(),
                amount: 1,
            },
        )
        .unwrap();
        assert!(a.admit(blocked, vec![]).is_err());
    }
    let honest = ledger::sign_transaction(
        &f.keys[2],
        &chain,
        1,
        Operation::Transfer {
            to_peer_id: f.members[4].peer_id.clone(),
            amount: 1,
        },
    )
    .unwrap();
    a.admit(honest, vec![]).unwrap();
    assert_eq!(a.pool.len(), 2 * PEER_POOL + 1);
}
