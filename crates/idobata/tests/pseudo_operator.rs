//! Post-0.4 test-only validation. All homes, keys and signed claims are temporary.
//! s21g and machinaai-test are synthetic labels under one real controller here.
//! Application-only ordered commits below do not claim consensus finality.
use idobata::{
    config, crypto,
    knowledge::{self, KnowledgeInput, RecordPacket, ReviewInput, Store},
    knowledge_abuse::{OperatorClaims, SearchMode},
    ledger::{self, Machine, Operation, Verdict},
    ledger_consensus as consensus, ledger_runtime,
    types::{Member, TrustedRoom},
    util,
};
use libp2p::identity;
use std::{
    collections::{BTreeMap, BTreeSet},
    path::PathBuf,
};

struct Fixture {
    _temporary: tempfile::TempDir,
    homes: Vec<PathBuf>,
    keys: Vec<identity::Keypair>,
    members: Vec<Member>,
    room: TrustedRoom,
    claims: OperatorClaims,
}
impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let homes = (0..4)
            .map(|i| temporary.path().join(format!("peer-{i}")))
            .collect::<Vec<_>>();
        let members = homes
            .iter()
            .enumerate()
            .map(|(index, home)| {
                config::init(home, vec![format!("/ip4/127.0.0.1/tcp/{}", 49300 + index)]).unwrap()
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
                .map(|(i, member)| {
                    (
                        member.peer_id.clone(),
                        if i == 3 { "machinaai-test" } else { "s21g" }.into(),
                    )
                })
                .collect(),
            credits: BTreeMap::from([("s21g".into(), 1000), ("machinaai-test".into(), 1000)]),
        };
        let certificate = config::create_room_with_operators(
            &homes[0],
            "pseudo",
            members.clone(),
            1,
            false,
            false,
            Some(claims.clone()),
        )
        .unwrap();
        for home in &homes[1..] {
            config::join_room(home, "pseudo", certificate.clone(), &members[0].peer_id).unwrap();
        }
        let room = TrustedRoom {
            authority_peer_id: members[0].peer_id.clone(),
            certificate,
        };
        Self {
            _temporary: temporary,
            homes,
            keys,
            members,
            room,
            claims,
        }
    }
    fn record(&self, author: usize, label: &str) -> RecordPacket {
        knowledge::create_record(
            &self.keys[author],
            &self.room,
            KnowledgeInput {
                problem: format!("擬似運営者の検証 {label}"),
                solution: "接続状態を確認し、記載された条件で再試行します。".into(),
                context: "一時領域だけを使用する隔離試験です。".into(),
                references: vec![],
                kind: "answer".into(),
            },
            false,
            util::now(),
        )
        .unwrap()
    }
    fn application(&self) -> ledger::SignedGenesis {
        ledger::sign_genesis(
            &self.keys[0],
            ledger::Genesis {
                version: 1,
                experiment_only: true,
                room_id: self.room.certificate.signed.room_id.clone(),
                network_salt: util::hash(b"post-0.4 two synthetic operator validation"),
                authority_peer_id: self.members[0].peer_id.clone(),
                operator_epoch: 1,
                participants: self
                    .members
                    .iter()
                    .map(|member| {
                        (
                            member.peer_id.clone(),
                            ledger::Participant {
                                public_key: member.public_key.clone(),
                                operator: self.claims.bindings[&member.peer_id].clone(),
                                credit: 1000,
                            },
                        )
                    })
                    .collect(),
                parameters: ledger::Parameters::default(),
                bootstrap_balances: BTreeMap::new(),
            },
        )
        .unwrap()
    }
    fn machine(&self) -> Machine {
        Machine::new(ledger::verify_genesis(self.application(), &self.members[0].peer_id).unwrap())
            .unwrap()
    }
    fn consensus(&self) -> consensus::Genesis {
        let machine = self.machine();
        consensus::Genesis {
            version: 1,
            chain_id: machine.genesis().chain_id().into(),
            application_genesis_hash: machine.genesis().genesis_hash().into(),
            initial_application_hash: machine.state_root().unwrap(),
            validators: self
                .members
                .iter()
                .map(|member| consensus::Validator {
                    peer_id: member.peer_id.clone(),
                    public_key: member.public_key.clone(),
                    operator: self.claims.bindings[&member.peer_id].clone(),
                })
                .collect(),
            fault_bound: 1,
            quorum: 3,
            timeout_ms: 3000,
            experiment_only: true,
        }
    }
}

#[test]
fn signed_two_operator_reviews_are_retained_but_never_become_three_external_supporters() {
    let fixture = Fixture::new();
    let mut store = Store::open(&fixture.homes[0]).unwrap();
    store.set_rooms([fixture.room.clone()]);
    for (author, reviewers, label) in [
        (0, vec![1, 2, 3], "同じ著者運営者の別鍵"),
        (3, vec![0, 1, 2], "同じ外部運営者の三つの鍵"),
    ] {
        let record = fixture.record(author, label);
        assert!(store.insert(record.clone(), false, util::now()).unwrap());
        for reviewer in reviewers {
            let review = knowledge::create_review(
                &fixture.keys[reviewer],
                &fixture.room,
                &record,
                ReviewInput {
                    verdict: "useful".into(),
                    evidence: "記載された条件で結果を確認しました。".into(),
                    references: vec![],
                },
                1,
                util::now(),
            )
            .unwrap();
            assert!(store.evaluate(review, util::now()).unwrap());
        }
        let saved = store
            .get(
                &fixture.room.certificate.signed.room_id,
                &record.record.signed.id,
            )
            .unwrap();
        assert_eq!(saved.reviews.len(), 3);
        let evidence = knowledge::verified_evidence(&saved.packet, &saved.reviews, &fixture.room);
        let assessment = knowledge::assess_evidence(&saved.packet, &fixture.room, &evidence);
        assert_eq!(assessment.positive_groups, 1);
        assert_eq!(assessment.positive_weight, 1000);
        assert!(!assessment.promoted);
    }
    assert!(
        store
            .search(
                &fixture.room.certificate.signed.room_id,
                "擬似運営者の検証",
                10,
                util::now()
            )
            .is_empty()
    );
    assert_eq!(
        store
            .search_mode(
                &fixture.room.certificate.signed.room_id,
                "擬似運営者の検証",
                10,
                util::now(),
                SearchMode::Explore
            )
            .len(),
        2
    );
}

#[test]
fn two_validator_genesis_is_rejected_and_four_validators_from_two_operators_hold_without_signing() {
    let fixture = Fixture::new();
    let mut two = fixture.consensus();
    two.validators.truncate(2);
    assert_eq!(
        consensus::sign_genesis(&fixture.keys[0], two)
            .err()
            .unwrap()
            .code,
        30
    );
    let signed = consensus::sign_genesis(&fixture.keys[0], fixture.consensus()).unwrap();
    let settings = ledger_runtime::Settings {
        version: 1,
        room_alias: "pseudo".into(),
        authority_peer_id: fixture.members[0].peer_id.clone(),
        application: fixture.application(),
        consensus: signed.clone(),
    };
    ledger_runtime::configure(&fixture.homes[0], &settings).unwrap();
    let mut runtime =
        ledger_runtime::Runtime::open(&fixture.homes[0], fixture.keys[0].clone()).unwrap();
    let status = runtime.status();
    assert_eq!(status["status"], "hold");
    assert_eq!(status["reason"], "insufficient_independent_operators");
    assert_eq!(status["consensus"]["independent_operators"], 2);
    assert_eq!(status["consensus"]["quorum"], 3);
    assert_eq!(
        runtime
            .submit(
                Operation::RegisterQuestion {
                    question: ledger::QuestionTerms {
                        source_record_id: util::hash(b"source"),
                        criteria_record_id: util::hash(b"criteria"),
                        deadline_height: 20,
                        bounty: 0,
                        conflict_operators: BTreeSet::new()
                    }
                },
                vec![]
            )
            .err()
            .unwrap()
            .code,
        10
    );
    assert_eq!(runtime.status()["pending_transactions"], 0);
    assert_eq!(runtime.status()["total_minted"], 0);
    assert_eq!(runtime.status()["next_nonce"], 1);
    drop(runtime);
    let mut node = consensus::Node::open(
        &fixture.homes[0],
        fixture.keys[0].clone(),
        signed,
        &fixture.members[0].peer_id,
    )
    .unwrap();
    let path = fixture.homes[0].join("ledger-consensus.enc");
    let before = std::fs::read(&path).unwrap();
    assert!(!node.ready());
    assert_eq!(node.timeout().err().unwrap().code, 10);
    assert_eq!(node.precommit().err().unwrap().code, 10);
    let machine = fixture.machine();
    assert_eq!(
        node.propose(vec![], machine.state_root().unwrap(), &machine)
            .err()
            .unwrap()
            .code,
        10
    );
    assert_eq!(std::fs::read(path).unwrap(), before);
    assert!(node.local_votes().is_empty());
    assert!(node.local_timeout().is_none());
}

fn ordered_application_fixture_commit(
    machine: &mut Machine,
    transactions: &[ledger::SignedTransaction],
) {
    let height = machine.state().height + 1;
    let parent = machine.state_root().unwrap();
    let block = util::hash(&util::canonical(&(height, &parent, transactions)).unwrap());
    machine
        .apply_committed(height, &block, &parent, transactions)
        .unwrap();
}

#[test]
fn two_operator_asker_finder_and_beneficiary_conflicts_leave_no_judges_or_mint() {
    let fixture = Fixture::new();
    let mut machine = fixture.machine();
    let chain = machine.genesis().chain_id().to_owned();
    let source = util::hash(b"two operator question");
    let answer = util::hash(b"machinaai original signed answer");
    let question = ledger::question_id(&chain, &source).unwrap();
    let register = ledger::sign_transaction(
        &fixture.keys[0],
        &chain,
        1,
        Operation::RegisterQuestion {
            question: ledger::QuestionTerms {
                source_record_id: source,
                criteria_record_id: util::hash(b"criterion"),
                deadline_height: 30,
                bounty: 0,
                conflict_operators: BTreeSet::new(),
            },
        },
    )
    .unwrap();
    let submit = ledger::sign_transaction(
        &fixture.keys[1],
        &chain,
        1,
        Operation::SubmitAnswer {
            answer: ledger::AnswerSubmission {
                question_id: question.clone(),
                source_record_id: answer.clone(),
                beneficiary_peer_id: fixture.members[3].peer_id.clone(),
            },
        },
    )
    .unwrap();
    ordered_application_fixture_commit(&mut machine, &[register, submit]);
    let before = machine.state_root().unwrap();
    for signer in 0..4 {
        let nonce = machine
            .next_nonce(&fixture.members[signer].peer_id)
            .unwrap();
        let vote = machine
            .acceptance_vote(
                &question,
                &answer,
                &fixture.members[signer].peer_id,
                nonce,
                Verdict::Satisfied,
            )
            .unwrap();
        let signed = ledger::sign_acceptance_vote(&fixture.keys[signer], vote).unwrap();
        let transaction = ledger::sign_transaction(
            &fixture.keys[signer],
            &chain,
            nonce,
            Operation::CastAcceptanceVote {
                vote: Box::new(signed),
            },
        )
        .unwrap();
        assert_eq!(
            machine
                .validate_batch(2, &before, &[transaction])
                .err()
                .unwrap()
                .error,
            "ledger_conflicted_acceptance_voter"
        );
        assert_eq!(machine.state_root().unwrap(), before);
    }
    let certificate = machine.acceptance_certificate(&question, &answer).unwrap();
    let settle = ledger::sign_transaction(
        &fixture.keys[0],
        &chain,
        2,
        Operation::SettleAnswer {
            certificate: Box::new(certificate),
        },
    )
    .unwrap();
    assert_eq!(
        machine
            .validate_batch(2, &before, &[settle])
            .err()
            .unwrap()
            .code,
        10
    );
    assert_eq!(machine.state().total_minted, 0);
}

#[test]
fn signed_labels_do_not_attest_common_control_executor_or_allow_another_peers_signing_key() {
    let fixture = Fixture::new();
    assert_eq!(
        fixture
            .members
            .iter()
            .map(|member| &member.public_key)
            .collect::<BTreeSet<_>>()
            .len(),
        4
    );
    let plain = serde_json::to_value(&fixture.claims).unwrap();
    assert_eq!(plain.as_object().unwrap().len(), 2);
    for field in ["common_controller", "synthetic", "executor"] {
        let mut extended = plain.clone();
        extended
            .as_object_mut()
            .unwrap()
            .insert(field.into(), serde_json::json!("test-only"));
        assert!(serde_json::from_value::<OperatorClaims>(extended).is_err());
    }
    let record = fixture.record(0, "署名主体はモデル名ではなくdaemonの鍵");
    let mut review = knowledge::create_review(
        &fixture.keys[3],
        &fixture.room,
        &record,
        ReviewInput {
            verdict: "useful".into(),
            evidence: "この条件で結果を確認しました。".into(),
            references: vec![],
        },
        1,
        util::now(),
    )
    .unwrap();
    review.review.signed.reviewer_peer_id = fixture.members[1].peer_id.clone();
    assert!(knowledge::validate_review(&review, &record, &fixture.room, util::now()).is_err());
}
