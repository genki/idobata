use idobata::{
    config, crypto,
    knowledge::{
        self, KnowledgeInput, RecordPacket, ReviewConflict, ReviewInput, ReviewPacket, Store,
    },
    knowledge_abuse::{OperatorClaims, SearchMode},
    types::{Member, TrustedRoom},
    util,
};
use libp2p::identity;
use std::{collections::BTreeMap, path::PathBuf};

// These are synthetic registered operators in an isolated acceptance fixture.
// Different keys here are not evidence of independent real-world ownership.
struct Fixture {
    _root: tempfile::TempDir,
    homes: Vec<PathBuf>,
    keys: Vec<identity::Keypair>,
    members: Vec<Member>,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let mut homes = Vec::new();
        let mut keys = Vec::new();
        let mut members = Vec::new();
        for index in 0..7 {
            let home = root.path().join(format!("node-{index}"));
            members.push(
                config::init(&home, vec![format!("/ip4/127.0.0.1/tcp/{}", 39160 + index)]).unwrap(),
            );
            keys.push(crypto::load_key(&home).unwrap());
            homes.push(home);
        }
        Self {
            _root: root,
            homes,
            keys,
            members,
        }
    }

    fn room(&self, first_external_credit: u16) -> TrustedRoom {
        let groups = [
            "authority",
            "author",
            "author",
            "one",
            "two",
            "three",
            "other",
        ];
        let claims = OperatorClaims {
            bindings: self
                .members
                .iter()
                .zip(groups)
                .map(|(member, group)| (member.peer_id.clone(), group.into()))
                .collect(),
            credits: BTreeMap::from([
                ("authority".into(), 1000),
                ("author".into(), 1000),
                ("one".into(), first_external_credit),
                ("two".into(), 1000),
                ("three".into(), 1000),
                ("other".into(), 1000),
            ]),
        };
        let certificate = config::create_room_with_operators(
            &self.homes[0],
            "knowledge",
            self.members.clone(),
            1,
            false,
            false,
            Some(claims),
        )
        .unwrap();
        TrustedRoom {
            authority_peer_id: self.members[0].peer_id.clone(),
            certificate,
        }
    }

    fn store(&self, room: &TrustedRoom) -> Store {
        let mut store = Store::open(&self.homes[0]).unwrap();
        self.configure(&mut store, room);
        store
    }

    fn configure(&self, store: &mut Store, room: &TrustedRoom) {
        let saved = config::load(&self.homes[0]).unwrap();
        store.set_rooms([room.clone()]);
        store.set_operator_history(&saved.knowledge_operator_history);
    }

    fn record(&self, room: &TrustedRoom, author: usize, label: &str) -> RecordPacket {
        knowledge::create_record(
            &self.keys[author],
            room,
            KnowledgeInput {
                problem: format!("再接続の確認 {label}"),
                solution: "接続状態を確認して再試行します。".into(),
                context: "独立した受入試験の安全な入力です。".into(),
                references: Vec::new(),
                kind: "answer".into(),
            },
            false,
            util::now(),
        )
        .unwrap()
    }

    fn review(
        &self,
        room: &TrustedRoom,
        record: &RecordPacket,
        reviewer: usize,
        sequence: u64,
        verdict: &str,
    ) -> ReviewPacket {
        knowledge::create_review(
            &self.keys[reviewer],
            room,
            record,
            ReviewInput {
                verdict: verdict.into(),
                evidence: if verdict == "useful" {
                    "記載された条件で動作を確認しました。".into()
                } else {
                    "異なる条件では記載の結果になりませんでした。".into()
                },
                references: Vec::new(),
            },
            sequence,
            util::now(),
        )
        .unwrap()
    }

    fn positives(&self, room: &TrustedRoom, record: &RecordPacket) -> Vec<ReviewPacket> {
        (3..6)
            .map(|reviewer| self.review(room, record, reviewer, 1, "useful"))
            .collect()
    }
}

#[test]
fn overlapping_stronger_certificate_cannot_upgrade_old_signed_authorization() {
    let fixture = Fixture::new();
    let weak = fixture.room(100);
    let record = fixture.record(&weak, 1, "過去の認可");
    let weak_review = fixture.review(&weak, &record, 3, 1, "useful");
    let stronger = fixture.room(1000);
    let at = util::now();
    assert!(weak.certificate.signed.expires_at > stronger.certificate.signed.issued_at);
    knowledge::validate_record(&record, &stronger, at).unwrap();
    knowledge::validate_review(&weak_review, &record, &stronger, at).unwrap();

    let reviews = vec![
        weak_review.clone(),
        fixture.review(&stronger, &record, 4, 1, "useful"),
        fixture.review(&stronger, &record, 5, 1, "useful"),
    ];
    let verified = knowledge::verified_evidence(&record, &reviews, &stronger);
    let assessment = knowledge::assess_evidence(&record, &stronger, &verified);
    assert_eq!(assessment.positive_groups, 3);
    assert_eq!(assessment.positive_weight, 2100);
    assert!(!assessment.promoted);
    let reduced = fixture.room(50);
    for review in &reviews {
        knowledge::validate_review(review, &record, &reduced, at).unwrap();
    }
    let verified = knowledge::verified_evidence(&record, &reviews, &reduced);
    assert_eq!(
        knowledge::assess_evidence(&record, &reduced, &verified).positive_weight,
        2050
    );
    let mut store = fixture.store(&reduced);
    assert!(
        store
            .insert_with_reviews(record.clone(), reviews, false, at)
            .unwrap()
    );
    let room_id = &record.record.signed.room_id;
    assert!(store.search(room_id, "再接続", 10, at).is_empty());
    let ciphertext = std::fs::read(fixture.homes[0].join("knowledge.enc")).unwrap();

    let mut swapped_review = weak_review;
    swapped_review.certificate = stronger.clone();
    assert!(knowledge::validate_review(&swapped_review, &record, &reduced, at).is_err());
    assert!(store.evaluate(swapped_review, at).is_err());
    let mut swapped_record = record;
    swapped_record.certificate = stronger;
    assert!(knowledge::validate_record(&swapped_record, &reduced, at).is_err());
    assert!(store.insert(swapped_record, false, at).is_err());
    assert_eq!(
        std::fs::read(fixture.homes[0].join("knowledge.enc")).unwrap(),
        ciphertext
    );
}

#[test]
fn public_store_search_requires_external_support_and_caps_same_operator_exploration() {
    let fixture = Fixture::new();
    let room = fixture.room(1000);
    let mut store = fixture.store(&room);
    let records = [
        fixture.record(&room, 1, "一つ目"),
        fixture.record(&room, 2, "同じ運営主体の別鍵"),
        fixture.record(&room, 1, "三つ目"),
    ];
    let at = util::now();
    let room_id = &room.certificate.signed.room_id;
    for record in &records {
        assert!(store.insert(record.clone(), false, at).unwrap());
    }
    assert!(store.search(room_id, "再接続", 10, at).is_empty());
    assert_eq!(
        store
            .search_mode(room_id, "再接続", 10, at, SearchMode::Explore)
            .len(),
        1
    );
    let target = &records[0];
    // The author's other key does not provide external support.
    store
        .evaluate(fixture.review(&room, target, 2, 1, "useful"), at)
        .unwrap();
    for reviewer in 3..5 {
        store
            .evaluate(fixture.review(&room, target, reviewer, 1, "useful"), at)
            .unwrap();
    }
    assert!(store.search(room_id, "再接続", 10, at).is_empty());
    store
        .evaluate(fixture.review(&room, target, 5, 1, "useful"), at)
        .unwrap();
    let normal = store.search(room_id, "再接続", 10, at);
    assert_eq!(normal.len(), 1);
    assert_eq!(normal[0].packet.record.signed.id, target.record.signed.id);
    assert_eq!(normal[0].quality.useful_votes, 3);
    let explored = store.search_mode(room_id, "再接続", 10, at, SearchMode::Explore);
    assert_eq!(explored.len(), 2);
    assert_eq!(
        explored
            .iter()
            .filter(|hit| hit.packet.record.signed.id != target.record.signed.id)
            .count(),
        1
    );
}

fn quota_fixture(fork: bool) {
    let fixture = Fixture::new();
    let room = fixture.room(1000);
    let target = fixture.record(&room, 1, "確認済み本文");
    let staged = fixture.record(&room, 0, "別主体の未複製本文");
    let mut reviews = fixture.positives(&room, &target);
    let first = fixture.review(&room, &target, 6, 1, "useful");
    if fork {
        reviews.push(first.clone());
    }
    let at = util::now();
    let mut store = fixture.store(&room);
    store
        .insert_with_reviews(target.clone(), reviews, false, at)
        .unwrap();
    store.insert(staged.clone(), true, at).unwrap();
    let file = fixture.homes[0].join("knowledge.enc");
    let ciphertext = std::fs::read(&file).unwrap();
    let snapshot = util::canonical(&store.state).unwrap();
    let baseline_bytes = store.metrics().bytes;
    drop(store);
    // Only 64 new bytes remain, below even the fixed signed review overhead.
    let quota = ciphertext.len() + 64;
    let mut limited = Store::with_quota(&fixture.homes[0], quota).unwrap();
    fixture.configure(&mut limited, &room);
    let result = if fork {
        let proof = ReviewConflict {
            first,
            second: fixture.review(&room, &target, 6, 1, "incorrect"),
        };
        knowledge::validate_conflicts(&target, std::slice::from_ref(&proof), &room, at).unwrap();
        limited.insert_with_reviews_and_conflicts(
            target.clone(),
            Vec::new(),
            vec![proof],
            false,
            at,
        )
    } else {
        limited.evaluate(first, at)
    };
    let error = result.unwrap_err();
    assert_eq!(error.code, 30);
    assert_eq!(error.error, "knowledge_metadata_quota_exceeded");
    assert_eq!(std::fs::read(&file).unwrap(), ciphertext);
    assert_eq!(util::canonical(&limited.state).unwrap(), snapshot);
    assert_eq!(limited.metrics().bytes, baseline_bytes);
    let room_id = &room.certificate.signed.room_id;
    assert!(
        limited
            .get(room_id, &staged.record.signed.id)
            .unwrap()
            .staging
    );
    let target_state = limited.get(room_id, &target.record.signed.id).unwrap();
    assert!(!target_state.staging);
    assert!(target_state.review_conflicts.is_empty());
    assert_eq!(limited.search(room_id, "確認済み本文", 10, at).len(), 1);
    drop(limited);
    let reopened = Store::with_quota(&fixture.homes[0], quota).unwrap();
    assert_eq!(util::canonical(&reopened.state).unwrap(), snapshot);
}

#[test]
fn metadata_quota_rejection_preserves_ciphertext_bodies_staging_and_other_actors() {
    quota_fixture(false);
}

#[test]
fn fork_proof_quota_rejection_preserves_promoted_content_and_existing_state() {
    quota_fixture(true);
}
