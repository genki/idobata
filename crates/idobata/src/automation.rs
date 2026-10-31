//! A peer-issued automation capability test, never an AI identity assertion.
//!
//! This module validates bounded signed data only. The Runtime must durably
//! reserve/consume challenge IDs, authorize the current transport peer, and scan
//! the action before it issues a challenge or admits a contribution.
use crate::{
    crypto,
    error::{INVALID, Result},
    scanner::Scanner,
    types::{Signed, TrustedRoom},
    util,
};
use libp2p::identity;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub const CHALLENGE_TTL_SECONDS: u64 = 120;
pub const MAX_PACKET_BYTES: usize = 16 * 1024;
pub const CASE_COUNT: usize = 24;
pub const VALUES_PER_CASE: usize = 16;
pub const MAX_OBJECT_DELAY_SECONDS: u64 = 300;
const MAX_INTEGER: u64 = 9_007_199_254_740_991;
const CHALLENGE_DOMAIN: &str = "idobata.automation.challenge.v1";
const RECEIPT_DOMAIN: &str = "idobata.automation.receipt.v1";
const TASK_DOMAIN: &[u8] = b"idobata.automation.tasks.v1\0";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationChallenge {
    pub version: u32,
    pub id: String,
    pub room_id: String,
    pub subject_peer_id: String,
    pub action_digest: String,
    pub purpose: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub seed: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengePacket {
    pub challenge: Signed<AutomationChallenge>,
    pub certificate: TrustedRoom,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationAnswer {
    pub challenge: ChallengePacket,
    pub answers: Vec<u32>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationReceipt {
    pub version: u32,
    pub challenge_id: String,
    pub room_id: String,
    pub subject_peer_id: String,
    pub action_digest: String,
    pub purpose: String,
    pub verified_at: u64,
    pub assurance: String,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutomationProof {
    pub answer: AutomationAnswer,
    pub receipt: Signed<AutomationReceipt>,
}

/// Public inputs and transforms, containing neither an answer nor its digest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskCase {
    pub index: u32,
    pub values: Vec<u32>,
    pub sort: String,
    pub rotate_left: u32,
    pub initial: u32,
    pub multiplier: u32,
}

/// Include this fixed description alongside the signed packet in challenge JSON.
pub fn task_spec() -> Value {
    json!({
        "algorithm": "sha256-u16le-sort-rotate-fold-v1",
        "version": 1,
        "case_count": CASE_COUNT,
        "values_per_case": VALUES_PER_CASE,
        "seed_encoding": "32 bytes encoded as 64 lowercase hexadecimal characters",
        "generation": "For index i=0..23: SHA256(UTF8(idobata.automation.tasks.v1) || 0x00 || decoded_seed || little_endian_u32(i)). Decode its 32 bytes as 16 little-endian u16 values, each modulo 997.",
        "sort": "i modulo 3: 0 ascending, 1 descending, 2 unchanged",
        "rotate": "Rotate the sorted value array left by i modulo 16 positions",
        "fold": "Start acc=i+1, multiplier=33+2*(i modulo 5). For each zero-based position j: acc=(acc*multiplier+(j+1)*value) modulo 2^32; then rotate acc left by ((i+j) modulo 31)+1 bits in a 32-bit word.",
        "output": "Return exactly 24 unsigned 32-bit integers in index order",
        "assurance": "automation_tested",
        "meaning": "Ability to perform this machine task; no AI identity or operator independence claim"
    })
}

/// Deterministic public task inputs. Invalid seed encodings produce no cases.
pub fn tasks(challenge: &AutomationChallenge) -> Vec<TaskCase> {
    if !util::valid_id(&challenge.seed) {
        return vec![];
    }
    let Ok(seed) = hex::decode(&challenge.seed) else {
        return vec![];
    };
    (0..CASE_COUNT)
        .map(|index| {
            let index = index as u32;
            let mut hash = Sha256::new();
            hash.update(TASK_DOMAIN);
            hash.update(&seed);
            hash.update(index.to_le_bytes());
            let digest = hash.finalize();
            TaskCase {
                index,
                values: digest
                    .chunks_exact(2)
                    .map(|pair| u32::from(u16::from_le_bytes([pair[0], pair[1]])) % 997)
                    .collect(),
                sort: match index % 3 {
                    0 => "ascending",
                    1 => "descending",
                    _ => "none",
                }
                .into(),
                rotate_left: index % VALUES_PER_CASE as u32,
                initial: index + 1,
                multiplier: 33 + 2 * (index % 5),
            }
        })
        .collect()
}

fn bounded<T: Serialize>(value: &T) -> Result<()> {
    if util::canonical(value)?.len() > MAX_PACKET_BYTES {
        return Err(INVALID);
    }
    Ok(())
}

fn valid_purpose(purpose: &str) -> bool {
    matches!(purpose, "publish" | "evaluate")
}

fn member(room: &TrustedRoom, peer: &str, public_key: Option<&str>) -> bool {
    room.certificate.signed.members.iter().any(|member| {
        member.peer_id == peer && public_key.is_none_or(|key| member.public_key == key)
    })
}

fn issuer(packet: &ChallengePacket) -> Result<String> {
    let key = crypto::public_key(&packet.challenge.public_key)?;
    if key.key_type() != identity::KeyType::Ed25519 {
        return Err(INVALID);
    }
    Ok(key.to_peer_id().to_string())
}

fn validate_at(room: &TrustedRoom, at: u64) -> Result<()> {
    if at > MAX_INTEGER || room.certificate.signed.issued_at > at {
        return Err(INVALID);
    }
    crypto::validate_room(room, &Scanner::policy_id(), at)
}

fn same_trust(old: &TrustedRoom, current: &TrustedRoom) -> Result<()> {
    let previous = &old.certificate.signed;
    let latest = &current.certificate.signed;
    if old.authority_peer_id != current.authority_peer_id
        || old.certificate.public_key != current.certificate.public_key
        || previous.room_id != latest.room_id
        || previous.policy_id != latest.policy_id
        || previous.public != latest.public
        || previous.epoch > latest.epoch
    {
        return Err(INVALID);
    }
    Ok(())
}

pub fn create_challenge(
    issuer_key: &identity::Keypair,
    room: &TrustedRoom,
    subject: &str,
    digest: &str,
    purpose: &str,
    at: u64,
) -> Result<ChallengePacket> {
    validate_at(room, at)?;
    let issuer = issuer_key.public().to_peer_id().to_string();
    let public_key = crypto::public(issuer_key);
    if !util::valid_id(digest)
        || !valid_purpose(purpose)
        || subject == issuer
        || !member(room, &issuer, Some(&public_key))
        || !member(room, subject, None)
    {
        return Err(INVALID);
    }
    let challenge = AutomationChallenge {
        version: 1,
        id: util::random_id(),
        room_id: room.certificate.signed.room_id.clone(),
        subject_peer_id: subject.into(),
        action_digest: digest.into(),
        purpose: purpose.into(),
        issued_at: at,
        expires_at: (at + CHALLENGE_TTL_SECONDS).min(room.certificate.signed.expires_at),
        seed: util::random_id(),
    };
    let packet = ChallengePacket {
        challenge: Signed {
            signature: crypto::sign(issuer_key, CHALLENGE_DOMAIN, &challenge)?,
            public_key,
            signed: challenge,
        },
        certificate: room.clone(),
    };
    bounded(&packet)?;
    Ok(packet)
}

/// `fresh=false` validates old evidence, without renewing its admission window.
/// Current transport authorization and nonce use are separate Runtime checks.
#[allow(clippy::too_many_arguments)]
pub fn verify_challenge(
    packet: &ChallengePacket,
    current: &TrustedRoom,
    subject: &str,
    digest: &str,
    purpose: &str,
    at: u64,
    fresh: bool,
) -> Result<()> {
    bounded(packet)?;
    let challenge = &packet.challenge.signed;
    if at > MAX_INTEGER
        || challenge.version != 1
        || !util::valid_id(&challenge.id)
        || !util::valid_id(&challenge.seed)
        || !util::valid_id(digest)
        || !valid_purpose(purpose)
        || challenge.room_id != packet.certificate.certificate.signed.room_id
        || challenge.subject_peer_id != subject
        || challenge.action_digest != digest
        || challenge.purpose != purpose
        || challenge.issued_at > at.saturating_add(300)
        || challenge.issued_at > MAX_INTEGER
        || challenge.expires_at > MAX_INTEGER
        || challenge.expires_at <= challenge.issued_at
        || challenge.expires_at - challenge.issued_at > CHALLENGE_TTL_SECONDS
        || challenge.expires_at > packet.certificate.certificate.signed.expires_at
    {
        return Err(INVALID);
    }
    validate_at(&packet.certificate, challenge.issued_at)?;
    // Historical knowledge remains verifiable after room/challenge expiry. A
    // caller passing an expired latest certificate gains no fresh admission.
    validate_at(
        current,
        if fresh {
            at
        } else {
            current.certificate.signed.issued_at
        },
    )?;
    same_trust(&packet.certificate, current)?;
    let issuer = issuer(packet)?;
    if issuer == subject
        || !member(
            &packet.certificate,
            &issuer,
            Some(&packet.challenge.public_key),
        )
        || !member(&packet.certificate, subject, None)
        || (fresh
            && (at < challenge.issued_at
                || at >= challenge.expires_at
                || !member(current, &issuer, Some(&packet.challenge.public_key))
                || !member(current, subject, None)))
    {
        return Err(INVALID);
    }
    crypto::verify(
        &crypto::public_key(&packet.challenge.public_key)?,
        CHALLENGE_DOMAIN,
        challenge,
        &packet.challenge.signature,
    )
}

fn verify_answers(answer: &AutomationAnswer) -> Result<()> {
    bounded(answer)?;
    if answer.answers.len() != CASE_COUNT {
        return Err(INVALID);
    }
    let cases = tasks(&answer.challenge.challenge.signed);
    if cases.len() != CASE_COUNT {
        return Err(INVALID);
    }
    for (case, provided) in cases.into_iter().zip(&answer.answers) {
        let mut values = case.values;
        match case.sort.as_str() {
            "ascending" => values.sort_unstable(),
            "descending" => values.sort_unstable_by(|left, right| right.cmp(left)),
            _ => {}
        }
        values.rotate_left(case.rotate_left as usize);
        let mut accumulated = case.initial;
        for (position, value) in values.into_iter().enumerate() {
            accumulated = accumulated
                .wrapping_mul(case.multiplier)
                .wrapping_add((position as u32 + 1) * value)
                .rotate_left((case.index + position as u32) % 31 + 1);
        }
        if accumulated != *provided {
            return Err(INVALID);
        }
    }
    Ok(())
}

/// Runtime must atomically consume an issued nonce before returning this receipt.
pub fn certify_answer(
    issuer_key: &identity::Keypair,
    current: &TrustedRoom,
    answer: &AutomationAnswer,
    at: u64,
) -> Result<Signed<AutomationReceipt>> {
    let challenge = &answer.challenge.challenge.signed;
    verify_challenge(
        &answer.challenge,
        current,
        &challenge.subject_peer_id,
        &challenge.action_digest,
        &challenge.purpose,
        at,
        true,
    )?;
    if crypto::public(issuer_key) != answer.challenge.challenge.public_key {
        return Err(INVALID);
    }
    verify_answers(answer)?;
    let receipt = AutomationReceipt {
        version: 1,
        challenge_id: challenge.id.clone(),
        room_id: challenge.room_id.clone(),
        subject_peer_id: challenge.subject_peer_id.clone(),
        action_digest: challenge.action_digest.clone(),
        purpose: challenge.purpose.clone(),
        verified_at: at,
        assurance: "automation_tested".into(),
    };
    let signed = Signed {
        signature: crypto::sign(issuer_key, RECEIPT_DOMAIN, &receipt)?,
        public_key: crypto::public(issuer_key),
        signed: receipt,
    };
    bounded(&signed)?;
    Ok(signed)
}

#[allow(clippy::too_many_arguments)]
pub fn verify_proof(
    proof: &AutomationProof,
    current: &TrustedRoom,
    subject: &str,
    digest: &str,
    purpose: &str,
    object_created_at: u64,
    now: u64,
) -> Result<()> {
    bounded(proof)?;
    verify_challenge(
        &proof.answer.challenge,
        current,
        subject,
        digest,
        purpose,
        now,
        false,
    )?;
    verify_answers(&proof.answer)?;
    let challenge = &proof.answer.challenge.challenge.signed;
    let receipt = &proof.receipt.signed;
    if receipt.version != 1
        || receipt.assurance != "automation_tested"
        || proof.receipt.public_key != proof.answer.challenge.challenge.public_key
        || receipt.challenge_id != challenge.id
        || receipt.room_id != challenge.room_id
        || receipt.subject_peer_id != subject
        || receipt.action_digest != digest
        || receipt.purpose != purpose
        || receipt.verified_at < challenge.issued_at
        || receipt.verified_at > challenge.expires_at
        || receipt.verified_at > MAX_INTEGER
        || receipt.verified_at > now.saturating_add(300)
        || object_created_at > MAX_INTEGER
        || object_created_at > now.saturating_add(300)
        || object_created_at.abs_diff(receipt.verified_at) > MAX_OBJECT_DELAY_SECONDS
    {
        return Err(INVALID);
    }
    validate_at(&proof.answer.challenge.certificate, receipt.verified_at)?;
    crypto::verify(
        &crypto::public_key(&proof.receipt.public_key)?,
        RECEIPT_DOMAIN,
        receipt,
        &proof.receipt.signature,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const AT: u64 = 10_000;

    fn room(authority: &identity::Keypair, peers: &[&identity::Keypair]) -> TrustedRoom {
        let body = json!({
            "version": 1,
            "room_id": "a".repeat(64),
            "epoch": 1,
            "issued_at": AT,
            "expires_at": AT + 3600,
            "policy_id": Scanner::policy_id(),
            "members": peers.iter().map(|key| json!({
                "peer_id": key.public().to_peer_id().to_string(),
                "public_key": crypto::public(key),
                "addresses": []
            })).collect::<Vec<_>>()
        });
        let signed = serde_json::from_value(body).unwrap();
        TrustedRoom {
            authority_peer_id: authority.public().to_peer_id().to_string(),
            certificate: Signed {
                signature: crypto::sign(authority, "idobata.room.v1", &signed).unwrap(),
                public_key: crypto::public(authority),
                signed,
            },
        }
    }

    struct Fixture {
        authority: identity::Keypair,
        issuer: identity::Keypair,
        subject: identity::Keypair,
        room: TrustedRoom,
        packet: ChallengePacket,
    }

    impl Fixture {
        fn new(purpose: &str) -> Self {
            let authority = identity::Keypair::generate_ed25519();
            let issuer = identity::Keypair::generate_ed25519();
            let subject = identity::Keypair::generate_ed25519();
            let room = room(&authority, &[&authority, &issuer, &subject]);
            let packet = create_challenge(
                &issuer,
                &room,
                &subject.public().to_peer_id().to_string(),
                &"b".repeat(64),
                purpose,
                AT,
            )
            .unwrap();
            Self {
                authority,
                issuer,
                subject,
                room,
                packet,
            }
        }

        fn subject(&self) -> String {
            self.subject.public().to_peer_id().to_string()
        }

        fn answer(&self) -> AutomationAnswer {
            AutomationAnswer {
                challenge: self.packet.clone(),
                answers: solve_for_test(&self.packet.challenge.signed),
            }
        }

        fn proof(&self) -> AutomationProof {
            let answer = self.answer();
            AutomationProof {
                receipt: certify_answer(&self.issuer, &self.room, &answer, AT + 1).unwrap(),
                answer,
            }
        }

        fn resign_room(&self, room: &mut TrustedRoom) {
            room.certificate.signature =
                crypto::sign(&self.authority, "idobata.room.v1", &room.certificate.signed).unwrap();
        }

        fn resign_challenge(&self, packet: &mut ChallengePacket) {
            packet.challenge.signature =
                crypto::sign(&self.issuer, CHALLENGE_DOMAIN, &packet.challenge.signed).unwrap();
        }

        fn verify(&self, packet: &ChallengePacket, at: u64, fresh: bool) -> Result<()> {
            verify_challenge(
                packet,
                &self.room,
                &self.subject(),
                &"b".repeat(64),
                &self.packet.challenge.signed.purpose,
                at,
                fresh,
            )
        }

        fn verify_proof(&self, proof: &AutomationProof, created: u64, now: u64) -> Result<()> {
            verify_proof(
                proof,
                &self.room,
                &self.subject(),
                &"b".repeat(64),
                &self.packet.challenge.signed.purpose,
                created,
                now,
            )
        }
    }

    // A solver is deliberately confined to tests. Production only compares a
    // provided vector and never returns expected answers to an agent.
    fn solve_for_test(challenge: &AutomationChallenge) -> Vec<u32> {
        tasks(challenge)
            .into_iter()
            .map(|task| {
                let mut values = task.values;
                if task.index % 3 != 2 {
                    values.sort_unstable();
                    if task.index % 3 == 1 {
                        values.reverse();
                    }
                }
                let offset = task.index as usize % VALUES_PER_CASE;
                (0..VALUES_PER_CASE).fold(task.index + 1, |acc, position| {
                    let value = values[(position + offset) % VALUES_PER_CASE];
                    let sum = u64::from(acc) * u64::from(33 + 2 * (task.index % 5))
                        + (position as u64 + 1) * u64::from(value);
                    (sum as u32).rotate_left((task.index + position as u32) % 31 + 1)
                })
            })
            .collect()
    }

    #[test]
    fn deterministic_tasks_match_independent_zero_seed_vector() {
        let mut fixture = Fixture::new("publish");
        fixture.packet.challenge.signed.seed = "0".repeat(64);
        let cases = tasks(&fixture.packet.challenge.signed);
        assert_eq!(cases.len(), CASE_COUNT);
        assert!(cases.iter().all(|task| task.values.len() == VALUES_PER_CASE
            && task.values.iter().all(|value| *value < 997)));
        assert_eq!(
            cases[0].values,
            [
                207, 5, 296, 354, 158, 74, 847, 233, 522, 830, 186, 101, 542, 16, 908, 760
            ]
        );
        assert_eq!(
            solve_for_test(&fixture.packet.challenge.signed),
            [
                241154151, 3547265955, 1116561072, 2108799716, 2999146339, 4136467445, 2520180127,
                1542230348, 1890627663, 2315501570, 3496633469, 143891129, 1987887498, 2998518041,
                4212433332, 3003736209, 921108977, 2091693371, 1883997569, 2008552011, 3831226734,
                94727809, 1398741250, 856323620
            ]
        );
        let mut invalid = fixture.packet.challenge.signed.clone();
        invalid.seed.push('0');
        assert!(tasks(&invalid).is_empty());
        let public = serde_json::to_value(&fixture.packet).unwrap();
        assert!(public.get("answers").is_none());
        assert!(public["challenge"]["signed"].get("answer_digest").is_none());
        assert_eq!(task_spec()["assurance"], "automation_tested");
    }

    #[test]
    fn correct_answers_are_bound_to_a_different_peer_and_action() {
        for purpose in ["publish", "evaluate"] {
            let fixture = Fixture::new(purpose);
            let proof = fixture.proof();
            fixture.verify_proof(&proof, AT + 1, AT + 2).unwrap();
            assert_eq!(proof.receipt.signed.assurance, "automation_tested");
            assert_ne!(
                fixture.packet.challenge.public_key,
                crypto::public(&fixture.subject)
            );
            let second = create_challenge(
                &fixture.issuer,
                &fixture.room,
                &fixture.subject(),
                &"b".repeat(64),
                purpose,
                AT,
            )
            .unwrap();
            assert_ne!(
                second.challenge.signed.id,
                fixture.packet.challenge.signed.id
            );
            assert_ne!(
                second.challenge.signed.seed,
                fixture.packet.challenge.signed.seed
            );
        }
    }

    #[test]
    fn wrong_answers_and_exact_answer_count_are_rejected() {
        let fixture = Fixture::new("publish");
        let mut answer = fixture.answer();
        answer.answers[0] ^= 1;
        assert!(certify_answer(&fixture.issuer, &fixture.room, &answer, AT + 1).is_err());
        for count in [0, CASE_COUNT - 1, CASE_COUNT + 1, 4096] {
            answer.answers = vec![0; count];
            assert!(certify_answer(&fixture.issuer, &fixture.room, &answer, AT + 1).is_err());
        }
        let mut proof = fixture.proof();
        proof.answer.answers[0] ^= 1;
        assert!(fixture.verify_proof(&proof, AT + 1, AT + 2).is_err());
        let mut encoded = serde_json::to_value(fixture.answer()).unwrap();
        encoded["answers"][0] = json!(u64::from(u32::MAX) + 1);
        assert!(serde_json::from_value::<AutomationAnswer>(encoded).is_err());
    }

    #[test]
    fn wrong_digest_peer_purpose_and_room_are_rejected() {
        let fixture = Fixture::new("publish");
        for (subject, digest, purpose) in [
            (fixture.subject(), "c".repeat(64), "publish"),
            (
                fixture.issuer.public().to_peer_id().to_string(),
                "b".repeat(64),
                "publish",
            ),
            (fixture.subject(), "b".repeat(64), "evaluate"),
            (fixture.subject(), "b".repeat(64), "ai_identity"),
        ] {
            assert!(
                verify_challenge(
                    &fixture.packet,
                    &fixture.room,
                    &subject,
                    &digest,
                    purpose,
                    AT + 1,
                    true
                )
                .is_err()
            );
            assert!(
                verify_proof(
                    &fixture.proof(),
                    &fixture.room,
                    &subject,
                    &digest,
                    purpose,
                    AT + 1,
                    AT + 2
                )
                .is_err()
            );
        }
        let mut other_room = fixture.room.clone();
        other_room.certificate.signed.room_id = "d".repeat(64);
        fixture.resign_room(&mut other_room);
        assert!(
            verify_challenge(
                &fixture.packet,
                &other_room,
                &fixture.subject(),
                &"b".repeat(64),
                "publish",
                AT + 1,
                true
            )
            .is_err()
        );
    }

    #[test]
    fn fresh_window_has_exact_expiry_and_rejects_future_or_oversized_lifetimes() {
        let fixture = Fixture::new("publish");
        fixture.verify(&fixture.packet, AT + 119, true).unwrap();
        assert!(fixture.verify(&fixture.packet, AT + 120, true).is_err());
        assert!(fixture.verify(&fixture.packet, AT - 1, true).is_err());
        assert!(
            certify_answer(&fixture.issuer, &fixture.room, &fixture.answer(), AT + 120).is_err()
        );
        let mut too_long = fixture.packet.clone();
        too_long.challenge.signed.expires_at += 1;
        fixture.resign_challenge(&mut too_long);
        assert!(fixture.verify(&too_long, AT, true).is_err());
        let mut zero = fixture.packet.clone();
        zero.challenge.signed.expires_at = AT;
        fixture.resign_challenge(&mut zero);
        assert!(fixture.verify(&zero, AT, true).is_err());
        assert!(fixture.verify(&fixture.packet, u64::MAX, true).is_err());
    }

    #[test]
    fn revoked_issuer_or_subject_cannot_certify_a_fresh_answer() {
        let fixture = Fixture::new("publish");
        for removed in [
            fixture.issuer.public().to_peer_id().to_string(),
            fixture.subject(),
        ] {
            let mut current = fixture.room.clone();
            current.certificate.signed.epoch += 1;
            current.certificate.signed.issued_at = AT + 1;
            current
                .certificate
                .signed
                .members
                .retain(|peer| peer.peer_id != removed);
            fixture.resign_room(&mut current);
            assert!(
                verify_challenge(
                    &fixture.packet,
                    &current,
                    &fixture.subject(),
                    &"b".repeat(64),
                    "publish",
                    AT + 2,
                    true
                )
                .is_err()
            );
            assert!(certify_answer(&fixture.issuer, &current, &fixture.answer(), AT + 2).is_err());
        }
    }

    #[test]
    fn historical_expiry_does_not_expire_existing_knowledge_evidence() {
        let fixture = Fixture::new("publish");
        let proof = fixture.proof();
        // Both the challenge and old room certificate have expired by now.
        fixture
            .verify_proof(&proof, AT + 1, AT + 365 * 86400)
            .unwrap();
        let mut current = fixture.room.clone();
        current.certificate.signed.epoch += 1;
        current.certificate.signed.issued_at = AT + 100;
        current
            .certificate
            .signed
            .members
            .retain(|peer| peer.peer_id != fixture.issuer.public().to_peer_id().to_string());
        fixture.resign_room(&mut current);
        verify_proof(
            &proof,
            &current,
            &fixture.subject(),
            &"b".repeat(64),
            "publish",
            AT + 1,
            AT + 365 * 86400,
        )
        .unwrap();
    }

    #[test]
    fn object_timestamp_is_within_exactly_three_hundred_seconds_of_receipt() {
        let fixture = Fixture::new("publish");
        let proof = fixture.proof();
        let verified = proof.receipt.signed.verified_at;
        for created in [verified - 300, verified, verified + 300] {
            fixture.verify_proof(&proof, created, AT + 1000).unwrap();
        }
        for created in [verified - 301, verified + 301, u64::MAX] {
            assert!(fixture.verify_proof(&proof, created, AT + 1000).is_err());
        }
    }

    #[test]
    fn forged_challenge_receipt_and_authority_signatures_are_rejected() {
        let fixture = Fixture::new("publish");
        let mut challenge = fixture.packet.clone();
        challenge.challenge.signed.seed = "f".repeat(64);
        assert!(fixture.verify(&challenge, AT + 1, true).is_err());
        let mut certificate = fixture.packet.clone();
        certificate.certificate.certificate.signed.epoch += 1;
        assert!(fixture.verify(&certificate, AT + 1, true).is_err());
        let mut proof = fixture.proof();
        proof.receipt.signed.verified_at += 1;
        assert!(fixture.verify_proof(&proof, AT + 1, AT + 2).is_err());
        let wrong = identity::Keypair::generate_ed25519();
        let mut proof = fixture.proof();
        proof.receipt.signature =
            crypto::sign(&wrong, RECEIPT_DOMAIN, &proof.receipt.signed).unwrap();
        assert!(fixture.verify_proof(&proof, AT + 1, AT + 2).is_err());
        assert!(
            certify_answer(&fixture.subject, &fixture.room, &fixture.answer(), AT + 1).is_err()
        );
    }

    #[test]
    fn a_receipt_cannot_be_moved_to_another_challenge_or_claim_identity() {
        let fixture = Fixture::new("evaluate");
        let mut proof = fixture.proof();
        let another = Fixture::new("evaluate");
        proof.receipt = another.proof().receipt;
        assert!(fixture.verify_proof(&proof, AT + 1, AT + 2).is_err());
        let mut proof = fixture.proof();
        proof.receipt.signed.assurance = "ai_verified".into();
        proof.receipt.signature =
            crypto::sign(&fixture.issuer, RECEIPT_DOMAIN, &proof.receipt.signed).unwrap();
        assert!(fixture.verify_proof(&proof, AT + 1, AT + 2).is_err());
        for verified_at in [AT - 1, AT + CHALLENGE_TTL_SECONDS + 1] {
            let mut proof = fixture.proof();
            proof.receipt.signed.verified_at = verified_at;
            proof.receipt.signature =
                crypto::sign(&fixture.issuer, RECEIPT_DOMAIN, &proof.receipt.signed).unwrap();
            assert!(
                fixture
                    .verify_proof(&proof, verified_at, AT + 1000)
                    .is_err()
            );
        }
    }

    #[test]
    fn typed_fields_and_packet_sizes_have_exact_bounds() {
        let fixture = Fixture::new("publish");
        for digest in ["b".repeat(63), "b".repeat(65), "B".repeat(64)] {
            assert!(
                create_challenge(
                    &fixture.issuer,
                    &fixture.room,
                    &fixture.subject(),
                    &digest,
                    "publish",
                    AT
                )
                .is_err()
            );
        }
        assert!(
            create_challenge(
                &fixture.subject,
                &fixture.room,
                &fixture.subject(),
                &"b".repeat(64),
                "publish",
                AT
            )
            .is_err()
        );
        assert!(
            create_challenge(
                &fixture.issuer,
                &fixture.room,
                &fixture.subject(),
                &"b".repeat(64),
                "model_claim",
                AT
            )
            .is_err()
        );
        // JSON quotes contribute two bytes; exercise the inclusive byte limit.
        bounded(&"x".repeat(MAX_PACKET_BYTES - 2)).unwrap();
        assert!(bounded(&"x".repeat(MAX_PACKET_BYTES - 1)).is_err());
        let mut oversized = fixture.packet.clone();
        oversized.challenge.signed.seed = "0".repeat(MAX_PACKET_BYTES);
        assert!(fixture.verify(&oversized, AT + 1, true).is_err());
        let mut unknown = serde_json::to_value(fixture.answer()).unwrap();
        unknown["model"] = json!("claimed AI");
        assert!(serde_json::from_value::<AutomationAnswer>(unknown).is_err());
    }
}
