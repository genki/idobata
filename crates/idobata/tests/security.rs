use idobata::{config, crypto, scanner::Scanner, storage::Storage, types::*, util};
use libp2p::identity;
fn room(a: &identity::Keypair, b: &identity::Keypair) -> TrustedRoom {
    let at = util::now();
    let signed = Room {
        version: 1,
        room_id: util::random_id(),
        epoch: 1,
        issued_at: at,
        expires_at: at + 3600,
        policy_id: Scanner::policy_id(),
        members: [a, b]
            .iter()
            .map(|k| Member {
                peer_id: k.public().to_peer_id().to_string(),
                public_key: crypto::public(k),
                addresses: vec![],
            })
            .collect(),
        public: false,
        knowledge_automation_required: false,
    };
    TrustedRoom {
        authority_peer_id: a.public().to_peer_id().to_string(),
        certificate: Signed {
            public_key: crypto::public(a),
            signature: crypto::sign(a, "idobata.room.v1", &signed).unwrap(),
            signed,
        },
    }
}
#[test]
fn signer_transport_membership_and_expiry_are_independent_checks() {
    let a = identity::Keypair::generate_ed25519();
    let b = identity::Keypair::generate_ed25519();
    let r = room(&a, &b);
    let policy = Scanner::policy_id();
    let at = util::now();
    let mut env = crypto::new_envelope(
        &a,
        &r.certificate.signed,
        &policy,
        Draft::plain("The work is ready.".into()),
    )
    .unwrap();
    crypto::verify_message(&env, &a.public().to_peer_id(), &r, &policy, at).unwrap();
    assert!(crypto::verify_message(&env, &b.public().to_peer_id(), &r, &policy, at).is_err());
    assert!(
        crypto::verify_message(&env, &a.public().to_peer_id(), &r, &policy, at + 3601).is_err()
    );
    env.payload.body = "A different message.".into();
    assert!(crypto::verify_message(&env, &a.public().to_peer_id(), &r, &policy, at).is_err());
    let mut other = r.clone();
    other.authority_peer_id = b.public().to_peer_id().to_string();
    assert!(crypto::validate_room(&other, &policy, at).is_err());
}
#[test]
fn encrypted_store_detects_tampering_and_keeps_text_off_disk() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("node");
    config::init(&home, vec!["/ip4/127.0.0.1/tcp/19061".into()]).unwrap();
    let storage = Storage::open(&home).unwrap();
    let text = "The public fixture is stored only after approval.";
    let mut state = State {
        version: 1,
        ..State::default()
    };
    state.prepared.push(Prepared {
        id: util::random_id(),
        owner: "test".into(),
        room: "test".into(),
        expires_at: util::now() + 300,
        policy_id: Scanner::policy_id(),
        draft: Draft::plain(text.into()),
    });
    storage.save(&state).unwrap();
    let mut bytes = std::fs::read(home.join("state.enc")).unwrap();
    assert!(!bytes.windows(text.len()).any(|b| b == text.as_bytes()));
    assert_eq!(storage.load().unwrap().prepared.len(), 1);
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(home.join("state.enc"), bytes).unwrap();
    assert!(storage.load().is_err());
}
#[test]
fn invite_does_not_grant_unlisted_identity() {
    let tmp = tempfile::tempdir().unwrap();
    let home = tmp.path().join("rogue");
    config::init(&home, vec!["/ip4/127.0.0.1/tcp/19061".into()]).unwrap();
    let a = identity::Keypair::generate_ed25519();
    let b = identity::Keypair::generate_ed25519();
    let r = room(&a, &b);
    assert!(config::join_room(&home, "test", r.certificate, &r.authority_peer_id).is_err());
    assert!(config::load(&home).unwrap().rooms.is_empty());
}
#[test]
fn parser_rejects_unknown_fields_duplicates_and_uri_credentials() {
    assert!(serde_json::from_str::<Draft>(r#"{"body":"one","body":"two"}"#).is_err());
    assert!(serde_json::from_str::<Draft>(r#"{"body":"one","token":"value"}"#).is_err());
    let mut draft = Draft::plain("The work is ready.".into());
    draft.references = vec!["https://user:password@example.org".into()];
    assert!(crypto::validate_draft(&draft).is_err());
}
#[cfg(unix)]
#[test]
fn private_state_rejects_shared_permissions() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(tmp.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(util::protected(tmp.path()).is_err());
}
