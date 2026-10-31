use idobata::{config, crypto, discussion, publication, scanner::Scanner, types::*, util};
use libp2p::identity;

#[test]
fn signed_manifest_detects_removal_expiry_wrong_key_and_rollback() {
    let key = identity::Keypair::generate_ed25519();
    let at = util::now();
    let feed = publication::append(
        None,
        &key,
        Draft::plain("公開する開発ノートです。".into()),
        true,
        at,
    )
    .unwrap();
    let doc = publication::seal(feed.clone(), vec![], 1, &key, at, 600).unwrap();
    let pin = crypto::public(&key);
    let checkpoint = publication::verify_manifest(&doc, &pin, at, None).unwrap();
    let mut removed = doc.clone();
    removed.signed.feed.posts.clear();
    removed.signed.count = 0;
    assert!(publication::verify_manifest(&removed, &pin, at, None).is_err());
    assert!(publication::verify_manifest(&doc, &pin, at + 601, None).is_err());
    let other = crypto::public(&identity::Keypair::generate_ed25519());
    assert!(publication::verify_manifest(&doc, &other, at, None).is_err());
    let newer = publication::seal(feed.clone(), vec![], 2, &key, at, 600).unwrap();
    let newer_checkpoint =
        publication::verify_manifest(&newer, &pin, at, Some(&checkpoint)).unwrap();
    assert!(publication::verify_manifest(&doc, &pin, at, Some(&newer_checkpoint)).is_err());
    let different = publication::seal(feed, vec![], 2, &key, at + 1, 600).unwrap();
    assert!(
        publication::verify_manifest(&different, &pin, at + 1, Some(&newer_checkpoint)).is_err()
    );
}

#[test]
fn private_room_cannot_be_promoted_or_used_for_public_posts() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("node");
    let own = config::init(&home, vec!["/ip4/127.0.0.1/tcp/39101".into()]).unwrap();
    let cert = config::create_room(&home, "test", vec![own.clone()], 24).unwrap();
    assert!(
        config::create_room_with_visibility(&home, "test", vec![own.clone()], 24, true).is_err()
    );
    let key = crypto::load_key(&home).unwrap();
    assert!(
        crypto::new_envelope_with_options(
            &key,
            &cert.signed,
            &Scanner::policy_id(),
            Draft::plain("公開する開発ノートです。".into()),
            PostOptions {
                public: true,
                ..Default::default()
            }
        )
        .is_err()
    );
    let public = config::create_room_with_visibility(&home, "public", vec![own], 24, true).unwrap();
    let env = crypto::new_envelope_with_options(
        &key,
        &public.signed,
        &Scanner::policy_id(),
        Draft::plain("公開する開発ノートです。".into()),
        PostOptions {
            public: true,
            ..Default::default()
        },
    )
    .unwrap();
    let trusted = TrustedRoom {
        authority_peer_id: key.public().to_peer_id().to_string(),
        certificate: public,
    };
    crypto::verify_message(
        &env,
        &key.public().to_peer_id(),
        &trusted,
        &Scanner::policy_id(),
        util::now(),
    )
    .unwrap();
    let mut tampered = env;
    tampered.payload.options.public = false;
    assert!(
        crypto::verify_message(
            &tampered,
            &key.public().to_peer_id(),
            &trusted,
            &Scanner::policy_id(),
            util::now()
        )
        .is_err()
    );
}

#[test]
fn only_question_author_can_resolve_and_private_replies_stay_private() {
    let temp = tempfile::tempdir().unwrap();
    let home = temp.path().join("node");
    let own = config::init(&home, vec!["/ip4/127.0.0.1/tcp/39101".into()]).unwrap();
    let cert = config::create_room(&home, "test", vec![own], 24).unwrap();
    let key = crypto::load_key(&home).unwrap();
    let sender = key.public().to_peer_id().to_string();
    let mut question = Draft::plain("どのように検証しますか。".into());
    question.kind = "question".into();
    let env = crypto::new_envelope(&key, &cert.signed, &Scanner::policy_id(), question).unwrap();
    let state = State {
        version: 1,
        outbox: vec![Outbox {
            request_id: util::random_id(),
            owner: "test".into(),
            room_alias: "test".into(),
            wire: util::canonical(&env).unwrap(),
            created_at: util::now(),
            expires_at: util::now() + 3600,
            recipients: vec![],
            delivered: Default::default(),
            held: None,
        }],
        ..Default::default()
    };
    let options = PostOptions {
        reply_to: Some(env.payload.message_id.clone()),
        resolution: Some(Resolution::Resolved),
        public: false,
    };
    let draft = Draft::plain("検証を終えました。".into());
    discussion::validate(&state, &cert.signed.room_id, &sender, &draft, &options).unwrap();
    assert!(
        discussion::validate(
            &state,
            &cert.signed.room_id,
            "another-peer",
            &draft,
            &options
        )
        .is_err()
    );
    assert!(discussion::validate(&state, &util::random_id(), &sender, &draft, &options).is_err());
    assert!(
        discussion::validate(
            &state,
            &cert.signed.room_id,
            &sender,
            &draft,
            &PostOptions {
                public: true,
                ..options
            }
        )
        .is_err()
    );
}

#[test]
fn offline_root_authorizes_rotation_preserves_old_signatures_and_revokes_keys() {
    use idobata::trust::{self, Grant};
    let root = identity::Keypair::generate_ed25519();
    let first = identity::Keypair::generate_ed25519();
    let next = identity::Keypair::generate_ed25519();
    let at = util::now();
    let old = crypto::public(&first);
    let new = crypto::public(&next);
    let pin = crypto::public(&root);
    let grants = vec![
        Grant {
            public_key: old.clone(),
            not_before: at - 30,
            not_after: at + 5,
        },
        Grant {
            public_key: new.clone(),
            not_before: at,
            not_after: at + 3600,
        },
    ];
    let trust = trust::create(&root, grants.clone(), vec![], 2, at).unwrap();
    let feed = publication::append(
        None,
        &first,
        Draft::plain("最初の公開投稿です。".into()),
        true,
        at,
    )
    .unwrap();
    let old_signature = feed.posts[0].signature.clone();
    let feed = publication::append_with_keys(
        Some(feed),
        &next,
        Draft::plain("新しい鍵の公開投稿です。".into()),
        true,
        at + 6,
        &[old.clone(), new.clone()],
    )
    .unwrap();
    assert_eq!(feed.posts[1].signature, old_signature);
    let doc = publication::seal_with_keys(
        feed.clone(),
        vec![],
        3,
        &next,
        at + 6,
        600,
        &[old.clone(), new.clone()],
    )
    .unwrap();
    let checkpoint = trust::verify_feed(&doc, &trust, &pin, at + 6, None).unwrap();
    let revoked = trust::create(&root, grants.clone(), vec![old.clone()], 3, at + 6).unwrap();
    assert!(trust::verify_feed(&doc, &revoked, &pin, at + 6, Some(&checkpoint)).is_err());
    let old_policy = trust::create(&root, grants, vec![], 1, at).unwrap();
    assert!(trust::verify_feed(&doc, &old_policy, &pin, at + 6, Some(&checkpoint)).is_err());
    let mut altered = trust;
    altered.signed.keys.push(Grant {
        public_key: crypto::public(&identity::Keypair::generate_ed25519()),
        not_before: at,
        not_after: at + 3600,
    });
    assert!(trust::verify(&altered, &pin, at, None).is_err());
}
