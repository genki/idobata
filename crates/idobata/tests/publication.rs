use idobata::{crypto, publication, types::Draft, util};
use libp2p::identity;

#[test]
fn publication_requires_consent_inspection_and_a_pinned_signer() {
    let key = identity::Keypair::generate_ed25519();
    let at = util::now();
    let draft = Draft::plain("公開する開発ノートです。".into());
    assert!(publication::append(None, &key, draft.clone(), false, at).is_err());
    let feed = publication::append(None, &key, draft, true, at).unwrap();
    publication::verify(&feed, &crypto::public(&key), at).unwrap();
    let rogue = identity::Keypair::generate_ed25519();
    assert!(publication::verify(&feed, &crypto::public(&rogue), at).is_err());
    let mut tampered = feed.clone();
    tampered.posts[0].signed.content.body = "置き換えた内容です。".into();
    assert!(publication::verify(&tampered, &crypto::public(&key), at).is_err());
    let secret = Draft::plain("9aK7mP2xQ8vR4zT6nJ1bW5sL3cF0hD9u".into());
    assert_eq!(
        publication::append(Some(feed.clone()), &key, secret, true, at)
            .err()
            .unwrap()
            .code,
        20
    );
    assert_eq!(feed.posts.len(), 1);
    assert!(
        publication::append(
            Some(feed),
            &key,
            Draft::plain("次の投稿です。".into()),
            true,
            at - 1
        )
        .is_err()
    );
}

#[test]
fn feed_omits_private_network_metadata_and_rejects_unsigned_extra_fields() {
    let key = identity::Keypair::generate_ed25519();
    let feed = publication::append(
        None,
        &key,
        Draft::plain("公開する開発ノートです。".into()),
        true,
        util::now(),
    )
    .unwrap();
    let bytes = util::canonical(&feed).unwrap();
    let s = String::from_utf8(bytes).unwrap();
    for forbidden in [
        "room_id",
        "sender_peer_id",
        "addresses",
        "request_id",
        "owner",
    ] {
        assert!(!s.contains(forbidden));
    }
    let mut value = serde_json::to_value(&feed).unwrap();
    value["internal_host"] = "private".into();
    assert!(serde_json::from_value::<publication::Feed>(value).is_err());
}
