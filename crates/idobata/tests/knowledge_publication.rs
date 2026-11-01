#![cfg(unix)]
//! The publisher is deliberately NOT a keeper. Its public-only cache must not
//! become a fourth storage replica or disappear during a partial peer fetch.
use idobata::{
    config, crypto, daemon, ipc,
    knowledge::{self, KnowledgeInput, Store},
    knowledge_abuse::OperatorClaims,
    knowledge_publication,
    types::*,
    util,
};
use std::{collections::BTreeMap, time::Duration};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn nonkeeper_publication_browses_distributed_records_and_preserves_verified_partial_cache() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let dir = tempfile::tempdir().unwrap();
    let listeners = (0..4)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect::<Vec<_>>();
    let homes = (0..4)
        .map(|i| dir.path().join(format!("node-{i}")))
        .collect::<Vec<_>>();
    let members = homes
        .iter()
        .zip(&listeners)
        .map(|(home, listener)| {
            config::init(
                home,
                vec![format!(
                    "/ip4/127.0.0.1/tcp/{}",
                    listener.local_addr().unwrap().port()
                )],
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let claims = OperatorClaims {
        bindings: members
            .iter()
            .map(|m| (m.peer_id.clone(), "fixture-one-operator".into()))
            .collect(),
        credits: BTreeMap::from([("fixture-one-operator".into(), 1000)]),
    };
    let cert = config::create_room_with_operators(
        &homes[0],
        "public",
        members.clone(),
        1,
        true,
        false,
        Some(claims),
    )
    .unwrap();
    for home in homes.iter().skip(1) {
        config::join_room(home, "public", cert.clone(), &members[0].peer_id).unwrap();
    }
    let room = config::load(&homes[0]).unwrap().rooms["public"].clone();
    let key = crypto::load_key(&homes[1]).unwrap();
    let at = util::now();
    let packet = (0..100)
        .find_map(|i| {
            let packet = knowledge::create_record(
                &key,
                &room,
                KnowledgeInput {
                    problem: format!(
                        "How can a public distributed answer be retrieved safely? Case {i}"
                    ),
                    solution: "Use the bounded documented public view and retain all conditions."
                        .into(),
                    context: "The publisher is not assigned to store the original record.".into(),
                    references: vec!["https://example.org/manual".into()],
                    kind: "answer".into(),
                },
                true,
                at,
            )
            .unwrap();
            (!knowledge::replica_peers(&room.certificate.signed, &packet.record.signed.id, 3)
                .contains(&members[0].peer_id))
            .then_some(packet)
        })
        .unwrap();
    for home in homes.iter().skip(1) {
        let mut store = Store::open(home).unwrap();
        store.set_rooms([room.clone()]);
        store.insert(packet.clone(), false, at).unwrap();
    }
    let endpoints = homes
        .iter()
        .map(|home| config::load(home).unwrap().endpoint)
        .collect::<Vec<_>>();
    drop(listeners);
    let mut tasks = homes
        .iter()
        .map(|home| {
            let home = home.clone();
            tokio::spawn(async move { daemon::run(&home).await })
        })
        .collect::<Vec<_>>();
    struct Stop(Vec<tokio::task::AbortHandle>);
    impl Drop for Stop {
        fn drop(&mut self) {
            for handle in &self.0 {
                handle.abort();
            }
        }
    }
    let _stop = Stop(tasks.iter().map(|t| t.abort_handle()).collect());
    for endpoint in &endpoints {
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if ipc::call(endpoint, &Request::Info).await.is_ok() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .unwrap();
    }
    let scope = util::hash(b"fixture-publisher-feed");
    let request = || Request::KnowledgePublicSnapshot {
        room: "public".into(),
        scope: scope.clone(),
        cursor: None,
        withdrawn: vec![],
        reset_withdrawn: false,
        forget_only: false,
    };
    let first = ipc::call(&endpoints[0], &request()).await.unwrap();
    assert_eq!(first.code, 0, "{}", first.result);
    let entries: Vec<idobata::publication::PublicEntry> =
        serde_json::from_value(first.result["entries"].clone()).unwrap();
    assert_eq!(entries.len(), 1, "{}", first.result);
    assert_eq!(
        entries[0].origin.message_id,
        knowledge_publication::public_record_id(&packet.record.signed.id)
    );
    assert!(
        entries[0]
            .content
            .body
            .contains(&packet.record.signed.solution)
    );
    assert!(
        entries[0]
            .content
            .body
            .contains(&packet.record.signed.context)
    );
    let public = serde_json::to_string(&first.result).unwrap();
    for member in &members {
        assert!(!public.contains(&member.peer_id));
        assert!(!public.contains(&member.public_key));
        for address in &member.addresses {
            assert!(!public.contains(address));
        }
    }
    let status = ipc::call(
        &endpoints[0],
        &Request::KnowledgeStatus {
            room: Some("public".into()),
        },
    )
    .await
    .unwrap();
    assert!(
        status.result["records"].as_array().unwrap().is_empty(),
        "projection cache must not become a keeper replica"
    );
    let info = ipc::call(&endpoints[0], &Request::Info).await.unwrap();
    assert!(
        info.result["knowledge"]["public_projection"]["sources"]
            .as_u64()
            .unwrap()
            >= 1
    );
    // Exercise the real publisher CLI with a different publisher key/home.
    // It must sign the distributed projection, preserve legacy schema and
    // reject arbitrary ID-shaped withdrawal input before writing the manifest.
    let publisher_home = dir.path().join("publisher");
    config::init(&publisher_home, vec!["/ip4/127.0.0.1/tcp/0".into()]).unwrap();
    let feed_path = dir.path().join("public-feed.json");
    let publisher = crypto::load_key(&publisher_home).unwrap();
    let run_refresh = |withdraw: Option<String>| {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_idobata"));
        command
            .arg("--home")
            .arg(&publisher_home)
            .arg("--socket")
            .arg(&endpoints[0])
            .args(["public", "refresh", "--feed"])
            .arg(&feed_path)
            .args(["--room", "public"]);
        if let Some(id) = withdraw {
            command.arg("--withdraw").arg(id);
        }
        async move { command.output().await.unwrap() }
    };
    let refreshed = run_refresh(None).await;
    assert!(refreshed.status.success(), "publisher CLI failed");
    let mut manifest: Signed<idobata::publication::Manifest> =
        serde_json::from_slice(&std::fs::read(&feed_path).unwrap()).unwrap();
    idobata::publication::verify_manifest(
        &manifest,
        &crypto::public(&publisher),
        util::now(),
        None,
    )
    .unwrap();
    assert_eq!(manifest.signed.count, 1);
    assert_eq!(
        manifest.signed.feed.posts[0].signed.id,
        entries[0].origin.message_id
    );
    let previous_id = util::hash(b"a previously signed public legacy post");
    let mut previous = entries[0].clone();
    previous.origin.message_id = previous_id.clone();
    previous.content.title = "A previous public legacy entry".into();
    idobata::publication::import(
        &mut manifest.signed.feed,
        &publisher,
        vec![previous],
        util::now(),
    )
    .unwrap();
    manifest = idobata::publication::seal(
        manifest.signed.feed,
        manifest.signed.withdrawn,
        manifest.signed.revision + 1,
        &publisher,
        util::now(),
        600,
    )
    .unwrap();
    util::atomic_write(&feed_path, &util::canonical(&manifest).unwrap()).unwrap();
    let withdrawn = run_refresh(Some(previous_id.clone())).await;
    assert!(
        withdrawn.status.success(),
        "an existing automatic post remains retractable after selection omits it"
    );
    let before_unknown = std::fs::read(&feed_path).unwrap();
    let manifest: Signed<idobata::publication::Manifest> =
        serde_json::from_slice(&before_unknown).unwrap();
    assert!(manifest.signed.withdrawn.contains(&previous_id));
    let unknown_id = util::hash(b"an unknown pasted identifier is not public publication data");
    let unknown = run_refresh(Some(unknown_id.clone())).await;
    assert!(!unknown.status.success());
    assert!(!String::from_utf8_lossy(&unknown.stdout).contains(&unknown_id));
    assert_eq!(std::fs::read(&feed_path).unwrap(), before_unknown);
    for task in tasks.drain(1..) {
        task.abort();
        let _ = task.await;
    }
    let partial = ipc::call(&endpoints[0], &request()).await.unwrap();
    assert_eq!(partial.code, 0, "{}", partial.result);
    assert_eq!(partial.result["partial"], true);
    assert_eq!(partial.result["entries"].as_array().unwrap().len(), 1);
    assert_eq!(
        partial.result["oldest_source_observed_at"],
        first.result["oldest_source_observed_at"]
    );
    assert_eq!(partial.result["observed_at"], first.result["observed_at"]);
    let forgotten = ipc::call(
        &endpoints[0],
        &Request::KnowledgePublicSnapshot {
            room: "public".into(),
            scope: scope.clone(),
            cursor: None,
            withdrawn: vec![entries[0].origin.message_id.clone()],
            reset_withdrawn: false,
            forget_only: true,
        },
    )
    .await
    .unwrap();
    assert_eq!(forgotten.code, 0);
    let last = ipc::call(&endpoints[0], &request()).await.unwrap();
    assert_eq!(last.code, 0, "{}", last.result);
    assert!(last.result["entries"].as_array().unwrap().is_empty());
    assert_eq!(last.result["partial"], true);
}
