#![cfg(unix)]

// Real IPC/transport deadlines run in their own test executable, so unrelated
// CPU-heavy WASM unit tests cannot starve the fixtures. All tests remain part of
// ordinary `cargo test --workspace`; production deadlines stay unchanged.
use futures::StreamExt;
use idobata::{
    config, crypto,
    daemon::run,
    error::Result,
    ipc,
    network::{self, BehaviourEvent},
    types::*,
    util,
};
use libp2p::{
    PeerId,
    request_response::{self, Message},
    swarm::SwarmEvent,
};
use std::{collections::BTreeSet, path::PathBuf, time::Duration};

// Each case contains a concurrent multi-peer cluster. Do not run several such
// clusters on the same test host's CPU budget: the tests assert real protocol
// deadlines, rather than overload behavior, and still run under normal cargo test.
static CLUSTER_SLOT: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

use idobata::{
    knowledge::{KnowledgeInput, ReviewInput},
    knowledge_runtime::{WireReply, WireRequest},
};

struct Fixture {
    _temporary: tempfile::TempDir,
    homes: Vec<PathBuf>,
    endpoints: Vec<String>,
    members: Vec<Member>,
    tasks: Vec<tokio::task::JoinHandle<Result<()>>>,
}

impl Fixture {
    fn new() -> Self {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let temporary = tempfile::tempdir().unwrap();
        // Reserve both ephemeral ports together, so the two fixtures cannot
        // accidentally choose the same address before the daemons start.
        let listeners: Vec<_> = (0..2)
            .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
            .collect();
        let homes: Vec<_> = (0..2)
            .map(|index| temporary.path().join(format!("node-{index}")))
            .collect();
        let members: Vec<_> = homes
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
            .collect();
        let shared = config::create_room(&homes[0], "exchange", members.clone(), 1).unwrap();
        config::join_room(&homes[1], "exchange", shared, &members[0].peer_id).unwrap();
        config::create_room(&homes[0], "isolated", vec![members[0].clone()], 1).unwrap();
        let endpoints = homes
            .iter()
            .map(|home| config::load(home).unwrap().endpoint)
            .collect();
        drop(listeners);
        Self {
            _temporary: temporary,
            homes,
            endpoints,
            members,
            tasks: vec![],
        }
    }

    async fn start(&mut self, index: usize) {
        let home = self.homes[index].clone();
        self.tasks
            .push(tokio::spawn(async move { run(&home).await }));
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if ipc::call(&self.endpoints[index], &Request::Info)
                    .await
                    .is_ok()
                {
                    break;
                }
                assert!(
                    !self.tasks.last().unwrap().is_finished(),
                    "fixture daemon failed to start"
                );
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("fixture IPC did not start");
    }

    async fn call(&self, index: usize, request: Request) -> Reply {
        ipc::call(&self.endpoints[index], &request).await.unwrap()
    }

    async fn wait_connected(&self) {
        // IPC readiness does not promise that a cold TCP/Noise dial has
        // completed. Strict complete-response assertions need both peers
        // reachable before the operation begins.
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let first = self.call(0, Request::Info).await;
                let second = self.call(1, Request::Info).await;
                if first.result["connected_peers"].as_u64().unwrap() >= 1
                    && second.result["connected_peers"].as_u64().unwrap() >= 1
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("fixture peers did not establish TCP/Noise connectivity");
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn knowledge_ipc_routes_signed_records_queries_and_evaluations_between_daemons() {
    let _cluster = CLUSTER_SLOT.lock().await;
    let mut fixture = Fixture::new();
    fixture.start(0).await;
    fixture.start(1).await;
    fixture.wait_connected().await;
    let published = fixture
        .call(
            0,
            Request::KnowledgePublish {
                room: "exchange".into(),
                input: KnowledgeInput {
                    problem: "How should an agent retry a transient connection failure?".into(),
                    solution: "Reconnect and retry with a bounded backoff.".into(),
                    context: "The operation must tolerate duplicate delivery.".into(),
                    references: vec![],
                    kind: "answer".into(),
                },
                public: false,
                proof: None,
            },
        )
        .await;
    assert_eq!(published.code, 0, "{}", published.result);
    let id = published.result["id"].as_str().unwrap().to_owned();
    let found = fixture
        .call(
            1,
            Request::KnowledgeSearch {
                room: "exchange".into(),
                query: "retry".into(),
                limit: 10,
            },
        )
        .await;
    assert_eq!(found.code, 0);
    assert_eq!(found.result["untrusted"], true);
    let query_metrics = serde_json::json!({
        "partial": found.result["partial"],
        "responded_peers": found.result["responded_peers"],
        "failed_peers": found.result["failed_peers"],
        "hits": found.result["hits"].as_array().map(Vec::len),
    });
    eprintln!("fixture_query_metrics {query_metrics}");
    assert_eq!(found.result["partial"], false, "{query_metrics}");
    assert!(found.result["responded_peers"].as_u64().unwrap() >= 1);
    assert!(
        found.result["hits"]
            .as_array()
            .unwrap()
            .iter()
            .any(|hit| hit["id"] == id)
    );

    let fetched = fixture
        .call(
            1,
            Request::KnowledgeGet {
                room: "exchange".into(),
                id: id.clone(),
            },
        )
        .await;
    assert_eq!(fetched.code, 0);
    assert_eq!(
        fetched.result["record"]["author_peer_id"],
        fixture.members[0].peer_id
    );
    assert_eq!(fetched.result["untrusted"], true);

    for verdict in ["useful", "incorrect"] {
        let evaluated = fixture
            .call(
                1,
                Request::KnowledgeEvaluate {
                    room: "exchange".into(),
                    id: id.clone(),
                    proof: None,
                    input: ReviewInput {
                        verdict: verdict.into(),
                        evidence: "The retry behavior was checked against the stated conditions."
                            .into(),
                        references: vec![],
                    },
                },
            )
            .await;
        assert_eq!(evaluated.code, 0, "{}", evaluated.result);
    }
    let reviewed = fixture
        .call(
            0,
            Request::KnowledgeGet {
                room: "exchange".into(),
                id: id.clone(),
            },
        )
        .await;
    assert_eq!(reviewed.code, 0);
    assert_eq!(reviewed.result["quality"]["useful_votes"], 0);
    assert_eq!(reviewed.result["quality"]["negative_votes"], 1);
    assert_eq!(
        reviewed.result["record"]["author_peer_id"],
        fixture.members[0].peer_id
    );

    let peers = fixture
        .call(
            1,
            Request::KnowledgePeers {
                room: "exchange".into(),
                query: "retry".into(),
                limit: 10,
            },
        )
        .await;
    assert_eq!(peers.code, 0);
    assert!(
        peers.result["peers"]
            .as_array()
            .unwrap()
            .iter()
            .any(|peer| peer["peer_id"] == fixture.members[0].peer_id)
    );
    let info = fixture.call(0, Request::Info).await;
    assert_eq!(info.result["knowledge"]["storage"]["objects"], 1);
    assert_eq!(info.result["inbox_count"], 0);
    let inbox = fixture
        .call(
            0,
            Request::Inbox {
                room: "exchange".into(),
                limit: 10,
            },
        )
        .await;
    assert_eq!(inbox.code, 0);
    assert!(inbox.result["messages"].as_array().unwrap().is_empty());
    let legacy_snapshot = fixture
        .call(
            0,
            Request::PublicSnapshot {
                room: "exchange".into(),
                before: None,
            },
        )
        .await;
    assert_ne!(legacy_snapshot.code, 0);
    let status = fixture
        .call(
            0,
            Request::KnowledgeStatus {
                room: Some("exchange".into()),
            },
        )
        .await;
    assert_eq!(status.code, 0);
    assert_eq!(status.result["objects"], 1);
}

fn answer_public_tasks(
    packet: idobata::automation::ChallengePacket,
) -> idobata::automation::AutomationAnswer {
    // This is an integration-test client for the published task format. The
    // production CLI deliberately contains no automatic challenge solver.
    let answers = idobata::automation::tasks(&packet.challenge.signed)
        .into_iter()
        .map(|case| {
            let mut values = case.values;
            if case.sort == "ascending" {
                values.sort_unstable();
            } else if case.sort == "descending" {
                values.sort_unstable_by(|left, right| right.cmp(left));
            }
            values.rotate_left(case.rotate_left as usize);
            values
                .into_iter()
                .enumerate()
                .fold(case.initial, |accumulator, (position, value)| {
                    let next = (u64::from(accumulator) * u64::from(case.multiplier)
                        + (position as u64 + 1) * u64::from(value))
                        as u32;
                    next.rotate_left((case.index + position as u32) % 31 + 1)
                })
        })
        .collect();
    idobata::automation::AutomationAnswer {
        challenge: packet,
        answers,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn required_automation_admission_returns_a_task_before_storing_and_accepts_its_answer() {
    let _cluster = CLUSTER_SLOT.lock().await;
    let mut fixture = Fixture::new();
    let gated = config::create_room_with_policy(
        &fixture.homes[0],
        "exchange",
        fixture.members.clone(),
        1,
        false,
        true,
    )
    .unwrap();
    config::join_room(
        &fixture.homes[1],
        "exchange",
        gated,
        &fixture.members[0].peer_id,
    )
    .unwrap();
    fixture.start(0).await;
    fixture.start(1).await;
    fixture.wait_connected().await;
    let input = KnowledgeInput {
        problem: "How should an agent retry after a connection failure?".into(),
        solution: "Reconnect before retrying with bounded backoff.".into(),
        context: "Use an operation that tolerates duplicate delivery.".into(),
        references: vec![],
        kind: "answer".into(),
    };
    let challenge = fixture
        .call(
            0,
            Request::KnowledgePublish {
                room: "exchange".into(),
                input: input.clone(),
                public: false,
                proof: None,
            },
        )
        .await;
    assert_eq!(challenge.code, 31, "{}", challenge.result);
    assert_eq!(challenge.result["enqueued"], false);
    assert_eq!(challenge.result["stored"], false);
    assert_eq!(
        challenge.result["task_spec"]["assurance"],
        "automation_tested"
    );
    assert!(challenge.result.get("assurance").is_none());
    assert_eq!(
        challenge.result["tasks"].as_array().unwrap().len(),
        idobata::automation::CASE_COUNT
    );
    let before = fixture
        .call(
            0,
            Request::KnowledgeStatus {
                room: Some("exchange".into()),
            },
        )
        .await;
    assert_eq!(before.result["objects"], 0);
    let packet = serde_json::from_value(challenge.result["challenge"].clone()).unwrap();
    let published = fixture
        .call(
            0,
            Request::KnowledgePublish {
                room: "exchange".into(),
                input,
                public: false,
                proof: Some(answer_public_tasks(packet)),
            },
        )
        .await;
    assert_eq!(published.code, 0, "{}", published.result);
    assert_eq!(published.result["assurance"], "automation_tested");
    let id = published.result["id"].as_str().unwrap().to_owned();
    let replicated = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let status = fixture
                .call(
                    1,
                    Request::KnowledgeStatus {
                        room: Some("exchange".into()),
                    },
                )
                .await;
            if status.result["records"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["id"] == id)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    if replicated.is_err() {
        let mut snapshots = vec![];
        for index in 0..2 {
            let status = fixture
                .call(
                    index,
                    Request::KnowledgeStatus {
                        room: Some("exchange".into()),
                    },
                )
                .await;
            let info = fixture.call(index, Request::Info).await;
            let row = status.result["records"]
                .as_array()
                .and_then(|rows| rows.iter().find(|row| row["id"] == id));
            snapshots.push(serde_json::json!({
                "node_index":index,
                "record_present":row.is_some(),
                "objects":status.result["objects"],
                "local_role":row.map(|row| &row["local_role"]),
                "staging":row.map(|row| &row["staging"]),
                "replica_acks":row.and_then(|row| row["replica_acks"].as_array()).map(Vec::len),
                "pending_replications":info.result["knowledge"]["pending_replications"],
                "pending_repairs":info.result["knowledge"]["pending_repairs"],
                "pending_automation":info.result["knowledge"]["pending_automation"],
            }));
        }
        panic!("fixture_replica_metrics {}", serde_json::json!(snapshots));
    }
    let review = ReviewInput {
        verdict: "useful".into(),
        evidence: "The retry procedure worked under the stated conditions.".into(),
        references: vec![],
    };
    let challenge = fixture
        .call(
            1,
            Request::KnowledgeEvaluate {
                room: "exchange".into(),
                id: id.clone(),
                input: review.clone(),
                proof: None,
            },
        )
        .await;
    assert_eq!(challenge.code, 31, "{}", challenge.result);
    assert_eq!(challenge.result["enqueued"], false);
    let packet = serde_json::from_value(challenge.result["challenge"].clone()).unwrap();
    let evaluated = fixture
        .call(
            1,
            Request::KnowledgeEvaluate {
                room: "exchange".into(),
                id: id.clone(),
                input: review,
                proof: Some(answer_public_tasks(packet)),
            },
        )
        .await;
    assert_eq!(evaluated.code, 0, "{}", evaluated.result);
    assert_eq!(evaluated.result["assurance"], "automation_tested");
    let fetched = fixture
        .call(
            0,
            Request::KnowledgeGet {
                room: "exchange".into(),
                id,
            },
        )
        .await;
    assert_eq!(fetched.result["quality"]["useful_votes"], 1);
    assert_eq!(fetched.result["untrusted"], true);
}

async fn wire_call(
    swarm: &mut libp2p::Swarm<network::Behaviour>,
    peer: PeerId,
    request: WireRequest,
) -> WireReply {
    let outbound = swarm
        .behaviour_mut()
        .knowledge
        .send_request(&peer, util::canonical(&request).unwrap());
    tokio::time::timeout(Duration::from_secs(8), async {
        loop {
            match swarm.select_next_some().await {
                SwarmEvent::Behaviour(BehaviourEvent::Knowledge(
                    request_response::Event::Message {
                        message:
                            Message::Response {
                                request_id,
                                response,
                            },
                        ..
                    },
                )) if request_id == outbound => {
                    return serde_json::from_slice(&response).unwrap();
                }
                SwarmEvent::Behaviour(BehaviourEvent::Knowledge(
                    request_response::Event::OutboundFailure { request_id, .. },
                )) if request_id == outbound => panic!("fixture knowledge transport failed"),
                _ => {}
            }
        }
    })
    .await
    .expect("fixture knowledge transport timed out")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authenticated_shared_peer_cannot_query_another_room_over_knowledge_protocol() {
    let _cluster = CLUSTER_SLOT.lock().await;
    let mut fixture = Fixture::new();
    fixture.start(0).await;
    let client_config = config::load(&fixture.homes[1]).unwrap();
    let key = crypto::load_key(&fixture.homes[1]).unwrap();
    let own = key.public().to_peer_id().to_string();
    let mut swarm = network::build(key, &client_config).await.unwrap();
    network::refresh(&mut swarm, &client_config, &mut BTreeSet::new(), &own);
    let host_config = config::load(&fixture.homes[0]).unwrap();
    let peer = fixture.members[0].peer_id.parse().unwrap();
    let private_id = host_config.rooms["isolated"]
        .certificate
        .signed
        .room_id
        .clone();
    let rejected = wire_call(
        &mut swarm,
        peer,
        WireRequest::Search {
            room_id: private_id,
            query: "retry".into(),
            limit: 10,
        },
    )
    .await;
    assert!(matches!(rejected, WireReply::Rejected { .. }));
    let shared_id = client_config.rooms["exchange"]
        .certificate
        .signed
        .room_id
        .clone();
    let accepted = wire_call(
        &mut swarm,
        peer,
        WireRequest::Search {
            room_id: shared_id,
            query: "retry".into(),
            limit: 10,
        },
    )
    .await;
    assert!(matches!(accepted, WireReply::Hits { hits, truncated: false } if hits.is_empty()));
}
