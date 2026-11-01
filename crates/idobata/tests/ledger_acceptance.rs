#![cfg(unix)]
//! Seven synthetic operators in separate production daemon processes. These
//! generated test identities say nothing about the independence of live hosts.
use idobata::{
    config, crypto,
    knowledge::{self, KnowledgeInput},
    knowledge_abuse::OperatorClaims,
    ledger, ledger_consensus as consensus, ledger_runtime,
    types::{Member, TrustedRoom},
    util,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::Write,
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Cluster {
    _temporary: tempfile::TempDir,
    executable: PathBuf,
    homes: Vec<PathBuf>,
    endpoints: Vec<String>,
    members: Vec<Member>,
    processes: Vec<Option<Child>>,
    records: [String; 3],
    chain: String,
}
struct CliReply {
    code: i32,
    value: Value,
}
impl Cluster {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        // Pin all daemon and CLI launches to one immutable compiled artifact even
        // while other owners finish independent library-focused checks.
        let executable = temporary.path().join("fixture-sdk");
        std::fs::copy(env!("CARGO_BIN_EXE_idobata"), &executable).unwrap();
        eprintln!(
            "ledger acceptance artifact_sha256={}",
            util::hash(&std::fs::read(&executable).unwrap())
        );
        let listeners = (0..7)
            .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
            .collect::<Vec<_>>();
        let homes = (0..7)
            .map(|i| temporary.path().join(format!("node-{i}")))
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
        let keys = homes
            .iter()
            .map(|home| crypto::load_key(home).unwrap())
            .collect::<Vec<_>>();
        let claims = OperatorClaims {
            bindings: members
                .iter()
                .enumerate()
                .map(|(i, m)| (m.peer_id.clone(), format!("synthetic-operator-{i}")))
                .collect(),
            credits: (0..7)
                .map(|i| (format!("synthetic-operator-{i}"), 1000))
                .collect(),
        };
        let certificate = config::create_room_with_operators(
            &homes[0],
            "experiment",
            members.clone(),
            1,
            false,
            false,
            Some(claims),
        )
        .unwrap();
        for home in &homes[1..] {
            config::join_room(home, "experiment", certificate.clone(), &members[0].peer_id)
                .unwrap();
        }
        let room = TrustedRoom {
            authority_peer_id: members[0].peer_id.clone(),
            certificate: certificate.clone(),
        };
        let application = ledger::sign_genesis(
            &keys[0],
            ledger::Genesis {
                version: 1,
                experiment_only: true,
                room_id: certificate.signed.room_id.clone(),
                network_salt: util::hash(b"seven operator CLI acceptance fixture"),
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
                                operator: format!("synthetic-operator-{i}"),
                                credit: 1000,
                            },
                        )
                    })
                    .collect(),
                parameters: ledger::Parameters::default(),
                bootstrap_balances: BTreeMap::new(),
            },
        )
        .unwrap();
        let machine = ledger::Machine::new(
            ledger::verify_genesis(application.clone(), &members[0].peer_id).unwrap(),
        )
        .unwrap();
        let chain = machine.genesis().chain_id().to_owned();
        let consensus = consensus::sign_genesis(
            &keys[0],
            consensus::Genesis {
                version: 1,
                chain_id: chain.clone(),
                application_genesis_hash: machine.genesis().genesis_hash().into(),
                initial_application_hash: machine.state_root().unwrap(),
                validators: members
                    .iter()
                    .enumerate()
                    .map(|(i, m)| consensus::Validator {
                        peer_id: m.peer_id.clone(),
                        public_key: m.public_key.clone(),
                        operator: format!("synthetic-operator-{i}"),
                    })
                    .collect(),
                fault_bound: 2,
                quorum: 5,
                timeout_ms: 3000,
                experiment_only: true,
            },
        )
        .unwrap();
        let settings = ledger_runtime::Settings {
            version: 1,
            room_alias: "experiment".into(),
            authority_peer_id: members[0].peer_id.clone(),
            application,
            consensus,
        };
        for home in &homes {
            ledger_runtime::configure(home, &settings).unwrap();
        }
        // Prepare independently signed/inspected knowledge before daemon startup.
        // All three R3 assignments exclude finder2, proving later IDs need remote
        // retrieval rather than caller-supplied packets or a local keeper copy.
        let mut stores = homes[..2]
            .iter()
            .map(|home| {
                let mut store = knowledge::Store::open(home).unwrap();
                let current = config::load(home).unwrap();
                store.set_operator_history(&current.knowledge_operator_history);
                store.set_rooms(current.rooms.into_values());
                store
            })
            .collect::<Vec<_>>();
        let records = std::array::from_fn(|kind| {
            for variant in 0..100 {
                let packet=knowledge::create_record(&keys[usize::from(kind == 2)],&room,KnowledgeInput {problem:format!("Private acceptance fixture task {kind} variant {variant}: which cache reset procedure is appropriate?"),solution:match kind {0=>"Find the documented safe cache reset procedure.",1=>"Accept an answer that stops the worker, clears only the cache, restarts the worker and verifies the result.",_=>"Stop the worker, clear only its cache, restart the worker, and verify the next successful result."}.into(),context:"Synthetic private test data. No commands are executed from this text.".into(),references:vec![],kind:if kind==2 {"answer"}else{"hint"}.into()},false,util::now()).unwrap();
                let id = packet.record.signed.id.clone();
                let keepers = knowledge::replica_peers(&certificate.signed, &id, 3);
                if !keepers.contains(&members[2].peer_id) {
                    assert!(
                        stores[usize::from(kind == 2)]
                            .insert(packet, true, util::now())
                            .unwrap()
                    );
                    return id;
                }
            }
            panic!("could not choose a deterministic nonkeeper fixture");
        });
        let endpoints = homes
            .iter()
            .map(|home| config::load(home).unwrap().endpoint)
            .collect();
        drop(stores);
        drop(listeners);
        Self {
            _temporary: temporary,
            executable,
            homes,
            endpoints,
            members,
            processes: (0..7).map(|_| None).collect(),
            records,
            chain,
        }
    }
    fn start(&mut self, i: usize) {
        assert!(self.processes[i].is_none());
        self.processes[i] = Some(
            Command::new(&self.executable)
                .args(["--home", self.homes[i].to_str().unwrap(), "daemon"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
    }
    fn stop(&mut self, i: usize) {
        if let Some(mut child) = self.processes[i].take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
    fn spawn_cli(&self, i: usize, args: &[&str], input: Option<Value>) -> Child {
        let mut child = Command::new(&self.executable)
            .args(["--socket", &self.endpoints[i]])
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        if let Some(input) = input {
            child
                .stdin
                .take()
                .unwrap()
                .write_all(&serde_json::to_vec(&input).unwrap())
                .unwrap();
        } else {
            drop(child.stdin.take());
        }
        child
    }
    fn finish(child: Child) -> CliReply {
        let output = child.wait_with_output().unwrap();
        let value = serde_json::from_slice(&output.stdout).unwrap_or_else(|_| {
            panic!(
                "CLI invalid output: {}",
                String::from_utf8_lossy(&output.stderr)
            )
        });
        CliReply {
            code: output.status.code().unwrap_or(-1),
            value,
        }
    }
    fn call(&self, i: usize, args: &[&str], input: Option<Value>) -> CliReply {
        Self::finish(self.spawn_cli(i, args, input))
    }
    fn wait(&self, label: &str, timeout: Duration, mut condition: impl FnMut() -> bool) {
        let until = Instant::now() + timeout;
        while Instant::now() < until {
            if condition() {
                eprintln!("ledger acceptance phase passed: {label}");
                return;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let states = (0..7)
            .filter(|i| self.processes[*i].is_some())
            .map(|i| (i, self.call(i, &["ledger", "status"], None).value))
            .collect::<Vec<_>>();
        let summaries=states.iter().map(|(node,state)|json!({"node":node,"application_height":state["application_height"],"consensus":state["consensus"],"status":state["status"],"reason":state["reason"],"balance":state["balance"],"total_minted":state["total_minted"],"pending_transactions":state["pending_transactions"],"queued_requests":state["queued_requests"],"pending_requests":state["pending_requests"],"seconds_since_commit":state["seconds_since_commit"],"performance":state["performance"]})).collect::<Vec<_>>();
        eprintln!(
            "ledger_acceptance_failure={}",
            json!({"phase":label,"nodes":summaries})
        );
        panic!("{label} timed out");
    }
    fn pending(reply: CliReply) -> String {
        assert_eq!(reply.code, 10, "{}", reply.value);
        assert_eq!(reply.value["status"], "pending");
        reply.value["transaction_id"].as_str().unwrap().to_owned()
    }
    fn judge_views(&self, question: &str, answer: &str) -> Vec<Value> {
        (3..6).map(|node| {
            let reply=self.call(node,&["ledger","get","--question",question],None);
            let height=self.call(node,&["ledger","balance"],None).value["application_height"].clone();
            let answers=reply.value["question"]["answers"].as_array();
            json!({"node":node,"reply_code":reply.code,"question_status":reply.value["status"],"local_height":height,"deadline_height":reply.value["question"]["deadline_height"],"answer_count":answers.map(Vec::len),"target_answer_visible":answers.is_some_and(|rows|rows.iter().any(|row|row["id"]==answer)),"closed_outcome":reply.value["question"]["outcome"]["status"]})
        }).collect()
    }
    fn confirmed(&self, i: usize, id: &str) -> Option<Value> {
        let reply = self.call(i, &["ledger", "tx", "--id", id], None);
        (reply.code == 0 && reply.value["status"] == "confirmed").then_some(reply.value)
    }
}
impl Drop for Cluster {
    fn drop(&mut self) {
        for i in 0..7 {
            self.stop(i);
        }
    }
}

#[test]
fn seven_operator_actual_daemon_cli_automatically_pays_offline_author_and_transfers() {
    let mut cluster = Cluster::new();
    for i in 0..7 {
        cluster.start(i);
    }
    cluster.wait(
        "authorized full-mesh readiness",
        Duration::from_secs(25),
        || {
            (0..7).all(|i| {
                let r = cluster.call(i, &["info"], None);
                r.code == 0
                    && r.value["connected_peers"].as_u64() == Some(6)
                    && r.value["ledger"]["status"] == "ready"
            })
        },
    );
    for i in 0..7 {
        let balance = cluster.call(i, &["ledger", "balance"], None);
        assert_eq!(balance.code, 0);
        assert_eq!(balance.value["balance"], 0);
    }
    cluster.wait(
        "three real keeper copies and nonkeeper handoff",
        Duration::from_secs(30),
        || {
            let states = (0..7)
                .map(|i| {
                    cluster
                        .call(i, &["knowledge", "status", "--room", "experiment"], None)
                        .value
                })
                .collect::<Vec<_>>();
            cluster.records.iter().all(|id| {
                let holders = states
                    .iter()
                    .enumerate()
                    .filter_map(|(i, s)| {
                        s["records"]
                            .as_array()
                            .and_then(|rows| rows.iter().find(|row| row["id"] == *id))
                            .map(|row| (i, row))
                    })
                    .collect::<Vec<_>>();
                holders.len() == 3
                    && holders.iter().all(|(i, row)| {
                        row["staging"] == false
                            && row["assigned_keepers"]
                                .as_array()
                                .unwrap()
                                .iter()
                                .any(|p| p == &cluster.members[*i].peer_id)
                    })
                    && holders.iter().all(|(i, _)| *i != 2)
            })
        },
    );
    let height = cluster.call(0, &["ledger", "status"], None).value["application_height"]
        .as_u64()
        .unwrap();
    assert!(
        height % 100 < 50,
        "fresh fixture unexpectedly advanced an epoch"
    );
    let question = ledger::question_id(&cluster.chain, &cluster.records[0]).unwrap();
    let ask=Cluster::pending(cluster.call(0,&["ledger","ask","--stdin"],Some(json!({"source_record_id":cluster.records[0],"criteria_record_id":cluster.records[1],"deadline_height":height+45,"bounty":0,"conflict_operators":[]}))));
    cluster.wait(
        "question commit with zero wallet and bounty",
        Duration::from_secs(30),
        || cluster.confirmed(0, &ask).is_some(),
    );
    cluster.wait(
        "question known before author goes offline",
        Duration::from_secs(25),
        || {
            (1..7).all(|i| {
                cluster
                    .call(i, &["ledger", "get", "--question", &question], None)
                    .value["status"]
                    == "open"
            })
        },
    );
    // Finder has never performed a get, and is not any of the three keepers.
    let finder_state = cluster.call(2, &["knowledge", "status", "--room", "experiment"], None);
    assert!(
        !finder_state.value["records"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["id"] == cluster.records[2])
    );
    cluster.stop(0);
    cluster.stop(1);
    let answer=Cluster::pending(cluster.call(2,&["ledger","answer","--stdin"],Some(json!({"question_id":question,"source_record_id":cluster.records[2],"beneficiary_peer_id":cluster.members[1].peer_id}))));
    cluster.wait(
        "nonkeeper finder answer commit while original author offline",
        Duration::from_secs(35),
        || cluster.confirmed(2, &answer).is_some(),
    );
    let before_visibility = cluster.judge_views(&question, &cluster.records[2]);
    eprintln!(
        "ledger_judge_visibility_before={}",
        json!(before_visibility)
    );
    cluster.wait(
        "three judges observe committed answer before voting",
        Duration::from_secs(30),
        || {
            let views = cluster.judge_views(&question, &cluster.records[2]);
            if views.iter().any(|view| view["question_status"] == "closed") {
                eprintln!("ledger_judge_known_closed_before_vote={}", json!(views));
                panic!("a judge already observes the question closed before voting");
            }
            views.iter().all(|view| {
                view["question_status"] == "open" && view["target_answer_visible"] == true
            })
        },
    );
    eprintln!(
        "ledger_judge_visibility_after={}",
        json!(cluster.judge_views(&question, &cluster.records[2]))
    );
    let judges = (3..6)
        .map(|i| {
            cluster.spawn_cli(
                i,
                &["ledger", "vote", "--stdin"],
                Some(
                    json!({"question":question,"answer":cluster.records[2],"verdict":"satisfied"}),
                ),
            )
        })
        .collect::<Vec<_>>();
    let votes = judges.into_iter().enumerate().map(|(offset,child)| {
        let reply=Cluster::finish(child);
        if reply.code!=10 || reply.value["status"]!="pending" {
            eprintln!("ledger_judge_vote_rejected={}",json!({"node":offset+3,"code":reply.code,"status":reply.value["status"],"error":reply.value["error"]}));
            eprintln!("ledger_judge_visibility_after_rejection={}",json!(cluster.judge_views(&question,&cluster.records[2])));
        }
        Cluster::pending(reply)
    }).collect::<Vec<_>>();
    cluster.wait(
        "three satisfaction votes auto settle without a separate settle command",
        Duration::from_secs(40),
        || {
            votes.iter().all(|id| cluster.confirmed(2, id).is_some())
                && cluster
                    .call(2, &["ledger", "get", "--question", &question], None)
                    .value["status"]
                    == "closed"
        },
    );
    let closed = cluster
        .call(2, &["ledger", "get", "--question", &question], None)
        .value;
    assert_eq!(
        closed["question"]["outcome"]["beneficiary_peer_id"],
        cluster.members[1].peer_id
    );
    assert_eq!(
        closed["question"]["outcome"]["submitted_by_peer_id"],
        cluster.members[2].peer_id
    );
    let status = cluster.call(2, &["ledger", "status"], None).value;
    assert_eq!(status["total_minted"], 1);
    assert_eq!(status["balance"], 0);
    let paid = cluster
        .call(
            2,
            &[
                "ledger",
                "balance",
                "--peer-id",
                &cluster.members[1].peer_id,
            ],
            None,
        )
        .value;
    assert_eq!(paid["balance"], 1);
    let settled = closed["question"]["outcome"]["settled_height"]
        .as_u64()
        .unwrap()
        .to_string();
    let blocks = cluster
        .call(
            2,
            &["ledger", "blocks", "--from", &settled, "--limit", "1"],
            None,
        )
        .value;
    assert_eq!(blocks["blocks"][0]["commit_votes"], 5);
    cluster.start(1);
    cluster.wait(
        "returning author's authenticated reward sync",
        Duration::from_secs(35),
        || cluster.call(1, &["ledger", "balance"], None).value["balance"] == 1,
    );
    let transfer = Cluster::pending(cluster.call(
        1,
        &["ledger", "transfer", "--stdin"],
        Some(json!({"to_peer_id":cluster.members[2].peer_id,"amount":1})),
    ));
    cluster.wait(
        "earned unit transfer commit",
        Duration::from_secs(30),
        || cluster.confirmed(1, &transfer).is_some(),
    );
    assert_eq!(
        cluster.call(1, &["ledger", "balance"], None).value["balance"],
        0
    );
    cluster.wait(
        "finder receives transferred unit",
        Duration::from_secs(20),
        || cluster.call(2, &["ledger", "balance"], None).value["balance"] == 1,
    );
    assert_eq!(
        cluster.call(2, &["ledger", "status"], None).value["total_minted"],
        1
    );
}
