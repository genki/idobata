#![cfg(unix)]
//! Actual independent processes using production Noise codec and ledger Runtime.
//! Operator identities here are synthetic closed-experiment registrations; this
//! does not establish independence of the four real production hosts.
use futures::StreamExt;
use idobata::{
    config, crypto,
    error::Result,
    knowledge_abuse::OperatorClaims,
    knowledge_runtime, ledger, ledger_consensus as consensus, ledger_runtime,
    network::{self, BehaviourEvent},
    types::Member,
    util,
};
use libp2p::swarm::SwarmEvent;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{BufRead, BufReader, Write},
    path::PathBuf,
    process::{Child, ChildStdin, Command, Stdio},
    sync::mpsc,
    time::{Duration, Instant},
};

#[test]
fn ledger_fixture_child() {
    let Ok(home) = std::env::var("IDOBATA_TEST_LEDGER_HOME") else {
        return;
    };
    let home = PathBuf::from(home);
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async move {
  let _=rustls::crypto::ring::default_provider().install_default();
  let config=config::load(&home).unwrap();let key=crypto::load_key(&home).unwrap();let own=key.public().to_peer_id().to_string();
  let mut ledger=ledger_runtime::Runtime::open(&home,key.clone()).unwrap();let knowledge=knowledge_runtime::Runtime::open(&home,key.clone()).unwrap();
  let mut swarm=network::build(key,&config).await.unwrap();let mut allowed=BTreeSet::new();network::refresh(&mut swarm,&config,&mut allowed,&own);
  let (tx,mut rx)=tokio::sync::mpsc::channel(8);
  std::thread::spawn(move||{for line in std::io::stdin().lock().lines(){let Ok(line)=line else{break};if tx.blocking_send(line).is_err(){break}}});
  let mut poll=tokio::time::interval(Duration::from_millis(25));
  loop {tokio::select!{
   Some(line)=rx.recv()=>{let command:Value=serde_json::from_str(&line).unwrap();let value:Result<Value>=match command["action"].as_str().unwrap_or(""){
    "status"=>Ok(ledger.status()),
    "transfer"=>ledger.submit(ledger::Operation::Transfer{to_peer_id:command["to"].as_str().unwrap().into(),amount:command["amount"].as_u64().unwrap()},vec![]),
    "transaction"=>ledger.transaction(command["id"].as_str().unwrap()),
    _=>panic!("invalid test control"),};let result=match value{Ok(value)=>json!({"request":command["request"],"ok":true,"result":value}),Err(error)=>json!({"request":command["request"],"ok":false,"error":error})};println!("{}",result);},
   _=poll.tick()=>ledger.poll(&mut swarm,&knowledge),
   event=swarm.select_next_some()=>if let SwarmEvent::Behaviour(BehaviourEvent::Ledger(event))=event{ledger.event(event,&mut swarm)},
  }}
 });
}

struct Process {
    child: Child,
    input: ChildStdin,
    output: mpsc::Receiver<Value>,
    request: u64,
}
impl Process {
    fn start(home: &std::path::Path) -> Self {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "ledger_fixture_child", "--nocapture"])
            .env("IDOBATA_TEST_LEDGER_HOME", home)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let input = child.stdin.take().unwrap();
        let stdout = child.stdout.take().unwrap();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if let Ok(value) = serde_json::from_str::<Value>(&line)
                    && tx.send(value).is_err()
                {
                    break;
                }
            }
        });
        Self {
            child,
            input,
            output: rx,
            request: 0,
        }
    }
    fn call(&mut self, mut command: Value) -> Value {
        self.request += 1;
        command["request"] = self.request.into();
        writeln!(self.input, "{command}").unwrap();
        self.input.flush().unwrap();
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            let value = self
                .output
                .recv_timeout(until.saturating_duration_since(Instant::now()))
                .expect("ledger child RPC timeout");
            if value["request"] == self.request {
                return value;
            }
        }
    }
    fn status(&mut self) -> Value {
        let value = self.call(json!({"action":"status"}));
        assert_eq!(value["ok"], true, "{value}");
        value["result"].clone()
    }
    fn stop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
impl Drop for Process {
    fn drop(&mut self) {
        self.stop();
    }
}

struct Cluster {
    _temporary: tempfile::TempDir,
    homes: Vec<PathBuf>,
    members: Vec<Member>,
    processes: Vec<Option<Process>>,
}
impl Cluster {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let listeners = (0..4)
            .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
            .collect::<Vec<_>>();
        let homes = (0..4)
            .map(|i| temporary.path().join(format!("ledger-{i}")))
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
            credits: (0..4)
                .map(|i| (format!("synthetic-operator-{i}"), 1000))
                .collect(),
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
                network_salt: util::hash(b"actual process test"),
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
                bootstrap_balances: members
                    .iter()
                    .map(|m| (m.peer_id.clone(), 10))
                    .collect::<BTreeMap<_, _>>(),
            },
        )
        .unwrap();
        let machine = ledger::Machine::new(
            ledger::verify_genesis(application.clone(), &members[0].peer_id).unwrap(),
        )
        .unwrap();
        let genesis = consensus::sign_genesis(
            &keys[0],
            consensus::Genesis {
                version: 1,
                chain_id: machine.genesis().chain_id().into(),
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
                fault_bound: 1,
                quorum: 3,
                timeout_ms: 5000,
                experiment_only: true,
            },
        )
        .unwrap();
        let settings = ledger_runtime::Settings {
            version: 1,
            room_alias: "ledger".into(),
            authority_peer_id: members[0].peer_id.clone(),
            application,
            consensus: genesis,
        };
        for home in &homes {
            ledger_runtime::configure(home, &settings).unwrap();
        }
        drop(listeners);
        Self {
            _temporary: temporary,
            homes,
            members,
            processes: (0..4).map(|_| None).collect(),
        }
    }
    fn start(&mut self, i: usize) {
        assert!(self.processes[i].is_none());
        let mut process = Process::start(&self.homes[i]);
        let status = process.status();
        assert_eq!(status["status"], "ready", "{status}");
        self.processes[i] = Some(process);
    }
    fn stop(&mut self, i: usize) {
        if let Some(mut process) = self.processes[i].take() {
            process.stop();
        }
    }
    fn statuses(&mut self) -> Vec<Value> {
        self.processes
            .iter_mut()
            .filter_map(|p| p.as_mut().map(Process::status))
            .collect()
    }
    fn wait_balance(&mut self, index: usize, amount: u64) {
        let until = Instant::now() + Duration::from_secs(40);
        loop {
            let status = self.processes[index].as_mut().unwrap().status();
            if status["balance"] == amount {
                return;
            }
            assert!(
                Instant::now() < until,
                "ledger balance did not converge: {:?}",
                self.statuses()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

#[test]
fn four_process_noise_consensus_transfer_partition_hold_and_restart_sync() {
    let mut cluster = Cluster::new();
    for i in 0..4 {
        cluster.start(i);
    }
    let until = Instant::now() + Duration::from_secs(30);
    loop {
        let statuses = cluster.statuses();
        if statuses
            .iter()
            .all(|s| s["application_height"].as_u64().unwrap() > 0)
        {
            break;
        }
        assert!(
            Instant::now() < until,
            "four-process consensus stalled: {statuses:?}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    let recipient = cluster.members[1].peer_id.clone();
    let response = cluster.processes[0]
        .as_mut()
        .unwrap()
        .call(json!({"action":"transfer","to":recipient,"amount":1}));
    assert_eq!(response["ok"], true, "{response}");
    let first = response["result"]["transaction_id"]
        .as_str()
        .unwrap()
        .to_owned();
    cluster.wait_balance(0, 9);
    cluster.wait_balance(1, 11);
    cluster.stop(3);
    let response = cluster.processes[0]
        .as_mut()
        .unwrap()
        .call(json!({"action":"transfer","to":recipient,"amount":1}));
    assert_eq!(response["ok"], true, "{response}");
    cluster.wait_balance(0, 8);
    cluster.wait_balance(1, 12);
    cluster.start(3);
    let until = Instant::now() + Duration::from_secs(40);
    loop {
        let response = cluster.processes[3]
            .as_mut()
            .unwrap()
            .call(json!({"action":"transaction","id":first}));
        if response["result"]["status"] == "confirmed" {
            break;
        }
        assert!(
            Instant::now() < until,
            "restarted process did not sync: {response}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
    cluster.stop(3);
    cluster.stop(2);
    let response = cluster.processes[0]
        .as_mut()
        .unwrap()
        .call(json!({"action":"transfer","to":recipient,"amount":1}));
    assert_eq!(response["ok"], true, "{response}");
    let held = response["result"]["transaction_id"]
        .as_str()
        .unwrap()
        .to_owned();
    std::thread::sleep(Duration::from_secs(6));
    assert_eq!(
        cluster.processes[0].as_mut().unwrap().status()["balance"],
        8
    );
    assert_eq!(
        cluster.processes[1].as_mut().unwrap().status()["balance"],
        12
    );
    let state = cluster.processes[0]
        .as_mut()
        .unwrap()
        .call(json!({"action":"transaction","id":held}));
    assert_eq!(state["result"]["status"], "pending", "{state}");
    cluster.start(2);
    cluster.wait_balance(0, 7);
    cluster.wait_balance(1, 13);
}
