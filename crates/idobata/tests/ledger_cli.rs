#![cfg(unix)]
//! Actual CLI/IPC framing regression for uncertain mutations. A missing response
//! must never tell an agent that it is safe to repeat a wallet transfer.
use idobata::{
    ledger::Operation,
    types::{Reply, Request},
};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    os::unix::net::UnixListener,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[test]
fn uncertain_transfer_and_pending_transfer_remain_nonzero_and_distinct() {
    for lose_response in [true, false] {
        let temporary = tempfile::tempdir().unwrap();
        let socket = temporary.path().join("ipc.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let server = std::thread::spawn(move || {
            let until = Instant::now() + Duration::from_secs(5);
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && Instant::now() < until =>
                    {
                        std::thread::sleep(Duration::from_millis(10))
                    }
                    Err(error) => panic!("CLI did not connect: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut header = [0; 4];
            stream.read_exact(&mut header).unwrap();
            let length = u32::from_be_bytes(header) as usize;
            assert!(length <= 65536);
            let mut bytes = vec![0; length];
            stream.read_exact(&mut bytes).unwrap();
            let request: Request = serde_json::from_slice(&bytes).unwrap();
            assert!(matches!(
                request,
                Request::LedgerSubmit {
                    operation: Operation::Transfer { amount: 1, .. }
                }
            ));
            if !lose_response {
                let bytes = serde_json::to_vec(&Reply::new(
                    10,
                    json!({"status":"pending","transaction_id":"a".repeat(64),"finalized":false}),
                ))
                .unwrap();
                stream
                    .write_all(&(bytes.len() as u32).to_be_bytes())
                    .unwrap();
                stream.write_all(&bytes).unwrap();
            }
        });
        let mut child = Command::new(env!("CARGO_BIN_EXE_idobata"))
            .args([
                "--socket",
                socket.to_str().unwrap(),
                "ledger",
                "transfer",
                "--stdin",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(br#"{"to_peer_id":"recipient","amount":1}"#)
            .unwrap();
        let output = child.wait_with_output().unwrap();
        server.join().unwrap();
        let value: Value = serde_json::from_slice(&output.stdout).unwrap();
        if lose_response {
            assert_eq!(output.status.code(), Some(40));
            assert_eq!(value["status"], "unknown");
            assert!(value["enqueued"].is_null());
            assert!(value["finalized"].is_null());
            assert!(value["retry_policy"].as_str().unwrap().contains("nonce"));
        } else {
            assert_eq!(output.status.code(), Some(10));
            assert_eq!(value["status"], "pending");
            assert_eq!(value["finalized"], false);
        }
    }
}

#[test]
fn explicit_owner_can_create_signed_zero_bootstrap_settings_without_configuring_or_issuing() {
    use idobata::{config, crypto, ledger, ledger_consensus as consensus, ledger_runtime, util};
    use std::collections::BTreeMap;
    let temporary = tempfile::tempdir().unwrap();
    let home = temporary.path().join("authority");
    config::init(&home, vec!["/ip4/127.0.0.1/tcp/35000".into()]).unwrap();
    let authority = crypto::load_key(&home).unwrap();
    let keys = std::iter::once(authority.clone())
        .chain((0..6).map(|_| libp2p::identity::Keypair::generate_ed25519()))
        .collect::<Vec<_>>();
    let participants = keys
        .iter()
        .enumerate()
        .map(|(i, key)| {
            (
                key.public().to_peer_id().to_string(),
                ledger::Participant {
                    public_key: crypto::public(key),
                    operator: format!("fixture-{i}"),
                    credit: 1000,
                },
            )
        })
        .collect::<BTreeMap<_, _>>();
    let genesis = ledger::Genesis {
        version: 1,
        experiment_only: true,
        room_id: util::hash(b"explicit private room fixture"),
        network_salt: util::hash(b"CLI initialization fixture"),
        authority_peer_id: authority.public().to_peer_id().to_string(),
        operator_epoch: 1,
        participants,
        parameters: ledger::Parameters::default(),
        bootstrap_balances: BTreeMap::new(),
    };
    let validators = keys
        .iter()
        .enumerate()
        .map(|(i, key)| consensus::Validator {
            peer_id: key.public().to_peer_id().to_string(),
            public_key: crypto::public(key),
            operator: format!("fixture-{i}"),
        })
        .collect::<Vec<_>>();
    let input = temporary.path().join("application.json");
    let validators_file = temporary.path().join("validators.json");
    let settings_file = temporary.path().join("settings.json");
    std::fs::write(&input, util::canonical(&genesis).unwrap()).unwrap();
    std::fs::write(&validators_file, util::canonical(&validators).unwrap()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_idobata"))
        .args([
            "--home",
            home.to_str().unwrap(),
            "ledger",
            "genesis",
            "--input",
            input.to_str().unwrap(),
            "--validators-file",
            validators_file.to_str().unwrap(),
            "--room",
            "experiment",
            "--output",
            settings_file.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["bootstrap_units"], 0);
    assert_eq!(value["configured"], false);
    let settings: ledger_runtime::Settings =
        serde_json::from_slice(&std::fs::read(&settings_file).unwrap()).unwrap();
    let machine = ledger::Machine::new(
        ledger::verify_genesis(settings.application.clone(), &genesis.authority_peer_id).unwrap(),
    )
    .unwrap();
    assert_eq!(machine.state().total_minted, 0);
    assert!(machine.state().balances.values().all(|n| *n == 0));
    assert_eq!(settings.consensus.signed.fault_bound, 2);
    assert_eq!(settings.consensus.signed.quorum, 5);
    assert_eq!(
        settings.consensus.signed.initial_application_hash,
        machine.state_root().unwrap()
    );
    crypto::verify(
        &authority.public(),
        "idobata.ledger.genesis.v1",
        &settings.consensus.signed,
        &settings.consensus.signature,
    )
    .unwrap();
    assert!(!home.join("ledger-settings.json").exists());
}
