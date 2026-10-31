use idobata::{config, knowledge_abuse::OperatorClaims, util};
use std::{
    collections::BTreeMap,
    fs::OpenOptions,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[test]
fn concurrent_admin_cli_updates_preserve_operator_history_and_epoch() {
    let temporary = tempfile::tempdir().unwrap();
    let home = temporary.path().join("node");
    let member = config::init(&home, vec!["/ip4/127.0.0.1/tcp/39140".into()]).unwrap();
    let members = temporary.path().join("members.json");
    let operators = temporary.path().join("operators.json");
    util::atomic_write(
        &members,
        &serde_json::to_vec(&vec![member.clone()]).unwrap(),
    )
    .unwrap();
    let policy = OperatorClaims {
        bindings: BTreeMap::from([(member.peer_id.clone(), "s21g".into())]),
        credits: BTreeMap::from([("s21g".into(), 700)]),
    };
    util::atomic_write(&operators, &serde_json::to_vec(&policy).unwrap()).unwrap();
    let guard = OpenOptions::new()
        .read(true)
        .write(true)
        .open(home.join("config.lock"))
        .unwrap();
    fs2::FileExt::lock_exclusive(&guard).unwrap();
    let mut children = Vec::new();
    for index in 0..2 {
        children.push(
            Command::new(env!("CARGO_BIN_EXE_idobata"))
                .arg("--home")
                .arg(&home)
                .args(["room", "invite", "--room", "race", "--members-file"])
                .arg(&members)
                .arg("--operators-file")
                .arg(&operators)
                .arg("--output")
                .arg(temporary.path().join(format!("invite-{index}.json")))
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
    }
    std::thread::sleep(Duration::from_millis(100));
    let both_waited_for_guard = children
        .iter_mut()
        .all(|child| child.try_wait().unwrap().is_none());
    drop(guard);
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut success = true;
    for child in &mut children {
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                success &= status.success();
                break;
            }
            if Instant::now() > deadline {
                child.kill().unwrap();
                child.wait().unwrap();
                success = false;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    assert!(both_waited_for_guard);
    assert!(success);
    let saved = config::load(&home).unwrap();
    let room = &saved.rooms["race"].certificate.signed;
    assert_eq!(room.version, 4);
    assert_eq!(room.epoch, 2);
    assert_eq!(room.knowledge_operators, Some(policy));
    let history = &saved.knowledge_operator_history[&room.room_id];
    assert_eq!(history.epoch, 2);
    assert_eq!(history.bindings[&member.peer_id], "s21g");
    assert_eq!(
        history.certificate_digest,
        util::hash(&util::canonical(&saved.rooms["race"].certificate).unwrap())
    );
}
