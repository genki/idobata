//! 日常更新にroot/targets秘密鍵を渡さない、運用者用の限定署名器。
use idobata::util;
use libp2p::identity;
use serde::Serialize;
use serde_json::{Value, json};
use std::{collections::BTreeSet, path::Path};

fn canonical(v: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    v.serialize(&mut serde_json::Serializer::with_formatter(
        &mut out,
        olpc_cjson::CanonicalFormatter::new(),
    ))
    .unwrap();
    out
}
fn read(path: &Path) -> Value {
    serde_json::from_slice(&util::read_bounded(path, 262144).unwrap()).unwrap()
}
fn now() -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc()
}
fn valid_expiry(doc: &Value) {
    let end = time::OffsetDateTime::parse(
        doc["signed"]["expires"].as_str().unwrap(),
        &time::format_description::well_known::Rfc3339,
    )
    .unwrap();
    assert!(end > now(), "offline metadata expired");
}
fn verify(doc: &Value, role: &str, root: &Value) {
    let r = &root["signed"]["roles"][role];
    let bytes = canonical(&doc["signed"]);
    let mut seen = BTreeSet::new();
    for s in doc["signatures"].as_array().unwrap() {
        let id = s["keyid"].as_str().unwrap();
        if !r["keyids"].as_array().unwrap().contains(&json!(id)) {
            continue;
        }
        let k = &root["signed"]["keys"][id];
        assert_eq!(k["keytype"], "ed25519");
        assert_eq!(k["scheme"], "ed25519");
        let raw = hex::decode(k["keyval"]["public"].as_str().unwrap()).unwrap();
        let mut protobuf = vec![8, 1, 18, 32];
        protobuf.extend(raw);
        let public = identity::PublicKey::try_decode_protobuf(&protobuf).unwrap();
        if public.verify(&bytes, &hex::decode(s["sig"].as_str().unwrap()).unwrap()) {
            seen.insert(id);
        }
    }
    assert!(
        seen.len() >= r["threshold"].as_u64().unwrap() as usize,
        "untrusted metadata"
    );
}
fn sign(value: Value, role: &str, home: &Path, root: &Value) -> Value {
    let path = home.join(format!("{role}.key"));
    util::protected(&path).unwrap();
    let key = identity::Keypair::from_protobuf_encoding(&util::read_bounded(&path, 1024).unwrap())
        .unwrap();
    let public = key.public().encode_protobuf();
    assert_eq!(public.len(), 36);
    let data = json!({"keytype":"ed25519","scheme":"ed25519","keyval":{"public":hex::encode(&public[4..])}});
    let id = util::hash(&canonical(&data));
    let doc = json!({"signed":value,"signatures":[{"keyid":id,"sig":hex::encode(key.sign(&canonical(&value)).unwrap())}]});
    verify(&doc, role, root);
    doc
}
fn meta(value: &Value) -> Value {
    let bytes = canonical(value);
    json!({"version":value["signed"]["version"],"length":bytes.len(),"hashes":{"sha256":util::hash(&bytes)}})
}
fn expires(seconds: i64, root: &Value, targets: &Value) -> String {
    let parse = |d: &Value| {
        time::OffsetDateTime::parse(
            d["signed"]["expires"].as_str().unwrap(),
            &time::format_description::well_known::Rfc3339,
        )
        .unwrap()
    };
    (now() + time::Duration::seconds(seconds))
        .min(parse(root))
        .min(parse(targets))
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap()
}
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(args.len(), 3, "refresh-tuf ONLINE_KEYS METADATA_DIR");
    let home = Path::new(&args[1]);
    let out = Path::new(&args[2]);
    let root = read(&out.join("root.json"));
    let targets = read(&out.join("targets.json"));
    verify(&root, "root", &root);
    valid_expiry(&root);
    verify(&targets, "targets", &root);
    valid_expiry(&targets);
    let snapshot = read(&out.join("snapshot.json"));
    let timestamp = read(&out.join("timestamp.json"));
    verify(&snapshot, "snapshot", &root);
    verify(&timestamp, "timestamp", &root);
    assert_eq!(snapshot["signed"]["meta"]["targets.json"], meta(&targets));
    assert_eq!(
        timestamp["signed"]["meta"]["snapshot.json"],
        meta(&snapshot)
    );
    let version = snapshot["signed"]["version"]
        .as_u64()
        .unwrap()
        .max(timestamp["signed"]["version"].as_u64().unwrap())
        + 1;
    assert!(version < 9_007_199_254_740_991);
    let snapshot = sign(
        json!({"_type":"snapshot","spec_version":"1.0.0","version":version,
        "expires":expires(7*86400,&root,&targets),"meta":{"targets.json":meta(&targets)}}),
        "snapshot",
        home,
        &root,
    );
    let timestamp = sign(
        json!({"_type":"timestamp","spec_version":"1.0.0","version":version,
        "expires":expires(86400,&root,&targets),"meta":{"snapshot.json":meta(&snapshot)}}),
        "timestamp",
        home,
        &root,
    );
    util::atomic_write(&out.join("snapshot.json"), &canonical(&snapshot)).unwrap();
    util::atomic_write(&out.join("timestamp.json"), &canonical(&timestamp)).unwrap();
    println!(
        "{}",
        json!({"status":"refreshed","version":version,"target_count":targets["signed"]["targets"].as_object().unwrap().len()})
    );
}
