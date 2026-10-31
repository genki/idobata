//! TUFの検証はtoughへ委ね、検証済みの完全なtargetだけを保存する。
use crate::{
    error::{Error, INVALID, Result, STORAGE},
    util,
};
use futures::TryStreamExt;
use libp2p::identity;
use serde::Serialize;
use serde_json::{Value, json};
use std::{collections::BTreeMap, path::Path};
use tough::{Transport, TransportError, TransportErrorKind, TransportStream};
use url::Url;

fn canonical(value: &Value) -> Result<Vec<u8>> {
    let mut out = vec![];
    let mut serializer =
        serde_json::Serializer::with_formatter(&mut out, olpc_cjson::CanonicalFormatter::new());
    value.serialize(&mut serializer).map_err(|_| INVALID)?;
    Ok(out)
}
fn key(home: &Path, role: &str) -> Result<identity::Keypair> {
    let path = home.join(format!("{role}.key"));
    if !path.exists() {
        let key = identity::Keypair::generate_ed25519();
        util::atomic_write(&path, &key.to_protobuf_encoding().map_err(|_| STORAGE)?)?;
    }
    util::protected(&path)?;
    identity::Keypair::from_protobuf_encoding(&util::read_bounded(&path, 1024)?)
        .map_err(|_| INVALID)
}
fn public(key: &identity::Keypair) -> Result<(String, Value)> {
    let public = key.public().encode_protobuf();
    if public.len() != 36 {
        return Err(INVALID);
    }
    let data = json!({"keytype":"ed25519","scheme":"ed25519","keyval":{"public":hex::encode(&public[4..])}});
    Ok((util::hash(&canonical(&data)?), data))
}
fn signed(value: Value, key: &identity::Keypair) -> Result<Value> {
    let bytes = canonical(&value)?;
    Ok(json!({"signed":value,"signatures":[{"keyid":public(key)?.0,
        "sig":hex::encode(key.sign(&bytes).map_err(|_|INVALID)?)}]}))
}
fn expiry(seconds: u64) -> Result<String> {
    time::OffsetDateTime::from_unix_timestamp((util::now() + seconds) as i64)
        .map_err(|_| INVALID)?
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|_| INVALID)
}
fn meta(value: &Value) -> Result<Value> {
    let bytes = canonical(value)?;
    Ok(
        json!({"version":value["signed"]["version"],"length":bytes.len(),"hashes":{"sha256":util::hash(&bytes)}}),
    )
}
pub fn create(keys_home: &Path, targets_dir: &Path, out: &Path, version: u64) -> Result<Value> {
    if version == 0 || version > 9_007_199_254_740_991 {
        return Err(INVALID);
    }
    util::private_dir(keys_home)?;
    std::fs::create_dir_all(out).map_err(|_| STORAGE)?;
    let previous = out.join("timestamp.json");
    if previous.exists() {
        let old: Value =
            serde_json::from_slice(&util::read_bounded(&previous, 262144)?).map_err(|_| INVALID)?;
        if old["signed"]["version"]
            .as_u64()
            .is_none_or(|v| version <= v)
        {
            return Err(INVALID);
        }
    }
    let mut keys = BTreeMap::new();
    let mut roles = BTreeMap::new();
    let mut private = BTreeMap::new();
    for role in ["root", "targets", "snapshot", "timestamp"] {
        let key = key(keys_home, role)?;
        let (id, public) = public(&key)?;
        keys.insert(id.clone(), public);
        roles.insert(role, json!({"keyids":[id],"threshold":1}));
        private.insert(role, key);
    }
    let root_path = out.join("root.json");
    let root = if root_path.exists() {
        let value: Value = serde_json::from_slice(&util::read_bounded(&root_path, 262144)?)
            .map_err(|_| INVALID)?;
        if value["signed"]["keys"] != json!(keys) {
            return Err(INVALID);
        }
        value
    } else {
        signed(
            json!({"_type":"root","spec_version":"1.0.0","version":1,
            "expires":expiry(365*86400)?,"consistent_snapshot":false,"keys":keys,"roles":roles}),
            &private["root"],
        )?
    };
    let mut targets = BTreeMap::new();
    for entry in std::fs::read_dir(targets_dir).map_err(|_| STORAGE)? {
        let entry = entry.map_err(|_| STORAGE)?;
        let name = entry.file_name().into_string().map_err(|_| INVALID)?;
        if !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
            || name.starts_with('.')
        {
            return Err(INVALID);
        }
        let bytes = util::read_bounded(&entry.path(), 128 * 1024 * 1024)?;
        targets.insert(
            name,
            json!({"length":bytes.len(),"hashes":{"sha256":util::hash(&bytes)}}),
        );
    }
    if targets.is_empty() || targets.len() > 32 {
        return Err(INVALID);
    }
    let targets = signed(
        json!({"_type":"targets","spec_version":"1.0.0","version":version,
        "expires":expiry(90*86400)?,"targets":targets}),
        &private["targets"],
    )?;
    let snapshot = signed(
        json!({"_type":"snapshot","spec_version":"1.0.0","version":version,
        "expires":expiry(7*86400)?,"meta":{"targets.json":meta(&targets)?}}),
        &private["snapshot"],
    )?;
    let timestamp = signed(
        json!({"_type":"timestamp","spec_version":"1.0.0","version":version,
        "expires":expiry(86400)?,"meta":{"snapshot.json":meta(&snapshot)?}}),
        &private["timestamp"],
    )?;
    for (name, value) in [
        ("root.json", &root),
        ("1.root.json", &root),
        ("targets.json", &targets),
        ("snapshot.json", &snapshot),
        ("timestamp.json", &timestamp),
    ] {
        util::atomic_write(&out.join(name), &canonical(value)?)?;
    }
    Ok(
        json!({"status":"signed","version":version,"root_sha256":util::hash(&canonical(&root)?),
        "target_count":targets["signed"]["targets"].as_object().ok_or(INVALID)?.len()}),
    )
}

#[derive(Clone, Debug)]
struct Http {
    client: reqwest::Client,
}
#[async_trait::async_trait]
impl Transport for Http {
    async fn fetch(&self, url: Url) -> std::result::Result<TransportStream, TransportError> {
        if url.scheme() == "file" {
            return tough::FilesystemTransport.fetch(url).await;
        }
        let fail = |kind| TransportError::new(kind, url.as_str());
        if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
            return Err(fail(TransportErrorKind::UnsupportedUrlScheme));
        }
        let response = self
            .client
            .get(url.clone())
            .send()
            .await
            .map_err(|_| fail(TransportErrorKind::Other))?;
        if response.status() == 404 {
            return Err(fail(TransportErrorKind::FileNotFound));
        }
        if !response.status().is_success() {
            return Err(fail(TransportErrorKind::Other));
        }
        let origin = url.to_string();
        Ok(Box::pin(response.bytes_stream().map_err(move |_| {
            TransportError::new(TransportErrorKind::Other, origin.clone())
        })))
    }
}
pub async fn download(
    root_file: &Path,
    metadata: &str,
    targets: &str,
    target: &str,
    state: &Path,
    output: &Path,
) -> Result<Value> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    if output.exists() {
        return Err(Error::new(30, "output_already_exists"));
    }
    util::private_dir(state)?;
    let root = util::read_bounded(root_file, 262144)?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 8 || attempt.url().scheme() != "https" {
                attempt.stop()
            } else {
                attempt.follow()
            }
        }))
        .build()
        .map_err(|_| INVALID)?;
    let repository = tough::RepositoryLoader::new(
        &root,
        Url::parse(metadata).map_err(|_| INVALID)?,
        Url::parse(targets).map_err(|_| INVALID)?,
    )
    .datastore(state)
    .transport(Http { client })
    .load()
    .await
    .map_err(|_| Error::new(30, "tuf_metadata_rejected"))?;
    let name = tough::TargetName::new(target).map_err(|_| INVALID)?;
    let target_meta = repository
        .targets()
        .signed
        .targets
        .get(&name)
        .ok_or(INVALID)?;
    if target_meta.length > 128 * 1024 * 1024 {
        return Err(INVALID);
    }
    let mut stream = repository
        .read_target(&name)
        .await
        .map_err(|_| INVALID)?
        .ok_or(INVALID)?;
    let mut bytes = Vec::new();
    while let Some(chunk) = stream
        .try_next()
        .await
        .map_err(|_| Error::new(30, "tuf_target_rejected"))?
    {
        if bytes.len() + chunk.len() > 128 * 1024 * 1024 {
            return Err(INVALID);
        }
        bytes.extend_from_slice(&chunk);
    }
    // 検証済みstreamが完全に終わるまで出力先を作らない。
    util::atomic_write(output, &bytes)?;
    Ok(json!({"status":"verified","target":target,"bytes":bytes.len(),"sha256":util::hash(&bytes)}))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn tuf_end_to_end_checks_hash_signature_expiry_and_persisted_rollback() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path();
        let keys = base.join("keys");
        let targets = base.join("targets");
        let metadata = base.join("metadata");
        std::fs::create_dir(&targets).unwrap();
        std::fs::write(targets.join("fixture.bin"), b"public fixture").unwrap();
        create(&keys, &targets, &metadata, 1).unwrap();
        let root = metadata.join("root.json");
        let meta_url = Url::from_directory_path(&metadata).unwrap().to_string();
        let target_url = Url::from_directory_path(&targets).unwrap().to_string();
        let state = base.join("cache");
        let output = base.join("download.bin");
        download(
            &root,
            &meta_url,
            &target_url,
            "fixture.bin",
            &state,
            &output,
        )
        .await
        .unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), b"public fixture");
        std::fs::write(targets.join("fixture.bin"), b"tampered fixture").unwrap();
        let failed = base.join("tampered.bin");
        assert!(
            download(
                &root,
                &meta_url,
                &target_url,
                "fixture.bin",
                &state,
                &failed
            )
            .await
            .is_err()
        );
        assert!(!failed.exists());
        std::fs::write(targets.join("fixture.bin"), b"public fixture").unwrap();
        let old_timestamp = std::fs::read(metadata.join("timestamp.json")).unwrap();
        create(&keys, &targets, &metadata, 2).unwrap();
        download(
            &root,
            &meta_url,
            &target_url,
            "fixture.bin",
            &state,
            &base.join("new.bin"),
        )
        .await
        .unwrap();
        let current: Value =
            serde_json::from_slice(&std::fs::read(metadata.join("timestamp.json")).unwrap())
                .unwrap();
        std::fs::write(metadata.join("timestamp.json"), old_timestamp).unwrap();
        assert!(
            download(
                &root,
                &meta_url,
                &target_url,
                "fixture.bin",
                &state,
                &base.join("rollback.bin")
            )
            .await
            .is_err()
        );
        let mut expired = current["signed"].clone();
        expired["expires"] = "2020-01-01T00:00:00Z".into();
        let expired = signed(expired, &key(&keys, "timestamp").unwrap()).unwrap();
        std::fs::write(
            metadata.join("timestamp.json"),
            canonical(&expired).unwrap(),
        )
        .unwrap();
        assert!(
            download(
                &root,
                &meta_url,
                &target_url,
                "fixture.bin",
                &base.join("fresh-cache"),
                &base.join("expired.bin")
            )
            .await
            .is_err()
        );
    }
}
